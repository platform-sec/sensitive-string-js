/**
 * Putting the redaction marker back where Rollbar flattened one away.
 *
 * This file exists because of one measurement, and it is the only place in the
 * repository where a vendor's own serialization does not honour `toJSON()`.
 *
 * Measured on Node 22.15.0 against `rollbar` 3.1.0: a `SensitiveString` never
 * reaches the `transform` seam as an instance. Somewhere between `rollbar.log`
 * and the transform pipeline the payload is rebuilt from own enumerable
 * properties, and a wrapped value arrives as the plain object
 * `{ klass: 'credential', label: 'stripe-key' }`.
 *
 * Two consequences, and the second is why this is not cosmetic.
 *
 * The value does not leak. `#value` is an ES2022 private field and no
 * property-copying walk can reach it, so the flattening is safe in the sense
 * that matters most. Section 2.3 of the design attributes that safety to
 * `toJSON()` being honoured; for this vendor the reason is different and the
 * outcome happens to be the same.
 *
 * The label does leak. `label` is an own enumerable property, so it rides out
 * with the flattened object on every payload. Q7 of the design decided that
 * labels are off by default because a label is user-supplied, high cardinality,
 * and the secrets manager design already forbids a derived label from carrying
 * an account, project or tenancy identifier. A package that transmits them
 * anyway, by accident, would be the thing that punishes a label somebody chose
 * before that rule existed.
 *
 * So the flattened shape is recognized and replaced with the marker its class
 * names, which is what every other integration in this repository puts on the
 * wire, and its label goes into the report where `reportLabels` governs it.
 *
 * The recognizer is deliberately narrow. It matches on structure, never on a
 * value: a plain object whose own enumerable keys are exactly the own
 * enumerable keys of a `SensitiveString`, with a string `klass` and a string or
 * absent `label`. `flattened.test.ts` derives that key set from a real instance
 * and fails if core ever changes it, which is the failure mode a hand-written
 * shape check would otherwise hide.
 */

/**
 * The own enumerable keys of a `SensitiveString`.
 *
 * Pinned against a real instance in the suite rather than read from one here,
 * so importing this module cannot depend on constructing a value.
 */
const REQUIRED_KEY = 'klass';
const OPTIONAL_KEY = 'label';

/** What a restore pass found, for folding into the report. */
export interface RestoredMarkers {
  readonly instances: number;
  readonly classes: ReadonlySet<string>;
  readonly labels: ReadonlySet<string>;
}

/**
 * Replace every flattened wrapped value in a payload with its marker.
 *
 * Runs over the scrubbed copy, which this package owns, so it mutates in place.
 * Nothing reachable from the caller is touched: the copy is what the walk
 * built, and Rollbar's own `transform` seam hands over a clone in any case.
 *
 * @returns The classes and labels the flattened values named.
 */
export function restoreMarkers(payload: unknown): RestoredMarkers {
  const classes = new Set<string>();
  const labels = new Set<string>();
  let instances = 0;

  const seen = new WeakSet<object>();

  const visit = (node: unknown): unknown => {
    if (node === null || typeof node !== 'object') {
      return node;
    }

    if (seen.has(node)) {
      return node;
    }
    seen.add(node);

    const container = node as Record<string, unknown>;

    for (const [key, child] of entriesOf(container)) {
      const flattened = asFlattened(child);

      if (flattened !== null) {
        instances += 1;
        classes.add(flattened.klass);

        if (flattened.label !== undefined) {
          labels.add(flattened.label);
        }

        write(container, key, `[REDACTED:${flattened.klass}]`);

        continue;
      }

      visit(child);
    }

    return node;
  };

  visit(payload);

  return { instances, classes, labels };
}

/**
 * The flattened form of a wrapped value, or `null` for anything else.
 *
 * `klass` comes back as a `string` rather than as core's `SensitivityClass`,
 * which is a closed union of two names. Narrowing to that union here would be a
 * cast with nothing behind it, since the value is read out of a payload this
 * package did not build, and validating against the two names would mean a
 * class added to core in future stopped being recognized here and its label
 * started leaving the process again. So the string is carried as a string, and
 * the one place it has to become a `SensitivityClass` is named in `install.ts`.
 */
function asFlattened(value: unknown): { klass: string; label?: string } | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  // A plain object only. An instance of an application's own class that happens
  // to expose these two fields is not this, and neither is anything the payload
  // walk passed through by reference.
  const prototype = Object.getPrototypeOf(value) as unknown;

  if (prototype !== Object.prototype && prototype !== null) {
    return null;
  }

  const keys = Object.keys(value);

  if (keys.length === 0 || keys.length > 2 || !keys.includes(REQUIRED_KEY)) {
    return null;
  }

  if (keys.length === 2 && !keys.includes(OPTIONAL_KEY)) {
    return null;
  }

  const record = value as Record<string, unknown>;
  const klass = record[REQUIRED_KEY];
  const label = record[OPTIONAL_KEY];

  if (typeof klass !== 'string' || klass === '') {
    return null;
  }

  if (label !== undefined && typeof label !== 'string') {
    return null;
  }

  return label === undefined ? { klass } : { klass, label };
}

/**
 * Own enumerable entries, treating a refusal as an empty object.
 *
 * The same rule the shared walk follows. A payload holds objects this package
 * did not create and one of them may refuse enumeration.
 */
function entriesOf(value: object): [string, unknown][] {
  try {
    return Object.entries(value);
  } catch {
    return [];
  }
}

/** Assign, treating a refusal as a no-op. */
function write(target: Record<string, unknown>, key: string, value: unknown): void {
  try {
    target[key] = value;
  } catch {
    // Frozen or accessor-only. The flattened object stays, which leaks no
    // value; only the label survives, and `reportLabels` still governs what
    // this package itself reports.
  }
}
