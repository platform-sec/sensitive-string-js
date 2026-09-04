import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { probeProperty } from '@platform-sec/sensitive-string-env';
import { makeValidator } from 'envalid';
import type { RequiredValidatorSpec } from 'envalid';

import { SensitiveFormatError } from './errors.js';

/**
 * Validators that produce a `SensitiveString`, and the four options they refuse.
 *
 * Built on envalid's own `makeValidator`, so the class parameter survives into
 * the inferred type of `cleanEnvSafe`'s result. A generic factory typed as
 * `Function` would throw that away, and the point of the integration is that
 * `env.DB_PASSWORD` is a `SensitiveString<'credential'>` to the type checker as
 * well as at runtime.
 */

/**
 * The key a sensitive spec carries so `cleanEnvSafe` can find its class.
 *
 * A string key rather than a symbol. envalid builds a spec with
 * `tslib.__assign({}, spec, { _parse })`, and tslib's own fallback for
 * `Object.assign` copies own enumerable **string** keys only, so a
 * symbol-keyed marker would survive on a modern runtime and vanish on one
 * where tslib's polyfill is in play. The key holds a class and a label. It
 * never holds a value.
 */
const SENSITIVE_META = '__sensitiveStringMeta';

/** What the adapter needs to know about a spec after envalid has copied it. */
export interface SensitiveMeta {
  readonly klass: SensitivityClass;
  /** The caller's label, or `undefined` to fall back to the variable's name. */
  readonly label: string | undefined;
  /** The raw development fallback, when one was given. */
  readonly sensitiveDefault: string | undefined;
  /**
   * Rebuild the parse function bound to a variable name.
   *
   * A validator cannot see its own name: envalid calls `spec._parse(rawValue)`
   * and nothing else. Binding the name here is what lets the label default to
   * it, which is what `loadEnv` does on the other half of this row and what
   * makes an audit record say `SensitiveString<credential:DB_PASSWORD>` rather
   * than `SensitiveString<credential>`.
   */
  bind(name: string): (input: string) => SensitiveString<SensitivityClass>;
}

/** A check that runs on the raw string, before it is wrapped. */
export interface SensitiveFormat {
  /**
   * Whether the raw value is acceptable.
   *
   * If this throws, the throw is caught and replaced: a check written as
   * `(raw) => Boolean(new URL(raw))` throws a `TypeError` whose message holds
   * the input.
   */
  check(raw: string): boolean;
  /**
   * A fixed phrase naming the check, used in the failure message.
   *
   * Never derive it from the value.
   */
  readonly detail: string;
}

/** Options a sensitive validator accepts, and the four it refuses. */
export interface SensitiveSpec {
  /** Audit label. Defaults to the variable's own name. */
  readonly label?: string;
  /** A description, used only in the message for an absent variable. */
  readonly desc?: string;
  /** An example value, used only in the message for an absent variable. */
  readonly example?: string;
  /** A documentation URL, used only in the message for an absent variable. */
  readonly docs?: string;
  /**
   * A fallback for when the variable is absent, wrapped like a parsed value.
   *
   * envalid's own `default` is refused, because it is assigned **without
   * passing through validation**: `credential({ default: 'dev-fallback' })`
   * types as `SensitiveString<'credential'>` and produces a raw `string` at
   * run time. Every later `.reveal()` throws a `TypeError`, every log line
   * prints the development key, and nothing about the failure points at the
   * default. This option is the same convenience without the type erosion.
   */
  readonly sensitiveDefault?: string;
  /** A format check on the raw string, run before wrapping. */
  readonly format?: SensitiveFormat;
  /** envalid's conditional requirement. Passed straight through. */
  readonly requiredWhen?: (cleanedEnv: Record<string, unknown>) => boolean | undefined;

  /** Refused at construction. Use `sensitiveDefault`. */
  readonly default?: never;
  /** Refused at construction. Use `sensitiveDefault`. */
  readonly devDefault?: never;
  /** Refused at construction. Use `sensitiveDefault`. */
  readonly testDefault?: never;
  /** Refused at construction. Use `format`, on the raw string. */
  readonly choices?: never;
}

/** A validator produced by `makeSensitiveValidator`. */
export type SensitiveValidator<C extends SensitivityClass> = (
  spec?: SensitiveSpec
) => RequiredValidatorSpec<SensitiveString<C>>;

/** Every option that is refused, with the replacement each message names. */
const REFUSALS: ReadonlyArray<readonly [string, string]> = [
  [
    'default',
    'Use `sensitiveDefault`. envalid assigns `default` without passing it through the ' +
      'validator, so the variable types as a SensitiveString and holds a raw string at run time.',
  ],
  [
    'devDefault',
    'Use `sensitiveDefault`. envalid assigns `devDefault` without passing it through the ' +
      'validator, so the variable types as a SensitiveString and holds a raw string at run time.',
  ],
  [
    'testDefault',
    'Use `sensitiveDefault`. envalid assigns `testDefault` without passing it through the ' +
      'validator, so the variable types as a SensitiveString and holds a raw string at run time.',
  ],
  [
    'choices',
    'Use `format`, which runs on the raw string. envalid checks `choices` against the parsed ' +
      'value, so a wrapped value never matches and the check is broken rather than strict. A ' +
      'variable whose value is one of a short list of known constants is also, usually, not ' +
      'sensitive to begin with.',
  ],
];

/**
 * Build a validator that wraps its input in a `SensitiveString`.
 *
 * @example
 * ```ts
 * export const credential = makeSensitiveValidator('credential');
 * export const sensitive = makeSensitiveValidator('sensitive');
 *
 * const env = cleanEnvSafe(process.env, {
 *   DB_PASSWORD: credential({ label: 'db_password' }),
 *   SUPPORT_EMAIL: sensitive(),
 *   PORT: port(),
 * });
 * // env.DB_PASSWORD is SensitiveString<'credential'>
 * ```
 */
export function makeSensitiveValidator<C extends SensitivityClass>(
  klass: C
): SensitiveValidator<C> {
  return (spec: SensitiveSpec = {}): RequiredValidatorSpec<SensitiveString<C>> => {
    if (spec === null || typeof spec !== 'object') {
      throw new TypeError(`A ${klass} validator takes an options object or nothing.`);
    }

    for (const [option, replacement] of REFUSALS) {
      if (Object.hasOwn(spec, option)) {
        throw new Error(`\`${option}\` is not supported on a ${klass} validator. ${replacement}`);
      }
    }

    const { label, format, sensitiveDefault } = spec;
    const bind =
      (name: string) =>
      (input: string): SensitiveString<C> =>
        parseSensitive(input, klass, label ?? name, format);

    const meta: SensitiveMeta = {
      klass,
      label,
      sensitiveDefault,
      bind: bind,
    };

    // `makeValidator` is what carries the output type into `CleanedEnv`. The
    // parse function bound here is a placeholder: `cleanEnvSafe` rebinds it to
    // the variable's own name, which is the only place that name is known.
    const validator = makeValidator<SensitiveString<C>>(bind(''));

    const base = validator({
      ...(spec.desc === undefined ? {} : { desc: spec.desc }),
      ...(spec.example === undefined ? {} : { example: spec.example }),
      ...(spec.docs === undefined ? {} : { docs: spec.docs }),
      ...(spec.requiredWhen === undefined ? {} : { requiredWhen: spec.requiredWhen }),
    });

    const withMeta = {
      ...base,
      // The raw string goes down as envalid's own `default` so the variable is
      // not reported missing, and `cleanEnvSafe` wraps it afterwards for
      // exactly the names envalid filled from a default. Wrapping it here
      // instead would build the instance at module load, which moves a policy
      // error from the `cleanEnvSafe` call to an import, and would share one
      // instance across every call. The cast is the price: envalid types
      // `default` as the validator's output type, and the whole point is that
      // this value bypasses the validator.
      ...(sensitiveDefault === undefined
        ? {}
        : { default: sensitiveDefault as unknown as SensitiveString<C> }),
      [SENSITIVE_META]: meta,
    };

    // The marker is not part of envalid's `Spec`, and `default` deliberately
    // holds a raw string rather than the validator's output type. Both are the
    // point of this function, so the assertion is here rather than spread over
    // the two properties that need it.
    return withMeta;
  };
}

/** Parse one raw value: check the format on the string, then wrap it. */
function parseSensitive<C extends SensitivityClass>(
  input: string,
  klass: C,
  label: string,
  format: SensitiveFormat | undefined
): SensitiveString<C> {
  if (typeof input !== 'string') {
    throw new SensitiveFormatError('value is not a string');
  }

  if (format !== undefined) {
    let accepted: boolean;

    try {
      accepted = format.check(input) === true;
    } catch {
      // A check written around a parser puts its input in its own error:
      // `new URL(raw)` is the common one. The throw is the answer, not the
      // message.
      throw new SensitiveFormatError(`the '${format.detail}' check threw`);
    }

    if (!accepted) {
      throw new SensitiveFormatError(`value rejected by the '${format.detail}' check`);
    }
  }

  return new SensitiveString(input, klass, label);
}

/** The adapter's metadata for a spec, or `undefined` for a stock envalid one. */
export function sensitiveMeta(spec: unknown): SensitiveMeta | undefined {
  if (spec === null || typeof spec !== 'object') {
    return undefined;
  }

  const meta = probeProperty(spec, SENSITIVE_META);

  if (meta === null || typeof meta !== 'object') {
    return undefined;
  }

  const klass = probeProperty(meta, 'klass');

  return klass === 'credential' || klass === 'sensitive' ? (meta as SensitiveMeta) : undefined;
}

/** A `credential` validator. Constant-time `equals`, and the strictest policy. */
export const credential: SensitiveValidator<'credential'> = makeSensitiveValidator('credential');

/** A `sensitive` validator, for PII and anything else that must not be logged. */
export const sensitive: SensitiveValidator<'sensitive'> = makeSensitiveValidator('sensitive');
