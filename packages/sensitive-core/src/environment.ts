import type {
  EnvironmentInfo,
  EnvironmentRestrictions,
  SerializedEnvironmentRestrictions,
  SensitiveStringOptions,
} from './types.js';
import { SensitiveStringError } from './errors.js';
import { getGlobalSingleton } from './global-state.js';

/**
 * Describe a rejected option without disclosing it.
 */
function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

/**
 * Raised when `setEnvironmentInfo()` is called after `lockEnvironmentInfo()`.
 *
 * The lock is the whole of what this feature offers against a later
 * reconfiguration, so a refused write is reported rather than ignored: code
 * that believed it had set the region must not carry on believing it.
 */
export class EnvironmentLockedError extends SensitiveStringError {
  override readonly name = 'EnvironmentLockedError';
  override readonly code = 'environment-locked';

  constructor() {
    super(
      'Environment info is locked. lockEnvironmentInfo() was already called, so the environment ' +
        'a restricted value is checked against cannot be changed for the rest of the process.'
    );
  }
}

/**
 * Raised when a value carrying a custom restriction is put on the wire.
 *
 * Its own class rather than an `EnvironmentRestrictedError`, because it is a
 * different question with a different answer. That error means "not here, try
 * where the value allows"; this one means "not anywhere, because a function has
 * no wire form", and a caller who retries elsewhere on it retries forever.
 */
export class UnserializableRestrictionError extends SensitiveStringError {
  override readonly name = 'UnserializableRestrictionError';
  override readonly code = 'unserializable-restriction';

  constructor(readonly label?: string) {
    super(
      `Sensitive value${label !== undefined ? ` '${label}'` : ''} cannot be serialized: it ` +
        'carries a custom restriction, which is a function and has no wire form. Emitting the ' +
        'declarative half would hand the receiver a value it believes it has fully checked. ' +
        'Express the restriction with allowedEnvironments, allowedRegions or allowedDatacenters, ' +
        'which do cross, or do not transmit the value.'
    );
  }
}

/** Which half of the environment a restriction refused on. */
export type RestrictionKind = 'environment' | 'region' | 'datacenter' | 'custom';

/**
 * Raised when an operation needs the raw value of an instance the current
 * environment is not allowed to read.
 *
 * `restriction` says which field refused and `currentValue` is what the
 * environment reported for it, or `undefined` when the environment does not
 * state that field at all. `allowedValues` and `deniedValues` are the patterns
 * the value was constructed with. All four are configuration, never any part
 * of the protected value, so the message is safe to log.
 */
export class EnvironmentRestrictedError extends SensitiveStringError {
  override readonly name = 'EnvironmentRestrictedError';
  override readonly code = 'environment-restricted';

  constructor(
    readonly restriction: RestrictionKind,
    readonly currentValue: string | undefined,
    readonly allowedValues?: readonly string[],
    readonly deniedValues?: readonly string[],
    readonly label?: string,
    /** For a custom refusal: the caller's `customMessage`, or why the function could not answer. */
    readonly detail?: string,
    cause?: unknown
  ) {
    const named = label !== undefined ? ` '${label}'` : '';
    super(
      `Sensitive value${named} cannot be read in this environment: ` +
        describeRefusal(restriction, currentValue, allowedValues, deniedValues, detail),
      cause === undefined ? undefined : { cause }
    );
  }
}

function describeRefusal(
  restriction: RestrictionKind,
  currentValue: string | undefined,
  allowedValues: readonly string[] | undefined,
  deniedValues: readonly string[] | undefined,
  detail: string | undefined
): string {
  if (restriction === 'custom') {
    return detail ?? 'a custom restriction refused it';
  }

  if (deniedValues !== undefined) {
    const denied = deniedValues.join(', ');

    return currentValue === undefined
      ? `this environment states no ${restriction}, and the value denies ${denied}`
      : `${restriction} is '${currentValue}', which the value denies as ${denied}`;
  }

  const allowed = allowedValues?.join(', ') ?? '';

  return currentValue === undefined
    ? `this environment states no ${restriction}, and the value allows only ${allowed}`
    : `${restriction} is '${currentValue}', and the value allows only ${allowed}`;
}

/**
 * The environment the process believes it is running in.
 *
 * Process-global under rule R6, and keyed on a `Symbol.for()` so an application
 * that resolves two physical copies of core configures one environment rather
 * than two. Being global is also the limit of what it protects: any code in the
 * process can call `setEnvironmentInfo()` before the lock, so a restriction
 * defends against a deploy to the wrong region, not against a caller who wants
 * the value.
 */
interface EnvironmentState {
  info: Readonly<EnvironmentInfo>;
  /** Whether anything ever called `setEnvironmentInfo()`. */
  declared: boolean;
  locked: boolean;
  /** Whether the undeclared-environment warning has already been printed. */
  warned: boolean;
}

const UNDECLARED: Readonly<EnvironmentInfo> = Object.freeze({ environment: 'unknown' });

const environment = getGlobalSingleton<EnvironmentState>('environment', () => ({
  info: UNDECLARED,
  declared: false,
  locked: false,
  warned: false,
}));

function requireName(value: unknown, name: string): string {
  if (typeof value !== 'string') {
    throw new TypeError(
      `setEnvironmentInfo: ${name} must be a string, received ${describeType(value)}`
    );
  }

  if (value === '') {
    throw new RangeError(`setEnvironmentInfo: ${name} must not be empty`);
  }

  return value;
}

function requireOptionalName(value: unknown, name: string): string | undefined {
  return value === undefined ? undefined : requireName(value, name);
}

/**
 * Copy the caller's tags into our own frozen object.
 *
 * Copied because the environment is read on every restricted access: keeping
 * the caller's object would let a mutation after the lock change what a locked
 * environment reports, which is the one thing the lock exists to prevent.
 */
function requireTags(value: unknown): Readonly<Record<string, string>> | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(
      `setEnvironmentInfo: customTags must be an object, received ${describeType(value)}`
    );
  }

  const tags: Record<string, string> = Object.create(null) as Record<string, string>;

  for (const [key, tag] of Object.entries(value)) {
    if (typeof tag !== 'string') {
      throw new TypeError(
        `setEnvironmentInfo: customTags.${key} must be a string, received ${describeType(tag)}`
      );
    }

    tags[key] = tag;
  }

  return Object.freeze(tags);
}

/**
 * Declare the environment restricted values are checked against.
 *
 * ⚠️ This is process-global mutable state. It protects against a value being
 * deployed somewhere it was not meant to run; it does not protect against code
 * already executing in the process, which can call this function itself until
 * `lockEnvironmentInfo()` has run, and can call `resetEnvironmentInfo()` even
 * after. Call it once, from application startup, with values read from a source
 * you trust, and lock it before serving anything.
 *
 * Every field is copied, so mutating the object afterwards does not move the
 * environment.
 *
 * @throws EnvironmentLockedError If `lockEnvironmentInfo()` has already run.
 * @throws TypeError If `info`, or one of its fields, has the wrong type.
 * @throws RangeError If a field is an empty string.
 *
 * @example
 * ```ts
 * setEnvironmentInfo({
 *   environment: process.env['NODE_ENV'] ?? 'unknown',
 *   region: await instanceRegion(),
 * });
 * lockEnvironmentInfo();
 * ```
 */
export function setEnvironmentInfo(info: EnvironmentInfo): void {
  if (environment.locked) {
    throw new EnvironmentLockedError();
  }

  if (typeof info !== 'object' || info === null) {
    throw new TypeError(
      `setEnvironmentInfo: info must be an object, received ${describeType(info)}`
    );
  }

  const region = requireOptionalName(info.region, 'region');
  const datacenter = requireOptionalName(info.datacenter, 'datacenter');
  const customTags = requireTags(info.customTags);

  environment.info = Object.freeze({
    environment: requireName(info.environment, 'environment'),
    ...(region !== undefined ? { region } : {}),
    ...(datacenter !== undefined ? { datacenter } : {}),
    ...(customTags !== undefined ? { customTags } : {}),
  });
  environment.declared = true;
}

/**
 * Freeze the environment for the rest of the process.
 *
 * Call it once startup has finished detecting where it is running and before
 * the first request. There is no unlock: `resetEnvironmentInfo()` clears the
 * lock, and exists for test isolation rather than for production use.
 */
export function lockEnvironmentInfo(): void {
  environment.locked = true;
}

/** Whether `lockEnvironmentInfo()` has run. */
export function isEnvironmentLocked(): boolean {
  return environment.locked;
}

/**
 * The current environment, frozen.
 *
 * The same object a custom restriction is handed, so neither a caller nor a
 * restriction can write to it.
 */
export function getEnvironmentInfo(): Readonly<EnvironmentInfo> {
  return environment.info;
}

/**
 * Forget the environment and the lock.
 *
 * For test isolation, which rule R6 requires of every process-global singleton
 * here, and the counterpart of `resetPolicies()`. It undoes `lockEnvironmentInfo()`,
 * which is the honest statement of what the lock is worth: the threat model is
 * a misconfigured deploy, not code already running in the process.
 */
export function resetEnvironmentInfo(): void {
  environment.info = UNDECLARED;
  environment.declared = false;
  environment.locked = false;
  environment.warned = false;
}

/**
 * A validated restriction set, held by the value that declares it.
 *
 * Lists are copied out of the caller's object for the reason the environment's
 * own fields are: they are read on every access, and a caller who mutates the
 * array they passed must not be able to widen a restriction after the fact.
 */
export interface ResolvedRestrictions {
  readonly allowedEnvironments: readonly string[] | undefined;
  readonly deniedEnvironments: readonly string[] | undefined;
  readonly allowedRegions: readonly string[] | undefined;
  readonly deniedRegions: readonly string[] | undefined;
  readonly allowedDatacenters: readonly string[] | undefined;
  readonly deniedDatacenters: readonly string[] | undefined;
  readonly custom: ((env: Readonly<EnvironmentInfo>) => boolean) | undefined;
  readonly customMessage: string | undefined;
}

/** The shared empty array a value with no restrictions points at. */
export const NO_RESTRICTIONS: readonly ResolvedRestrictions[] = Object.freeze([]);

/** The declarative fields, in the order they are checked and serialized. */
const LIST_FIELDS = [
  'allowedEnvironments',
  'deniedEnvironments',
  'allowedRegions',
  'deniedRegions',
  'allowedDatacenters',
  'deniedDatacenters',
] as const;

type ListField = (typeof LIST_FIELDS)[number];

/** The fields whose entries are matched as patterns rather than literally. */
const PATTERN_FIELDS: ReadonlySet<ListField> = new Set(['allowedRegions', 'deniedRegions']);

/**
 * Validate one list of names or patterns.
 *
 * An empty array is refused rather than read either way. `allowedRegions: []`
 * says "no region is allowed" if read literally and "every region is allowed"
 * if read as "no restriction expressed", and a security control must not pick
 * one of those silently: a caller who built the list from configuration that
 * came back empty has a bug, and this is where they find it.
 */
function requireList(value: unknown, name: string, patterns: boolean): readonly string[] {
  if (!Array.isArray(value)) {
    throw new TypeError(
      `SensitiveString: restrictions.${name} must be an array of strings, received ${describeType(value)}`
    );
  }

  if (value.length === 0) {
    throw new RangeError(
      `SensitiveString: restrictions.${name} is empty. An empty list expresses no restriction ` +
        'and would silently allow everything; omit the field instead.'
    );
  }

  return Object.freeze(
    value.map((entry: unknown, index) => {
      if (typeof entry !== 'string') {
        throw new TypeError(
          `SensitiveString: restrictions.${name}[${index}] must be a string, received ${describeType(entry)}`
        );
      }

      if (entry === '') {
        throw new RangeError(`SensitiveString: restrictions.${name}[${index}] must not be empty`);
      }

      const star = entry.indexOf('*');

      if (!patterns && star !== -1) {
        throw new RangeError(
          `SensitiveString: restrictions.${name}[${index}] contains '*', and ${name} entries are ` +
            'matched literally. Only region patterns take a wildcard.'
        );
      }

      // A trailing '*' and nothing else, so a pattern that reads like a glob
      // but is matched as a prefix is refused rather than quietly matching
      // nothing. 'eu-*' is a prefix; '*-east-1' and 'eu-*-1' are neither a
      // prefix nor a literal region, and either would leave a denylist
      // matching nothing at all.
      if (star !== -1 && star !== entry.length - 1) {
        throw new RangeError(
          `SensitiveString: restrictions.${name}[${index}] may only carry '*' as its last ` +
            "character. A region pattern is a literal name or a prefix such as 'eu-*'; " +
            'anything more expressive belongs in a custom restriction.'
        );
      }

      return entry;
    })
  );
}

function requireCustom(value: unknown): ((env: Readonly<EnvironmentInfo>) => boolean) | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'function') {
    throw new TypeError(
      `SensitiveString: restrictions.custom must be a function, received ${describeType(value)}`
    );
  }

  return value as (env: Readonly<EnvironmentInfo>) => boolean;
}

function requireMessage(value: unknown): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'string') {
    throw new TypeError(
      `SensitiveString: restrictions.customMessage must be a string, received ${describeType(value)}`
    );
  }

  return value;
}

function resolveOne(restrictions: EnvironmentRestrictions, index: number): ResolvedRestrictions {
  if (typeof restrictions !== 'object' || restrictions === null || Array.isArray(restrictions)) {
    throw new TypeError(
      `SensitiveString: restrictions[${index}] must be an object, received ` +
        `${Array.isArray(restrictions) ? 'an array' : describeType(restrictions)}`
    );
  }

  const lists: Partial<Record<ListField, readonly string[]>> = {};
  let declared = false;

  for (const field of LIST_FIELDS) {
    const value = restrictions[field];

    if (value !== undefined) {
      lists[field] = requireList(value, field, PATTERN_FIELDS.has(field));
      declared = true;
    }
  }

  const custom = requireCustom(restrictions.custom);
  const customMessage = requireMessage(restrictions.customMessage);

  if (custom === undefined) {
    if (!declared) {
      // A restriction set that restricts nothing is configuration that was
      // meant to do something. Refusing it here is the same choice the empty
      // list makes, for the same reason.
      throw new Error(
        'SensitiveString: restrictions declares no restriction. Give it at least one list or a ' +
          'custom function, or omit the option.'
      );
    }

    if (customMessage !== undefined) {
      throw new Error(
        'SensitiveString: restrictions.customMessage has no custom function to describe.'
      );
    }
  }

  return {
    allowedEnvironments: lists.allowedEnvironments,
    deniedEnvironments: lists.deniedEnvironments,
    allowedRegions: lists.allowedRegions,
    deniedRegions: lists.deniedRegions,
    allowedDatacenters: lists.allowedDatacenters,
    deniedDatacenters: lists.deniedDatacenters,
    custom,
    customMessage,
  };
}

/**
 * Build the restriction state for a newly constructed value.
 *
 * Every list is validated here, at construction, so a malformed pattern is
 * rejected at the call that wrote it rather than inside a reveal months later
 * in a region nobody is watching.
 *
 * The option accepts a list as well as a single set, because a value derived
 * from two restricted values carries both, and the wire format has to be able
 * to carry them back.
 *
 * @throws TypeError If an option has the wrong type.
 * @throws RangeError If a list is empty or a pattern is not a literal or a prefix.
 * @throws Error If a restriction set expresses no restriction.
 */
export function planRestrictions(
  options: SensitiveStringOptions | undefined
): readonly ResolvedRestrictions[] | undefined {
  const declared = options?.restrictions;

  if (declared === undefined) {
    return undefined;
  }

  const sets = Array.isArray(declared)
    ? (declared as readonly EnvironmentRestrictions[])
    : [declared as EnvironmentRestrictions];

  if (sets.length === 0) {
    throw new RangeError(
      'SensitiveString: restrictions is an empty list, which expresses no restriction; ' +
        'omit the option instead.'
    );
  }

  return Object.freeze(sets.map(resolveOne));
}

/**
 * Warn once that restrictions are being decided against an environment nobody
 * declared.
 *
 * An undeclared environment reports `unknown` and no region, which refuses
 * every allowlist and satisfies every denylist. The first half fails loudly on
 * its own; the second is the quiet one, and this is what makes it audible.
 *
 * Deliberately `console.warn`: what is being reported is that startup never
 * configured the library, so routing it through anything the library was also
 * never told about would be the one place it could be missed.
 */
function warnUndeclared(): void {
  if (environment.declared || environment.warned) {
    return;
  }

  environment.warned = true;

  // eslint-disable-next-line no-console -- see above
  console.warn(
    '[SensitiveString] A value with environment restrictions was read before ' +
      'setEnvironmentInfo() was called. The environment reports itself as ' +
      "'unknown' with no region, so every allowlist refuses and every denylist passes."
  );
}

/**
 * Whether a name matches one entry of a list.
 *
 * A trailing `*` is a prefix and nothing else is a wildcard, which
 * `requireList` has already enforced, so this is the whole matching rule.
 */
function matchesEntry(value: string, entry: string): boolean {
  return entry.endsWith('*') ? value.startsWith(entry.slice(0, -1)) : value === entry;
}

function matchesAny(value: string, entries: readonly string[]): boolean {
  for (const entry of entries) {
    if (matchesEntry(value, entry)) {
      return true;
    }
  }

  return false;
}

/**
 * Decide one field against its allowlist and its denylist.
 *
 * The allowlist is checked first so that when both would refuse, the caller is
 * told where the value *may* be read rather than only where it may not.
 *
 * A field the environment does not state is treated differently by the two
 * lists, and the asymmetry is deliberate. An allowlist is the statement "only
 * here", and an environment that cannot say where it is has not shown that it
 * is here, so the read is refused. A denylist is the statement "not there", and
 * it concludes nothing from silence: reading it the other way would refuse
 * every read on every machine that never sets a region, which is every laptop
 * and every CI runner.
 */
function checkField(
  kind: RestrictionKind,
  current: string | undefined,
  allowed: readonly string[] | undefined,
  denied: readonly string[] | undefined,
  label: string | undefined
): void {
  if (allowed !== undefined && (current === undefined || !matchesAny(current, allowed))) {
    throw new EnvironmentRestrictedError(kind, current, allowed, undefined, label);
  }

  if (denied !== undefined && current !== undefined && matchesAny(current, denied)) {
    throw new EnvironmentRestrictedError(kind, current, undefined, denied, label);
  }
}

/**
 * Ask a custom restriction, and treat everything but `true` as a refusal.
 *
 * A function that throws denies the read, for the reason a revocation registry
 * that throws does: something that cannot answer whether this environment
 * qualifies has not said that it does. A function that answers with anything
 * but a boolean denies too, since an `async` one returns a Promise, which is
 * truthy and would otherwise allow every read it was written to refuse.
 */
function checkCustom(
  restrictions: ResolvedRestrictions,
  info: Readonly<EnvironmentInfo>,
  label: string | undefined
): void {
  const { custom, customMessage } = restrictions;

  if (custom === undefined) {
    return;
  }

  let answer: unknown;

  try {
    answer = custom(info);
  } catch (error) {
    throw new EnvironmentRestrictedError(
      'custom',
      info.environment,
      undefined,
      undefined,
      label,
      customMessage ?? 'a custom restriction threw instead of answering',
      error
    );
  }

  if (answer === true) {
    return;
  }

  throw new EnvironmentRestrictedError(
    'custom',
    info.environment,
    undefined,
    undefined,
    label,
    customMessage ??
      (typeof answer === 'boolean'
        ? 'a custom restriction refused it'
        : `a custom restriction answered with ${describeType(answer)} instead of a boolean, ` +
          'which is read as a refusal')
  );
}

/**
 * Refuse the read unless the current environment satisfies every restriction.
 *
 * Every set has to pass, so a value derived from two restricted values is at
 * least as restricted as each of them, which is rule R2's combination rule with
 * nothing to decide: an intersection is what sharing the state already gives.
 *
 * @throws EnvironmentRestrictedError If any restriction refuses.
 */
export function checkEnvironmentRestrictions(
  restrictions: readonly ResolvedRestrictions[],
  label: string | undefined
): void {
  warnUndeclared();

  const info = environment.info;

  for (const set of restrictions) {
    checkField(
      'environment',
      info.environment,
      set.allowedEnvironments,
      set.deniedEnvironments,
      label
    );
    checkField('region', info.region, set.allowedRegions, set.deniedRegions, label);
    checkField('datacenter', info.datacenter, set.allowedDatacenters, set.deniedDatacenters, label);
    checkCustom(set, info, label);
  }
}

/**
 * Whether any of these restriction sets carries a function.
 *
 * A function is not data. It cannot be serialized and it cannot cross into
 * another isolate, so a payload built from a value that carries one would
 * arrive enforcing the declarative half and silently not the rest.
 */
export function carriesCustomRestriction(restrictions: readonly ResolvedRestrictions[]): boolean {
  for (const set of restrictions) {
    if (set.custom !== undefined) {
      return true;
    }
  }

  return false;
}

/**
 * The wire form of these restrictions.
 *
 * Declarative only, and the caller has already been refused if any of them
 * carries a function, so nothing is dropped here.
 */
export function serializeRestrictions(
  restrictions: readonly ResolvedRestrictions[]
): SerializedEnvironmentRestrictions[] {
  return restrictions.map((set) => {
    const wire: SerializedEnvironmentRestrictions = {};

    for (const field of LIST_FIELDS) {
      const list = set[field];

      if (list !== undefined) {
        wire[field] = [...list];
      }
    }

    return wire;
  });
}

/**
 * Read restrictions out of an untrusted payload.
 *
 * They can only tighten: a value rebuilt by `deserialize()` starts with none,
 * so anything a payload carries here refuses reads that would otherwise have
 * been allowed, and there is no spelling of "no restriction" that lifts one the
 * receiving process would have applied anyway.
 *
 * An unknown key is rejected rather than ignored. A sender that knows a
 * restriction this receiver does not is describing a limit that would be
 * silently unenforced, which is the failure this whole feature exists to avoid.
 */
export function deserializeRestrictions(
  serialized: object
): readonly EnvironmentRestrictions[] | undefined {
  if (!('restrictions' in serialized) || serialized.restrictions === undefined) {
    return undefined;
  }

  const declared: unknown = serialized.restrictions;

  if (!Array.isArray(declared)) {
    throw new Error('Invalid SerializedSensitiveString: restrictions must be an array');
  }

  if (declared.length === 0) {
    throw new Error(
      'Invalid SerializedSensitiveString: restrictions is empty. A payload that restricts ' +
        'nothing omits the field rather than carrying an empty list.'
    );
  }

  return declared.map((entry: unknown, index): EnvironmentRestrictions => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throw new Error(
        `Invalid SerializedSensitiveString: restrictions[${index}] must be an object`
      );
    }

    const set: EnvironmentRestrictions = {};

    for (const key of Object.keys(entry)) {
      if (!(LIST_FIELDS as readonly string[]).includes(key)) {
        throw new Error(
          `Invalid SerializedSensitiveString: restrictions[${index}] carries unknown key '${key}'. ` +
            'A restriction this receiver cannot enforce is refused rather than ignored.'
        );
      }

      (set as Record<string, unknown>)[key] = (entry as Record<string, unknown>)[key];
    }

    // The lists themselves are validated by `planRestrictions`, which is the
    // same check a locally constructed value gets, so a payload cannot smuggle
    // a pattern shape the constructor would have refused.
    return set;
  });
}
