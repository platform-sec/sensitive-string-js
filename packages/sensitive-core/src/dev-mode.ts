import { getGlobalSingleton } from './global-state.js';
import type { RevealContext, RevealDetails, SensitivityClass } from './types.js';
import { minMaskedFloor } from './mask.js';

/**
 * What a value's own history was, for the engineer debugging it.
 *
 * A reveal that fails, or one that should never have happened, says nothing
 * about where the value came from or how often it has been read: a stack trace
 * names the caller of `reveal()` and nothing else. Development mode records
 * that history next to the value, behind a flag that is off by default. Every
 * path it adds begins with the same guard, so a process that never turns it on
 * pays one property read per construction and one per exposure.
 *
 * Nothing here is meant for production. The partial rendering in particular is
 * a deliberate, opt-in disclosure of the first few characters of a value, which
 * is exactly what the rest of this library exists to prevent; it is bounded by
 * the same floor `mask()` enforces, so it can never show more of a value than a
 * mask of the same class would.
 */

/**
 * The most characters a partial rendering may ever show.
 *
 * A cap rather than a warning, because the option exists to tell two values
 * apart while debugging and no amount of prefix beyond a handful helps with
 * that. It is a ceiling on the option, not on the disclosure: the class floor
 * below can lower it further and often does.
 */
const MAX_PARTIAL_LENGTH = 8;

/** Characters a partial rendering shows when the caller does not choose. */
const DEFAULT_PARTIAL_LENGTH = 4;

/**
 * Reveal times retained per value.
 *
 * A ring, so a value revealed in a loop for an hour holds a fixed amount of
 * memory rather than one number per read. `revealCount` stays exact; only the
 * timestamps are forgotten, oldest first.
 */
const TIMESTAMP_CAPACITY = 64;

/** What a stack renders as when the runtime supplied none. */
const NO_STACK = '    (no stack available)';

/** Time window options for the repeated-reveal warning. */
export interface RepeatedRevealOptions {
  /** Reveals within one window that trigger the warning. */
  threshold: number;
  /** Window length in milliseconds. */
  window: number;
}

/** Logging options for exposures. */
export interface RevealLogOptions {
  /** Whether every exposure is logged, rather than only the unexplained ones. */
  enabled: boolean;
  /** Where the lines go. Defaults to `console.warn`. */
  logger?: (message: string) => void;
  /**
   * Whether the log line shows the first few characters of the value.
   *
   * ⚠️ A real, if small, disclosure. Development only.
   */
  showPartialValue?: boolean;
  /** Characters the partial rendering shows. Defaults to 4, capped at 8. */
  partialLength?: number;
}

/** Development mode configuration, as given to {@link setDevMode}. */
export interface DevModeConfig {
  /** The one switch. Everything else is inert while this is false. */
  enabled: boolean;

  /** Capture the stack of each exposure. */
  captureStackTraces?: boolean;

  /** Capture the stack of each construction. */
  captureCreationStack?: boolean;

  /** Warn when one value is exposed repeatedly in a short window. */
  warnOnRepeatedReveal?: RepeatedRevealOptions | false;

  /** Warn when an exposure has no reveal context, explicit or ambient. */
  warnOnMissingContext?: boolean;

  /** Log every exposure, not only the unexplained ones. */
  logReveals?: RevealLogOptions | false;
}

/**
 * What development mode recorded about one value.
 *
 * Read through `SensitiveString.__devInfo`, which is `undefined` unless
 * development mode is on.
 */
export interface DevInfo {
  /** When the value was constructed. */
  readonly createdAt: Date;
  /** The construction stack, when `captureCreationStack` was set. */
  readonly creationStack?: string;
  /** Exposures since construction. Exact, and never forgotten. */
  readonly revealCount: number;
  /** The most recent exposure times, oldest first, capped at 64. */
  readonly revealTimestamps: readonly number[];
  /** The stack of the most recent exposure, when `captureStackTraces` was set. */
  readonly lastRevealStack?: string;
}

/** Configuration with every default resolved, which is what the hooks read. */
interface ResolvedDevMode {
  readonly enabled: boolean;
  readonly captureStackTraces: boolean;
  readonly captureCreationStack: boolean;
  readonly warnOnMissingContext: boolean;
  readonly repeated: Readonly<RepeatedRevealOptions> | undefined;
  readonly log: {
    readonly enabled: boolean;
    /**
     * Left unresolved on purpose. Binding `console.warn` here would capture
     * whatever it was at configuration time, and a test that installs a spy
     * afterwards would see nothing.
     */
    readonly logger: ((message: string) => void) | undefined;
    readonly showPartialValue: boolean;
    readonly partialLength: number;
  };
}

/** What is recorded per value. */
interface DevRecord {
  readonly createdAt: number;
  readonly creationStack: string | undefined;
  revealCount: number;
  /** Ring of the last {@link TIMESTAMP_CAPACITY} exposure times. */
  readonly timestamps: number[];
  /** Where the next timestamp is written once the ring is full. */
  ringNext: number;
  lastRevealStack: string | undefined;
  /** Start of the window the repeated-reveal warning is counting in. */
  windowStart: number;
  /** Exposures counted in that window. */
  windowCount: number;
}

interface DevModeState {
  config: ResolvedDevMode;
  /**
   * Keyed by the instance, so a value's history is collected with the value and
   * a long-lived process cannot accumulate records for values it has dropped.
   * Typed by `object` rather than by the class, because a second physical copy
   * of core reaching this same global state has its own class identity.
   */
  readonly records: WeakMap<object, DevRecord>;
}

const DISABLED: ResolvedDevMode = Object.freeze({
  enabled: false,
  captureStackTraces: false,
  captureCreationStack: false,
  warnOnMissingContext: false,
  repeated: undefined,
  log: Object.freeze({
    enabled: false,
    logger: undefined,
    showPartialValue: false,
    partialLength: DEFAULT_PARTIAL_LENGTH,
  }),
});

/**
 * Process-global, for the reason the policy registry is: an application that
 * resolves two physical copies of core must not have to configure each one.
 */
export const devMode = getGlobalSingleton<DevModeState>('dev-mode', () => ({
  config: DISABLED,
  records: new WeakMap<object, DevRecord>(),
}));

/**
 * Describe a rejected option without disclosing it.
 */
function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

function requireBoolean(value: unknown, name: string, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }

  if (typeof value !== 'boolean') {
    throw new TypeError(`setDevMode: ${name} must be a boolean, received ${describeType(value)}`);
  }

  return value;
}

function requireLogger(value: unknown): ((message: string) => void) | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'function') {
    throw new TypeError(
      `setDevMode: logReveals.logger must be a function, received ${describeType(value)}`
    );
  }

  return value as (message: string) => void;
}

function requirePartialLength(value: unknown): number {
  if (value === undefined) {
    return DEFAULT_PARTIAL_LENGTH;
  }

  if (typeof value !== 'number') {
    throw new TypeError(
      `setDevMode: logReveals.partialLength must be a number, received ${describeType(value)}`
    );
  }

  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError('setDevMode: logReveals.partialLength must be a non-negative integer');
  }

  if (value > MAX_PARTIAL_LENGTH) {
    throw new RangeError(
      `setDevMode: logReveals.partialLength ${value} exceeds the cap of ${MAX_PARTIAL_LENGTH}; ` +
        'a longer prefix does not help tell two values apart and discloses more of both'
    );
  }

  return value;
}

function resolveRepeated(value: unknown): Readonly<RepeatedRevealOptions> | undefined {
  if (value === undefined || value === false) {
    return undefined;
  }

  if (typeof value !== 'object' || value === null) {
    throw new TypeError(
      `setDevMode: warnOnRepeatedReveal must be an object or false, received ${describeType(value)}`
    );
  }

  const { threshold, window } = value as Partial<RepeatedRevealOptions>;

  if (typeof threshold !== 'number' || typeof window !== 'number') {
    throw new TypeError('setDevMode: warnOnRepeatedReveal requires a numeric threshold and window');
  }

  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new RangeError(
      'setDevMode: warnOnRepeatedReveal.threshold must be an integer of at least 1'
    );
  }

  if (!Number.isFinite(window) || window <= 0) {
    throw new RangeError(
      'setDevMode: warnOnRepeatedReveal.window must be a positive, finite number of milliseconds'
    );
  }

  return Object.freeze({ threshold, window });
}

function resolveLog(value: unknown): ResolvedDevMode['log'] {
  if (value === undefined || value === false) {
    return DISABLED.log;
  }

  if (typeof value !== 'object' || value === null) {
    throw new TypeError(
      `setDevMode: logReveals must be an object or false, received ${describeType(value)}`
    );
  }

  const options = value as Partial<RevealLogOptions>;

  if (typeof options.enabled !== 'boolean') {
    throw new TypeError(
      `setDevMode: logReveals.enabled must be a boolean, received ${describeType(options.enabled)}`
    );
  }

  return Object.freeze({
    enabled: options.enabled,
    logger: requireLogger(options.logger),
    showPartialValue: requireBoolean(
      options.showPartialValue,
      'logReveals.showPartialValue',
      false
    ),
    partialLength: requirePartialLength(options.partialLength),
  });
}

function resolve(config: DevModeConfig): ResolvedDevMode {
  if (typeof config !== 'object' || config === null) {
    throw new TypeError(
      `setDevMode expects a configuration object; received ${describeType(config)}`
    );
  }

  if (typeof config.enabled !== 'boolean') {
    throw new TypeError(
      `setDevMode: enabled must be a boolean, received ${describeType(config.enabled)}`
    );
  }

  return Object.freeze({
    enabled: config.enabled,
    captureStackTraces: requireBoolean(config.captureStackTraces, 'captureStackTraces', false),
    captureCreationStack: requireBoolean(
      config.captureCreationStack,
      'captureCreationStack',
      false
    ),
    warnOnMissingContext: requireBoolean(
      config.warnOnMissingContext,
      'warnOnMissingContext',
      false
    ),
    repeated: resolveRepeated(config.warnOnRepeatedReveal),
    log: resolveLog(config.logReveals),
  });
}

/**
 * Configure development mode. Off until this is called with `enabled: true`.
 *
 * A value records nothing about a period during which development mode was off,
 * so turn it on before constructing the values you intend to inspect.
 *
 * @param config - The configuration. Options are resolved and validated here, so a malformed one is rejected at the call rather than inside a later reveal.
 * @throws TypeError If the configuration, or one of its options, has the wrong type.
 * @throws RangeError If a count is out of range.
 *
 * @example
 * ```ts
 * if (process.env['NODE_ENV'] === 'development') {
 *   setDevMode({
 *     enabled: true,
 *     captureStackTraces: true,
 *     warnOnMissingContext: true,
 *     logReveals: { enabled: true, showPartialValue: true },
 *   });
 * }
 * ```
 */
export function setDevMode(config: DevModeConfig): void {
  const resolved = resolve(config);

  if (resolved.enabled && process.env['NODE_ENV'] === 'production') {
    // Deliberately `console.warn` and not the configured logger: what is being
    // reported is the configuration itself, so routing it through a sink that
    // same configuration just named would be the one place it could be missed.
    // eslint-disable-next-line no-console -- see above
    console.warn(
      '[SensitiveString] Dev mode enabled in production! This is a security risk: it records ' +
        'stacks and, with showPartialValue, writes part of every revealed value to a log.'
    );
  }

  devMode.config = resolved;
}

/**
 * The current configuration, with every default resolved.
 *
 * The result is frozen and is accepted by {@link setDevMode}, so it can be
 * saved and restored. `false` and an absent option both resolve to the disabled
 * object form, which behaves identically.
 */
export function getDevModeConfig(): Readonly<DevModeConfig> {
  const config = devMode.config;
  const log: RevealLogOptions = {
    enabled: config.log.enabled,
    showPartialValue: config.log.showPartialValue,
    partialLength: config.log.partialLength,
    ...(config.log.logger !== undefined ? { logger: config.log.logger } : {}),
  };

  return Object.freeze({
    enabled: config.enabled,
    captureStackTraces: config.captureStackTraces,
    captureCreationStack: config.captureCreationStack,
    warnOnMissingContext: config.warnOnMissingContext,
    warnOnRepeatedReveal: config.repeated ?? false,
    logReveals: Object.freeze(log),
  });
}

/**
 * Run `fn` with `config` in force, restoring the previous configuration after.
 *
 * Synchronous. The configuration is process-global, so it cannot follow one
 * asynchronous task without following every other task interleaved with it; a
 * function that returns a promise has its configuration restored when it
 * returns, not when it settles.
 */
export function withDevMode<T>(config: DevModeConfig, fn: () => T): T {
  const previous = devMode.config;
  setDevMode(config);

  try {
    return fn();
  } finally {
    // The resolved object goes back directly: it was validated when it was set,
    // and restoring must not re-emit the production warning.
    devMode.config = previous;
  }
}

/**
 * The file this module was loaded from, so its own frames can be dropped from a
 * captured stack.
 *
 * Read from a stack rather than from `import.meta.url`, which does not exist in
 * the CommonJS form this package also emits.
 */
const OWN_FILE = ownFile();

function ownFile(): string | undefined {
  // Line 0 is the `Error` header and line 1 is this function's own frame.
  return frameFile(new Error().stack?.split('\n')[1]);
}

/**
 * The source file a stack frame names, or undefined when the frame has none.
 */
function frameFile(frame: string | undefined): string | undefined {
  if (frame === undefined) {
    return undefined;
  }

  // `at name (/dir/file.js:12:3)`, `at /dir/file.js:12:3`, and the `file://`
  // form ESM produces. The two trailing numbers are the position, so whatever
  // precedes them is the file, drive letter and all.
  return /\(?((?:[A-Za-z]:)?[^()]+?):\d+:\d+\)?\s*$/.exec(frame)?.[1];
}

/**
 * Render a captured stack as the caller's frames alone.
 *
 * Two runs of frames sit above the caller: this module's, and those of whichever
 * module called into it, which is the raw-value gate. The gate's file is not
 * known here, so it is taken from the first frame that is not this module's and
 * its contiguous run is dropped with it. Both runs are library code by
 * construction, since nothing outside core calls in.
 *
 * A build that inlines this module and its caller into one file leaves nothing
 * after the filter, and the unfiltered frames are used instead: too much
 * context beats none.
 */
function formatStack(stack: string | undefined): string {
  if (stack === undefined) {
    return NO_STACK;
  }

  const frames = stack.split('\n').slice(1);
  let start = 0;

  if (OWN_FILE !== undefined) {
    while (start < frames.length && frameFile(frames[start]) === OWN_FILE) {
      start += 1;
    }

    const gate = frameFile(frames[start]);

    if (gate !== undefined) {
      while (start < frames.length && frameFile(frames[start]) === gate) {
        start += 1;
      }
    }

    if (start === frames.length) {
      start = 0;
    }
  }

  const kept = frames.slice(start).map((frame) => `    ${frame.trim()}`);
  return kept.length > 0 ? kept.join('\n') : NO_STACK;
}

function captureStack(): string {
  return formatStack(new Error().stack);
}

/**
 * Record the construction of a value.
 *
 * Called from the constructor once its arguments have been accepted, so a
 * rejected construction leaves no record behind.
 */
export function recordCreation(instance: object): void {
  const config = devMode.config;

  devMode.records.set(instance, {
    createdAt: Date.now(),
    creationStack: config.captureCreationStack ? captureStack() : undefined,
    revealCount: 0,
    timestamps: [],
    ringNext: 0,
    lastRevealStack: undefined,
    windowStart: 0,
    windowCount: 0,
  });
}

function pushTimestamp(record: DevRecord, now: number): void {
  if (record.timestamps.length < TIMESTAMP_CAPACITY) {
    record.timestamps.push(now);
    return;
  }

  record.timestamps[record.ringNext] = now;
  record.ringNext = (record.ringNext + 1) % TIMESTAMP_CAPACITY;
}

function readTimestamps(record: DevRecord): number[] {
  if (record.timestamps.length < TIMESTAMP_CAPACITY) {
    return [...record.timestamps];
  }

  return [
    ...record.timestamps.slice(record.ringNext),
    ...record.timestamps.slice(0, record.ringNext),
  ];
}

/**
 * The first few characters of a value, or undefined when none may be shown.
 *
 * Bounded twice: by the configured length, and by the same floor on hidden
 * characters that `mask()` enforces for the class. A value short enough that
 * the floor leaves nothing shows nothing, rather than most of itself. Counts
 * are code points, so a prefix never ends inside a surrogate pair.
 */
function partialValue(value: string, length: number, klass: SensitivityClass): string | undefined {
  if (length <= 0) {
    return undefined;
  }

  const chars = [...value];
  const shown = Math.min(length, chars.length - minMaskedFloor(klass));

  return shown > 0 ? chars.slice(0, shown).join('') : undefined;
}

/**
 * Write one line, swallowing whatever the sink does with it.
 *
 * A debugging aid must not change what the program does. Without this, a logger
 * that throws would turn a successful reveal into a failed one, after the audit
 * hook had already recorded it as successful, and only in development: the one
 * environment where the difference would be mistaken for a bug in the caller.
 */
function emit(config: ResolvedDevMode, message: string): void {
  try {
    // eslint-disable-next-line no-console -- the documented default sink for a feature that only runs in development
    const logger = config.log.logger ?? console.warn;
    logger(message);
  } catch {
    // See above.
  }
}

function describeValue(klass: SensitivityClass, label: string | undefined): string {
  return `'${label ?? klass}'`;
}

/**
 * Log one exposure, when the configuration asks for it.
 *
 * An exposure with no context is reported under `warnOnMissingContext` even
 * when full logging is off, which is the point of that option: the reveals
 * worth seeing first are the ones nothing explains.
 */
function logExposure(
  record: DevRecord,
  klass: SensitivityClass,
  label: string | undefined,
  value: string,
  ctx: RevealContext | null | undefined,
  details: RevealDetails,
  config: ResolvedDevMode
): void {
  const missingContext = ctx === null || ctx === undefined;

  if (!config.log.enabled && !(config.warnOnMissingContext && missingContext)) {
    return;
  }

  const operation = details.operation === 'mask' ? 'Mask' : 'Reveal';
  let message = `[SensitiveString] ${operation} of ${describeValue(klass, label)}`;

  if (config.log.showPartialValue) {
    const partial = partialValue(value, config.log.partialLength, klass);

    if (partial !== undefined) {
      message += ` (${partial}...)`;
    }
  }

  message += missingContext ? ' without context' : ` with context '${ctx.name}'`;

  if (record.lastRevealStack !== undefined) {
    message += `\n${record.lastRevealStack}`;
  }

  if (record.creationStack !== undefined) {
    message += `\nCreated at:\n${record.creationStack}`;
  }

  emit(config, message);
}

/**
 * Warn when one value is exposed repeatedly, at most once per window.
 *
 * Counted in fixed windows rather than a sliding one: a sliding count of an
 * unbounded history is what the ring buffer exists to avoid, and rate limiting
 * the warning is a feature in its own right. A loop that reveals a thousand
 * times a second produces one line per window, not a thousand; a burst that
 * straddles a boundary is reported by the window it finishes in.
 */
function warnOnRepeats(
  record: DevRecord,
  klass: SensitivityClass,
  label: string | undefined,
  now: number,
  config: ResolvedDevMode
): void {
  const repeated = config.repeated;

  if (repeated === undefined) {
    return;
  }

  if (now - record.windowStart >= repeated.window) {
    record.windowStart = now;
    record.windowCount = 0;
  }

  record.windowCount += 1;

  // Equality, not `>=`: the warning fires as the threshold is crossed and stays
  // quiet for the rest of the window.
  if (record.windowCount !== repeated.threshold) {
    return;
  }

  let message =
    `[SensitiveString] Warning: ${describeValue(klass, label)} revealed ` +
    `${repeated.threshold} times in ${repeated.window}ms\n` +
    '    Consider caching the revealed value or reviewing the code path.';

  if (record.lastRevealStack !== undefined) {
    message += `\n    Most recent reveal at:\n${record.lastRevealStack}`;
  }

  emit(config, message);
}

/**
 * Record one exposure of a value.
 *
 * Called from the raw-value gate for exactly the reads an audit hook sees: the
 * ones where the value reaches the caller. A comparison reads the value without
 * disclosing it and is not counted, and neither is a read that only feeds
 * redaction. A read the gate refused never reaches here, so a denied reveal is
 * not counted as one.
 */
export function recordReveal(
  instance: object,
  klass: SensitivityClass,
  label: string | undefined,
  value: string,
  ctx: RevealContext | null | undefined,
  details: RevealDetails
): void {
  const record = devMode.records.get(instance);

  if (record === undefined) {
    // Constructed before development mode was turned on.
    return;
  }

  const config = devMode.config;
  const now = Date.now();

  record.revealCount += 1;
  pushTimestamp(record, now);

  if (config.captureStackTraces) {
    record.lastRevealStack = captureStack();
  }

  logExposure(record, klass, label, value, ctx, details, config);
  warnOnRepeats(record, klass, label, now, config);
}

/**
 * What development mode recorded about one value, or undefined when it is off.
 */
export function readDevInfo(instance: object): DevInfo | undefined {
  if (!devMode.config.enabled) {
    return undefined;
  }

  const record = devMode.records.get(instance);

  if (record === undefined) {
    return undefined;
  }

  return Object.freeze({
    createdAt: new Date(record.createdAt),
    revealCount: record.revealCount,
    revealTimestamps: Object.freeze(readTimestamps(record)),
    ...(record.creationStack !== undefined ? { creationStack: record.creationStack } : {}),
    ...(record.lastRevealStack !== undefined ? { lastRevealStack: record.lastRevealStack } : {}),
  });
}
