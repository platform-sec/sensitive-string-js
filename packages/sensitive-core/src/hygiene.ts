import { getGlobalSingleton } from './global-state.js';
import { SensitiveStringError } from './errors.js';
import type { SensitivityClass } from './types.js';
import type { SensitiveString } from './sensitive-string.js';

/**
 * What this library can do about the plaintext already in the V8 heap, which
 * is less than the phrase "memory hygiene" suggests and is worth stating
 * before the API rather than after it.
 *
 * JavaScript cannot overwrite the backing store of a string it holds a
 * reference to. There is no primitive for it, and encoding the value into a
 * buffer so the buffer can be zeroed only adds a second copy, in external
 * memory a heap snapshot cannot even show. The one thing available is dropping
 * the last reference and letting the collector reclaim the memory on its own
 * schedule.
 *
 * So `clear()` drops *the library's* reference. Whether that was the last
 * reference is a property of the calling code: a route that wraps
 * `req.body.token` and keeps the parsed body alive for the rest of the request
 * gains nothing from it, because the instance's value and `req.body.token` are
 * the same string object. The shape this feature is for is a credential the
 * library holds alone, loaded once and used once.
 *
 * Two process-global switches sit beside it, both off by default and both
 * under rule R6: they narrow an accident, not an attacker who is already
 * running code in the process.
 */

/**
 * Raised when an operation needs the raw value of a cleared instance.
 *
 * Distinguished from `ExpiredSensitiveValueError` so a caller can tell a value
 * that lapsed from one this process destroyed: the first may be worth fetching
 * again, the second means the code holds a reference it was done with.
 */
export class ClearedSensitiveValueError extends SensitiveStringError {
  override readonly name = 'ClearedSensitiveValueError';
  override readonly code = 'cleared-value';

  constructor(
    readonly clearedAt: Date,
    readonly attemptedAt: Date,
    readonly label?: string
  ) {
    super(
      `Sensitive value${label !== undefined ? ` '${label}'` : ''} was cleared at ` +
        clearedAt.toISOString()
    );
  }

  /** Milliseconds between the clear and the attempted access. */
  get clearedFor(): number {
    return this.attemptedAt.getTime() - this.clearedAt.getTime();
  }
}

/**
 * Process-global memory hygiene settings.
 *
 * Both are read at construction, so a value built before {@link setMemoryHygiene}
 * runs is neither frozen nor tracked. Configure this alongside policy
 * registration in the process's entry module, before anything wraps a secret.
 */
export interface MemoryHygieneConfig {
  /**
   * Freeze each new instance at construction, so its public surface cannot be
   * rewritten.
   *
   * What that blocks is more than the obvious: an own `toJSON` replaces
   * redaction outright on the path most likely to reach a log aggregator, and
   * a `klass` rewrite downgrades a credential to a class with different
   * redaction, permitted partial queries, permitted masking, and no
   * constant-time comparison. Prototype replacement goes too.
   *
   * What it does not touch: `#private` fields, so `clear()` still works, and
   * the shared state an instance points at, so `renew()` still moves a frozen
   * value's deadline. Freezing an object does not freeze what it references.
   *
   * Costs roughly 51 ns per construction, on Node 22.15.0. It is off by
   * default for the other reason: it is a breaking change for any consumer, or
   * any framework, that decorates an instance with a property of its own.
   *
   * Default `false`.
   */
  freezeInstances?: boolean;
  /**
   * Track instances so {@link clearAllSensitiveValues} can reach them.
   *
   * Costs about 202 bytes per instance, roughly 87% on top of the instance
   * itself, split between a `WeakRef` in a `Set` and its `FinalizationRegistry`
   * entry. A service that wraps a few dozen credentials at boot will never
   * notice. A service that wraps a value per request roughly doubles the
   * memory cost of doing so.
   *
   * Default `false`.
   */
  trackInstances?: boolean;
}

/**
 * Every switch resolved, which is what the singleton holds.
 *
 * Module-private, and `getMemoryHygiene` spells its return type out rather than
 * naming it: a consumer reading the declaration should see the shape, not an
 * alias it cannot import.
 */
type ResolvedHygiene = Readonly<Required<MemoryHygieneConfig>>;

const DISABLED: ResolvedHygiene = Object.freeze({
  freezeInstances: false,
  trackInstances: false,
});

/**
 * The tracked value's type, loose on purpose: this module is imported by
 * `sensitive-string.ts`, so the only binding it may take from there is a type.
 */
type TrackedValue = SensitiveString<SensitivityClass>;

interface HygieneGlobals {
  config: ResolvedHygiene;
  /**
   * Every instance built while tracking was on and not yet collected.
   *
   * A `WeakRef` each, so tracking never keeps alive the thing it exists to
   * destroy. The set is not a census: it lags collection by at least a turn,
   * for the reasons on `clearAllSensitiveValues`.
   */
  tracked: Set<WeakRef<TrackedValue>>;
  /** Prunes the set as instances are collected, so it does not grow forever. */
  finalizer: FinalizationRegistry<WeakRef<TrackedValue>>;
}

/**
 * The one registry and configuration every physical copy of core shares.
 *
 * Exported for `sensitive-string.ts`, which reads `config` on the construction
 * path: one property chain rather than a call through an accessor, which is
 * what a process that never turns either switch on pays for the feature.
 *
 * @internal
 */
export const hygiene = getGlobalSingleton<HygieneGlobals>('memory-hygiene', () => {
  const tracked = new Set<WeakRef<TrackedValue>>();

  return {
    config: DISABLED,
    tracked,
    finalizer: new FinalizationRegistry<WeakRef<TrackedValue>>((ref) => {
      tracked.delete(ref);
    }),
  };
});

/**
 * Start tracking an instance, so a later bulk clear can reach it.
 *
 * The instance is its own unregister token, so `clearAllSensitiveValues` can
 * drop what it has already destroyed.
 *
 * @internal
 */
export function trackInstance(instance: TrackedValue): void {
  const ref = new WeakRef(instance);
  hygiene.tracked.add(ref);
  hygiene.finalizer.register(instance, ref, instance);
}

function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

function requireBoolean(value: unknown, name: string, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }

  if (typeof value !== 'boolean') {
    throw new TypeError(
      `setMemoryHygiene: ${name} must be a boolean, received ${describeType(value)}`
    );
  }

  return value;
}

/**
 * Configure memory hygiene for this process. Merges: an unset field is left as
 * it was, so turning tracking on later does not silently unfreeze.
 *
 * Both switches are read at construction, so this belongs in the entry module
 * beside `registerPolicy`, before anything wraps a value. An instance built
 * before this call is neither frozen nor tracked, and there is no way to
 * retrofit either onto it.
 *
 * Per-isolate, like every other process-global in this library: a worker
 * thread has its own `globalThis` and so its own configuration and its own
 * tracked set. Configuring the main thread configures the main thread.
 *
 * @param config - The switches to change.
 * @throws TypeError If the configuration, or one of its fields, has the wrong type.
 *
 * @example
 * ```ts
 * setMemoryHygiene({ trackInstances: true, freezeInstances: true });
 * ```
 */
export function setMemoryHygiene(config: MemoryHygieneConfig): void {
  if (typeof config !== 'object' || config === null) {
    throw new TypeError(
      `setMemoryHygiene expects a configuration object; received ${describeType(config)}`
    );
  }

  const current = hygiene.config;

  hygiene.config = Object.freeze({
    freezeInstances: requireBoolean(
      config.freezeInstances,
      'freezeInstances',
      current.freezeInstances
    ),
    trackInstances: requireBoolean(config.trackInstances, 'trackInstances', current.trackInstances),
  });
}

/**
 * The configuration in force, with every default resolved.
 *
 * A frozen copy of the live object rather than the object itself, so a caller
 * cannot reconfigure the process by writing to what it reads back. The result
 * is accepted by {@link setMemoryHygiene}, so it can be saved and restored.
 */
export function getMemoryHygiene(): Readonly<Required<MemoryHygieneConfig>> {
  const { freezeInstances, trackInstances } = hygiene.config;
  return Object.freeze({ freezeInstances, trackInstances });
}

/**
 * Clear every instance this process is still tracking, and report how many.
 *
 * Only reaches values constructed while `trackInstances` was on, so this
 * returns `0` in a process that never turned tracking on. It is the only way
 * to reach a derivative whose holder cannot be named, which is what makes it
 * more than a convenience: a substring of 13 characters or more pins its
 * parent's entire backing store, so the parent's own `clear()` frees nothing
 * until that substring is cleared too, and the substring is usually a local
 * some function has already dropped.
 *
 * The walk reaches origins and derivatives in whatever order the set holds
 * them, so it clears values whose origin it has already cleared. That is
 * deliberate: `clear()` is idempotent per instance and not per lineage, so a
 * derivative reached after its origin still drops its own copy and releases
 * its own pin.
 *
 * The set is emptied of what this call reached, and is not empty afterwards in
 * any promised sense: entries whose instance has been collected are removed by
 * a `FinalizationRegistry` that needs at least two GC cycles and two macrotask
 * turns to run, and a pass that calls `deref()` on an entry keeps that target
 * alive to the end of the current job. The set's size is a lagging indicator
 * with no bound worth promising.
 *
 * On a `SIGTERM` handler, call it after the drain and not before it: clearing
 * at the top of the handler destroys credentials that in-flight requests are
 * still using. It buys nothing at all if the handler ends in `process.exit()`;
 * what it narrows is the window a process stays alive after draining, where a
 * heap snapshot or a crash dump can still be taken.
 *
 * @returns How many instances were cleared by this call.
 *
 * @example
 * ```ts
 * process.on('SIGTERM', async () => {
 *   await server.close();       // stop accepting, drain what is in flight
 *   await pool.end();           // nothing still needs a credential
 *   clearAllSensitiveValues();  // now the values are dead weight
 * });
 * ```
 */
export function clearAllSensitiveValues(): number {
  let cleared = 0;

  // A snapshot, not the live set. `clear()` calls the class policy's `redact`,
  // and a policy is caller-supplied code: one that constructs a value of its
  // own while tracking is on would add to the set being iterated, and a `Set`
  // iterator visits what is added during iteration. That is an unbounded loop
  // in a shutdown handler. The copy costs one array on a path that runs once.
  for (const ref of [...hygiene.tracked]) {
    const instance = ref.deref();

    if (instance === undefined) {
      // Cheap, and finds little: a ref whose target was collected before this
      // loop began. Anything collected since is still held by the deref above.
      hygiene.tracked.delete(ref);
      continue;
    }

    instance.clear();
    hygiene.finalizer.unregister(instance);
    hygiene.tracked.delete(ref);
    cleared++;
  }

  return cleared;
}

/**
 * Restore the defaults and forget every tracked instance.
 *
 * Test-only, and gated exactly as `resetPolicies()` is: it undoes process-wide
 * configuration, so a production caller reaching for it is describing a bug.
 * It does not clear the instances it forgets, because forgetting is not
 * destroying and a test that wanted them cleared has
 * {@link clearAllSensitiveValues} for that.
 *
 * The finalizer entries for forgotten instances are left registered. Their
 * callbacks delete a ref from a set that no longer holds it, which costs
 * nothing and is the only alternative to `deref()`ing every entry, which would
 * keep every one of them alive to the end of the turn.
 */
export function resetMemoryHygiene(): void {
  hygiene.config = DISABLED;
  hygiene.tracked.clear();
}

/**
 * How many refs the tracked set currently holds.
 *
 * Not a census of live values, and read it as a ceiling rather than a count.
 * It is `0` in any process that never turned `trackInstances` on, since
 * nothing is tracked there. Where tracking is on it counts every instance
 * built since, minus the ones a `FinalizationRegistry` has already pruned, and
 * that pruning needs at least two GC cycles and two macrotask turns, so a value
 * that became garbage a moment ago is still in this number and there is no
 * bound on how long it stays.
 *
 * Exported because a gauge is the one reader that wants it besides the suite
 * measuring that lag: `@platform-sec/sensitive-string-metrics` publishes it as
 * `sensitive_values_tracked`, under that name rather than an `active` one
 * precisely because the lag makes "active" a claim this number cannot support.
 *
 * There is deliberately no per-class breakdown. Splitting the set by class
 * means calling `deref()` on every entry, and a `deref()` that returns an
 * instance keeps that instance alive to the end of the current job, so a
 * gauge scraped every fifteen seconds would extend the life of everything it
 * measured.
 */
export function trackedInstanceCount(): number {
  return hygiene.tracked.size;
}
