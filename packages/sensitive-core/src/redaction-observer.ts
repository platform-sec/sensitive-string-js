import { getGlobalSingleton } from './global-state.js';
import type { SensitivityClass } from './types.js';

/**
 * Observation of redactions, which is the count that says what the library
 * prevented.
 *
 * A reveal is the sanctioned path and is already audited. A redaction is the
 * other one: every time `toString()`, `toJSON()` or the inspect hook renders a
 * marker, some caller was about to write the plain string somewhere, and the
 * marker went instead. Nothing recorded that before this module. The rendering
 * runs on the `'safe'` read, which fires no audit hook, charges no budget and
 * consults no policy, and it must stay that way: a log line must not need
 * authorization. So observation sits beside the rendering rather than inside
 * the gate, and reports the class, the label and the surface, never the value
 * and never its rendering.
 *
 * The registry is process-global under rule R6 and keyed on `Symbol.for()`, so
 * a second installed copy of core shares it. Any code in the process can
 * subscribe or unsubscribe; this protects a dashboard against a missing
 * subscription, not against a hostile caller.
 *
 * What an unobserved process pays is one array-length read per rendering,
 * priced in the changeset. The observed path adds one frozen object and one
 * call per observer.
 */

/**
 * Where a redaction was rendered.
 *
 * - `'toString'`: a coercion. A template literal, string concatenation,
 *   `String()`, or a direct call. This is the surface T13 describes, where the
 *   rendering may be a prevented log line or a broken request, and the event
 *   cannot tell the two apart.
 * - `'toJSON'`: `JSON.stringify()`, or a serializer that honours `toJSON()`.
 *   A JSON logger and a JSON request body both arrive here.
 * - `'inspect'`: `util.inspect()` and `console.log()`.
 * - `'structure'`: a walker replaced the value inside a structure it was
 *   asked to clean. `redactInStructure`, `redactCopy`, `safeStringify`,
 *   `safeLog`, the winston format and the pino serializer all report here,
 *   and a `serialize()` result one of them replaced reports here too. This is
 *   the one surface that is unambiguously a sink that installed redaction.
 */
export type RedactionSurface = 'toString' | 'toJSON' | 'inspect' | 'structure';

/**
 * One rendering of a redaction marker.
 *
 * Exactly these three fields, frozen, and shared by every observer of the
 * same rendering. The label is `undefined` for a `serialize()` result a walker
 * replaced: the label in a wire shape is data off the wire, and an event that
 * carried it would let a request body choose a metric dimension.
 */
export interface RedactionEvent {
  readonly klass: SensitivityClass;
  readonly label: string | undefined;
  readonly surface: RedactionSurface;
}

/**
 * Receives every redaction rendered in the process while subscribed.
 *
 * Must not throw. One that does is reported once through `process.emitWarning`
 * and its later throws are swallowed, because a redaction is a log line and a
 * log line must never throw. Its own redactions are not observed: a dashboard
 * that logs a wrapped value inside its observer would otherwise recurse.
 */
export type RedactionObserver = (event: RedactionEvent) => void;

interface ObserverState {
  /**
   * Replaced rather than mutated on every subscribe and unsubscribe, so a
   * notification in flight iterates the list it started with.
   */
  observers: readonly RedactionObserver[];
  /** True while observers are being called, so a nested rendering is not reported. */
  notifying: boolean;
  /** Observers already reported for throwing, so a broken one warns once. */
  readonly warned: WeakSet<RedactionObserver>;
}

/** @internal */
export const redactionObservers = getGlobalSingleton<ObserverState>('redaction-observers', () => ({
  observers: [],
  notifying: false,
  warned: new WeakSet(),
}));

/**
 * Subscribe to every redaction rendered in this process.
 *
 * Returns the function that unsubscribes. Calling it twice is harmless.
 * Subscribing the same function twice notifies it twice, and each unsubscribe
 * removes one subscription.
 *
 * The event carries the class, the label and the surface. The rendering is not
 * in it, deliberately: under a deterministic-redaction policy the marker is a
 * pseudonym of the value, and a metric dimension is the wrong place for one.
 *
 * @example
 * ```ts
 * const stop = observeRedactions(({ klass, label, surface }) => {
 *   redactions.inc({ klass, label: label ?? '', surface });
 * });
 * ```
 */
export function observeRedactions(observer: RedactionObserver): () => void {
  if (typeof observer !== 'function') {
    throw new TypeError('observeRedactions() requires a function');
  }

  const state = redactionObservers;
  state.observers = [...state.observers, observer];

  let subscribed = true;

  return () => {
    if (!subscribed) {
      return;
    }

    subscribed = false;

    const index = state.observers.indexOf(observer);

    if (index !== -1) {
      state.observers = [...state.observers.slice(0, index), ...state.observers.slice(index + 1)];
    }
  };
}

/**
 * Report one rendering to every observer.
 *
 * Called after the rendering succeeded, never before: a policy whose `redact`
 * throws rendered nothing, so there is nothing to count. The caller checks
 * `redactionObservers.observers.length` first, so an unobserved process never
 * enters this function.
 *
 * @internal
 */
export function notifyRedaction(
  klass: SensitivityClass,
  label: string | undefined,
  surface: RedactionSurface
): void {
  const state = redactionObservers;

  // An observer that renders a wrapped value, by logging it, say, reaches
  // here again from inside its own notification. Reporting that would recurse
  // until the stack ran out, and each level would swallow the overflow of the
  // one below. The nested rendering still produces its marker; it is just not
  // an event.
  if (state.notifying) {
    return;
  }

  const observers = state.observers;
  const event: RedactionEvent = Object.freeze({ klass, label, surface });

  state.notifying = true;

  try {
    for (const observer of observers) {
      try {
        observer(event);
      } catch (error) {
        warnOnce(state, observer, error);
      }
    }
  } finally {
    state.notifying = false;
  }
}

/**
 * Say once, on stderr, that an observer is broken.
 *
 * Once per observer rather than once per process, so a second broken
 * exporter is not hidden behind the first, and once rather than every time,
 * because the rendering that triggered it is a log line and a warning per log
 * line is a second log.
 */
function warnOnce(state: ObserverState, observer: RedactionObserver, error: unknown): void {
  if (state.warned.has(observer)) {
    return;
  }

  state.warned.add(observer);

  const reason = error instanceof Error ? `${error.name}: ${error.message}` : String(error);

  process.emitWarning(
    `A redaction observer threw (${reason}). Redaction is unaffected, and later throws from ` +
      'this observer are swallowed without a warning.',
    'SensitiveStringWarning'
  );
}
