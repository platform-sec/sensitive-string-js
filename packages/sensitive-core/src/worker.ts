/**
 * Moving a value across a thread or process boundary, and getting it back.
 *
 * `structuredClone` turns a `SensitiveString` into a plain `{ klass, label }`
 * with no value and no methods, and nothing throws at the boundary: the
 * failure surfaces at the first method call, in another thread, in a stack
 * that names neither. The usual fix is `workerData: { token: token.reveal() }`,
 * which works, and which leaves the plaintext in a plain string for the life
 * of the thread with no class, no deadline, and no audit record.
 *
 * `toWorkerPayload()` builds a payload out of the wire format, which is the
 * shape `serialize()` already produces for a socket, so every marker-aware
 * walk in this library redacts it, and `fromWorkerPayload()` rebuilds the
 * instances on the far side. Building the payload is a reveal, authorized as
 * an ordinary `expose` and audited as a `worker-handoff`. The one thing that
 * cannot cross is a function, so the audit hook does not, and the receiving
 * side is required to install its own.
 *
 * Neither function imports `node:worker_threads`. One builds a plain object
 * and the other reads one, so the same pair works over `workerData`,
 * `postMessage`, a `MessagePort`, a `BroadcastChannel`, and, with
 * `transport: 'json'`, `child_process` IPC.
 */
import { getCurrentRevealContext, withRevealContext } from './context.js';
import { SensitiveStringError } from './errors.js';
import { assignOwn } from './own-property.js';
import { getRegisteredClasses, hasPolicy } from './policy.js';
import { probeBuiltin, probeEntries, probeProperty, probeTag } from './probe.js';
import { containsSensitive, sensitiveClassesIn } from './redact.js';
import {
  SensitiveString,
  serializeSensitiveString,
  unshareableConstraints,
} from './sensitive-string.js';
import { ExpiredSensitiveValueError } from './ttl.js';
import type {
  RevealContext,
  SensitiveStringOptions,
  SensitivityClass,
  SerializedSensitiveString,
  WorkerHandoffAuditDetails,
} from './types.js';

/**
 * The marker a payload carries.
 *
 * Distinct from `__sensitive`: the payload is a container of wire objects, not
 * a wire object, and giving it the same marker would make `redactSerialized`
 * render the whole container as one redaction and hide the structure from
 * anyone debugging a handoff.
 */
const PAYLOAD_MARKER = '__sensitiveWorkerPayload';

/**
 * How a payload will be sent.
 *
 * `'clone'` is structured clone: `workerData`, `postMessage`, a `MessagePort`,
 * and `BroadcastChannel`. `'json'` is `child_process` IPC, whose serializer
 * disagrees with structured clone in both directions: it drops a function
 * where the clone throws, and it turns a `Date` into a string and a `Map` into
 * `{}` where the clone keeps all three. A payload validated for one is not
 * validated for the other.
 */
export type WorkerTransport = 'clone' | 'json';

/**
 * The constraint on what a payload carries: every property an instance.
 *
 * Written over the caller's own keys rather than as an index signature, so an
 * `interface` declaring the shape satisfies it. A `Record<string, ...>` would
 * reject every interface for lacking an index signature, which is the shape
 * a caller most naturally writes.
 */
export type SensitiveValues<T = Record<string, unknown>> = {
  readonly [K in keyof T]: SensitiveString<SensitivityClass>;
};

/** The shape a payload defaults to when the caller claims none. */
export type AnySensitiveValues = Record<string, SensitiveString<SensitivityClass>>;

/**
 * The part of a reveal context that can cross an isolate boundary.
 *
 * `auditReveal` is a function, and functions do not clone, so it is not here.
 */
export interface PortableRevealContext {
  readonly name: string;
  readonly reason?: string;
  readonly tags?: Record<string, unknown>;
}

/**
 * Options for `toWorkerPayload()`.
 */
export interface WorkerPayloadOptions {
  /**
   * Identifies the destination in the audit record: a file path, a URL, or
   * any stable name.
   *
   * Recorded, never verified. Both sides of the boundary are inside the same
   * trust boundary, so a check would stop no attacker and would break one
   * payload builder feeding a pool of differently named workers.
   */
  worker?: string | URL;

  /** The context to authorize against and to carry. Defaults to the ambient context. */
  context?: RevealContext;

  /**
   * Non-sensitive data carried alongside the values, checked against
   * `transport`.
   *
   * A `SensitiveString` anywhere inside it is refused: it would arrive as
   * `{ klass, label }` in silence, and `values` is where it belongs.
   */
  data?: unknown;

  /**
   * How the payload will be sent, which decides how `data` and the context's
   * `tags` are validated. Defaults to `'clone'`.
   *
   * `'json'` rejects everything `'clone'` rejects and more, so a payload built
   * under it is safe for either transport. The one mistake this option cannot
   * catch is the omission: a `Date` in `data` passes the clone check and
   * arrives at a forked child as a string.
   */
  transport?: WorkerTransport;
}

/** The wire form of each value, under the key it had. */
export type WorkerPayloadValues<T> = { readonly [K in keyof T]: SerializedSensitiveString };

/**
 * What `toWorkerPayload()` returns.
 *
 * ⚠️ Contains RAW (UNREDACTED) values, one per entry of `values`, in the wire
 * format. Pass it to the `Worker` constructor or to `postMessage` as an
 * expression rather than binding it, so the sender's copy is unreachable as
 * soon as it is cloned.
 *
 * Mutable on purpose: `fromWorkerPayload()` deletes the raw values from it and
 * marks it consumed, so that the object the thread shares stops holding
 * plaintext once the instances have been rebuilt.
 */
export interface WorkerPayload<T extends SensitiveValues<T> = AnySensitiveValues> {
  readonly __sensitiveWorkerPayload: 1;
  readonly values: WorkerPayloadValues<T>;
  readonly context?: PortableRevealContext;
  /** The authorizing context carried an `auditReveal` that could not cross. */
  readonly audited: boolean;
  readonly data?: unknown;
  /** Set by `fromWorkerPayload()`. Present only on a consumed payload. */
  consumed?: true;
}

/**
 * Options for `fromWorkerPayload()` and `withWorkerPayload()`.
 */
export interface FromWorkerPayloadOptions {
  /**
   * Installed as this side's audit hook.
   *
   * Required when the payload was built under an audited context and no
   * ambient context on this side carries a hook, because the sender's hook
   * was dropped at the boundary and a reveal here would otherwise go
   * unrecorded after the sender asked for it to be recorded.
   */
  auditReveal?: RevealContext['auditReveal'];

  /**
   * Accept an audited payload with no hook on this side. Off by default.
   *
   * ⚠️ Every reveal in this scope then goes unrecorded even though the sender
   * asked for it to be recorded. The `no-allow-unaudited` ESLint rule reports
   * it, and an inline disable comment is the place for the reason.
   */
  allowUnaudited?: boolean;

  /**
   * Keys that must be present. A missing one throws at the boundary rather
   * than arriving as `undefined` and failing later inside worker code.
   */
  require?: readonly string[];

  /**
   * Leave the raw values in the payload object. Off by default.
   *
   * With it, the payload keeps holding plaintext for as long as it is
   * reachable, which for `workerData` is the life of the thread, and a second
   * `fromWorkerPayload()` on it succeeds. Only for a payload that genuinely
   * has to feed two consumers.
   */
  keepPayload?: boolean;
}

/** What `fromWorkerPayload()` returns. */
export interface ReceivedWorkerPayload<T extends SensitiveValues<T>> {
  /** The rebuilt instances, under the keys they were sent with. */
  readonly values: T;
  /**
   * The carried context with this side's audit hook attached, or a context
   * named `'worker'` carrying the hook when the payload carried none. Always
   * installable, so a caller never branches on `undefined`.
   */
  readonly context: RevealContext;
  /** The non-sensitive `data` the sender attached, untouched. */
  readonly data: unknown;
}

/**
 * Raised when what `fromWorkerPayload()` was handed is not a payload, or holds
 * an entry that is not a serialized sensitive value.
 *
 * The message describes the shape received and never its contents.
 */
export class MalformedWorkerPayloadError extends SensitiveStringError {
  override readonly name = 'MalformedWorkerPayloadError';
  override readonly code = 'malformed-payload';

  constructor(detail: string) {
    super(`Invalid worker payload: ${detail}`);
  }
}

/**
 * Raised when a payload is consumed a second time.
 *
 * The first `fromWorkerPayload()` deleted the raw values, so there is nothing
 * left to rebuild.
 *
 * ⚠️ This is per copy, not per payload. Every transport clones, so a payload
 * the sender posts to two workers arrives twice, whole, and each copy is
 * consumable once; only the copy that was consumed, and anything it is passed
 * on to, refuses. Consumption shortens how long *one thread* holds plaintext.
 * It is not a use-once token, and nothing here makes it one: build a payload
 * per destination, and remember the sender's own object still holds the
 * values until it is unreachable.
 */
export class ConsumedWorkerPayloadError extends SensitiveStringError {
  override readonly name = 'ConsumedWorkerPayloadError';
  override readonly code = 'consumed-payload';

  constructor() {
    super(
      'This worker payload has already been consumed: the first fromWorkerPayload() call ' +
        'deleted its raw values. Build a new payload for a second handoff, or pass ' +
        'keepPayload: true if one payload must feed two consumers.'
    );
  }
}

/**
 * Raised when a key named in `require` is absent from the payload.
 */
export class MissingWorkerValueError extends SensitiveStringError {
  override readonly name = 'MissingWorkerValueError';
  override readonly code = 'missing-value';

  constructor(readonly key: string) {
    super(`Worker payload has no value under the required key '${key}'`);
  }
}

/**
 * Raised when a payload names a sensitivity class this thread has not
 * registered.
 *
 * Policies are per isolate: a class registered with `registerPolicy()` on the
 * main thread does not exist in a worker, and a `redact` function could not be
 * carried in the payload even if functions cloned, since a payload that can
 * install a policy can install one that returns its input. The worker's own
 * bootstrap registers what it needs.
 */
export class UnregisteredClassError extends SensitiveStringError {
  override readonly name = 'UnregisteredClassError';
  override readonly code = 'unregistered-class';

  constructor(
    readonly key: string,
    readonly klass: string,
    registered: readonly string[]
  ) {
    super(
      `Worker payload value '${key}' has sensitivity class '${klass}', which is not registered ` +
        'on this thread. Policies are per-thread: call registerPolicy() in the receiving ' +
        `thread's own bootstrap. Registered here: ${registered.join(', ')}.`
    );
  }
}

/**
 * Raised when a payload built under an audited context is consumed with no
 * audit hook on this side.
 *
 * A refusal rather than a warning. A warning from a worker is a line on the
 * parent's stderr that nothing reads, and the condition it would report is a
 * security control the sender asked for being dropped in silence.
 */
export class UnauditedWorkerError extends SensitiveStringError {
  override readonly name = 'UnauditedWorkerError';
  override readonly code = 'unaudited-worker';

  constructor() {
    super(
      'Worker payload was built under an audited context, and the audit hook cannot cross a ' +
        'thread boundary. Pass auditReveal to fromWorkerPayload(), consume it inside a ' +
        'withRevealContext() that carries one, or pass allowUnaudited: true to accept that ' +
        'reveals in this thread will go unrecorded.'
    );
  }
}

/**
 * Raised when `data` or the context's `tags` would not survive the transport.
 *
 * The message names the path of the offending entry and never its value. A
 * `DataCloneError` from the runtime quotes the source text of a function it
 * could not clone, so that message is discarded rather than wrapped.
 */
export class UnportableDataError extends SensitiveStringError {
  override readonly name = 'UnportableDataError';
  override readonly code = 'unportable-data';

  constructor(
    /** Where in the payload the entry sits, such as `data.batch.onDone`. */
    readonly path: string,
    readonly transport: WorkerTransport,
    detail: string
  ) {
    super(`Worker payload cannot carry ${path} over the '${transport}' transport: ${detail}`);
  }
}

/**
 * Raised when a value carries a constraint no other isolate can share.
 *
 * Today that is a reveal budget. The counter is shared by reference between a
 * value and its derivatives, a thread has no reference to share, and the wire
 * format resets counters, so a handoff would hand every worker a fresh budget.
 * The refusal is the rule that a derivative carries its parent's counter or
 * refuses to exist, applied to a transport.
 */
export class UnshareableConstraintError extends SensitiveStringError {
  override readonly name = 'UnshareableConstraintError';
  override readonly code = 'unshareable-constraint';

  constructor(
    readonly key: string,
    readonly constraints: readonly (keyof SensitiveStringOptions)[]
  ) {
    super(
      `Worker payload value '${key}' carries ${constraints.join(' and ')}, a reveal limit ` +
        'that another thread cannot share. A handoff would give the receiving thread a fresh ' +
        'budget, so the value is refused rather than the limit silently reset.'
    );
  }
}

/**
 * Describe a value without disclosing it.
 *
 * Only the kind is reported, never any content: what arrives here may be a
 * secret handed to the wrong function.
 */
function describeKind(value: unknown): string {
  if (value === null) {
    return 'null';
  }

  if (Array.isArray(value)) {
    return 'an array';
  }

  if (typeof value !== 'object') {
    return `a ${typeof value}`;
  }

  const tag = probeTag(value).slice(8, -1);
  return tag === 'Object' ? 'an object' : `a ${tag}`;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** A guard rather than a bare `instanceof`, which narrows to `SensitiveString<any>`. */
function isInstance(value: unknown): value is SensitiveString<SensitivityClass> {
  return value instanceof SensitiveString;
}

/** The audit field for a destination, from whatever the caller named it with. */
function describeWorker(worker: string | URL | undefined): string | undefined {
  if (worker === undefined) {
    return undefined;
  }

  if (typeof worker === 'string') {
    return worker;
  }

  if (worker instanceof URL) {
    return worker.href;
  }

  throw new TypeError(
    `toWorkerPayload: worker must be a string or a URL, received ${describeKind(worker)}`
  );
}

function requireTransport(transport: unknown): WorkerTransport {
  if (transport === undefined) {
    return 'clone';
  }

  if (transport === 'clone' || transport === 'json') {
    return transport;
  }

  throw new TypeError(
    `toWorkerPayload: transport must be 'clone' or 'json', received ${describeKind(transport)}`
  );
}

/**
 * The entries of `values`, each checked to be an instance.
 *
 * A non-instance is refused by name: it is the value the caller meant to
 * protect, or non-sensitive data that belongs in `options.data`, and either way
 * a payload that silently carried it would be the accident this module exists
 * to prevent.
 */
function requireValues(values: unknown): [string, SensitiveString<SensitivityClass>][] {
  if (!isPlainRecord(values)) {
    throw new TypeError(
      'toWorkerPayload: values must be a plain object of SensitiveString instances, received ' +
        describeKind(values)
    );
  }

  const entries: [string, SensitiveString<SensitivityClass>][] = [];

  for (const key of Object.keys(values)) {
    const value = values[key];

    if (!isInstance(value)) {
      throw new TypeError(
        `toWorkerPayload: values.${key} is ${describeKind(value)}, not a SensitiveString. ` +
          'Non-sensitive data belongs in options.data.'
      );
    }

    entries.push([key, value]);
  }

  return entries;
}

/** The three fields of a context that can cross, and nothing else. */
function portableContext(context: RevealContext): PortableRevealContext {
  const portable: { name: string; reason?: string; tags?: Record<string, unknown> } = {
    name: context.name,
  };

  if (context.reason !== undefined) {
    portable.reason = context.reason;
  }

  if (context.tags !== undefined) {
    portable.tags = context.tags;
  }

  return portable;
}

/** Where a transport check failed, and why. Never a value. */
interface PortabilityFailure {
  readonly path: string;
  readonly detail: string;
}

function isCloneable(value: unknown): boolean {
  try {
    structuredClone(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * The children of a container, each with the path it will be reported under.
 *
 * Map and Set entries are numbered rather than keyed, because a Map key is a
 * value and could be a secret.
 */
function childrenOf(value: object, path: string): [string, unknown][] {
  // Iteration is the collection's own code, and a Proxy in front of a built-in
  // is free to throw from it. A refusal answers "no children", which leaves
  // the caller reporting the container itself: this runs while building an
  // error message, and an object that will not be read must not replace that
  // message with an exception of its own.
  if (Array.isArray(value)) {
    return (
      probeBuiltin(() =>
        value.map((item, index): [string, unknown] => [`${path}[${index}]`, item])
      ) ?? []
    );
  }

  if (value instanceof Map) {
    return (
      probeBuiltin(() => {
        const children: [string, unknown][] = [];
        let index = 0;

        for (const [key, entry] of value) {
          children.push(
            [`${path}[entry ${index}].key`, key],
            [`${path}[entry ${index}].value`, entry]
          );
          index++;
        }

        return children;
      }) ?? []
    );
  }

  if (value instanceof Set) {
    return (
      probeBuiltin(() =>
        Array.from(value, (entry, index): [string, unknown] => [`${path}[entry ${index}]`, entry])
      ) ?? []
    );
  }

  return (probeEntries(value) ?? []).map(([key, entry]) => [`${path}.${key}`, entry]);
}

/**
 * The path of the entry structured clone refuses, given a value it refuses.
 *
 * Descends into whichever child also refuses, and reports the node whose
 * children all clone, which is the offending leaf: a function, a symbol, or
 * an object the algorithm has no serialization for.
 */
function locateCloneFailure(value: unknown, path: string, seen: Set<object>): PortabilityFailure {
  if (typeof value === 'function') {
    return { path, detail: 'a function cannot be cloned' };
  }

  if (typeof value === 'symbol') {
    return { path, detail: 'a symbol cannot be cloned' };
  }

  if (value !== null && typeof value === 'object' && !seen.has(value)) {
    seen.add(value);

    for (const [childPath, child] of childrenOf(value, path)) {
      if (!isCloneable(child)) {
        return locateCloneFailure(child, childPath, seen);
      }
    }
  }

  return { path, detail: `${describeKind(value)} cannot be cloned` };
}

function findCloneFailure(value: unknown, path: string): PortabilityFailure | undefined {
  return isCloneable(value) ? undefined : locateCloneFailure(value, path, new Set());
}

/**
 * Built-ins JSON does not round-trip, with what each arrives as.
 *
 * Keyed by `Object.prototype.toString` tag, so a `Date` from another realm is
 * still a Date.
 */
const JSON_LOSSY_TAGS: ReadonlyMap<string, string> = new Map([
  ['Date', 'a string'],
  ['RegExp', 'an empty object'],
  ['Map', 'an empty object'],
  ['Set', 'an empty object'],
  ['WeakMap', 'an empty object'],
  ['WeakSet', 'an empty object'],
  ['Error', 'an empty object'],
  ['Promise', 'an empty object'],
  ['ArrayBuffer', 'an empty object'],
  ['DataView', 'an empty object'],
]);

/**
 * The first entry JSON would lose or change, compared structurally against
 * the input rather than by a round trip alone: a round trip succeeds on a
 * `Date` and hands back a string, which is exactly the loss a caller is least
 * likely to notice.
 *
 * Two sets, not one. `onPath` holds the current path from the root and is
 * what detects a cycle, so it has to be unwound on the way back up; `cleared`
 * remembers every node already found lossless and is never unwound. With only
 * the first, a node reachable by several paths is re-walked once per path,
 * which is exponential on a shared subtree: a 24-deep diamond took 16 seconds
 * before `cleared` existed, against under a millisecond after.
 */
function findJsonLoss(
  value: unknown,
  path: string,
  onPath: Set<object>,
  cleared: Set<object>
): PortabilityFailure | undefined {
  switch (typeof value) {
    case 'undefined':
      return { path, detail: 'an undefined value is dropped by JSON' };
    case 'function':
      return { path, detail: 'a function is dropped by JSON' };
    case 'symbol':
      return { path, detail: 'a symbol is dropped by JSON' };
    case 'bigint':
      return { path, detail: 'a BigInt makes JSON.stringify throw' };
    case 'number':
      return Number.isFinite(value)
        ? undefined
        : { path, detail: 'a non-finite number becomes null in JSON' };
    case 'string':
    case 'boolean':
      return undefined;
    case 'object':
      break;
  }

  if (value === null) {
    return undefined;
  }

  if (onPath.has(value)) {
    return { path, detail: 'a circular reference makes JSON.stringify throw' };
  }

  // Already walked, by another path, and found lossless. A DAG is not a cycle.
  if (cleared.has(value)) {
    return undefined;
  }

  onPath.add(value);

  try {
    if (Array.isArray(value)) {
      for (const [childPath, child] of childrenOf(value, path)) {
        const loss = findJsonLoss(child, childPath, onPath, cleared);

        if (loss !== undefined) {
          return loss;
        }
      }

      cleared.add(value);
      return undefined;
    }

    if (ArrayBuffer.isView(value)) {
      return { path, detail: 'a typed array becomes an object of indexed keys in JSON' };
    }

    const tag = probeTag(value).slice(8, -1);
    const arrival = JSON_LOSSY_TAGS.get(tag);

    if (arrival !== undefined) {
      return { path, detail: `a ${tag} arrives as ${arrival} over JSON` };
    }

    // A toJSON rewrites the shape on the way out and nothing rewrites it back.
    // Whether the rewrite is a loss depends on what it returns, and the
    // conservative answer avoids running caller code to find out.
    if (typeof probeProperty(value, 'toJSON') === 'function') {
      return {
        path,
        detail: 'its toJSON() changes its shape in JSON, and the receiver gets the changed shape',
      };
    }

    for (const [childPath, child] of childrenOf(value, path)) {
      const loss = findJsonLoss(child, childPath, onPath, cleared);

      if (loss !== undefined) {
        return loss;
      }
    }

    cleared.add(value);
    return undefined;
  } finally {
    onPath.delete(value);
  }
}

/**
 * Refuse a passthrough that carries a protected value, at any depth.
 *
 * An instance would degrade to `{ klass, label }` in silence, and a wire
 * object would carry the raw value somewhere `fromWorkerPayload` does not
 * clear. `values` is the one place a protected value belongs, and it is the
 * only place consumption reaches.
 */
function requireNoSensitiveValue(value: unknown, path: string, transport: WorkerTransport): void {
  if (!containsSensitive(value)) {
    return;
  }

  const classes = Array.from(sensitiveClassesIn(value));
  const named = classes.length === 0 ? 'in an object that could not be read' : classes.join(', ');

  throw new UnportableDataError(
    path,
    transport,
    `it holds a sensitive value (${named}), which would arrive as { klass, label } with no ` +
      'value, or would carry the raw value past consumption. Put it in values instead.'
  );
}

/**
 * Refuse a value that would not survive the transport, naming where.
 *
 * The runtime's own `DataCloneError` is never consulted for its message, only
 * for its occurrence: that message embeds the source text of a function it
 * could not clone, and a function's body can hold a literal.
 */
function requirePortable(value: unknown, path: string, transport: WorkerTransport): void {
  const failure =
    transport === 'json'
      ? findJsonLoss(value, path, new Set(), new Set())
      : findCloneFailure(value, path);

  if (failure !== undefined) {
    throw new UnportableDataError(failure.path, transport, failure.detail);
  }
}

/**
 * Build a payload that carries sensitive values across a thread or process
 * boundary with their class, label, and deadline intact.
 *
 * ⚠️ RETURNS RAW VALUES, in the wire format, one per entry. Building the
 * payload is a reveal of each value: it goes through the same gate as
 * `reveal()`, so an expired, revoked, or policy-denied value refuses here, on
 * the sending side, and each value produces one audit record with
 * `operation: 'worker-handoff'`.
 *
 * The checks that do not need the value run first, over every entry: an
 * unshareable constraint, a protected value in `data` or `tags`, and anything
 * the transport would lose. Failing one of those reveals nothing and records
 * nothing.
 *
 * The gate's own refusals cannot be hoisted that way, because deciding them
 * means reading. Values are read in key order, so an expired, revoked or
 * policy-denied value at key *n* leaves the values before it revealed and
 * audited, with the payload discarded. That is `serialize()`'s behaviour in a
 * loop, and it is why the audit record names the key.
 *
 * @param values - The instances to carry, keyed however the receiver expects.
 * @param options - Destination, context, non-sensitive data, and transport.
 * @throws TypeError If `values` is not a plain object of instances.
 * @throws UnshareableConstraintError If a value carries a reveal limit.
 * @throws UnportableDataError If `data` holds a sensitive value, or `data` or the
 *   context's `tags` would not survive the transport.
 * @throws ExpiredSensitiveValueError, RevokedSensitiveValueError, or whatever
 *   the class policy throws, from the gate, exactly as `reveal()` would.
 *
 * @example
 * ```ts
 * const worker = new Worker(workerFile, {
 *   workerData: toWorkerPayload({ token }, { worker: workerFile, data: { batchSize: 100 } }),
 * });
 * ```
 *
 * @remarks
 * Pass the result as an expression, as above, rather than binding it: the
 * sender's copy holds plaintext until it is unreachable. For a long-lived
 * worker, `postMessage` after start keeps that window shorter than
 * `workerData` does, because a message is garbage once its handler returns
 * where `workerData` lives as long as the thread.
 *
 * The receiving thread's heap holds the plaintext once it consumes the
 * payload. `fromWorkerPayload()` deletes the raw values from the payload
 * object, which shortens the accident window; it does not erase a string from
 * memory, which nothing in JavaScript can.
 */
export function toWorkerPayload<T extends SensitiveValues<T>>(
  values: T,
  options: WorkerPayloadOptions = {}
): WorkerPayload<T> {
  const entries = requireValues(values);
  const transport = requireTransport(options.transport);
  const worker = describeWorker(options.worker);
  const context = options.context ?? getCurrentRevealContext() ?? undefined;
  const portable = context === undefined ? undefined : portableContext(context);
  const audited = typeof context?.auditReveal === 'function';

  // Everything that can refuse does so here, ahead of the reads below. A read
  // is a reveal, and a refusal is not: a payload that fails validation has
  // handed nothing out and must not be recorded as if it had.
  for (const [key, value] of entries) {
    const constraints = unshareableConstraints(value);

    if (constraints.length !== 0) {
      throw new UnshareableConstraintError(key, constraints);
    }
  }

  // Both passthroughs get the same two checks. `tags` used to get only the
  // portability one, which let a wire object ride across inside the context
  // and, because consumption only clears `values`, stay in the payload after
  // it had been consumed. A raw value has exactly one place in a payload.
  if (options.data !== undefined) {
    requireNoSensitiveValue(options.data, 'data', transport);
    requirePortable(options.data, 'data', transport);
  }

  if (portable?.tags !== undefined) {
    requireNoSensitiveValue(portable.tags, 'context.tags', transport);
    requirePortable(portable.tags, 'context.tags', transport);
  }

  const serialized: Record<string, SerializedSensitiveString> = {};

  for (const [key, value] of entries) {
    const details: WorkerHandoffAuditDetails = Object.freeze({
      operation: 'worker-handoff' as const,
      worker,
      key,
      auditHookDropped: audited,
    });

    assignOwn(serialized, key, serializeSensitiveString(value, context, details));
  }

  const payload: {
    __sensitiveWorkerPayload: 1;
    values: WorkerPayloadValues<T>;
    audited: boolean;
    context?: PortableRevealContext;
    data?: unknown;
  } = {
    __sensitiveWorkerPayload: 1,
    values: serialized as WorkerPayloadValues<T>,
    audited,
  };

  if (portable !== undefined) {
    payload.context = portable;
  }

  if (options.data !== undefined) {
    payload.data = options.data;
  }

  return payload;
}

function requirePayload(payload: unknown): Record<string, unknown> {
  if (!isPlainRecord(payload)) {
    throw new MalformedWorkerPayloadError(
      `expected the object toWorkerPayload() returns, received ${describeKind(payload)}`
    );
  }

  if (payload[PAYLOAD_MARKER] !== 1) {
    throw new MalformedWorkerPayloadError(
      `the object carries no ${PAYLOAD_MARKER} marker. Pass the object toWorkerPayload() ` +
        'returned, not one assembled by hand.'
    );
  }

  return payload;
}

function requireValueRecord(values: unknown): Record<string, unknown> {
  if (!isPlainRecord(values)) {
    throw new MalformedWorkerPayloadError(
      `values must be an object, received ${describeKind(values)}`
    );
  }

  return values;
}

/**
 * The parts of a wire object that decide whether it can be rebuilt here.
 *
 * `deserialize()` checks the rest, and its own errors are wrapped so they name
 * the key. The class check is separate because its failure has its own error
 * and its own instruction.
 */
function requireWireObject(entry: unknown, key: string): SerializedSensitiveString {
  if (!isPlainRecord(entry)) {
    throw new MalformedWorkerPayloadError(
      `values.${key} is ${describeKind(entry)}, not a serialized sensitive value`
    );
  }

  if (entry['__sensitive'] !== true) {
    throw new MalformedWorkerPayloadError(`values.${key} carries no __sensitive marker`);
  }

  if (typeof entry['value'] !== 'string') {
    throw new MalformedWorkerPayloadError(
      `values.${key} has ${describeKind(entry['value'])} where its string value belongs`
    );
  }

  const klass = entry['klass'];

  if (typeof klass !== 'string') {
    throw new MalformedWorkerPayloadError(
      `values.${key} has ${describeKind(klass)} where its sensitivity class belongs`
    );
  }

  if (!hasPolicy(klass as SensitivityClass)) {
    throw new UnregisteredClassError(key, klass, getRegisteredClasses());
  }

  return entry as unknown as SerializedSensitiveString;
}

function requireContext(context: unknown): PortableRevealContext | undefined {
  if (context === undefined) {
    return undefined;
  }

  if (!isPlainRecord(context) || typeof context['name'] !== 'string') {
    throw new MalformedWorkerPayloadError('context must be an object with a string name');
  }

  const reason = context['reason'];
  const tags = context['tags'];

  if (reason !== undefined && typeof reason !== 'string') {
    throw new MalformedWorkerPayloadError('context.reason must be a string when present');
  }

  if (tags !== undefined && !isPlainRecord(tags)) {
    throw new MalformedWorkerPayloadError('context.tags must be an object when present');
  }

  const portable: { name: string; reason?: string; tags?: Record<string, unknown> } = {
    name: context['name'],
  };

  if (reason !== undefined) {
    portable.reason = reason;
  }

  if (tags !== undefined) {
    portable.tags = tags;
  }

  return portable;
}

/**
 * Delete the raw values from the payload and mark it consumed.
 *
 * Deleting rather than overwriting is deliberate. A sentinel would leave a
 * payload that still deserializes, into an instance that wraps the sentinel
 * and looks valid. The `__sensitive` and `klass` fields stay, so a consumed
 * payload still renders as a redaction under the marker-aware walks.
 *
 * `workerData` is one mutable object shared by every module in the thread, so
 * this deletion is thread-wide *within that thread*: a later
 * `console.log(workerData)` or a crash handler serializing it no longer reads
 * the values. It does not reach back to the sender, whose own object was
 * cloned on the way out, and it does not erase the string from the heap.
 *
 * Every write is best-effort. This is hardening applied after the instances
 * have already been rebuilt, so a frozen payload must not turn a successful
 * consume into a throw that leaves the caller with no values *and* the
 * plaintext still in place, which is strictly worse than either alone.
 * `consumed` reports whether the payload can be relied on to refuse a second
 * call.
 */
function consume(payload: Record<string, unknown>, values: Record<string, unknown>): boolean {
  for (const key of Object.keys(values)) {
    const entry = values[key];

    if (isPlainRecord(entry)) {
      try {
        delete entry['value'];
      } catch {
        // A frozen or sealed entry keeps its value. Nothing else to try: the
        // caller froze it, and the rebuild has already succeeded.
      }
    }
  }

  try {
    payload['consumed'] = true;
    return payload['consumed'] === true;
  } catch {
    return false;
  }
}

/**
 * This side's audit hook: the one given, or the ambient one forwarded.
 *
 * Forwarded rather than copied, so the ambient context stays the receiver of
 * its own method. And forwarded rather than left implicit: the returned context
 * is meant to be installed, and installing a context without a hook would
 * replace the ambient one that has it.
 */
function resolveAuditHook(
  given: RevealContext['auditReveal'],
  ambient: RevealContext | null
): RevealContext['auditReveal'] {
  if (given !== undefined) {
    return given;
  }

  if (ambient?.auditReveal === undefined) {
    return undefined;
  }

  return (value, details) => ambient.auditReveal?.(value, details);
}

/**
 * Rebuild the instances a payload carries, and take the raw values out of it.
 *
 * Validation runs in full before anything is rebuilt, and rebuilding runs in
 * full before the payload is consumed, so a call that throws returns no
 * partial result and, with one exception, leaves the payload intact for a
 * corrected retry. The exception is a value that expired between build and
 * consume: that cannot be fixed by retrying, so the payload is consumed before
 * the throw rather than left holding plaintext for the life of the thread.
 *
 * @param payload - What arrived: `workerData`, a message, or an IPC message.
 * @param options - This side's audit hook, and what to require.
 * @throws MalformedWorkerPayloadError If `payload` is not what `toWorkerPayload()` returns.
 * @throws ConsumedWorkerPayloadError If the payload was consumed already.
 * @throws MissingWorkerValueError If a key in `require` is absent.
 * @throws UnregisteredClassError If a value's class is not registered on this thread.
 * @throws UnauditedWorkerError If the payload is audited and no hook is available here.
 * @throws ExpiredSensitiveValueError If a value expired in transit, naming its key.
 *
 * @example
 * ```ts
 * const { values, context } = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(
 *   workerData,
 *   { auditReveal: (value, details) => log.info('reveal', { klass: value.klass, ...details }) },
 * );
 * withRevealContext(context, () => callApi(values.token.reveal()));
 * ```
 *
 * @remarks
 * The type parameter is a claim about names and classes that the runtime
 * cannot check, as with `deserialize()`. `require` is what makes the names
 * enforceable.
 *
 * After this returns, the payload object holds no raw value and a second call
 * on it throws. A heap snapshot or a debugger still sees the string, which is
 * the same limitation the library has everywhere.
 */
export function fromWorkerPayload<T extends SensitiveValues<T>>(
  payload: unknown,
  options: FromWorkerPayloadOptions = {}
): ReceivedWorkerPayload<T> {
  const container = requirePayload(payload);

  if (container['consumed'] === true) {
    throw new ConsumedWorkerPayloadError();
  }

  const values = requireValueRecord(container['values']);

  for (const key of options.require ?? []) {
    if (!Object.hasOwn(values, key)) {
      throw new MissingWorkerValueError(key);
    }
  }

  const entries: [string, SerializedSensitiveString][] = Object.keys(values).map((key) => [
    key,
    requireWireObject(values[key], key),
  ]);

  const hook = resolveAuditHook(options.auditReveal, getCurrentRevealContext());

  if (container['audited'] === true && hook === undefined && options.allowUnaudited !== true) {
    throw new UnauditedWorkerError();
  }

  const carried = requireContext(container['context']);
  const rebuilt: Record<string, SensitiveString<SensitivityClass>> = {};

  for (const [key, wire] of entries) {
    let value: SensitiveString<SensitivityClass>;

    try {
      value = SensitiveString.deserialize(wire);
    } catch (error) {
      // `deserialize()` describes the field, never the value, so its message
      // is safe to carry; what it lacks is the key.
      throw new MalformedWorkerPayloadError(
        `values.${key}: ${error instanceof Error ? error.message : 'could not be deserialized'}`
      );
    }

    // A value with milliseconds left when the payload was built can be dead
    // by the time a thread has started. Refused here, where the cause is
    // visible, rather than handed back to throw from inside application code.
    if (value.isExpired()) {
      const deadline = value.expiresAt ?? new Date(NaN);

      if (options.keepPayload !== true) {
        consume(container, values);
      }

      throw new ExpiredSensitiveValueError(deadline, new Date(), value.label, key);
    }

    assignOwn(rebuilt, key, value);
  }

  if (options.keepPayload !== true) {
    consume(container, values);
  }

  const context: RevealContext = { ...(carried ?? { name: 'worker' }) };

  if (hook !== undefined) {
    context.auditReveal = hook;
  }

  return { values: rebuilt as T, context, data: container['data'] };
}

/**
 * `fromWorkerPayload()` followed by `withRevealContext()`.
 *
 * The two-call form has a failure mode that is invisible in review:
 * destructure `values`, forget `context`, and every reveal in the worker runs
 * unaudited while the code still reads as if the context were handled. This
 * form cannot express that mistake.
 *
 * Returns whatever `fn` returns, a Promise included, matching
 * `withRevealContext()`.
 *
 * @typeParam T - The values the payload is claimed to carry. Unverifiable at
 *   runtime, as with `deserialize()`; pass `require` to enforce the names.
 * @typeParam R - What `fn` returns. Inferred, and `unknown` when `T` is given
 *   explicitly, for the reason under @remarks.
 *
 * @example Annotate the callback, and both are inferred
 * ```ts
 * await withWorkerPayload(
 *   workerData,
 *   { auditReveal },
 *   ({ token }: { token: SensitiveString<'credential'> }, data) =>
 *     callApi(token.reveal(), data),
 * );
 * ```
 *
 * @example Or name both, when the return type matters and the callback is long
 * ```ts
 * const signatures = withWorkerPayload<SignerValues, string[]>(
 *   workerData,
 *   { auditReveal, require: ['signingKey'] },
 *   ({ signingKey }, data) => sign(signingKey.reveal(), data),
 * );
 * ```
 *
 * @remarks
 * TypeScript has no partial type argument inference: naming `T` alone fills
 * `R` from its default rather than inferring it, so the call still compiles
 * and its result is `unknown`. That is harmless when the result is discarded,
 * which is the common shape in a worker, and the two examples above are the
 * ways to keep it. `fromWorkerPayload()` takes one type parameter and has no
 * such wart, so the two-call form is the other way out.
 */
export function withWorkerPayload<T extends SensitiveValues<T>, R = unknown>(
  payload: unknown,
  options: FromWorkerPayloadOptions,
  fn: (values: T, data: unknown) => R
): R {
  const received = fromWorkerPayload<T>(payload, options);

  return withRevealContext(received.context, () => fn(received.values, received.data));
}
