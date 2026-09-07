import type {
  AuditContext,
  ISensitiveString,
  RevealContext,
  RevealDetails,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

/**
 * The audit callback shape core invokes, named so a mock factory can be typed
 * against it.
 */
export type AuditRevealFn = (
  value: ISensitiveString,
  details: RevealDetails,
  context: AuditContext
) => void;

/**
 * A factory that wraps a function in the host framework's spy, such as `vi.fn`
 * or `jest.fn`.
 *
 * The factory is passed in rather than detected at runtime. Detection would
 * mean reading a `vi` or `jest` global that only exists under one framework and
 * only when globals are enabled, and importing either framework would make this
 * package depend on the one the consumer might not be using.
 */
export type MockFunctionFactory = (implementation: AuditRevealFn) => AuditRevealFn;

/** One recorded call to a mock context's audit hook. */
export interface AuditCall {
  readonly timestamp: Date;
  /**
   * The value that was accessed.
   *
   * The instance, not its raw value: an assertion can read `klass` and `label`
   * from it, and reading anything more still has to go through `reveal()`.
   */
  readonly value: ISensitiveString;
  /** What the operation was, and its parameters. */
  readonly details: RevealDetails;
  /**
   * The context the operation ran under, copied rather than referenced.
   *
   * Not necessarily the mock context itself: an integration that nests a child
   * over it to tag a reveal is audited under the child, and the child's name
   * and tags are what appear here.
   *
   * A copy because the live context of a mock holds `calls`, and a record
   * pointing back at it would make the call log a cycle that neither
   * `JSON.stringify` nor a snapshot assertion could walk. `tags` is copied one
   * level, so a later reveal under the same context cannot rewrite what an
   * earlier record says.
   *
   * A caller that forwards the hook with two arguments names no context, and
   * the record then carries this context's own name and no tags.
   */
  readonly context: AuditContext;
}

/** Options for `mockRevealContext`. */
export interface MockRevealContextOptions {
  /** Spy factory, such as `vi.fn` or `jest.fn`. */
  fn?: MockFunctionFactory;
  /** Reason recorded on the context. */
  reason?: string;
  /** Tags recorded on the context. */
  tags?: Record<string, unknown>;
}

/** A `RevealContext` that records what was accessed through it. */
export interface MockRevealContext extends RevealContext {
  readonly name: string;
  /** The audit hook. A spy when a factory was given, a plain function otherwise. */
  auditReveal: AuditRevealFn;
  /** Calls in order. Recorded whether or not a spy factory was given. */
  readonly calls: readonly AuditCall[];
  /** Forget every recorded call, and clear the spy if there is one. */
  reset(): void;
}

/**
 * Create a `RevealContext` that records every access made through it.
 *
 * Pass it to `reveal()`, `mask()`, or `withRevealContext()` and assert on
 * `calls`. Passing a spy factory additionally makes `auditReveal` a spy, so the
 * framework's own call assertions work on it.
 *
 * @example
 * ```ts
 * const ctx = mockRevealContext('payment-handler', { fn: vi.fn });
 * const token = createTestSecret('credential', 'api_key');
 *
 * token.reveal(ctx);
 *
 * expect(ctx.calls).toHaveLength(1);
 * expect(ctx.calls[0]?.details.operation).toBe('reveal');
 * expect(ctx.auditReveal).toHaveBeenCalledTimes(1);
 * ```
 */
export function mockRevealContext(
  name: string,
  options: MockRevealContextOptions = {}
): MockRevealContext {
  const calls: AuditCall[] = [];

  const record: AuditRevealFn = (value, details, context) => {
    calls.push({ timestamp: new Date(), value, details, context: snapshot(context, name) });
  };

  const auditReveal = options.fn ? options.fn(record) : record;

  const context: MockRevealContext = {
    name,
    auditReveal,
    calls,
    reset() {
      calls.length = 0;
      clearSpy(auditReveal);
    },
  };

  if (options.reason !== undefined) {
    context.reason = options.reason;
  }

  if (options.tags !== undefined) {
    context.tags = options.tags;
  }

  return context;
}

/**
 * One recorded access, reduced to what an audit sink would keep.
 *
 * There is deliberately no raw value and no reference to the instance here: an
 * audit log is the thing most likely to be printed by a failing assertion or
 * dumped into a snapshot, so it holds classification and nothing else.
 */
export interface AuditEntry {
  readonly timestamp: Date;
  readonly klass: SensitivityClass;
  readonly label: string | undefined;
  /**
   * Name of the context the access was made under.
   *
   * Read from the context core reports, so a reveal made under a child context
   * is recorded under the child's name rather than this log's. A caller that
   * forwards the hook with two arguments names no context, and the entry then
   * carries this log's own name.
   */
  readonly contextName: string;
  /** `reveal`, `mask`, or `renew`. */
  readonly operation: RevealDetails['operation'];
  readonly details: RevealDetails;
}

/** A recording audit sink, plus the context that feeds it. */
export interface MockAuditLog {
  readonly entries: readonly AuditEntry[];
  /** Pass this to `withRevealContext()` or to an individual operation. */
  readonly context: RevealContext;
  /** Entries whose value carried this label. */
  getEntriesFor(label: string): AuditEntry[];
  /** Entries whose value had this sensitivity class. */
  getEntriesByClass(klass: SensitivityClass): AuditEntry[];
  /** Forget every entry. */
  clear(): void;
}

/**
 * Create a context whose audit hook records classification only.
 *
 * Use it to assert that a code path audited what it accessed, without the test
 * holding a second reference to the values.
 *
 * @example
 * ```ts
 * const audit = createMockAuditLog();
 *
 * await withRevealContext(audit.context, async () => {
 *   await chargeCard(card);
 * });
 *
 * expect(audit.getEntriesFor('card_number')).toHaveLength(1);
 * ```
 */
export function createMockAuditLog(name = 'mock-audit-log'): MockAuditLog {
  const entries: AuditEntry[] = [];

  const context: RevealContext = {
    name,
    // An arrow rather than a method, deliberately: this hook exists to be
    // handed to `withRevealContext()` and forwarded on, and a method that is
    // detached from its object loses `this`. It reads none, and this way it
    // cannot start to.
    auditReveal: (value, details, auditedUnder) => {
      entries.push({
        timestamp: new Date(),
        klass: value.klass,
        label: value.label,
        // Falls back for the same reason `snapshot()` does: a caller
        // forwarding this hook with two arguments names no context, and this
        // one is then the context the operation ran under.
        contextName: contextNameOr(auditedUnder, name),
        operation: details.operation,
        details,
      });
    },
  };

  return {
    entries,
    context,
    getEntriesFor(label) {
      return entries.filter((entry) => entry.label === label);
    },
    getEntriesByClass(klass) {
      return entries.filter((entry) => entry.klass === klass);
    },
    clear() {
      entries.length = 0;
    },
  };
}

/**
 * What a record keeps of the context an operation ran under.
 *
 * The descriptive fields only, one level deep. See `AuditCall.context` for why
 * this is a copy.
 *
 * `undefined` is not a shape core produces, and it is the shape a caller
 * forwarding the hook itself produces: a two-argument call, which is what core
 * made before it carried the context and what a consumer's own forwarder still
 * makes. This runs inside the raw-value gate, where a `TypeError` would surface
 * as a failing reveal in somebody's test rather than as a missing tag, so the
 * answer is the context the hook was installed on. For a two-argument caller
 * that is the truthful one: it is the context the operation ran under, and the
 * argument exists only because a nested child can now say otherwise.
 */
function snapshot(context: AuditContext | undefined, installedOn: string): AuditContext {
  if (context === undefined) return { name: installedOn };

  const copy: { name: string; reason?: string; tags?: Record<string, unknown> } = {
    name: context.name,
  };

  if (context.reason !== undefined) copy.reason = context.reason;
  if (context.tags !== undefined) copy.tags = { ...context.tags };

  return copy;
}

/**
 * The name of the context an operation ran under, falling back to the context
 * holding the hook when a two-argument caller named none. See `snapshot()`.
 */
function contextNameOr(context: AuditContext | undefined, installedOn: string): string {
  return context === undefined ? installedOn : context.name;
}

/**
 * Clear a spy's recorded calls when the function turns out to be one.
 *
 * Both frameworks expose `mockClear`, so this needs no knowledge of which one
 * produced the spy.
 */
function clearSpy(fn: AuditRevealFn): void {
  const candidate = fn as { mockClear?: () => void };

  if (typeof candidate.mockClear === 'function') {
    candidate.mockClear();
  }
}
