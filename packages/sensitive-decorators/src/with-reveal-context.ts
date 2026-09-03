import {
  createChildContext,
  withRevealContext,
  type RevealContext,
} from '@platform-sec/sensitive-string-core';
import { describeType } from './describe-type.js';

/**
 * Builds a reveal context from the call the decorated method received.
 *
 * `self` is the receiver. It is `unknown` because a decorator factory is
 * called before TypeScript knows which class the decorator lands on, so the
 * instance type cannot reach this signature; a factory that needs the instance
 * casts it.
 */
export type RevealContextFactory = (args: readonly unknown[], self: unknown) => RevealContext;

/** A fixed reveal context, or one built per call. */
export type RevealContextInput = RevealContext | RevealContextFactory;

/**
 * Iterator shape shared by generators and async generators, at the widest type
 * that lets both be forwarded.
 */
interface ResumableIterator {
  next(...args: unknown[]): unknown;
  return?(value?: unknown): unknown;
  throw?(error?: unknown): unknown;
}

const GENERATOR_TAG = '[object GeneratorFunction]';
const ASYNC_GENERATOR_TAG = '[object AsyncGeneratorFunction]';

/**
 * Validate a reveal context.
 *
 * No message renders the context or its tags. A factory reading a request
 * builds contexts out of exactly the material that must not reach a log.
 */
function checkContext(value: unknown, source: string, method: string): RevealContext {
  if (value === null || typeof value !== 'object') {
    throw new TypeError(
      `@WithRevealContext on ${method}: ${source} is ${describeType(value)}; ` +
        `expected a RevealContext object`
    );
  }

  const candidate = value as Partial<RevealContext>;

  if (typeof candidate.name !== 'string' || candidate.name.length === 0) {
    throw new TypeError(
      `@WithRevealContext on ${method}: ${source} has no non-empty 'name'; ` +
        `a reveal context names the operation an audit record is filed under`
    );
  }

  if (candidate.auditReveal !== undefined && typeof candidate.auditReveal !== 'function') {
    throw new TypeError(
      `@WithRevealContext on ${method}: ${source} has an 'auditReveal' that is ` +
        `${describeType(candidate.auditReveal)}; expected a function`
    );
  }

  return candidate as RevealContext;
}

/**
 * Copy a validated context, one call's worth.
 *
 * Two reasons this is per call rather than once at decoration. Own properties
 * set to `undefined` are dropped rather than copied, because
 * `createChildContext` spreads this object over the ambient one: a context
 * carrying `auditReveal: undefined` would otherwise erase the audit sink of
 * the context it is nested in, which is the one failure here that is silent.
 *
 * And `createChildContext` returns its argument unchanged when there is no
 * ambient context, so a single object copied once would become the live
 * ambient context of every later call to the method. A handler that reached
 * for `getCurrentRevealContext()` and added a tag would be writing into the
 * decorator itself, and every subsequent request would inherit it. A call site
 * that writes `withRevealContext({ ... })` by hand gets a fresh object each
 * time, and so does this.
 */
function copyContext(context: RevealContext): RevealContext {
  const copy: RevealContext = { name: context.name };

  if (context.reason !== undefined) {
    copy.reason = context.reason;
  }

  if (context.tags !== undefined) {
    copy.tags = { ...context.tags };
  }

  if (context.auditReveal !== undefined) {
    copy.auditReveal = context.auditReveal;
  }

  return copy;
}

/**
 * Run every resumption of a generator inside the context.
 *
 * Calling a generator function only builds the iterator; the body runs on
 * `next()`, which happens after `AsyncLocalStorage.run` has returned. Wrapping
 * the call alone would leave every `reveal()` in the body running with
 * whatever context the consumer happened to be under, which for the usual
 * consumer is none, and an unaudited reveal is the failure this decorator
 * exists to prevent.
 */
function resumeInContext(
  iterator: ResumableIterator,
  ctx: RevealContext,
  isAsync: boolean
): ResumableIterator {
  const run = <T>(fn: () => T): T => withRevealContext(ctx, fn);
  const wrapper: Record<string | symbol, unknown> = {
    next: (...args: unknown[]) => run(() => iterator.next(...args)),
  };

  // Forwarded only when present. Every iterator a generator function returns
  // has all three, so this is defensive: it keeps an iterator that arrived by
  // some other route failing the way it did, since `for...of` tests for
  // `return` before calling it and an unconditional one would throw instead.
  const finish = iterator.return;
  if (typeof finish === 'function') {
    wrapper['return'] = (value?: unknown) => run(() => finish.call(iterator, value));
  }

  const raise = iterator.throw;
  if (typeof raise === 'function') {
    wrapper['throw'] = (error?: unknown) => run(() => raise.call(iterator, error));
  }

  wrapper[isAsync ? Symbol.asyncIterator : Symbol.iterator] = () => wrapper;

  return wrapper as unknown as ResumableIterator;
}

/**
 * Run a method inside a reveal context, so every `reveal()` it reaches is
 * audited under one named operation.
 *
 * ```ts
 * class PaymentProcessor {
 *   \@WithRevealContext({ name: 'payment-processing', reason: 'charging card' })
 *   async processPayment(card: SensitiveString<'credential'>) {
 *     await gateway.charge(card.reveal());
 *   }
 * }
 * ```
 *
 * A factory builds the context from the call instead:
 *
 * ```ts
 * \@WithRevealContext((args, self) => ({
 *   name: 'refund-processing',
 *   tags: { orderId: (self as OrderService).currentOrderId },
 * }))
 * ```
 *
 * The context is nested rather than substituted, on the terms
 * `createChildContext` sets: `name`, `reason`, and `auditReveal` given here
 * replace the ambient ones, `tags` merge with these winning, and anything not
 * given is inherited. An outer audit sink therefore keeps receiving records
 * from a method that only names itself, which a substitution would silently
 * stop.
 *
 * Sync methods, async methods, generators, and async generators are all
 * covered. A method that is not itself a generator but returns an iterator
 * built elsewhere is not: the context ends when that method returns, and such
 * a method establishes its own context around the loop that produces values.
 *
 * @param context - The context, or a factory called with the call's arguments
 *   and receiver on every invocation
 * @throws TypeError At decoration time if the decorator is applied to anything
 *   but a method, or if a fixed context is not a usable one; at call time if a
 *   factory returns one that is not. A factory that throws propagates, and the
 *   method does not run.
 */
export function WithRevealContext(context: RevealContextInput) {
  return function <This, Args extends unknown[], Return>(
    method: (this: This, ...args: Args) => Return,
    decorator: ClassMethodDecoratorContext<This, (this: This, ...args: Args) => Return>
  ): (this: This, ...args: Args) => Return {
    // Widened, because TypeScript has already narrowed `kind` to 'method' from
    // the parameter type. The check is for JavaScript callers, whose only
    // other symptom would be a handler running with no context at all.
    const kind: string = decorator.kind;
    if (kind !== 'method') {
      throw new TypeError(
        `@WithRevealContext cannot decorate a ${kind}; it decorates a method. ` +
          `Call withRevealContext() inside the body instead`
      );
    }

    const name = `${decorator.static ? 'static method' : 'method'} '${String(decorator.name)}'`;

    // A fixed context is checked once, at class definition, so a malformed one
    // fails on load rather than on the first request that reaches the handler.
    // A factory result cannot be checked until there is one.
    //
    // The fixed path copies twice on purpose. The copy here snapshots the
    // object the caller passed, so mutating it afterwards does not change the
    // decorator; the copy inside `resolve` gives each call its own. A factory
    // returns a fresh object per call already, so it needs only the second.
    let resolve: RevealContextFactory;
    if (typeof context === 'function') {
      resolve = (args, self) =>
        copyContext(checkContext(context(args, self), 'the context factory result', name));
    } else {
      const fixed = copyContext(checkContext(context, 'the context argument', name));
      resolve = () => copyContext(fixed);
    }

    const tag = Object.prototype.toString.call(method);
    const isSyncGenerator = tag === GENERATOR_TAG;
    const isAsyncGenerator = tag === ASYNC_GENERATOR_TAG;

    const wrapped = function (this: This, ...args: Args): Return {
      // Nested, not substituted: an ambient audit sink survives a method that
      // only names itself.
      const ctx = createChildContext(resolve(args, this));

      if (!isSyncGenerator && !isAsyncGenerator) {
        return withRevealContext(ctx, () => method.apply(this, args));
      }

      const iterator = withRevealContext(ctx, () => method.apply(this, args));

      return resumeInContext(
        iterator as unknown as ResumableIterator,
        ctx,
        isAsyncGenerator
      ) as unknown as Return;
    };

    // A replacement function is anonymous and reports its own arity. Frameworks
    // and error messages read both, so they are restored from the original.
    Object.defineProperty(wrapped, 'name', { value: method.name, configurable: true });
    Object.defineProperty(wrapped, 'length', { value: method.length, configurable: true });

    return wrapped;
  };
}
