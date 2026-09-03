import { describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  getCurrentRevealContext,
  withRevealContext,
  type RevealContext,
} from '@platform-sec/sensitive-string-core';
import { WithRevealContext } from './with-reveal-context.js';

/** The context a method body sees, or null when it runs under none. */
function seen(): RevealContext | null {
  return getCurrentRevealContext();
}

/**
 * The runtime guard for a misapplied decorator is unreachable through the
 * decorator's own types. Applying the inner function by hand is what a
 * JavaScript caller does.
 */
function applyByHand(
  decorator: unknown,
  target: unknown,
  context: { kind: string; name: string | symbol; static: boolean }
): unknown {
  return (decorator as (value: unknown, context: unknown) => unknown)(target, context);
}

describe('@WithRevealContext', () => {
  describe('function kinds', () => {
    it('covers a synchronous method', () => {
      class Handler {
        @WithRevealContext({ name: 'sync-op' })
        run(): string | undefined {
          return seen()?.name;
        }
      }

      expect(new Handler().run()).toBe('sync-op');
    });

    it('covers an async method across an await', () => {
      class Handler {
        @WithRevealContext({ name: 'async-op' })
        async run(): Promise<string | undefined> {
          await Promise.resolve();

          return seen()?.name;
        }
      }

      return expect(new Handler().run()).resolves.toBe('async-op');
    });

    it('covers every resumption of a generator method', () => {
      class Handler {
        @WithRevealContext({ name: 'generator-op' })
        *run(): Generator<string | undefined> {
          yield seen()?.name;
          yield seen()?.name;
        }
      }

      expect([...new Handler().run()]).toEqual(['generator-op', 'generator-op']);
    });

    it('covers every resumption of an async generator method', async () => {
      class Handler {
        @WithRevealContext({ name: 'async-generator-op' })
        async *run(): AsyncGenerator<string | undefined> {
          await Promise.resolve();
          yield seen()?.name;
          await Promise.resolve();
          yield seen()?.name;
        }
      }

      const names: (string | undefined)[] = [];
      for await (const name of new Handler().run()) {
        names.push(name);
      }

      expect(names).toEqual(['async-generator-op', 'async-generator-op']);
    });

    it('forwards early termination of a generator', () => {
      const closed = vi.fn();

      class Handler {
        @WithRevealContext({ name: 'generator-op' })
        *run(): Generator<string | undefined> {
          try {
            yield seen()?.name;
            yield seen()?.name;
          } finally {
            closed(seen()?.name);
          }
        }
      }

      for (const _name of new Handler().run()) {
        break;
      }

      // `for...of` calls return() on an early exit, and the finally block runs
      // as part of that resumption, so it is still inside the context.
      expect(closed).toHaveBeenCalledWith('generator-op');
    });

    it('forwards early termination of an async generator', async () => {
      const closed = vi.fn();

      class Handler {
        @WithRevealContext({ name: 'async-generator-op' })
        async *run(): AsyncGenerator<string | undefined> {
          try {
            await Promise.resolve();
            yield seen()?.name;
            yield seen()?.name;
          } finally {
            closed(seen()?.name);
          }
        }
      }

      for await (const _name of new Handler().run()) {
        break;
      }

      expect(closed).toHaveBeenCalledWith('async-generator-op');
    });

    it('forwards a throw into a generator', () => {
      class Handler {
        @WithRevealContext({ name: 'generator-op' })
        *run(): Generator<string, string> {
          try {
            yield 'first';
          } catch {
            return seen()?.name ?? 'none';
          }

          return 'not reached';
        }
      }

      const iterator = new Handler().run();
      iterator.next();

      expect(iterator.throw(new Error('stop')).value).toBe('generator-op');
    });
  });

  describe('context resolution', () => {
    it('passes the reason and tags through', () => {
      class Handler {
        @WithRevealContext({ name: 'charge', reason: 'charging card', tags: { tier: 'gold' } })
        run(): RevealContext | null {
          return seen();
        }
      }

      const context = new Handler().run();

      expect(context?.reason).toBe('charging card');
      expect(context?.tags).toMatchObject({ tier: 'gold' });
    });

    it('builds the context from the call when given a factory', () => {
      class Handler {
        readonly region = 'eu-west-1';

        @WithRevealContext((args, self) => ({
          name: 'refund',
          tags: { orderId: args[0], region: (self as Handler).region },
        }))
        run(_orderId: string): RevealContext | null {
          return seen();
        }
      }

      const context = new Handler().run('ord_42');

      expect(context?.tags).toEqual({ orderId: 'ord_42', region: 'eu-west-1' });
    });

    it('calls the factory on every invocation', () => {
      let calls = 0;

      class Handler {
        @WithRevealContext(() => ({ name: `attempt-${++calls}` }))
        run(): string | undefined {
          return seen()?.name;
        }
      }

      const handler = new Handler();

      expect(handler.run()).toBe('attempt-1');
      expect(handler.run()).toBe('attempt-2');
    });

    it('gives each call its own context object', () => {
      class Handler {
        @WithRevealContext({ name: 'charge', tags: { stage: 'declared' } })
        run(): RevealContext | null {
          return seen();
        }
      }

      const handler = new Handler();
      const first = handler.run();

      // `createChildContext` returns its argument unchanged when nothing is
      // ambient, so a context object shared across calls would be the live
      // ambient context of every later one: a handler adding a tag here would
      // be writing into the decorator, and the next request would inherit it.
      (first?.tags as Record<string, unknown>)['requestId'] = 'req_1';

      const second = handler.run();

      expect(second).not.toBe(first);
      expect(second?.tags).toEqual({ stage: 'declared' });
    });

    it('reads the fixed context as it was at decoration time', () => {
      const context: RevealContext = { name: 'charge', reason: 'charging card' };

      class Handler {
        @WithRevealContext(context)
        run(): RevealContext | null {
          return seen();
        }
      }

      context.reason = 'rewritten after the fact';

      expect(new Handler().run()?.reason).toBe('charging card');
    });
  });

  describe('nesting', () => {
    it('overrides the ambient name and reason', () => {
      class Handler {
        @WithRevealContext({ name: 'charge' })
        run(): RevealContext | null {
          return seen();
        }
      }

      const context = withRevealContext({ name: 'http-request', reason: 'POST /charges' }, () =>
        new Handler().run()
      );

      expect(context?.name).toBe('charge');
      expect(context?.reason).toBe('POST /charges');
    });

    it('keeps an ambient audit sink the method does not replace', () => {
      const audit = vi.fn();

      class Handler {
        @WithRevealContext({ name: 'charge' })
        run(card: SensitiveString<'credential'>): string {
          return card.reveal();
        }
      }

      const card = new SensitiveString('4111111111111111', 'credential', 'pan');
      withRevealContext({ name: 'http-request', auditReveal: audit }, () =>
        new Handler().run(card)
      );

      expect(audit).toHaveBeenCalledTimes(1);
    });

    it('merges tags with the method winning on a conflict', () => {
      class Handler {
        @WithRevealContext({ name: 'charge', tags: { stage: 'inner' } })
        run(): RevealContext | null {
          return seen();
        }
      }

      const context = withRevealContext(
        { name: 'http-request', tags: { stage: 'outer', requestId: 'req_1' } },
        () => new Handler().run()
      );

      expect(context?.tags).toEqual({ stage: 'inner', requestId: 'req_1' });
    });

    it('does not erase an ambient audit sink with an explicit undefined', () => {
      const audit = vi.fn();
      // `exactOptionalPropertyTypes` stops a TypeScript caller from writing
      // `auditReveal: undefined`, so the reachable path is a context assembled
      // without types: a builder that fills in an optional sink it did not get.
      const assembled = { name: 'charge', auditReveal: undefined } as unknown as RevealContext;

      class Handler {
        @WithRevealContext(assembled)
        run(card: SensitiveString<'credential'>): string {
          return card.reveal();
        }
      }

      const card = new SensitiveString('4111111111111111', 'credential', 'pan');
      withRevealContext({ name: 'http-request', auditReveal: audit }, () =>
        new Handler().run(card)
      );

      expect(audit).toHaveBeenCalledTimes(1);
    });
  });

  describe('scope', () => {
    it('leaves no context behind after a synchronous call', () => {
      class Handler {
        @WithRevealContext({ name: 'charge' })
        run(): void {}
      }

      new Handler().run();

      expect(getCurrentRevealContext()).toBeNull();
    });

    it('leaves no context behind after a rejected call', async () => {
      class Handler {
        @WithRevealContext({ name: 'charge' })
        async run(): Promise<never> {
          await Promise.resolve();

          throw new Error('gateway refused');
        }
      }

      await expect(new Handler().run()).rejects.toThrow('gateway refused');
      expect(getCurrentRevealContext()).toBeNull();
    });

    it('propagates a synchronous throw', () => {
      class Handler {
        @WithRevealContext({ name: 'charge' })
        run(): never {
          throw new Error('gateway refused');
        }
      }

      expect(() => new Handler().run()).toThrow('gateway refused');
    });
  });

  describe('the replaced method', () => {
    it('keeps the receiver', () => {
      class Handler {
        readonly region = 'eu-west-1';

        @WithRevealContext({ name: 'charge' })
        run(): string {
          return this.region;
        }
      }

      expect(new Handler().run()).toBe('eu-west-1');
    });

    it('passes the arguments through and returns the result', () => {
      class Handler {
        @WithRevealContext({ name: 'charge' })
        run(a: number, b: number): number {
          return a + b;
        }
      }

      expect(new Handler().run(2, 3)).toBe(5);
    });

    it('keeps the name and arity of the method it replaced', () => {
      class Handler {
        @WithRevealContext({ name: 'charge' })
        run(_a: number, _b: number): void {}
      }

      // eslint-disable-next-line @typescript-eslint/unbound-method -- only .name and .length are read; the method is never called
      const method = Handler.prototype.run;

      expect(method.name).toBe('run');
      expect(method.length).toBe(2);
    });

    it('covers a static method', () => {
      class Handler {
        @WithRevealContext({ name: 'boot' })
        static run(): string | undefined {
          return seen()?.name;
        }
      }

      expect(Handler.run()).toBe('boot');
    });
  });

  describe('refusals', () => {
    it('refuses a fixed context that is not an object', () => {
      expect(() =>
        applyByHand(WithRevealContext('charge' as unknown as RevealContext), () => undefined, {
          kind: 'method',
          name: 'run',
          static: false,
        })
      ).toThrow(/expected a RevealContext object/);
    });

    it('refuses a null context', () => {
      expect(() =>
        applyByHand(WithRevealContext(null as unknown as RevealContext), () => undefined, {
          kind: 'method',
          name: 'run',
          static: false,
        })
      ).toThrow(/the context argument is null/);
    });

    it('refuses a fixed context with no name at decoration time', () => {
      expect(() =>
        applyByHand(WithRevealContext({} as unknown as RevealContext), () => undefined, {
          kind: 'method',
          name: 'run',
          static: false,
        })
      ).toThrow(/has no non-empty 'name'/);
    });

    it('names the method a bad fixed context was declared on', () => {
      expect(() =>
        applyByHand(WithRevealContext({ name: '' }), () => undefined, {
          kind: 'method',
          name: 'processPayment',
          static: false,
        })
      ).toThrow(/method 'processPayment'/);
    });

    it('refuses a factory result with no name, when it is called', () => {
      class Handler {
        @WithRevealContext(() => ({}) as unknown as RevealContext)
        run(): void {}
      }

      expect(() => new Handler().run()).toThrow(/the context factory result has no non-empty/);
    });

    it('refuses an auditReveal that is not a function', () => {
      const assembled = { name: 'charge', auditReveal: 'log' } as unknown as RevealContext;

      expect(() =>
        applyByHand(WithRevealContext(assembled), () => undefined, {
          kind: 'method',
          name: 'run',
          static: false,
        })
      ).toThrow(/'auditReveal' that is string/);
    });

    it('does not run the method when the factory throws', () => {
      const body = vi.fn();

      class Handler {
        @WithRevealContext(() => {
          throw new Error('no request in scope');
        })
        run(): void {
          body();
        }
      }

      expect(() => new Handler().run()).toThrow('no request in scope');
      expect(body).not.toHaveBeenCalled();
    });

    it('refuses to decorate anything but a method', () => {
      const decorator = WithRevealContext({ name: 'charge' });

      expect(() =>
        applyByHand(decorator, () => undefined, { kind: 'getter', name: 'token', static: false })
      ).toThrow(/cannot decorate a getter/);
      expect(() =>
        applyByHand(decorator, undefined, { kind: 'field', name: 'token', static: false })
      ).toThrow(/cannot decorate a field/);
    });
  });
});
