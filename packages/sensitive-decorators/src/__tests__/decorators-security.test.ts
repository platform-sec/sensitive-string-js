/**
 * Leak tests for the decorators package.
 *
 * The decorators exist so a class field holds a protected value rather than a
 * bare string. That claim has one failure mode worth testing directly: a path
 * that stores the raw string anyway, which nothing else in the library would
 * notice, because every redaction downstream keys off the value being a
 * `SensitiveString` in the first place.
 *
 * The field-initializer path is the specific case. Auto-accessor initializers
 * do not go through the decorator's `set`, so a decorator that implements only
 * `set` leaves `accessor email = 'jane@example.com'` holding a bare string and
 * every rendering below prints it.
 */

import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  containsSensitive,
  registerPolicy,
  resetPolicies,
  safeStringify,
  sensitiveClassesIn,
  withRevealContext,
  type RevealContext,
} from '@platform-sec/sensitive-string-core';
import { Sensitive, WithRevealContext } from '../index.js';

const CANARY = 'DECORATOR_CANARY_9f2c41ab';

/**
 * Every way a holder of a decorated field reaches output.
 *
 * A leak test that checks one rendering proves one rendering. These are the
 * shapes a value lands in when someone logs, serializes, or interpolates the
 * object that holds it.
 */
function everyRendering(holder: object): string[] {
  return [
    // Default stringification is one of the renderings under test, so this is
    // the coercion the rule warns about, on purpose.
    // eslint-disable-next-line @typescript-eslint/no-base-to-string
    String(holder),
    util.inspect(holder),
    util.inspect(holder, { depth: null, showHidden: true }),
    // `JSON.stringify` returns undefined for a class rather than a string, and
    // a rendering that produced nothing still has to be checked, not skipped.
    // `safeStringify` needs no such fallback: it substitutes 'null' for the
    // values JSON cannot represent, so it returns the string it declares.
    JSON.stringify(holder) ?? '',
    JSON.stringify({ wrapper: holder }) ?? '',
    safeStringify(holder),
    Object.keys(holder).join(','),
    Object.values(holder).map(String).join(','),
    Object.entries(holder).flat().map(String).join(','),
    Object.getOwnPropertyNames(holder).join(','),
    JSON.stringify(Object.getOwnPropertyDescriptors(holder)) ?? '',
  ];
}

function expectNoLeak(holder: object): void {
  for (const rendering of everyRendering(holder)) {
    expect(rendering).not.toContain(CANARY);
  }
}

describe('decorator leak resistance', () => {
  beforeEach(() => {
    resetPolicies();
  });

  afterEach(() => {
    resetPolicies();
  });

  describe('@Sensitive', () => {
    it('does not leak a value assigned after construction', () => {
      class User {
        @Sensitive('credential') accessor token!: string | SensitiveString<'credential'>;
      }

      const user = new User();
      user.token = CANARY;

      expectNoLeak(user);
    });

    it('does not leak a field initializer', () => {
      class User {
        @Sensitive('credential') accessor token: string | SensitiveString<'credential'> = CANARY;
      }

      expectNoLeak(new User());
    });

    it('does not leak a value hydrated onto the instance', () => {
      class User {
        @Sensitive('sensitive') accessor email!: string | SensitiveString<'sensitive'>;
      }

      // The shape an ORM row or a parsed payload arrives in, where no
      // constructor and no type annotation stand between the raw string and
      // the field.
      const user = Object.assign(new User(), JSON.parse(`{"email":"${CANARY}"}`) as object);

      expectNoLeak(user);
    });

    it('does not leak a value on a static field', () => {
      class Config {
        @Sensitive('credential') static accessor apiKey: string | SensitiveString<'credential'> =
          CANARY;
      }

      expectNoLeak(Config);
    });

    it('does not leak through the class prototype', () => {
      class User {
        @Sensitive('credential') accessor token: string | SensitiveString<'credential'> = CANARY;
      }

      const user = new User();
      const descriptors = Object.getOwnPropertyDescriptors(Object.getPrototypeOf(user) as object);

      expect(util.inspect(descriptors, { depth: null })).not.toContain(CANARY);
    });

    it('reveals only through reveal()', () => {
      class User {
        @Sensitive('credential') accessor token: string | SensitiveString<'credential'> = CANARY;
      }

      const token = new User().token;

      expect(token).toBeInstanceOf(SensitiveString);
      expect((token as SensitiveString<'credential'>).reveal()).toBe(CANARY);
    });

    it('does not name the value in the error that refuses it', () => {
      class Account {
        @Sensitive('credential') accessor token!: SensitiveString<'credential'>;
      }

      const account = new Account();
      const loose = new SensitiveString(CANARY, 'sensitive');

      try {
        account.token = loose as unknown as SensitiveString<'credential'>;
        expect.unreachable('the assignment should have been refused');
      } catch (error) {
        expect(String(error)).not.toContain(CANARY);
      }
    });

    it('does not run a toString() on the value it refuses', () => {
      class User {
        @Sensitive('sensitive') accessor email!: string | SensitiveString<'sensitive'>;
      }

      const user = new User();
      const hostile = {
        toString: (): string => CANARY,
      };

      try {
        user.email = hostile as unknown as string;
        expect.unreachable('the assignment should have been refused');
      } catch (error) {
        expect(String(error)).not.toContain(CANARY);
      }
    });

    it('refuses to store a credential field as a less protected value', () => {
      class Account {
        @Sensitive('credential') accessor token!: SensitiveString<'credential'>;
      }

      const account = new Account();

      // A silent downgrade would leave the field holding a value whose policy
      // allows partial queries and masking, which is what `credential` exists
      // to forbid.
      expect(() => {
        account.token = new SensitiveString(
          CANARY,
          'sensitive'
        ) as unknown as SensitiveString<'credential'>;
      }).toThrow(/less restrictive/);
    });
  });

  describe('what an accessor field does to serialization', () => {
    // A consequence of the `accessor` keyword rather than of the decorator: an
    // auto-accessor is a prototype getter and setter over a private field, so
    // the instance has no own enumerable property to walk or print. Nothing
    // leaks, but the shape changes, and these tests are here so a change in
    // that shape is a test failure rather than a surprise in a response body.
    class Accessed {
      @Sensitive('sensitive') accessor email!: string | SensitiveString<'sensitive'>;
    }

    class Declared {
      @Sensitive('sensitive') accessor email!: string | SensitiveString<'sensitive'>;

      toJSON(): { email: string | SensitiveString<'sensitive'> } {
        return { email: this.email };
      }
    }

    it('omits the field entirely rather than redacting it', () => {
      const user = new Accessed();
      user.email = CANARY;

      expect(JSON.stringify(user)).toBe('{}');
      expect(Object.keys(user)).toEqual([]);
      expect(safeStringify(user)).toBe('{}');
    });

    it('renders the field redacted once toJSON declares it', () => {
      const user = new Declared();
      user.email = CANARY;

      expect(JSON.stringify(user)).toBe('{"email":"[REDACTED:sensitive]"}');
      expect(safeStringify(user)).toBe('{"email":"[REDACTED:sensitive]"}');
      expectNoLeak(user);
    });

    it('stays invisible to the structural walks, toJSON or not', () => {
      const declared = new Declared();
      declared.email = CANARY;

      // Worth stating in a test because these two are what a caller reaches
      // for to check an object before sending it somewhere, and a false
      // negative reads exactly like a clean object.
      expect(containsSensitive(declared)).toBe(false);
      expect([...sensitiveClassesIn(declared)]).toEqual([]);

      expect(containsSensitive(declared.toJSON())).toBe(true);
      expect([...sensitiveClassesIn(declared.toJSON())]).toEqual(['sensitive']);
    });
  });

  describe('@WithRevealContext', () => {
    it('audits a reveal made inside the method', () => {
      const audit = vi.fn();

      class Processor {
        @WithRevealContext({ name: 'payment-processing', auditReveal: audit })
        charge(card: SensitiveString<'credential'>): string {
          return card.reveal();
        }
      }

      const card = new SensitiveString(CANARY, 'credential', 'pan');

      expect(new Processor().charge(card)).toBe(CANARY);
      expect(audit).toHaveBeenCalledTimes(1);
      expect(audit.mock.calls[0]?.[1]).toMatchObject({ operation: 'reveal' });
    });

    it('audits a reveal made after an await', async () => {
      const audit = vi.fn();

      class Processor {
        @WithRevealContext({ name: 'payment-processing', auditReveal: audit })
        async charge(card: SensitiveString<'credential'>): Promise<string> {
          await Promise.resolve();

          return card.reveal();
        }
      }

      await new Processor().charge(new SensitiveString(CANARY, 'credential', 'pan'));

      expect(audit).toHaveBeenCalledTimes(1);
    });

    it('audits every reveal a generator method makes', () => {
      const audit = vi.fn();

      class Processor {
        // Without wrapping the iterator, the body resumes after
        // AsyncLocalStorage.run has returned and every reveal below is
        // unaudited, which is silent: the values still come out.
        @WithRevealContext({ name: 'batch-processing', auditReveal: audit })
        *charge(cards: SensitiveString<'credential'>[]): Generator<string> {
          for (const card of cards) {
            yield card.reveal();
          }
        }
      }

      const cards = [
        new SensitiveString(CANARY, 'credential', 'pan'),
        new SensitiveString(CANARY, 'credential', 'pan'),
      ];

      expect([...new Processor().charge(cards)]).toEqual([CANARY, CANARY]);
      expect(audit).toHaveBeenCalledTimes(2);
    });

    it('audits every reveal an async generator method makes', async () => {
      const audit = vi.fn();

      class Processor {
        @WithRevealContext({ name: 'batch-processing', auditReveal: audit })
        async *charge(cards: SensitiveString<'credential'>[]): AsyncGenerator<string> {
          for (const card of cards) {
            await Promise.resolve();
            yield card.reveal();
          }
        }
      }

      const cards = [
        new SensitiveString(CANARY, 'credential', 'pan'),
        new SensitiveString(CANARY, 'credential', 'pan'),
      ];

      for await (const _revealed of new Processor().charge(cards)) {
        // draining is the point
      }

      expect(audit).toHaveBeenCalledTimes(2);
    });

    it('keeps an ambient audit sink receiving records', () => {
      const outer = vi.fn();

      class Processor {
        @WithRevealContext({ name: 'payment-processing', reason: 'charging card' })
        charge(card: SensitiveString<'credential'>): string {
          return card.reveal();
        }
      }

      const card = new SensitiveString(CANARY, 'credential', 'pan');
      withRevealContext({ name: 'http-request', auditReveal: outer }, () =>
        new Processor().charge(card)
      );

      expect(outer).toHaveBeenCalledTimes(1);
    });

    it('presents its context to the policy gate rather than bypassing it', () => {
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          requireConstantTimeEquals: true,
          allowPartialQueries: false,
          allowMask: false,
          checkRevealAllowed(ctx) {
            if (ctx?.name !== 'payment-processing') {
              throw new Error('reveal denied outside payment processing');
            }
          },
        },
        { overwrite: true }
      );

      class Processor {
        @WithRevealContext({ name: 'payment-processing' })
        charge(card: SensitiveString<'credential'>): string {
          return card.reveal();
        }

        @WithRevealContext({ name: 'reporting' })
        report(card: SensitiveString<'credential'>): string {
          return card.reveal();
        }
      }

      // The decorator names the operation; it grants no exemption. A reveal
      // under it goes through the same gate an explicit context does, and a
      // context the policy rejects is still rejected.
      const processor = new Processor();
      const card = new SensitiveString(CANARY, 'credential', 'pan');

      expect(processor.charge(card)).toBe(CANARY);
      expect(() => processor.report(card)).toThrow('reveal denied outside payment processing');
    });

    it('does not name the context in the error that refuses it', () => {
      const assembled = { name: '', tags: { apiKey: CANARY } } as unknown as RevealContext;

      // A decorator runs when the class statement it is attached to executes.
      const declare = (): unknown =>
        class {
          @WithRevealContext(assembled)
          charge(): void {}
        };

      try {
        declare();
        expect.unreachable('the decoration should have been refused');
      } catch (error) {
        expect(String(error)).not.toContain(CANARY);
      }
    });
  });
});
