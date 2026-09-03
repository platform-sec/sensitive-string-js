import { describe, expect, it } from 'vitest';
import { SensitiveString, type SensitivityClass } from '@platform-sec/sensitive-string-core';
import { Sensitive } from './sensitive.js';

/**
 * Read an accessor back as what the decorator stores.
 *
 * Assigning a string narrows the declared union to `string`, so a direct cast
 * on the read would be a cast between unrelated types. Going through `unknown`
 * also puts the assertion that a read really is wrapped in one place.
 */
function wrapped<C extends SensitivityClass>(value: unknown): SensitiveString<C> {
  expect(value).toBeInstanceOf(SensitiveString);

  return value as SensitiveString<C>;
}

/**
 * The runtime guards are unreachable through the decorator's own types, which
 * already reject a non-accessor target. Applying the inner function by hand is
 * what a JavaScript caller does, and what a build with mismatched decorator
 * types would do.
 */
function applyByHand(
  decorator: unknown,
  target: unknown,
  context: { kind: string; name: string | symbol; static: boolean }
): unknown {
  return (decorator as (value: unknown, context: unknown) => unknown)(target, context);
}

describe('@Sensitive', () => {
  describe('wrapping', () => {
    it('wraps a field initializer', () => {
      class User {
        @Sensitive('sensitive') accessor email: string | SensitiveString<'sensitive'> =
          'jane@example.com';
      }

      const email = new User().email;

      expect(email).toBeInstanceOf(SensitiveString);
      expect(wrapped<'sensitive'>(email).reveal()).toBe('jane@example.com');
    });

    it('wraps an assignment', () => {
      class User {
        @Sensitive('sensitive') accessor email!: string | SensitiveString<'sensitive'>;
      }

      const user = new User();
      user.email = 'jane@example.com';

      expect(user.email).toBeInstanceOf(SensitiveString);
    });

    it('applies the decorator class', () => {
      class Account {
        @Sensitive('credential') accessor token!: string | SensitiveString<'credential'>;
      }

      const account = new Account();
      account.token = 'tok_live_1';

      expect(wrapped<'credential'>(account.token).klass).toBe('credential');
    });

    it('keeps instances independent', () => {
      class User {
        @Sensitive('sensitive') accessor email!: string | SensitiveString<'sensitive'>;
      }

      const first = new User();
      const second = new User();
      first.email = 'first@example.com';
      second.email = 'second@example.com';

      expect(wrapped<'sensitive'>(first.email).reveal()).toBe('first@example.com');
      expect(wrapped<'sensitive'>(second.email).reveal()).toBe('second@example.com');
    });

    it('wraps on a static accessor', () => {
      class Config {
        @Sensitive('credential') static accessor apiKey: string | SensitiveString<'credential'> =
          'sk_live_1';
      }

      expect(Config.apiKey).toBeInstanceOf(SensitiveString);
    });

    it('wraps on a private accessor', () => {
      class Vault {
        @Sensitive('credential') accessor #token: string | SensitiveString<'credential'> =
          'tok_live_1';

        get label(): string | undefined {
          return wrapped<'credential'>(this.#token).label;
        }
      }

      expect(new Vault().label).toBe('#token');
    });

    it('wraps on an inherited accessor', () => {
      class Base {
        @Sensitive('sensitive') accessor email!: string | SensitiveString<'sensitive'>;
      }
      class Employee extends Base {}

      const employee = new Employee();
      employee.email = 'jane@example.com';

      expect(employee.email).toBeInstanceOf(SensitiveString);
    });
  });

  describe('nullish values', () => {
    it('leaves an unassigned accessor undefined', () => {
      class User {
        @Sensitive('sensitive') accessor email: SensitiveString<'sensitive'> | undefined;
      }

      expect(new User().email).toBeUndefined();
    });

    it('leaves an assigned null alone', () => {
      class User {
        @Sensitive('sensitive') accessor email: SensitiveString<'sensitive'> | null = null;
      }

      const user = new User();

      expect(user.email).toBeNull();
      user.email = null;
      expect(user.email).toBeNull();
    });
  });

  describe('already-wrapped values', () => {
    it('stores a value of the same class as it is', () => {
      class User {
        @Sensitive('sensitive') accessor email!: SensitiveString<'sensitive'>;
      }

      const existing = new SensitiveString('jane@example.com', 'sensitive', 'work_email');
      const user = new User();
      user.email = existing;

      expect(user.email).toBe(existing);
      expect(user.email.label).toBe('work_email');
    });

    it('stores a more restrictive value as it is', () => {
      class Record {
        @Sensitive('sensitive') accessor field!: SensitiveString<'sensitive'>;
      }

      const credential = new SensitiveString('tok_live_1', 'credential');
      const record = new Record();
      record.field = credential as unknown as SensitiveString<'sensitive'>;

      expect(record.field).toBe(credential);
      expect(record.field.klass).toBe('credential');
    });

    it('refuses a less restrictive value', () => {
      class Account {
        @Sensitive('credential') accessor token!: SensitiveString<'credential'>;
      }

      const account = new Account();
      const loose = new SensitiveString('tok_live_1', 'sensitive');

      expect(() => {
        account.token = loose as unknown as SensitiveString<'credential'>;
      }).toThrow(/less restrictive/);
    });

    it('names reclassify() when it refuses a downgrade', () => {
      class Account {
        @Sensitive('credential') accessor token!: SensitiveString<'credential'>;
      }

      const account = new Account();
      const loose = new SensitiveString('tok_live_1', 'sensitive');

      expect(() => {
        account.token = loose as unknown as SensitiveString<'credential'>;
      }).toThrow(/reclassify\(\)/);
    });
  });

  describe('labels', () => {
    it('defaults the label to the property name', () => {
      class User {
        @Sensitive('sensitive') accessor emailAddress!: string | SensitiveString<'sensitive'>;
      }

      const user = new User();
      user.emailAddress = 'jane@example.com';

      expect(wrapped<'sensitive'>(user.emailAddress).label).toBe('emailAddress');
    });

    it('prefers an explicit label', () => {
      class User {
        @Sensitive('sensitive', 'email') accessor emailAddress!:
          string | SensitiveString<'sensitive'>;
      }

      const user = new User();
      user.emailAddress = 'jane@example.com';

      expect(wrapped<'sensitive'>(user.emailAddress).label).toBe('email');
    });

    it('takes the label of a symbol-keyed accessor from its description', () => {
      const key = Symbol('recoveryCode');

      class User {
        @Sensitive('credential') accessor [key]!: string | SensitiveString<'credential'>;
      }

      const user = new User();
      user[key] = 'rc_1';

      expect(wrapped<'credential'>(user[key]).label).toBe('recoveryCode');
    });
  });

  describe('options', () => {
    it('forwards constructor options to values it wraps', () => {
      class Otp {
        @Sensitive('credential', 'otp', { ttl: 0 }) accessor code!:
          string | SensitiveString<'credential'>;
      }

      const otp = new Otp();
      otp.code = '123456';

      expect(wrapped<'credential'>(otp.code).isExpired()).toBe(true);
    });

    it('copies the options object at decoration time', () => {
      const options: { ttl?: number } = { ttl: 0 };

      class Otp {
        @Sensitive('credential', 'otp', options) accessor code!:
          string | SensitiveString<'credential'>;
      }

      // A caller that keeps the object and lifts the deadline afterwards must
      // not lift it for the field.
      delete options.ttl;

      const otp = new Otp();
      otp.code = '123456';

      expect(wrapped<'credential'>(otp.code).isExpired()).toBe(true);
    });

    it('leaves an already-wrapped value under its own options', () => {
      class Otp {
        @Sensitive('credential', 'otp', { ttl: 0 }) accessor code!: SensitiveString<'credential'>;
      }

      const otp = new Otp();
      otp.code = new SensitiveString('123456', 'credential');

      expect(otp.code.isExpired()).toBe(false);
    });
  });

  describe('refusals', () => {
    it('refuses a value that is neither a string nor wrapped', () => {
      class User {
        @Sensitive('sensitive') accessor email!: string | SensitiveString<'sensitive'>;
      }

      const user = new User();

      expect(() => {
        user.email = 42 as unknown as string;
      }).toThrow(/expected a string, a SensitiveString, or nullish/);
    });

    it('names the accessor it refused for', () => {
      class User {
        @Sensitive('sensitive') accessor email!: string | SensitiveString<'sensitive'>;
      }

      const user = new User();

      expect(() => {
        user.email = {} as unknown as string;
      }).toThrow(/accessor 'email'/);
    });

    it('refuses an unrecognized class at decoration time', () => {
      expect(() => Sensitive('secret' as unknown as 'sensitive')).toThrow(
        /'secret' is not a sensitivity class/
      );
    });

    it('describes a non-string class by type rather than quoting it', () => {
      expect(() => Sensitive(undefined as unknown as 'sensitive')).toThrow(
        /klass undefined is not a sensitivity class/
      );
    });

    it('refuses to decorate anything but an accessor', () => {
      const decorator = Sensitive('sensitive');

      expect(() =>
        applyByHand(decorator, () => undefined, { kind: 'method', name: 'send', static: false })
      ).toThrow(/cannot decorate a method/);
      expect(() =>
        applyByHand(decorator, undefined, { kind: 'field', name: 'email', static: false })
      ).toThrow(/cannot decorate a field/);
    });
  });
});
