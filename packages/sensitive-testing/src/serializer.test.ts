import { describe, expect, it } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { createSensitiveSerializer, sensitiveSerializer } from './serializer.js';
import defaultSerializer from './serializer.js';

/**
 * What a registered serializer would render, without registering one.
 *
 * Most of the suite asserts on this rather than on a snapshot, because a
 * snapshot assertion cannot distinguish a serializer that produced the expected
 * text from one that produced nothing and a stale file that already held it.
 * The end of the file registers the real thing and takes real snapshots.
 */
function renderWith(serializer: { serialize(value: unknown): string }, value: unknown): string {
  return serializer.serialize(value);
}

describe('sensitiveSerializer', () => {
  describe('what it claims', () => {
    it('claims a SensitiveString', () => {
      expect(sensitiveSerializer.test(new SensitiveString('v', 'sensitive'))).toBe(true);
    });

    it('claims nothing else', () => {
      const others = [
        'a string',
        42,
        null,
        undefined,
        {},
        [],
        new Date(0),
        Object.create(null) as unknown,
        // The redacted rendering is a plain string and is not this plugin's.
        new SensitiveString('v', 'sensitive').toString(),
      ];

      for (const other of others) {
        expect(sensitiveSerializer.test(other)).toBe(false);
      }
    });

    it('does not throw on a value whose getters do', () => {
      const hostile = new Proxy(
        {},
        {
          get() {
            throw new Error('should not be reached');
          },
        }
      );

      expect(() => sensitiveSerializer.test(hostile)).not.toThrow();
      expect(sensitiveSerializer.test(hostile)).toBe(false);
    });
  });

  describe('the default rendering', () => {
    it('renders the class and the label', () => {
      const secret = new SensitiveString('sk_live_x', 'credential', 'api_key');

      expect(renderWith(sensitiveSerializer, secret)).toBe('SensitiveString<credential:api_key>');
    });

    it('renders the class alone when there is no label', () => {
      const secret = new SensitiveString('+1-555-1234', 'sensitive');

      expect(renderWith(sensitiveSerializer, secret)).toBe('SensitiveString<sensitive>');
    });

    it('omits the length and the expiry', () => {
      const secret = new SensitiveString('123456', 'credential', 'otp', { ttl: 0 });

      expect(renderWith(sensitiveSerializer, secret)).toBe('SensitiveString<credential:otp>');
    });

    it('renders the same text for two instances of the same shape', () => {
      const first = new SensitiveString('one', 'sensitive', 'email');
      const second = new SensitiveString('a completely different value', 'sensitive', 'email');

      expect(renderWith(sensitiveSerializer, first)).toBe(renderWith(sensitiveSerializer, second));
    });

    it('is the same object as the default export', () => {
      expect(defaultSerializer).toBe(sensitiveSerializer);
    });
  });

  describe('the length option', () => {
    it('adds the length to the default format', () => {
      const serializer = createSensitiveSerializer({ showLength: true });
      const secret = new SensitiveString('0123456789abcdef', 'credential', 'api_key');

      expect(renderWith(serializer, secret)).toBe('SensitiveString<credential:api_key:len=16>');
    });

    it('reports zero for an empty value', () => {
      const serializer = createSensitiveSerializer({ showLength: true });

      expect(renderWith(serializer, new SensitiveString('', 'sensitive'))).toBe(
        'SensitiveString<sensitive:len=0>'
      );
    });

    it('counts UTF-16 code units, the same as String.prototype.length', () => {
      const serializer = createSensitiveSerializer({ showLength: true });
      const value = 'a\u{1f600}b';
      const secret = new SensitiveString(value, 'sensitive');

      expect(renderWith(serializer, secret)).toBe(`SensitiveString<sensitive:len=${value.length}>`);
    });

    it('is accurate for a long value', () => {
      const serializer = createSensitiveSerializer({ showLength: true });
      const secret = new SensitiveString('x'.repeat(100_000), 'sensitive');

      expect(renderWith(serializer, secret)).toBe('SensitiveString<sensitive:len=100000>');
    });
  });

  describe('the expiration option', () => {
    it('marks a value whose deadline has passed', () => {
      const serializer = createSensitiveSerializer({ showExpiration: true });
      const secret = new SensitiveString('123456', 'credential', 'otp', { ttl: 0 });

      expect(renderWith(serializer, secret)).toBe('SensitiveString<credential:otp:EXPIRED>');
    });

    it('does not mark a value that has time left', () => {
      const serializer = createSensitiveSerializer({ showExpiration: true });
      const secret = new SensitiveString('123456', 'credential', 'otp', { ttl: 60_000 });

      expect(renderWith(serializer, secret)).toBe('SensitiveString<credential:otp>');
    });

    it('does not mark a value that has no deadline', () => {
      const serializer = createSensitiveSerializer({ showExpiration: true });

      expect(renderWith(serializer, new SensitiveString('v', 'sensitive'))).toBe(
        'SensitiveString<sensitive>'
      );
    });

    it('does not fire the expiry callback of the value it renders', () => {
      // `isExpired()` would. Rendering a snapshot is an observation, and an
      // observation that trips a lifecycle hook makes the snapshot the cause of
      // whatever the hook does.
      const serializer = createSensitiveSerializer({ showExpiration: true });
      let fired = 0;
      const secret = new SensitiveString('123456', 'credential', 'otp', {
        ttl: 0,
        onExpire: () => {
          fired += 1;
        },
      });

      expect(renderWith(serializer, secret)).toContain(':EXPIRED');
      expect(renderWith(serializer, secret)).toContain(':EXPIRED');
      expect(fired).toBe(0);
    });

    it('combines with the length option', () => {
      const serializer = createSensitiveSerializer({ showLength: true, showExpiration: true });
      const secret = new SensitiveString('123456', 'credential', 'otp', { ttl: 0 });

      expect(renderWith(serializer, secret)).toBe('SensitiveString<credential:otp:len=6:EXPIRED>');
    });
  });

  describe('a custom format', () => {
    it('renders the placeholders it names', () => {
      const serializer = createSensitiveSerializer({ format: '<{class}{label}>' });
      const secret = new SensitiveString('v', 'sensitive', 'email');

      expect(renderWith(serializer, secret)).toBe('<sensitive:email>');
    });

    it('renders a placeholder named more than once', () => {
      const serializer = createSensitiveSerializer({ format: '{class}/{class}' });

      expect(renderWith(serializer, new SensitiveString('v', 'credential'))).toBe(
        'credential/credential'
      );
    });

    it('needs no placeholder at all', () => {
      const serializer = createSensitiveSerializer({ format: 'Sensitive' });

      expect(renderWith(serializer, new SensitiveString('v', 'sensitive', 'email'))).toBe(
        'Sensitive'
      );
    });

    it('decides on its own what appears, without the options', () => {
      // The two ways of asking for a field cannot disagree: a format is used as
      // written.
      const serializer = createSensitiveSerializer({
        format: 'SensitiveString<{class}{label}{length}{expired}>',
      });
      const secret = new SensitiveString('123456', 'credential', 'otp', { ttl: 0 });

      expect(renderWith(serializer, secret)).toBe('SensitiveString<credential:otp:len=6:EXPIRED>');
    });

    it('leaves text that only looks like a placeholder alone', () => {
      const serializer = createSensitiveSerializer({ format: '{ class } {} {{class}}' });

      expect(renderWith(serializer, new SensitiveString('v', 'sensitive'))).toBe(
        '{ class } {} {sensitive}'
      );
    });

    it('rejects a placeholder that does not exist', () => {
      expect(() => createSensitiveSerializer({ format: '{value}' })).toThrow(TypeError);
      expect(() => createSensitiveSerializer({ format: '{value}' })).toThrow(/unknown placeholder/);
    });

    it('rejects the bad placeholder at registration, not at the first snapshot', () => {
      // The failure has to land in the setup file. A serializer that only fails
      // once it meets a sensitive value fails inside an unrelated test.
      expect(() => createSensitiveSerializer({ format: '{reveal}' })).toThrow(TypeError);
    });

    it('rejects a format that is not a string', () => {
      expect(() => createSensitiveSerializer({ format: 42 as unknown as string })).toThrow(
        TypeError
      );
    });

    it('rejects an option that is not a boolean', () => {
      expect(() => createSensitiveSerializer({ showLength: 'yes' as unknown as boolean })).toThrow(
        TypeError
      );
      expect(() => createSensitiveSerializer({ showExpiration: 1 as unknown as boolean })).toThrow(
        TypeError
      );
    });
  });

  describe('labels', () => {
    it('keeps printable punctuation as it stands', () => {
      const secret = new SensitiveString('v', 'sensitive', 'user.email#1 (primary)');

      expect(renderWith(sensitiveSerializer, secret)).toBe(
        'SensitiveString<sensitive:user.email#1 (primary)>'
      );
    });

    it('does not expand a label that looks like a placeholder', () => {
      const secret = new SensitiveString('v', 'sensitive', '{class}');

      expect(renderWith(sensitiveSerializer, secret)).toBe('SensitiveString<sensitive:{class}>');
    });

    it('does not treat a label as a replacement pattern', () => {
      const secret = new SensitiveString('v', 'sensitive', "$&$'$`");

      expect(renderWith(sensitiveSerializer, secret)).toBe("SensitiveString<sensitive:$&$'$`>");
    });

    it('escapes control characters so one line stays one line', () => {
      const secret = new SensitiveString('v', 'sensitive', 'a\nb\tc\u0000d');

      expect(renderWith(sensitiveSerializer, secret)).toBe(
        'SensitiveString<sensitive:a\\nb\\tc\\x00d>'
      );
    });

    it('renders an empty label as an empty label, not as no label', () => {
      const secret = new SensitiveString('v', 'sensitive', '');

      expect(renderWith(sensitiveSerializer, secret)).toBe('SensitiveString<sensitive:>');
    });
  });

  describe('misuse', () => {
    it('refuses a value it did not claim', () => {
      expect(() => renderWith(sensitiveSerializer, 'a plain string')).toThrow(TypeError);
    });

    it('reports a bad option rather than crashing on it', () => {
      // The message about a bad argument must not be the thing that throws. An
      // object with no reachable `constructor` is the everyday way to get one
      // that cannot name itself.
      const nameless: unknown = Object.create(Object.create(null) as object);

      expect(() => createSensitiveSerializer({ format: nameless as string })).toThrow(
        /format must be a string/
      );
      expect(() => createSensitiveSerializer({ showLength: nameless as boolean })).toThrow(
        /showLength must be a boolean/
      );
    });

    it('names the type of that value and nothing else', () => {
      const decoy = 'RAW_VALUE_NOT_A_SENSITIVE_STRING_9f21';

      expect(() => renderWith(sensitiveSerializer, decoy)).toThrow(/not a SensitiveString/);

      try {
        renderWith(sensitiveSerializer, decoy);
        expect.unreachable('should have thrown');
      } catch (error) {
        expect((error as Error).message).not.toContain(decoy);
        expect((error as Error).message).toContain('string');
      }
    });
  });
});

describe('sensitiveSerializer, registered with Vitest', () => {
  // Registration is global to this file, so it happens last: the assertions
  // above are about the plugin, and these are about what a runner does with it.
  expect.addSnapshotSerializer(sensitiveSerializer);

  it('renders a sensitive field inside an object', () => {
    const user = {
      id: 1,
      name: 'Alice',
      email: new SensitiveString('alice@example.com', 'sensitive', 'email'),
      apiKey: new SensitiveString('sk_live_abc123', 'credential', 'api_key'),
      phone: new SensitiveString('+1-555-1234', 'sensitive'),
    };

    expect(user).toMatchInlineSnapshot(`
      {
        "apiKey": SensitiveString<credential:api_key>,
        "email": SensitiveString<sensitive:email>,
        "id": 1,
        "name": "Alice",
        "phone": SensitiveString<sensitive>,
      }
    `);
  });

  it('renders one on its own', () => {
    expect(new SensitiveString('alice@example.com', 'sensitive', 'email')).toMatchInlineSnapshot(
      `SensitiveString<sensitive:email>`
    );
  });

  it('renders them in an array', () => {
    const tokens = [
      new SensitiveString('one', 'credential', 'token'),
      new SensitiveString('two', 'credential', 'token'),
    ];

    expect(tokens).toMatchInlineSnapshot(`
      [
        SensitiveString<credential:token>,
        SensitiveString<credential:token>,
      ]
    `);
  });

  it('renders them at depth, in a mixed structure', () => {
    const response = {
      status: 'active',
      payment: {
        cardNumber: new SensitiveString('4111111111111111', 'credential', 'card'),
        cvv: new SensitiveString('123', 'credential', 'cvv'),
        billing: {
          ssn: new SensitiveString('123-45-6789', 'sensitive', 'ssn'),
          history: [{ note: 'ok' }, { token: new SensitiveString('t', 'credential') }],
        },
      },
    };

    expect(response).toMatchInlineSnapshot(`
      {
        "payment": {
          "billing": {
            "history": [
              {
                "note": "ok",
              },
              {
                "token": SensitiveString<credential>,
              },
            ],
            "ssn": SensitiveString<sensitive:ssn>,
          },
          "cardNumber": SensitiveString<credential:card>,
          "cvv": SensitiveString<credential:cvv>,
        },
        "status": "active",
      }
    `);
  });

  it('renders them as Map keys and Set members, where identity survives', () => {
    const key = new SensitiveString('alice@example.com', 'sensitive', 'email');

    expect({
      byEmail: new Map([[key, { id: 1 }]]),
      seen: new Set([new SensitiveString('t', 'credential', 'token')]),
    }).toMatchInlineSnapshot(`
      {
        "byEmail": Map {
          SensitiveString<sensitive:email> => {
            "id": 1,
          },
        },
        "seen": Set {
          SensitiveString<credential:token>,
        },
      }
    `);
  });

  it('renders one inside a structure that refers to itself', () => {
    const node: Record<string, unknown> = {
      token: new SensitiveString('t', 'credential', 'token'),
    };
    node['self'] = node;

    expect(node).toMatchInlineSnapshot(`
      {
        "self": [Circular],
        "token": SensitiveString<credential:token>,
      }
    `);
  });

  it('renders one at the bottom of a nested structure', () => {
    expect({ a: { b: { c: { token: new SensitiveString('t', 'credential', 'token') } } } })
      .toMatchInlineSnapshot(`
      {
        "a": {
          "b": {
            "c": {
              "token": SensitiveString<credential:token>,
            },
          },
        },
      }
    `);
  });

  it('ignores the depth and the indentation it is told it is at', () => {
    // pretty-format consults the plugin stack at every level and passes the
    // depth down, so a leaf renderer that read either of them would drift
    // between a top-level snapshot and a deeply nested one. This one reads
    // neither, which is what makes the nesting above uninteresting.
    const secret = new SensitiveString('t', 'credential', 'token');

    expect(
      sensitiveSerializer.serialize(secret, { maxDepth: 2 }, ' '.repeat(400), 200, [], () => '')
    ).toBe('SensitiveString<credential:token>');
  });

  it('leaves values another serializer claims to that serializer', () => {
    class Money {
      constructor(readonly cents: number) {}
    }

    expect.addSnapshotSerializer({
      test: (value: unknown) => value instanceof Money,
      serialize: (value: unknown) => `Money(${(value as Money).cents})`,
    });

    expect({
      price: new Money(1250),
      card: new SensitiveString('4111111111111111', 'credential', 'card'),
    }).toMatchInlineSnapshot(`
      {
        "card": SensitiveString<credential:card>,
        "price": Money(1250),
      }
    `);
  });
});
