import { describe, expect, it } from 'vitest';

import {
  SensitiveString,
  containsSensitive,
  createSensitiveSerializer,
  redactCopy,
  redactInStructure,
  safeLog,
  safeStringify,
  sensitiveClassesIn,
} from '../index.js';

/**
 * Every redaction walk, driven with objects that refuse to answer.
 *
 * A walk has to ask an arbitrary object a series of questions, and every one of
 * them runs through a hook the object controls. This suite is the adversarial
 * enumeration of that surface rather than a replay of the one object that was
 * observed failing, which is the difference that matters: the first defect of
 * this class was found from a measurement against envalid's strict proxy, the
 * second only because a test drove a proxy that refuses *every* unknown name,
 * and the remaining seven only because this table drives every hook at once.
 *
 * The rule under test: **failing to read is not a reason to fail the
 * redaction.** A logger calling `safeLog` must not be the thing that takes down
 * the request.
 *
 * The one shape here that is not a Proxy trick is `throwingGetter`, and it is
 * the most likely of all of them: an ORM produces exactly that for a relation
 * that was not loaded, and `Object.entries` invokes every enumerable getter.
 */

const CANARY = 'LEAKED_SECRET_abc123xyz';

/** One uncooperative object, and the hook it refuses through. */
function hostileObjects(): Record<string, object> {
  return {
    /** envalid's `cleanEnv` result: a `get` trap that throws for any undeclared name. */
    strictGet: new Proxy(
      { KNOWN: 'known' },
      {
        get(target, name): unknown {
          if (!Object.hasOwn(target, name)) {
            throw new ReferenceError(`[test] not found: ${String(name)}`);
          }
          return (target as Record<string | symbol, unknown>)[name];
        },
      }
    ),
    /** `Object.keys` goes through this trap. */
    throwingOwnKeys: new Proxy(
      { KNOWN: 'known' },
      {
        ownKeys(): never {
          throw new Error('[test] ownKeys refused');
        },
      }
    ),
    /** So does this one, which `Object.keys` calls per key to test enumerability. */
    throwingDescriptor: new Proxy(
      { KNOWN: 'known' },
      {
        getOwnPropertyDescriptor(): never {
          throw new Error('[test] getOwnPropertyDescriptor refused');
        },
      }
    ),
    /** `'toJSON' in obj` goes through this one. */
    throwingHas: new Proxy(
      { KNOWN: 'known' },
      {
        has(): never {
          throw new Error('[test] has refused');
        },
      }
    ),
    /** Every `instanceof` in the walk goes through this one. */
    throwingGetPrototypeOf: new Proxy(
      { KNOWN: 'known' },
      {
        getPrototypeOf(): never {
          throw new Error('[test] getPrototypeOf refused');
        },
      }
    ),
    /** A getter on the prototype chain, reached by any inherited-property read. */
    throwingPrototypeGetter: Object.create(
      new Proxy(
        {},
        {
          get(): never {
            throw new Error('[test] prototype refused');
          },
        }
      ),
      { KNOWN: { value: 'known', enumerable: true } }
    ) as object,
    /** Caller code the walk calls, entitled to throw and not entitled to take a log down. */
    throwingToJSON: {
      KNOWN: 'known',
      toJSON(): never {
        throw new Error('[test] toJSON refused');
      },
    },
    /** The exotic-object fallback calls this. */
    throwingToString: Object.assign(Object.create({ [Symbol.toStringTag]: 'Weird' }) as object, {
      KNOWN: 'known',
      toString(): never {
        throw new Error('[test] toString refused');
      },
    }),
    /** `String()` prefers this over `toString`. */
    throwingToPrimitive: Object.assign(Object.create({ [Symbol.toStringTag]: 'Weird' }) as object, {
      KNOWN: 'known',
      [Symbol.toPrimitive](): never {
        throw new Error('[test] toPrimitive refused');
      },
    }),
    /**
     * Not a Proxy, and the one a real application actually produces: a lazy
     * relation that has not been loaded. `Object.entries` invokes it.
     */
    throwingGetter: Object.defineProperty({ KNOWN: 'known' }, 'lazy', {
      enumerable: true,
      get(): never {
        throw new Error('[test] getter refused');
      },
    }),
    /** No prototype at all, so every `Object.prototype` method is absent. */
    nullPrototype: Object.assign(Object.create(null) as object, { KNOWN: 'known' }),
    /**
     * Built-in shapes. Each answers `instanceof` through the prototype the
     * Proxy forwards, and then throws from the built-in itself, whose internal
     * slot is on the target and not on the proxy.
     */
    proxiedMap: new Proxy(new Map([['KNOWN', 'known']]), {}),
    proxiedSet: new Proxy(new Set(['known']), {}),
    /** Throws from every method, the `toJSON()` a serializer calls later included. */
    proxiedDate: new Proxy(new Date(0), {}),
    /** The brand check on the private field refuses the proxy as `toString()`'s receiver. */
    proxiedInstance: new Proxy(new SensitiveString(CANARY, 'credential'), {}),
    /** An array behind a `get` trap that refuses `length`, `map`, the iterator and every index. */
    proxiedArray: new Proxy(['known'], {
      get(): never {
        throw new Error('[test] array refused');
      },
    }),
    /** An Error whose `message` is a getter that throws, and holds the canary in what it throws. */
    throwingErrorMessage: Object.defineProperty(new Error('[test] visible'), 'message', {
      get(): never {
        throw new Error(`[test] message refused, holding ${CANARY}`);
      },
    }),
    /** A handler that answers every trap with a throwing function. */
    everythingRefuses: new Proxy(
      {},
      new Proxy(
        {},
        {
          get() {
            return (): never => {
              throw new Error('[test] everything refused');
            };
          },
        }
      )
    ),
    /** Revoked, so the runtime itself refuses on this object's behalf. */
    revoked: (() => {
      const revocable = Proxy.revocable({ KNOWN: 'known' }, {});
      revocable.revoke();
      return revocable.proxy;
    })(),
  };
}

const walks = {
  redactInStructure,
  containsSensitive,
  safeStringify,
  sensitiveClassesIn,
  redactCopy,
  safeLog,
  serializer: createSensitiveSerializer(),
} as const;

/** Every position a hostile object can occupy in a payload. */
function positions(hostile: object): Record<string, unknown> {
  return {
    direct: hostile,
    nested: { config: hostile },
    array: [hostile],
    map: new Map([['key', hostile]]),
    set: new Set([hostile]),
    deep: { a: { b: { c: hostile } } },
    besideASecret: { secret: new SensitiveString(CANARY, 'credential'), hostile },
  };
}

const hostile = hostileObjects();

describe('redaction against objects that refuse to answer', () => {
  for (const [objectName, object] of Object.entries(hostile)) {
    for (const [walkName, walk] of Object.entries(walks)) {
      it(`${walkName} survives ${objectName} in every position`, () => {
        for (const [position, payload] of Object.entries(positions(object))) {
          expect(() => walk(payload), `${walkName} on ${objectName} as ${position}`).not.toThrow();
        }
      });
    }
  }
});

describe('what an unreadable object becomes', () => {
  it('is a marker rather than an empty object, which would claim it had no fields', () => {
    const redacted = redactInStructure({ config: hostile['throwingOwnKeys'] }) as {
      config: unknown;
    };

    expect(redacted.config).toBe('[Unreadable]');
  });

  it('is the same marker in a redactCopy, rather than an empty instance of its class', () => {
    const copied = redactCopy({ config: hostile['throwingOwnKeys'] }) as { config: unknown };

    expect(copied.config).toBe('[Unreadable]');
  });

  it('is reported as possibly sensitive, because it could not be proved otherwise', () => {
    // The two wrong answers are not symmetric for a leak detector: reporting an
    // unreadable value as clean is how a caller ships a payload believing it
    // was checked.
    expect(containsSensitive(hostile['throwingOwnKeys'])).toBe(true);
    expect(containsSensitive(hostile['revoked'])).toBe(true);
  });

  it('contributes no class, which is the one place the two walks differ', () => {
    // `containsSensitive` can say "there may be something in here" without
    // knowing what. This one cannot invent a class it never read.
    expect(sensitiveClassesIn(hostile['throwingOwnKeys']).size).toBe(0);
  });
});

describe('what a partially readable object becomes', () => {
  it('keeps the properties that do read and empties only the one that throws', () => {
    const redacted = redactInStructure(hostile['throwingGetter']) as Record<string, unknown>;

    expect(redacted['KNOWN']).toBe('known');
    // Present and empty, not missing: the key was enumerated, and only its
    // value could not be read.
    expect(Object.hasOwn(redacted, 'lazy')).toBe(true);
    expect(redacted['lazy']).toBeUndefined();
  });

  it('never enumerates a getter declared on the class rather than the instance', () => {
    class Order {
      readonly id = 7;
      get relation(): never {
        throw new Error('[test] relation not loaded');
      }
    }

    const redacted = redactInStructure(new Order()) as Record<string, unknown>;

    expect(redacted).toEqual({ id: 7 });
  });

  it('walks own properties when toJSON refuses, which is what no toJSON does', () => {
    const payload = {
      KNOWN: 'known',
      token: new SensitiveString(CANARY, 'credential'),
      toJSON(): never {
        throw new Error(`[test] refused, holding ${CANARY}`);
      },
    };

    const redacted = redactInStructure(payload) as Record<string, unknown>;

    expect(redacted['KNOWN']).toBe('known');
    expect(redacted['token']).toBe('[REDACTED:credential]');
    // The failed call's message is discarded unread, so the copy of the canary
    // it carried never reaches the output either.
    expect(JSON.stringify(redacted)).not.toContain(CANARY);
  });

  it('still answers for the names a strict proxy does allow', () => {
    const redacted = redactInStructure(hostile['strictGet']) as Record<string, unknown>;

    expect(redacted['KNOWN']).toBe('known');
  });
});

describe('what a built-in shape that refuses becomes', () => {
  it('is the marker for a proxied Map, Set, Date or array in a log line', () => {
    const redacted = redactInStructure({
      map: hostile['proxiedMap'],
      set: hostile['proxiedSet'],
      when: hostile['proxiedDate'],
      list: hostile['proxiedArray'],
    });

    expect(redacted).toEqual({
      map: '[Unreadable]',
      set: '[Unreadable]',
      when: '[Unreadable]',
      list: '[Unreadable]',
    });
  });

  it('is the marker for a proxied instance in both copying walks, never the value', () => {
    expect(redactInStructure(hostile['proxiedInstance'])).toBe('[Unreadable]');
    expect(redactCopy(hostile['proxiedInstance'])).toBe('[Unreadable]');
    expect(safeStringify({ token: hostile['proxiedInstance'] })).toBe('{"token":"[Unreadable]"}');
  });

  it('is the marker for a proxied collection in a redactCopy, with a Date still by reference', () => {
    const copied = redactCopy({
      map: hostile['proxiedMap'],
      set: hostile['proxiedSet'],
      list: hostile['proxiedArray'],
      when: hostile['proxiedDate'],
    }) as Record<string, unknown>;

    expect(copied['map']).toBe('[Unreadable]');
    expect(copied['set']).toBe('[Unreadable]');
    expect(copied['list']).toBe('[Unreadable]');
    // Passed through by contract; `redactInStructure` is the walk that asks it a question.
    expect(copied['when']).toBe(hostile['proxiedDate']);
  });

  it('keeps the Error properties that read and empties the ones that throw', () => {
    const redacted = redactInStructure(hostile['throwingErrorMessage']) as Record<string, unknown>;

    expect(redacted['name']).toBe('Error');
    expect(redacted['message']).toBeUndefined();
    // V8 formats `stack` on first access and reads `message` to do it, so the
    // getter takes the stack down with it. Absent, not an exception.
    expect(redacted['stack']).toBeUndefined();
    expect(Object.keys(redacted)).toEqual(['name', 'message', 'stack']);
    expect(JSON.stringify(redacted)).not.toContain(CANARY);
  });

  it('is reported as possibly sensitive, and contributes no class', () => {
    for (const name of ['proxiedMap', 'proxiedSet', 'proxiedArray'] as const) {
      expect(containsSensitive(hostile[name]), name).toBe(true);
      expect(sensitiveClassesIn(hostile[name]).size, name).toBe(0);
    }
  });

  it('still names the class of a proxied instance, which the proxy forwards', () => {
    expect(containsSensitive(hostile['proxiedInstance'])).toBe(true);
    expect(sensitiveClassesIn(hostile['proxiedInstance']).has('credential')).toBe(true);
  });
});

describe('the canary sweep, with a hostile object in the same payload', () => {
  for (const [objectName, object] of Object.entries(hostile)) {
    it(`redacts a sibling secret alongside ${objectName}`, () => {
      const payload = {
        secret: new SensitiveString(CANARY, 'credential'),
        hostile: object,
        nested: { deeper: new SensitiveString(CANARY, 'sensitive'), also: object },
      };

      for (const walk of [redactInStructure, redactCopy, safeLog] as const) {
        // Rendered through `safeStringify` rather than `JSON.stringify`, because
        // `redactCopy` faithfully preserves an own `toJSON` that throws: that is
        // its contract, and `JSON.stringify` of the *original* would throw the
        // same way. What is under test is that no canary survives the walk.
        expect(safeStringify(walk(payload))).not.toContain(CANARY);
      }

      expect(safeStringify(payload)).not.toContain(CANARY);
      expect(containsSensitive(payload)).toBe(true);
      expect(sensitiveClassesIn(payload).has('credential')).toBe(true);
    });
  }
});

describe('ordinary values are unaffected', () => {
  it('keeps the shapes the walks already produced', () => {
    const payload = {
      user: 'alice',
      token: new SensitiveString(CANARY, 'credential', 'api_key'),
      nested: { email: new SensitiveString(CANARY, 'sensitive', 'email'), n: 1 },
      list: [1, 'two', new SensitiveString(CANARY, 'credential')],
      when: new Date(0),
      url: new URL('https://example.invalid/p'),
      re: /abc/g,
      bytes: new Uint8Array([1, 2, 3]),
      nullProto: Object.assign(Object.create(null) as object, { k: 'v' }),
    };

    expect(safeStringify(payload)).toMatchInlineSnapshot(
      `"{"user":"alice","token":"[REDACTED:credential]","nested":{"email":"[REDACTED:sensitive]","n":1},"list":[1,"two","[REDACTED:credential]"],"when":"1970-01-01T00:00:00.000Z","url":"https://example.invalid/p","re":"/abc/g","bytes":"1,2,3","nullProto":{"k":"v"}}"`
    );
  });
});

describe('the boundary of what a walk absorbs', () => {
  it('lets a throwing toJSON no longer break safeStringify', () => {
    const payload = {
      token: new SensitiveString(CANARY, 'credential'),
      toJSON(): never {
        throw new Error(`[test] refused, holding ${CANARY}`);
      },
    };

    // The method is dropped from the result rather than copied into it, so the
    // next serializer to touch the result does not get the same throw.
    expect(safeStringify(payload)).toBe('{"token":"[REDACTED:credential]"}');
    expect(JSON.stringify(redactInStructure(payload))).not.toContain('toJSON');
  });

  it('still lets an error from the caller own replacer through', () => {
    // The walk absorbs what the *value* does. A replacer is the caller's own
    // code on the caller's own call, and swallowing its failure would turn a
    // bug in it into a silently lost log line rather than a stack trace.
    expect(() =>
      safeStringify(
        { k: 'v' },
        {
          replacer: () => {
            throw new Error('[test] replacer refused');
          },
        }
      )
    ).toThrow('[test] replacer refused');
  });
});
