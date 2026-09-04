import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, it, expect } from 'vitest';

import { assertSensitiveFlags } from './convict.js';
import { wrapFlat, wrapTree } from './wrap.js';
import { commonSecretNameRules } from './classify.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('wrapFlat', () => {
  it('matches names by exact key', () => {
    const result = wrapFlat(
      { DB_PASSWORD: CANARY, PORT: '3000' },
      { fields: { DB_PASSWORD: 'credential' }, fallback: 'plain' }
    );

    expect(result.fields.get('DB_PASSWORD')).toBeInstanceOf(SensitiveString);
    expect(result.plain.get('PORT')).toBe('3000');
  });

  /**
   * The reason this is not `wrapSensitiveByPath`. That helper splits keys on
   * `.`, so `A.B` is read as a nested path, matches nothing, and is silently
   * left a raw string. Environment names with dots are legal and are produced
   * by some container platforms.
   */
  it('wraps a name containing a dot like any other', () => {
    const result = wrapFlat(
      { 'com.example.token': CANARY },
      { fields: { 'com.example.token': 'credential' }, fallback: 'plain' }
    );

    expect(result.fields.get('com.example.token')?.reveal()).toBe(CANARY);
    expect(result.plain.size).toBe(0);
  });

  it('labels a wrapped value with its own name by default', () => {
    const result = wrapFlat(
      { API_KEY: CANARY },
      { fields: { API_KEY: 'credential' }, fallback: 'plain' }
    );

    expect(result.fields.get('API_KEY')?.label).toBe('API_KEY');
  });

  it('uses a caller label function, which sees the name and never the value', () => {
    const seen: string[] = [];
    const result = wrapFlat(
      { API_KEY: CANARY },
      {
        fields: { API_KEY: 'credential' },
        fallback: 'plain',
        label: (name) => {
          seen.push(name);
          return `env.${name.toLowerCase()}`;
        },
      }
    );

    expect(result.fields.get('API_KEY')?.label).toBe('env.api_key');
    expect(seen).toEqual(['API_KEY']);
  });

  it('keeps the two maps disjoint and reports every name', () => {
    const result = wrapFlat(
      { DB_PASSWORD: CANARY, PORT: '3000', ABSENT: undefined },
      { rules: commonSecretNameRules, fallback: 'plain' }
    );

    expect([...result.fields.keys()]).toEqual(['DB_PASSWORD']);
    expect([...result.plain.keys()]).toEqual(['PORT']);
    expect(result.names).toEqual(['DB_PASSWORD', 'PORT', 'ABSENT']);
    expect(result.counts).toEqual({ credential: 1, sensitive: 0, plain: 2 });
  });

  it('puts a name with no string value in neither map', () => {
    const result = wrapFlat(
      { GONE: undefined },
      { fields: { GONE: 'credential' }, fallback: 'plain' }
    );

    expect(result.fields.has('GONE')).toBe(false);
    expect(result.plain.has('GONE')).toBe(false);
    expect(result.names).toEqual(['GONE']);
    expect(result.classes.get('GONE')).toBe('credential');
  });

  it('wraps an empty string rather than treating it as absent', () => {
    const result = wrapFlat({ EMPTY: '' }, { fields: { EMPTY: 'credential' }, fallback: 'plain' });

    expect(result.fields.get('EMPTY')?.reveal()).toBe('');
  });

  it('does not mutate the source', () => {
    const source = { DB_PASSWORD: CANARY };
    wrapFlat(source, { fields: { DB_PASSWORD: 'credential' }, fallback: 'plain' });

    expect(source).toEqual({ DB_PASSWORD: CANARY });
  });

  it('never inherits a name from Object.prototype', () => {
    const result = wrapFlat({}, { fallback: 'plain' });

    expect(result.names).toEqual([]);
    expect(result.plain.has('toString')).toBe(false);
  });
});

describe('wrapTree', () => {
  const document = {
    db: { host: 'db.internal', password: CANARY },
    smtp: { password: CANARY },
    port: 5432,
  };

  it('wraps by dot path, which is a real separator in a config tree', () => {
    const wrapped = wrapTree(document, {
      'db.password': { klass: 'credential', label: 'db.password' },
      'smtp.password': 'credential',
    });

    expect(wrapped.db.password).toBeInstanceOf(SensitiveString);
    expect((wrapped.db.password as unknown as SensitiveString<'credential'>).label).toBe(
      'db.password'
    );
    expect(wrapped.db.host).toBe('db.internal');
    expect(wrapped.port).toBe(5432);
  });

  it('does not mutate the document it was given', () => {
    wrapTree(document, { 'db.password': 'credential', 'smtp.password': 'credential' });

    expect(document.db.password).toBe(CANARY);
  });

  it('throws for a path the document does not have, which is the typo case', () => {
    expect(() => wrapTree(document, { 'db.passwrod': 'credential' })).toThrow(/db\.passwrod/);
  });

  it('names no value in the typo error', () => {
    try {
      wrapTree(document, { 'db.passwrod': 'credential' });
      expect.unreachable();
    } catch (error) {
      expect((error as Error).message).not.toContain(CANARY);
    }
  });

  it('allows an optional path when the caller says so', () => {
    const wrapped = wrapTree(
      document,
      { 'db.password': 'credential', 'audit.token': 'credential' },
      { requireAllPaths: false }
    );

    expect(wrapped.db.password).toBeInstanceOf(SensitiveString);
  });

  it('leaves an already-wrapped value alone', () => {
    const once = wrapTree(document, { 'db.password': 'credential', 'smtp.password': 'credential' });
    const twice = wrapTree(once, { 'db.password': 'credential', 'smtp.password': 'credential' });

    expect(twice.db.password).toBe(once.db.password);
  });

  it('wraps a partially wrapped document without disturbing the wrapped half', () => {
    const partial = {
      db: { password: new SensitiveString(CANARY, 'credential', 'db.password') },
      smtp: { password: CANARY },
    };

    const wrapped = wrapTree(partial, {
      'db.password': 'credential',
      'smtp.password': 'credential',
    });

    expect(wrapped.db.password).toBe(partial.db.password);
    expect(wrapped.smtp.password).toBeInstanceOf(SensitiveString);
  });
});

describe('assertSensitiveFlags path resolution', () => {
  const schema = {
    db: { password: { doc: 'pw', format: String, default: '', sensitive: true } },
  };

  it('accepts a schema that flags every classified path', () => {
    expect(() => assertSensitiveFlags(schema, { 'db.password': 'credential' })).not.toThrow();
  });

  it('reports a path the schema declares without the flag', () => {
    const unflagged = { db: { password: { doc: 'pw', format: String, default: '' } } };

    expect(() => assertSensitiveFlags(unflagged, { 'db.password': 'credential' })).toThrow(
      /without `sensitive: true`/
    );
  });

  it('reports a path the schema does not have', () => {
    expect(() => assertSensitiveFlags(schema, { 'db.passwrod': 'credential' })).toThrow(
      /absent from the schema/
    );
  });

  it('refuses to walk through a prototype-polluting segment', () => {
    // Not a lookup that could ever succeed, and one that would otherwise read
    // Object.prototype and report a path as present that the schema never
    // declared.
    for (const path of ['__proto__.password', 'constructor.name', 'db.__proto__']) {
      expect(() => assertSensitiveFlags(schema, { [path]: 'credential' })).toThrow(
        /absent from the schema/
      );
    }
  });

  it('reports a path that bottoms out on a non-object', () => {
    expect(() =>
      assertSensitiveFlags({ db: 'not-a-node' }, { 'db.password': 'credential' })
    ).toThrow(/absent from the schema/);
  });

  it('reports a leaf that is not an object at all', () => {
    expect(() =>
      assertSensitiveFlags({ db: { password: 'plain-default' } }, { 'db.password': 'credential' })
    ).toThrow(/absent from the schema/);
  });

  it('lists both kinds of problem in one message, and no value', () => {
    const mixed = {
      db: { password: { default: CANARY } },
    };

    try {
      assertSensitiveFlags(mixed, { 'db.password': 'credential', 'smtp.password': 'credential' });
      expect.unreachable();
    } catch (error) {
      const message = (error as Error).message;

      expect(message).toContain('smtp.password');
      expect(message).toContain('db.password');
      expect(message).not.toContain(CANARY);
    }
  });
});
