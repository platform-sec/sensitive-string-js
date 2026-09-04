import { describe, it, expect } from 'vitest';
import { parse } from 'yaml';

import {
  ENC_MARKER,
  SOPS_BLOCK,
  deriveSpec,
  encryptedPaths,
  formatFor,
  parseCiphertext,
} from './derive.js';
import { enc } from './__tests__/fixtures.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const REF = { path: 'secrets.enc.yaml', version: 'ciphertext', metadata: {} };

const DOCUMENT = {
  database: { host: 'db.internal', port: 5432, password: enc(CANARY) },
  api: { key: enc(CANARY), endpoint: 'https://api.example.com' },
  tokens: [enc(CANARY), 'public'],
  sops: {
    age: [{ recipient: 'age1example', enc: '-----BEGIN AGE ENCRYPTED FILE-----' }],
    version: '3.9.4',
  },
};

describe('formatFor', () => {
  it('reads the format off the extension, as sops does', () => {
    expect(formatFor('/etc/app/secrets.enc.yaml')).toBe('yaml');
    expect(formatFor('/etc/app/secrets.yml')).toBe('yaml');
    expect(formatFor('/etc/app/secrets.enc.json')).toBe('json');
    expect(formatFor('/etc/app/.env')).toBe('env');
    expect(formatFor('/etc/app/prod.env.enc')).toBe('env');
    expect(formatFor('/etc/app/secrets.ini')).toBe('ini');
  });

  it('defaults to yaml, which is what sops defaults to', () => {
    expect(formatFor('/etc/app/secrets')).toBe('yaml');
  });
});

describe('ENC_MARKER', () => {
  it('matches what sops leaves in place of an encrypted scalar', () => {
    expect(ENC_MARKER.test(enc(CANARY))).toBe(true);
  });

  it('does not match a value that merely mentions encryption', () => {
    expect(ENC_MARKER.test('ENCRYPTED')).toBe(false);
    expect(ENC_MARKER.test('ENC[')).toBe(false);
  });
});

describe('encryptedPaths', () => {
  it('reports every leaf and whether sops encrypted it', () => {
    const paths = encryptedPaths(DOCUMENT);

    expect(paths.get('database.password')).toBe(true);
    expect(paths.get('database.host')).toBe(false);
    expect(paths.get('database.port')).toBe(false);
    expect(paths.get('api.key')).toBe(true);
  });

  it('walks arrays by index, since sops encrypts elements individually', () => {
    const paths = encryptedPaths(DOCUMENT);

    expect(paths.get('tokens.0')).toBe(true);
    expect(paths.get('tokens.1')).toBe(false);
  });

  it('skips the sops block, which is the tool own metadata', () => {
    const paths = [...encryptedPaths(DOCUMENT).keys()];

    expect(paths.some((path) => path.startsWith(`${SOPS_BLOCK}.`))).toBe(false);
  });
});

describe('deriveSpec', () => {
  it('classifies what sops encrypted as a credential and the rest as plain', () => {
    const spec = deriveSpec(DOCUMENT);

    expect(spec.fields?.['database.password']).toBe('credential');
    expect(spec.fields?.['api.key']).toBe('credential');
    expect(spec.fields?.['database.host']).toBe('plain');
    expect(spec.fields?.['api.endpoint']).toBe('plain');
  });

  it('falls closed for a key the ciphertext did not carry', () => {
    // Every key of the encrypted file is in `fields`, so the fallback only
    // applies to a key that turned up in the decrypted output and not in the
    // ciphertext, which should not happen.
    expect(deriveSpec(DOCUMENT).fallback).toBe('credential');
  });

  it('lets a rule promote a derived class', () => {
    const spec = deriveSpec(DOCUMENT, {
      rules: [{ pattern: /^host$/, klass: 'sensitive' }],
    });

    expect(spec.fields?.['database.host']).toBe('sensitive');
  });

  it('refuses a rule that would loosen what sops encrypted', () => {
    // The drift this derivation exists to prevent, arriving deliberately.
    expect(() =>
      deriveSpec(DOCUMENT, { rules: [{ pattern: /password/, klass: 'plain' }] })
    ).toThrow(/allowDemotion/);
  });

  it('allows the demotion when the caller means it', () => {
    const spec = deriveSpec(DOCUMENT, {
      rules: [{ pattern: /password/, klass: 'plain' }],
      allowDemotion: true,
    });

    expect(spec.fields?.['database.password']).toBe('plain');
  });

  it('classifies every key the same way when a rule pattern is global', () => {
    // A global pattern is stateful through `lastIndex`, so tested twice it
    // answers true then false for the same key. The compiler strips the flag.
    const spec = deriveSpec(DOCUMENT, {
      rules: [{ pattern: /key|password/g, klass: 'credential' }],
    });

    expect(spec.fields?.['database.password']).toBe('credential');
    expect(spec.fields?.['api.key']).toBe('credential');
  });

  it('takes the class an encrypted leaf gets from the caller', () => {
    const spec = deriveSpec(DOCUMENT, { encryptedAs: 'sensitive' });

    expect(spec.fields?.['database.password']).toBe('sensitive');
  });
});

describe('parseCiphertext', () => {
  it('parses YAML through an injected parser', () => {
    const source = ['a: 1', `b: ${enc(CANARY)}`].join('\n');

    expect(parseCiphertext(source, 'yaml', REF, parse)).toEqual({ a: 1, b: enc(CANARY) });
  });

  it('says what is missing when YAML has no parser', () => {
    expect(() => parseCiphertext('a: 1', 'yaml', REF, undefined)).toThrow(/YAML parser/);
  });

  it('parses JSON through the shared guard', () => {
    expect(parseCiphertext('{"a":1}', 'json', REF, undefined)).toEqual({ a: 1 });
  });

  it('does not report the document when JSON fails to parse', () => {
    try {
      parseCiphertext(CANARY, 'json', REF, undefined);
      expect.unreachable('the parse should have failed');
    } catch (error) {
      expect((error as Error).message).not.toContain(CANARY);
    }
  });

  it('parses an env document, ignoring comments and section headers', () => {
    const source = ['# a comment', '[section]', 'A=1', `B=${enc(CANARY)}`, 'nonsense'].join('\n');

    expect(parseCiphertext(source, 'env', REF, undefined)).toEqual({ A: '1', B: enc(CANARY) });
  });

  it('routes a YAML parse failure through the guard rather than reporting the line', () => {
    const thrower = (): unknown => {
      throw new Error(`bad indentation at line 3: ${CANARY}`);
    };

    try {
      parseCiphertext('anything', 'yaml', REF, thrower);
      expect.unreachable('the parse should have failed');
    } catch (error) {
      expect((error as Error).message).not.toContain(CANARY);
      expect((error as { cause?: unknown }).cause).toBeUndefined();
    }
  });
});
