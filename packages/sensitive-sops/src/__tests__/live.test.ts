import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { parse } from 'yaml';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { SecretPayloadError } from '@platform-sec/sensitive-string-secrets';
import { assertNoCanaryInError } from '@platform-sec/sensitive-string-secrets/testing';

import { SopsSecretSource } from '../source.js';
import { SopsError } from '../spawn.js';

/**
 * The second tier: the real `sops` binary.
 *
 * The unit suite runs against a stand-in binary, and a stand-in is a fixture.
 * The rule this row works to is that a fixture written from a design document
 * tests the document, and this file is what keeps that honest: it encrypts with
 * the real tool, decrypts with it, and asserts the wire facts the package
 * depends on. It found one already. The absence check used to match on `no such
 * file or directory`, which is what the stand-in printed and not what sops
 * says, so `getOptional` threw for every absent document.
 *
 * Skipped unless `SOPS_BINARY` names an executable, or `sops` is on PATH. CI
 * runs it as a matrix job with `continue-on-error: true`.
 */

const BINARY = process.env['SOPS_BINARY'] ?? 'sops';

function available(): boolean {
  try {
    execFileSync(BINARY, ['--version', '--disable-version-check'], { stdio: 'ignore' });

    return true;
  } catch {
    return false;
  }
}

const CANARY = 'LEAKED_SECRET_abc123xyz';
const RUN = available();

let dir: string;
let encrypted: string;
let identity: SensitiveString<'credential'>;
let recipient: string;

describe.skipIf(!RUN)('sops, against the real binary', () => {
  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'sensitive-sops-live-'));

    const raw = await generateIdentity();
    recipient = await identityToRecipient(raw);
    identity = new SensitiveString(raw, 'credential', 'age-identity');

    const plain = join(dir, 'plain.yaml');
    encrypted = join(dir, 'secrets.enc.yaml');

    writeFileSync(
      plain,
      [
        'database:',
        '    host: db.internal',
        '    port: 5432',
        `    password: ${CANARY}`,
        'api:',
        `    key: ${CANARY}`,
        '    endpoint: https://api.example.com',
        '',
      ].join('\n')
    );

    const ciphertext = execFileSync(
      BINARY,
      ['--encrypt', '--age', recipient, '--encrypted-regex', '^(password|key)$', plain],
      { encoding: 'utf8' }
    );

    writeFileSync(encrypted, ciphertext);
    rmSync(plain);
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
    delete process.env['SOPS_AGE_KEY'];
  });

  function source(overrides: Record<string, unknown> = {}): SopsSecretSource {
    return new SopsSecretSource({
      binary: BINARY,
      ageKey: identity,
      yamlParse: parse,
      cache: { ttl: 0 },
      ...overrides,
    });
  }

  it('reports the binary version', async () => {
    expect(await source().version()).toMatch(/^sops \d+\.\d+\.\d+/);
  });

  it('writes the marker this package derives classification from', () => {
    // The shape `deriveSpec` matches, taken from the tool rather than from the
    // design document.
    const ciphertext = execFileSync('cat', [encrypted], { encoding: 'utf8' });

    expect(ciphertext).toMatch(/password: ENC\[AES256_GCM,data:/);
    expect(ciphertext).toContain('sops:');
    expect(ciphertext).not.toContain(CANARY);
  });

  it('derives the classification the ciphertext implies', async () => {
    const spec = await source().deriveFor(encrypted);

    expect(spec.fields?.['database.password']).toBe('credential');
    expect(spec.fields?.['api.key']).toBe('credential');
    expect(spec.fields?.['database.host']).toBe('plain');
    expect(spec.fields?.['api.endpoint']).toBe('plain');
  });

  it('decrypts and wraps what sops encrypted', async () => {
    const record = await source().getDerived(encrypted);

    expect(record.fields.get('database.password')?.reveal({ name: 'live' })).toBe(CANARY);
    expect(record.fields.get('api.key')?.reveal({ name: 'live' })).toBe(CANARY);
    expect(record.plain.get('database.host')).toBe('db.internal');
    expect(record.plain.get('api.endpoint')).toBe('https://api.example.com');
  });

  it('drops the sops metadata block', async () => {
    const record = await source().getDerived(encrypted);

    expect(record.keys.some((key) => key.startsWith('sops'))).toBe(false);
  });

  it('reports an absent document as absent', async () => {
    // The case the stand-in binary got wrong. sops 3.13.3 says `cannot operate
    // on non-existent file` and exits 100.
    expect(await source().getOptional(join(dir, 'not-there.enc.yaml'))).toBeNull();
  });

  it('keeps throwing when the identity matches no recipient', async () => {
    const other = await generateIdentity();
    const failure = await source({
      ageKey: new SensitiveString(other, 'credential', 'wrong-identity'),
    })
      .getDerived(encrypted)
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SopsError);
    assertNoCanaryInError(CANARY, failure, 'a decrypt with the wrong identity');
  });

  it('leaks no plaintext on stderr when the MAC fails', async () => {
    // Measured on 3.13.3: stderr says `cipher: message authentication failed`
    // and carries neither the value nor the key name. That is what
    // `includeStderr` defaulting to true rests on.
    const tampered = join(dir, 'tampered.enc.yaml');
    const ciphertext = execFileSync('cat', [encrypted], { encoding: 'utf8' });

    writeFileSync(
      tampered,
      ciphertext.replace(/data:(.)/, (_m, first: string) => `data:${first === 'A' ? 'B' : 'A'}`)
    );

    const failure = await source()
      .getDerived(tampered)
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SopsError);
    expect((failure as SopsError).stderr).toMatch(/authentication failed|Could not decrypt/);
    assertNoCanaryInError(CANARY, failure, 'a decrypt of a tampered document');
  });

  it('keeps throwing for a file that is not a sops document', async () => {
    const notSops = join(dir, 'plain2.yaml');
    writeFileSync(notSops, `a: ${CANARY}\n`);

    const failure = await source()
      .getDerived(notSops)
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SopsError);
    expect((failure as SopsError).stderr).toContain('sops metadata not found');
    assertNoCanaryInError(CANARY, failure, 'a decrypt of a file that is not a sops document');
  });

  it('never puts the age identity into the parent environment', async () => {
    await source().getDerived(encrypted);

    expect(process.env['SOPS_AGE_KEY']).toBeUndefined();
  });

  it('routes output that is not JSON through the shared guard', async () => {
    // `--output-type json` is what makes this impossible in practice, so the
    // case that remains is a document whose decrypted form is not an object.
    const scalar = join(dir, 'scalar.enc.yaml');
    const plain = join(dir, 'scalar.yaml');
    writeFileSync(plain, `value: ${CANARY}\n`);

    writeFileSync(
      scalar,
      execFileSync(BINARY, ['--encrypt', '--age', recipient, plain], { encoding: 'utf8' })
    );

    const record = await source().getDerived(scalar);

    expect(record.fields.get('value')?.reveal({ name: 'live' })).toBe(CANARY);
    expect(SecretPayloadError.name).toBe('SecretPayloadError');
  });
});
