import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

import { SopsSecretSource } from '../source.js';
import type { SopsSecretSourceOptions } from '../source.js';

/**
 * The stand-in binary. Executable with a shebang, so it is spawned like one.
 *
 * Located from the working directory rather than from `import.meta.url`,
 * because this package emits CommonJS and `import.meta` is not available there.
 * Both invocations are covered: the repository root, which is where `pnpm test`
 * runs, and the package directory, which is where `pnpm --filter ... test`
 * runs.
 */
const FROM_ROOT = 'packages/sensitive-sops/src/__tests__/fake-sops.mjs';
const FROM_PACKAGE = 'src/__tests__/fake-sops.mjs';

export const FAKE_SOPS = existsSync(join(process.cwd(), FROM_ROOT))
  ? join(process.cwd(), FROM_ROOT)
  : join(process.cwd(), FROM_PACKAGE);

export const AGE_KEY = 'AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST';

export function ageIdentity(): SensitiveString<'credential'> {
  return new SensitiveString(AGE_KEY, 'credential', 'age-identity');
}

/** A SOPS marker holding the plaintext, which the stand-in binary reverses. */
export function enc(plaintext: string): string {
  return `ENC[AES256_GCM,data:${Buffer.from(plaintext, 'utf8').toString('base64')},iv:aaaa,tag:bbbb,type:str]`;
}

export function scratch(): string {
  return mkdtempSync(join(tmpdir(), 'sensitive-sops-'));
}

/**
 * An encrypted YAML document, in the shape SOPS leaves one.
 *
 * Keys in the clear, encrypted values replaced by markers, and a `sops`
 * metadata block at the root holding the recipient list.
 */
export function encryptedYaml(
  dir: string,
  name = 'secrets.enc.yaml',
  body = [
    'database:',
    '    host: db.internal',
    '    port: 5432',
    `    password: ${enc('LEAKED_SECRET_abc123xyz')}`,
    'api:',
    `    key: ${enc('LEAKED_SECRET_abc123xyz')}`,
    '    endpoint: https://api.example.com',
  ].join('\n')
): string {
  const path = join(dir, name);
  const metadata = [
    'sops:',
    '    age:',
    '        - recipient: age1exampleexampleexampleexampleexampleexampleexample',
    '          enc: |',
    '            -----BEGIN AGE ENCRYPTED FILE-----',
    '            example',
    '            -----END AGE ENCRYPTED FILE-----',
    '    lastmodified: "2026-09-01T00:00:00Z"',
    '    version: 3.9.4',
  ].join('\n');

  writeFileSync(path, `${body}\n${metadata}\n`);

  return path;
}

export function write(dir: string, name: string, body: string): string {
  const path = join(dir, name);
  writeFileSync(path, body);

  return path;
}

export function source(
  options: Partial<SopsSecretSourceOptions> = {},
  report?: string
): SopsSecretSource {
  return new SopsSecretSource({
    binary: FAKE_SOPS,
    ageKey: ageIdentity(),
    cache: { ttl: 0 },
    ...options,
    env: {
      ...(report === undefined ? {} : { FAKE_SOPS_REPORT: report }),
      ...options.env,
    },
  });
}
