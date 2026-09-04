import { describe, it, expect, afterEach } from 'vitest';
import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  SecretPayloadError,
  describeLabelDisclosure,
} from '@platform-sec/sensitive-string-secrets';
import type { FileWatcher, MultiSecretRecord } from '@platform-sec/sensitive-string-secrets';

import { SopsError } from './spawn.js';
import { enc, encryptedYaml, scratch, source, write } from './__tests__/fixtures.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

const dirs: string[] = [];
const watchers: FileWatcher[] = [];

afterEach(() => {
  for (const watcher of watchers.splice(0)) {
    watcher.close();
  }
  for (const dir of dirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
  delete process.env['SOPS_AGE_KEY'];
});

function dir(): string {
  const made = scratch();
  dirs.push(made);

  return made;
}

async function until(predicate: () => boolean, timeoutMs = 3_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error('condition was not met in time');
    }

    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe('SopsSecretSource.getDerived', () => {
  it('wraps what sops encrypted and leaves the rest alone', async () => {
    const path = encryptedYaml(dir());
    const record = await source({ yamlParse: parse }).getDerived(path);

    expect(record.fields.get('database.password')).toBeInstanceOf(SensitiveString);
    expect(record.fields.get('database.password')?.reveal({ name: 'test' })).toBe(CANARY);
    expect(record.fields.get('api.key')?.klass).toBe('credential');
    expect(record.plain.get('database.host')).toBe('db.internal');
    expect(record.plain.get('api.endpoint')).toBe('https://api.example.com');
  });

  it('labels by file name, not by directory', async () => {
    const path = encryptedYaml(dir());
    const record = await source({ yamlParse: parse }).getDerived(path);
    const label = record.fields.get('database.password')?.label ?? '';

    expect(label).toBe('secrets.enc.yaml#database.password');
    expect(label).not.toContain('/tmp');
    expect(describeLabelDisclosure(label)).toEqual([]);
  });

  it('reports the file on metadata, where the load hook sees it', async () => {
    const path = encryptedYaml(dir());
    const record = await source({ yamlParse: parse }).getDerived(path);

    expect(record.ref.metadata['file']).toBe(path);
  });

  it('needs no fallback, because the derivation supplies one per key', async () => {
    const path = encryptedYaml(dir());

    // The `getAll` requirement is turned back on by passing an explicit spec.
    await expect(source({ yamlParse: parse }).getDerived(path)).resolves.toBeDefined();
  });

  it('drops the sops metadata block rather than classifying it', async () => {
    const path = encryptedYaml(dir());
    const record = await source({ yamlParse: parse }).getDerived(path);

    expect(record.keys.some((key) => key.startsWith('sops'))).toBe(false);
  });
});

describe('SopsSecretSource.getAll with an explicit spec', () => {
  it('turns the derivation off and requires a fallback', async () => {
    const path = encryptedYaml(dir());
    const record = await source().getAll(path, {
      rules: [{ pattern: /password|key/, klass: 'credential' }],
      fallback: 'plain',
    });

    expect(record.fields.get('database.password')?.klass).toBe('credential');
    expect(record.plain.get('database.host')).toBe('db.internal');
  });

  it('does not read the encrypted file at all in that mode', async () => {
    // No YAML parser is configured, so a derivation would throw.
    const path = encryptedYaml(dir());

    await expect(source().getAll(path, { fallback: 'credential' })).resolves.toBeDefined();
  });
});

describe('failures', () => {
  it('reports an absent file as an absence', async () => {
    expect(
      await source({ yamlParse: parse }).getOptional('/definitely/not/a/file.enc.yaml')
    ).toBeNull();
  });

  it('attaches stderr to a decrypt failure, which is the whole diagnosis', async () => {
    const path = encryptedYaml(dir());
    const failure = await source({ yamlParse: parse, env: { FAKE_SOPS_FAIL: '1' } })
      .getAll(path, { fallback: 'credential' })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SopsError);
    expect((failure as SopsError).stderr).toContain('identity did not match any of the recipients');
  });

  it('leaves stderr out when the deployment would rather have less', async () => {
    const path = encryptedYaml(dir());
    const failure = await source({
      yamlParse: parse,
      includeStderr: false,
      env: { FAKE_SOPS_FAIL: '1' },
    })
      .getAll(path, { fallback: 'credential' })
      .catch((error: unknown) => error);

    expect((failure as SopsError).stderr).toBeUndefined();
  });

  it('routes output that is not JSON through the shared guard', async () => {
    const path = encryptedYaml(dir());
    const failure = await source({ yamlParse: parse, env: { FAKE_SOPS_BAD_OUTPUT: '1' } })
      .getAll(path, { fallback: 'credential' })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SecretPayloadError);
    expect((failure as { cause?: unknown }).cause).toBeUndefined();
  });

  it('fails where it can be read when the binary is missing', async () => {
    const failing = source({ binary: '/definitely/not/a/binary' });

    await expect(failing.version()).rejects.toThrow(/shells out to sops/);
  });

  it('says what is missing when a YAML document has no parser', async () => {
    const path = encryptedYaml(dir());

    await expect(source().getDerived(path)).rejects.toThrow(/YAML parser/);
  });

  it('reports an unreadable encrypted file without naming its contents', async () => {
    const failure = await source({ yamlParse: parse })
      .deriveFor('/definitely/not/a/file.enc.yaml')
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SecretPayloadError);
  });
});

describe('the age key', () => {
  it('reaches the child and never the parent, including on the failure path', async () => {
    const scratchDir = dir();
    const path = encryptedYaml(scratchDir);
    const report = join(scratchDir, 'report.json');

    await source({ yamlParse: parse, env: { FAKE_SOPS_FAIL: '1' } }, report)
      .getAll(path, { fallback: 'credential' })
      .catch(() => undefined);

    const seen = JSON.parse(readFileSync(report, 'utf8')) as { sawAgeKey: boolean };

    expect(seen.sawAgeKey).toBe(true);
    // A cleanup that only runs on success is the usual shape of this bug.
    expect(process.env['SOPS_AGE_KEY']).toBeUndefined();
  });
});

describe('a JSON document', () => {
  it('derives from the ciphertext without a YAML parser', async () => {
    const scratchDir = dir();
    const path = write(
      scratchDir,
      'secrets.enc.json',
      JSON.stringify({
        api: { key: enc(CANARY), endpoint: 'https://api.example.com' },
        sops: { version: '3.9.4' },
      })
    );

    const record = await source().getDerived(path);

    expect(record.fields.get('api.key')?.reveal({ name: 'test' })).toBe(CANARY);
    expect(record.plain.get('api.endpoint')).toBe('https://api.example.com');
  });
});

describe('SopsSecretSource.watch', () => {
  it('re-reads when a deployment replaces the document', async () => {
    const scratchDir = dir();
    const path = encryptedYaml(scratchDir);
    const sops = source({ yamlParse: parse });
    const seen: MultiSecretRecord[] = [];

    await sops.getDerived(path);

    watchers.push(sops.watch(path, {}, { debounceMs: 20, onChange: (next) => seen.push(next) }));

    encryptedYaml(scratchDir, 'secrets.enc.yaml', `api:\n    key: ${enc('rotated')}`);
    await until(() => seen.length > 0);

    expect(seen[0]?.fields.get('api.key')?.reveal({ name: 'test' })).toBe('rotated');
  });
});

describe('the absence path', () => {
  it('reports an absent document as absent, whatever the binary says about it', async () => {
    // The check is the filesystem's rather than the binary's message. An
    // earlier version matched on wording its own stand-in binary invented, so
    // every absent document threw instead of arriving as null. Real sops says
    // `cannot operate on non-existent file` and exits 100.
    expect(
      await source({ yamlParse: parse }).getOptional('/definitely/not/a/file.enc.yaml')
    ).toBeNull();
  });

  it('keeps throwing for a document that is there and does not decrypt', async () => {
    const path = encryptedYaml(dir());

    await expect(
      source({ yamlParse: parse, env: { FAKE_SOPS_FAIL: '1' } }).getOptional(path)
    ).rejects.toThrow(SopsError);
  });
});
