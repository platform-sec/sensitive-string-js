import { describe, it, expect, afterAll } from 'vitest';
import { rmSync } from 'node:fs';
import { parse } from 'yaml';
import { describeLabelDisclosure } from '@platform-sec/sensitive-string-secrets';
import type { SecretLoadEvent } from '@platform-sec/sensitive-string-secrets';
import {
  assertEverySourceSwept,
  assertNoCanary,
  sweep,
} from '@platform-sec/sensitive-string-secrets/testing';
import type { SweepCase } from '@platform-sec/sensitive-string-secrets/testing';

import * as sopsPackage from '../index.js';
import { AGE_KEY, enc, encryptedYaml, scratch, source, write } from './fixtures.js';

/** Exactly 20 characters, the length V8 echoes whole into a SyntaxError. */
const SHORT_CANARY = 'LEAKED_SECRET_abc123';
const CANARY = 'LEAKED_SECRET_abc123xyz';

const DIR = scratch();

afterAll(() => {
  rmSync(DIR, { recursive: true, force: true });
});

const YAML_DOC = encryptedYaml(DIR);
const SHORT_DOC = encryptedYaml(DIR, 'short.enc.yaml', `api:\n    key: ${enc(SHORT_CANARY)}`);
const JSON_DOC = write(
  DIR,
  'secrets.enc.json',
  JSON.stringify({ api: { key: enc(CANARY) }, sops: { version: '3.9.4' } })
);
const BROKEN_YAML = write(DIR, 'broken.enc.yaml', `api:\n  key: ${enc(CANARY)}\n   bad: indent`);
const DOTTED_DOC = write(
  DIR,
  'dotted.enc.json',
  JSON.stringify({ 'tls.key': enc(CANARY), sops: { version: '3.9.4' } })
);

/**
 * The sources are built once rather than per case.
 *
 * Every construction runs a `sops --version` and every case runs a decrypt, so
 * a sweep that built a source per case would spawn two processes per case, and
 * four sweeps would spawn over a hundred. Reusing them keeps the count to the
 * decrypts, which are the part being swept.
 */
const YAML_SOURCE = source({ yamlParse: parse });
const BARE_SOURCE = source();
const FAILING = source({ yamlParse: parse, env: { FAKE_SOPS_FAIL: '1' } });
const BAD_OUTPUT = source({ yamlParse: parse, env: { FAKE_SOPS_BAD_OUTPUT: '1' } });
const NO_BINARY = source({ binary: '/definitely/not/a/binary' });

/**
 * Longer than the default, because every case spawns a process.
 *
 * A wall clock budget that is fine on an idle machine is not fine when the rest
 * of the repository's suite is running beside it, and a sweep that flakes under
 * load is a sweep somebody eventually deletes.
 */
const SPAWN_TIMEOUT_MS = 60_000;

const CASES: readonly SweepCase[] = [
  {
    name: 'getDerived on a YAML document',
    run: () => YAML_SOURCE.getDerived(YAML_DOC),
  },
  { name: 'getDerived on a JSON document', run: () => BARE_SOURCE.getDerived(JSON_DOC) },
  {
    name: 'getDerived on a document with a dotted key',
    run: () => BARE_SOURCE.getDerived(DOTTED_DOC),
  },
  {
    name: 'getDerived on a 20-character secret',
    run: () => YAML_SOURCE.getDerived(SHORT_DOC),
  },
  {
    name: 'getDerived on a YAML document with no parser',
    run: () => BARE_SOURCE.getDerived(YAML_DOC),
  },
  {
    name: 'getDerived on a document the YAML parser refuses',
    run: () => YAML_SOURCE.getDerived(BROKEN_YAML),
  },
  {
    name: 'getAll with an explicit spec',
    run: () => BARE_SOURCE.getAll(YAML_DOC, { fallback: 'credential' }),
  },
  {
    name: 'getJson with a declared field the document lacks',
    run: () => BARE_SOURCE.getJson(YAML_DOC, { fields: { missing: 'credential' } }),
  },
  {
    name: 'get on a document that holds named fields',
    run: () => BARE_SOURCE.get(YAML_DOC),
  },
  {
    name: 'a decrypt the binary refuses',
    run: () => FAILING.getDerived(YAML_DOC),
  },
  {
    name: 'a decrypt whose output is not JSON',
    run: () => BAD_OUTPUT.getDerived(YAML_DOC),
  },
  {
    name: 'an absent document',
    run: () => BARE_SOURCE.getDerived('/definitely/not/a/file.enc.yaml'),
  },
  {
    name: 'a missing binary',
    run: () => NO_BINARY.getDerived(YAML_DOC),
  },
  { name: 'deriveFor on its own', run: () => YAML_SOURCE.deriveFor(YAML_DOC) },
];

describe('the sops sweep', () => {
  it(
    'leaks the canary in no result and no error',
    async () => {
      const results = await sweep(CANARY, CASES);

      expect(results).toHaveLength(CASES.length);
    },
    SPAWN_TIMEOUT_MS
  );

  it(
    'leaks the 20-character canary either',
    async () => {
      await sweep(SHORT_CANARY, CASES);
    },
    SPAWN_TIMEOUT_MS
  );

  it(
    'leaks the age identity in no result and no error',
    async () => {
      // The value that unlocks every other one. It reaches the child's
      // environment and nothing else.
      await sweep(AGE_KEY, CASES);
    },
    SPAWN_TIMEOUT_MS
  );

  it(
    'forces failures rather than sweeping only happy paths',
    async () => {
      const results = await sweep(CANARY, CASES);

      expect(results.filter((result) => result.threw).length).toBeGreaterThan(4);
    },
    SPAWN_TIMEOUT_MS
  );
});

describe('the parser that can leak', () => {
  it('only ever sees ciphertext', async () => {
    // The invariant, as a test. The encrypted document goes to a YAML parser
    // whose errors quote the offending line, which is safe because the values
    // there are ciphertext. The decrypted document is JSON and goes through the
    // shared guard.
    const seen: string[] = [];
    const recording = (text: string): unknown => {
      seen.push(text);

      return parse(text);
    };

    await source({ yamlParse: recording }).getDerived(YAML_DOC);

    expect(seen).toHaveLength(1);
    for (const text of seen) {
      expect(text).not.toContain(CANARY);
      expect(text).toContain('ENC[');
    }
  });
});

describe('the parent environment', () => {
  it('never gains the age key, on the success path or the failure one', async () => {
    await source({ yamlParse: parse }).getDerived(YAML_DOC);
    await source({ yamlParse: parse, env: { FAKE_SOPS_FAIL: '1' } })
      .getDerived(YAML_DOC)
      .catch(() => undefined);

    expect(process.env['SOPS_AGE_KEY']).toBeUndefined();
  });
});

describe('load events', () => {
  it('carry no secret material and no identity', async () => {
    const events: SecretLoadEvent[] = [];
    const sops = source({ yamlParse: parse, onLoad: (event) => events.push(event) });

    await sops.getDerived(YAML_DOC);

    assertNoCanary(CANARY, events, 'the sops load events');
    assertNoCanary(AGE_KEY, events, 'the sops load events');
  });
});

describe('labels', () => {
  it('disclose nothing under the rule, and never a directory path', async () => {
    const record = await source({ yamlParse: parse }).getDerived(YAML_DOC);

    for (const value of record.fields.values()) {
      expect(describeLabelDisclosure(value.label ?? '')).toEqual([]);
      expect(value.label).not.toContain('/');
    }
  });
});

describe('the registration test', () => {
  it('fails if a source implementation has no sweep entry', () => {
    expect(() => assertEverySourceSwept(sopsPackage, [])).toThrow(
      /no sweep entry: SopsSecretSource/
    );
  });

  it('passes now that SopsSecretSource is swept', () => {
    expect(() => assertEverySourceSwept(sopsPackage, ['SopsSecretSource'])).not.toThrow();
  });
});
