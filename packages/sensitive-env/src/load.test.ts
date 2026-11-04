import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseEnv } from 'node:util';

import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';

import { commonSecretNameRules } from './classify.js';
import { explainEnv, loadEnv } from './load.js';
import type { EnvLoadEvent, EnvSpec } from './types.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

/** Whether `util.parseEnv` folds a stray line into the next name; see `parse.test.ts`. */
const SWALLOWING_PARSER = !Object.hasOwn(parseEnv('KEY\nB=2\n'), 'B');

const SPEC: EnvSpec = {
  fields: { DB_PASSWORD: 'credential', SUPPORT_EMAIL: 'sensitive' },
  rules: commonSecretNameRules,
  fallback: 'plain',
};

let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'sensitive-env-load-'));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

function file(name: string, content: string): string {
  const path = join(dir, name);
  writeFileSync(path, content);
  return path;
}

describe('loadEnv', () => {
  it('wraps a classified name and leaves the rest alone', () => {
    const record = loadEnv(SPEC, {
      source: { DB_PASSWORD: CANARY, PORT: '3000', SUPPORT_EMAIL: 'a@b.example' },
    });

    expect(record.fields.get('DB_PASSWORD')).toBeInstanceOf(SensitiveString);
    expect(record.fields.get('DB_PASSWORD')?.klass).toBe('credential');
    expect(record.fields.get('SUPPORT_EMAIL')?.klass).toBe('sensitive');
    expect(record.plain.get('PORT')).toBe('3000');
  });

  it('reads process.env by default and does not write to it', () => {
    const before = { ...process.env };
    process.env['SENSITIVE_ENV_TEST_PLAIN'] = 'yes';

    try {
      const record = loadEnv({ fallback: 'plain' });

      expect(record.plain.get('SENSITIVE_ENV_TEST_PLAIN')).toBe('yes');
      expect(record.removed).toEqual([]);
      expect(process.env['SENSITIVE_ENV_TEST_PLAIN']).toBe('yes');
    } finally {
      for (const key of Object.keys(process.env)) {
        if (!Object.hasOwn(before, key)) {
          delete process.env[key];
        }
      }
      Object.assign(process.env, before);
    }
  });

  it('requires an explicit fallback', () => {
    expect(() => loadEnv({} as unknown as EnvSpec, { source: {} })).toThrow(/explicit fallback/);
  });

  it('keeps the two maps disjoint, and lists every name in both', () => {
    const record = loadEnv(SPEC, { source: { DB_PASSWORD: CANARY, PORT: '3000' } });

    const wrapped = new Set(record.fields.keys());
    for (const name of record.plain.keys()) {
      expect(wrapped.has(name)).toBe(false);
    }
    expect(record.names).toEqual(['DB_PASSWORD', 'PORT']);
  });

  it('reports kernelCopy as an empty array only when the check did not run', () => {
    const record = loadEnv(SPEC, { source: { DB_PASSWORD: CANARY } });

    // Off by default. The check that would produce `'unknown'` never ran.
    expect(record.kernelCopy).toEqual([]);
  });
});

describe('source precedence', () => {
  it('lets a later file win over an earlier one', () => {
    const first = file('first.env', 'SHARED=first\nONLY_FIRST=1\n');
    const second = file('second.env', 'SHARED=second\n');

    const record = loadEnv({ fallback: 'plain' }, { files: [first, second], source: {} });

    expect(record.plain.get('SHARED')).toBe('second');
    expect(record.plain.get('ONLY_FIRST')).toBe('1');
  });

  it('lets the source win over every file', () => {
    const path = file('lose.env', 'SHARED=fromFile\n');

    const record = loadEnv(
      { fallback: 'plain' },
      { files: [path], source: { SHARED: 'fromSource' } }
    );

    expect(record.plain.get('SHARED')).toBe('fromSource');
  });

  it('does not let a source key with no string value erase a file default', () => {
    const path = file('default.env', 'SHARED=fromFile\n');

    const record = loadEnv({ fallback: 'plain' }, { files: [path], source: { SHARED: undefined } });

    expect(record.plain.get('SHARED')).toBe('fromFile');
  });

  it('skips a file that does not exist', () => {
    const record = loadEnv(
      { fallback: 'plain' },
      { files: [join(dir, 'nope.env')], source: { A: '1' } }
    );

    expect(record.plain.get('A')).toBe('1');
  });

  it('throws for a file that exists and cannot be read', () => {
    expect(() => loadEnv({ fallback: 'plain' }, { files: [dir], source: {} })).toThrow(/EISDIR/);
  });
});

describe('the onLoad event', () => {
  it('reports names, classes and counts, and no value', () => {
    const events: EnvLoadEvent[] = [];

    loadEnv(SPEC, {
      source: { DB_PASSWORD: CANARY, PORT: '3000' },
      onLoad: (event) => events.push(event),
    });

    expect(events).toHaveLength(1);
    const event = events[0]!;
    expect(event.names).toEqual(['DB_PASSWORD', 'PORT']);
    expect(event.classes.get('DB_PASSWORD')).toBe('credential');
    expect(event.counts).toEqual({ credential: 1, sensitive: 0, plain: 1 });
    expect(JSON.stringify([...event.classes])).not.toContain(CANARY);
  });

  it('reports a dropped line by number and never by content', () => {
    const path = file('dropped.env', `A=1\n${CANARY}\nB=2\n`);
    const events: EnvLoadEvent[] = [];

    loadEnv({ fallback: 'plain' }, { files: [path], source: {}, onLoad: (e) => events.push(e) });

    const event = events[0]!;
    expect(event.files).toEqual([path]);
    // A swallowing parser also takes `B`, which is reported too.
    expect(event.droppedLines.map((d) => d.line)).toEqual(SWALLOWING_PARSER ? [2, 3] : [2]);
    expect(JSON.stringify(event.droppedLines)).not.toContain(CANARY);
  });

  it('reports a count for the names the parser produced that no exporter could set', () => {
    // A tab in a name is produced by every supported parser, so this runs the
    // count through the loader wherever the suite runs.
    const path = file('invented.env', `A\tTOKEN=${CANARY}\n`);
    const events: EnvLoadEvent[] = [];

    loadEnv({ fallback: 'plain' }, { files: [path], source: {}, onLoad: (e) => events.push(e) });

    expect(events[0]!.unexpectedNames).toBe(1);
    expect(JSON.stringify(events[0]!.names)).not.toContain(CANARY);
  });

  it('fires exactly once per load', () => {
    let calls = 0;

    loadEnv(SPEC, { source: { A: '1', B: '2', C: '3' }, onLoad: () => calls++ });

    expect(calls).toBe(1);
  });
});

describe('explainEnv', () => {
  it('reports the classification without wrapping anything', () => {
    const explained = explainEnv(SPEC, {
      source: { DB_PASSWORD: CANARY, GITHUB_TOKEN: CANARY, PORT: '3000' },
    });

    expect(explained.classes.get('DB_PASSWORD')).toBe('credential');
    expect(explained.classes.get('GITHUB_TOKEN')).toBe('credential');
    expect(explained.classes.get('PORT')).toBe('plain');
    expect(explained.counts).toEqual({ credential: 2, sensitive: 0, plain: 1 });
  });

  it('returns no value anywhere in its result', () => {
    const explained = explainEnv(SPEC, { source: { DB_PASSWORD: CANARY, PORT: CANARY } });

    expect(
      JSON.stringify([explained.names, [...explained.classes], explained.counts])
    ).not.toContain(CANARY);
  });

  it('never removes anything, whatever the options say', () => {
    process.env['SENSITIVE_ENV_EXPLAIN_ONLY'] = CANARY;

    try {
      explainEnv(
        { fields: { SENSITIVE_ENV_EXPLAIN_ONLY: 'credential' }, fallback: 'plain' },
        { removeFromProcessEnv: true }
      );

      expect(process.env['SENSITIVE_ENV_EXPLAIN_ONLY']).toBe(CANARY);
    } finally {
      delete process.env['SENSITIVE_ENV_EXPLAIN_ONLY'];
    }
  });
});
