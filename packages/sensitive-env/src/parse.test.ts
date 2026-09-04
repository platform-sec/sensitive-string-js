import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, it, expect, beforeAll, afterAll } from 'vitest';

import { parseEnvContent, readEnvFile } from './parse.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'sensitive-env-parse-'));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

function file(name: string, content: string): string {
  const path = join(dir, name);
  writeFileSync(path, content);
  return path;
}

/**
 * The `util.parseEnv` table, measured on Node 22.15.0.
 *
 * These are pins as much as tests: the loader's dropped-line report is built
 * around this behaviour, and a Node release that changes it should fail here
 * rather than silently invalidate the report.
 */
describe('util.parseEnv, as this package relies on it', () => {
  it.each([
    ['export A=1', { A: '1' }, 'the export prefix is stripped'],
    ["B='x\ny'", { B: 'x\ny' }, 'single-quoted multi-line values are preserved'],
    ['B="x\ny"', { B: 'x\ny' }, 'double-quoted multi-line values are preserved'],
    ['A=1\nA=2', { A: '2' }, 'last wins, silently'],
    ['JUSTNAME', {}, 'a line with no = at end of file is dropped'],
    ['A\u0009B=1\n', {}, 'a name holding a control character is refused'],
    ['K="unterminated', {}, 'an unterminated quote at end of file is dropped'],
    ['A = 1', { A: '1' }, 'whitespace around = is tolerated'],
    ['# a comment\nA=1', { A: '1' }, 'comments are skipped'],
    ['A=b # trailing\nB=2\n', { A: 'b', B: '2' }, 'a trailing comment is stripped'],
    // Measured, and pinned because it is a value-corrupting surprise: the
    // comment is stripped only when another line follows. The *last* variable
    // of a file keeps everything after the hash, trailing newline or not.
    ['A=b # trailing\n', { A: 'b # trailing' }, 'the last line keeps its comment'],
    ['A=b # trailing', { A: 'b # trailing' }, 'and so does an unterminated one'],
    ['A.B=1', { 'A.B': '1' }, 'a dot in a name is just a character'],
    ['A=1\r\nB=2', { A: '1', B: '2' }, 'CRLF is handled'],
  ] as ReadonlyArray<[string, Record<string, string>, string]>)('parses %j', (input, expected) => {
    expect(parseEnvContent(input, 'x.env').values).toEqual(expected);
  });

  it('never throws, whatever it is given', () => {
    const hostile = ['', '=', '===', '\0\0', 'a'.repeat(10_000), '"'.repeat(500), '\n'.repeat(500)];

    for (const input of hostile) {
      expect(() => parseEnvContent(input, 'x.env')).not.toThrow();
    }
  });

  /**
   * The two behaviours the dropped-line report exists for, and neither is what
   * the input looks like in isolation.
   */
  it("lets a line with no = swallow the next line's variable name", () => {
    // `util.parseEnv` on its own returns `{ 'KEY\nB': '2' }`. This wrapper
    // drops that name, because a newline in a variable name is impossible
    // through every real exporter and the name is built out of the previous
    // line's text. Either way `B` is gone; the difference is that the mangled
    // name does not become an unclassified variable holding part of a value.
    const { values, unexpectedNames, droppedLines } = parseEnvContent('KEY\nB=2\n', 'x.env');

    expect(values).toEqual({});
    expect(unexpectedNames).toBe(1);
    expect(droppedLines).toEqual([
      { file: 'x.env', line: 1, reason: 'not-an-assignment' },
      { file: 'x.env', line: 2, reason: 'unparsed-assignment' },
    ]);
  });

  it('drops a mangled name rather than classifying a secret fragment as plain', () => {
    // The shape that made this a fix rather than a tidy-up: a stray line two
    // lines above a credential makes the credential's own name unmatchable by
    // any rule, so it would have landed in the plain half while the report said
    // nothing was wrapped.
    const { values, unexpectedNames } = parseEnvContent(`A=1\n${CANARY}\nTOKEN=t\n`, 'x.env');

    expect(values).toEqual({ A: '1' });
    expect(unexpectedNames).toBe(1);
    expect(JSON.stringify(values)).not.toContain(CANARY);
  });

  it('keeps an unterminated quote as a raw value when a later line closes it', () => {
    const { values } = parseEnvContent('K="unterminated\nB=2\n', 'x.env');

    expect(values).toEqual({ K: '"unterminated', B: '2' });
  });

  it('invents a second key from a quoted value containing =, and it is dropped', () => {
    const { values, unexpectedNames } = parseEnvContent(`A="x=${CANARY}"\n`, 'x.env');

    expect(values['A']).toBe(`x=${CANARY}`);
    // `util.parseEnv` also returns a key named `"x` whose value is a slice of
    // A's value. The name starts with a quote, which no exporter can set, so
    // the wrapper drops it and reports it only as a count.
    expect(Object.keys(values)).toEqual(['A']);
    expect(unexpectedNames).toBe(1);
  });
});

describe('the dropped-line report', () => {
  it('reports a non-assignment line, and the variable it swallowed', () => {
    const { droppedLines } = parseEnvContent('A=1\nJUSTNAME\nB=2\n', 'x.env');

    // Two entries for one mistake, and both are wanted: line 2 is the stray
    // line, and line 3 is the variable that went missing because of it.
    expect(droppedLines).toEqual([
      { file: 'x.env', line: 2, reason: 'not-an-assignment' },
      { file: 'x.env', line: 3, reason: 'unparsed-assignment' },
    ]);
  });

  it('reports an assignment the parser produced no variable for', () => {
    const { droppedLines } = parseEnvContent('KEY\nB=2\n', 'x.env');

    expect(droppedLines).toEqual([
      { file: 'x.env', line: 1, reason: 'not-an-assignment' },
      { file: 'x.env', line: 2, reason: 'unparsed-assignment' },
    ]);
  });

  it('skips lines inside a quoted continuation rather than counting them', () => {
    const { droppedLines } = parseEnvContent('A="first\nsecond\nthird"\nB=2\n', 'x.env');

    expect(droppedLines).toEqual([]);
  });

  it('does not report a duplicate assignment, because the name did parse', () => {
    expect(parseEnvContent('A=1\nA=2\n', 'x.env').droppedLines).toEqual([]);
  });

  it('skips comments and blank lines', () => {
    expect(parseEnvContent('\n# comment\n\n   \nA=1\n', 'x.env').droppedLines).toEqual([]);
  });

  it('reports positions and never content', () => {
    const { droppedLines } = parseEnvContent(`A=1\n${CANARY}\nB=2\n`, 'x.env');

    expect(JSON.stringify(droppedLines)).not.toContain(CANARY);
    expect(droppedLines).toEqual([
      { file: 'x.env', line: 2, reason: 'not-an-assignment' },
      { file: 'x.env', line: 3, reason: 'unparsed-assignment' },
    ]);
  });

  it('reports an unterminated quote at end of file, by line', () => {
    const { droppedLines } = parseEnvContent(`A=1\nK="${CANARY}\n`, 'x.env');

    expect(droppedLines).toEqual([{ file: 'x.env', line: 2, reason: 'unparsed-assignment' }]);
    expect(JSON.stringify(droppedLines)).not.toContain(CANARY);
  });
});

describe('readEnvFile', () => {
  it('returns undefined for a file that does not exist', () => {
    expect(readEnvFile(join(dir, 'absent.env'))).toBeUndefined();
  });

  it('parses a file that exists', () => {
    const path = file('present.env', 'A=1\nB=2\n');

    expect(readEnvFile(path)?.values).toEqual({ A: '1', B: '2' });
  });

  it('throws with the path and the errno for a file it cannot read', () => {
    const path = file('unreadable.env', `SECRET=${CANARY}\n`);
    chmodSync(path, 0o000);

    let thrown: unknown;
    try {
      readEnvFile(path);
    } catch (error) {
      thrown = error;
    } finally {
      chmodSync(path, 0o600);
    }

    // Running as root defeats the mode, so the case only asserts when the read
    // actually failed. Skipping loudly beats a test that passes for the wrong
    // reason.
    if (thrown === undefined) {
      expect(process.getuid?.()).toBe(0);
      return;
    }

    expect((thrown as Error).message).toContain(path);
    expect((thrown as Error).message).toContain('EACCES');
    expect((thrown as Error).message).not.toContain(CANARY);
    expect((thrown as { cause?: unknown }).cause).toBeUndefined();
  });

  it('throws for a directory rather than treating it as absent', () => {
    expect(() => readEnvFile(dir)).toThrow(/EISDIR/);
  });
});
