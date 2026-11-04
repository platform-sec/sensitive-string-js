import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseEnv } from 'node:util';

import { describe, it, expect, beforeAll, afterAll } from 'vitest';

import { parseEnvContent, readEnvFile, reportParsedEnv } from './parse.js';

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
 * Whether this process's `util.parseEnv` folds a line with no `=` into the
 * next line's name, asked of the parser rather than read off the version.
 *
 * Node 22.16.0 rewrote the parser, and before that the shape moved between
 * patch releases. Measured: 22.12.0 to 22.15.0 and 23.0.0 to 23.11.0 all
 * swallow, so a version check of the form "22.16 or later" is wrong for the
 * whole of 23. Within the swallowing releases the rest differs: which of them
 * invent a name from `A="x=y"`, keep a last-line comment, drop an unterminated
 * quote after another line, or let a whitespace-only line swallow the next name
 * is a patch-level detail. 22.16.0, 22.23.3 and 24.19.0 do none of it.
 *
 * So the pins against the real parser hold only what every parser of a shape
 * agrees on, and the filter that cleans up after the swallowing parsers is
 * tested with their recorded output, on every runtime, below.
 */
const SWALLOWING_PARSER = !Object.hasOwn(parseEnv('KEY\nB=2\n'), 'B');

/**
 * The `util.parseEnv` table.
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
    ['A = 1', { A: '1' }, 'whitespace around = is tolerated'],
    ['# a comment\nA=1', { A: '1' }, 'comments are skipped'],
    ['A=b # trailing\nB=2\n', { A: 'b', B: '2' }, 'a trailing comment is stripped'],
    ['A.B=1', { 'A.B': '1' }, 'a dot in a name is just a character'],
    ['A=1\r\nB=2', { A: '1', B: '2' }, 'CRLF is handled'],
    ['K="unterminated\nB=2\n', { K: '"unterminated', B: '2' }, 'an unclosed quote keeps its quote'],
  ] as ReadonlyArray<[string, Record<string, string>, string]>)('parses %j', (input, expected) => {
    expect(parseEnvContent(input, 'x.env').values).toEqual(expected);
  });

  // What every parser of this process's shape agrees on. Before the rewrite the
  // last line keeps everything after a `#` on some releases and not others, so
  // that row is pinned only for the rewritten parser.
  it.each(
    SWALLOWING_PARSER
      ? ([
          ['K="unterminated', {}, 'an unterminated quote at end of file is dropped'],
          ['KEY\nB=2\n', {}, 'a stray line takes the next name, and the filter drops it'],
        ] as ReadonlyArray<[string, Record<string, string>, string]>)
      : ([
          ['K="unterminated', { K: '"unterminated' }, 'an unterminated quote is kept'],
          ['KEY\nB=2\n', { B: '2' }, 'a stray line is dropped on its own'],
          ['A="x=y"\n', { A: 'x=y' }, 'a quoted = invents no second name'],
          ['A=b # trailing\n', { A: 'b' }, 'the last line loses its comment'],
          ['A=b # trailing', { A: 'b' }, 'and so does an unterminated one'],
        ] as ReadonlyArray<[string, Record<string, string>, string]>)
  )('parses %j, which depends on the parser', (input, expected) => {
    expect(parseEnvContent(input, 'x.env').values).toEqual(expected);
  });

  it('never throws, whatever it is given', () => {
    const hostile = ['', '=', '===', '\0\0', 'a'.repeat(10_000), '"'.repeat(500), '\n'.repeat(500)];

    for (const input of hostile) {
      expect(() => parseEnvContent(input, 'x.env')).not.toThrow();
    }
  });

  it('drops a control character in a name on every parser, and reports the line', () => {
    // The one impossible name every supported parser produces, so the filter
    // and the report are exercised against the real parser wherever this runs.
    const { values, unexpectedNames, droppedLines } = parseEnvContent(
      `A\tTOKEN=${CANARY}\n`,
      'x.env'
    );

    expect(values).toEqual({});
    expect(unexpectedNames).toBe(1);
    expect(droppedLines).toEqual([{ file: 'x.env', line: 1, reason: 'unparsed-assignment' }]);
    expect(JSON.stringify({ values, droppedLines })).not.toContain(CANARY);
  });

  it.runIf(!SWALLOWING_PARSER)('keeps the variable after a stray line', () => {
    const { values, unexpectedNames, droppedLines } = parseEnvContent(
      `A=1\n${CANARY}\nTOKEN=t\n`,
      'x.env'
    );

    // The credential keeps its own name, so a rule anchored on it still
    // matches. The stray line is still reported, by number.
    expect(values).toEqual({ A: '1', TOKEN: 't' });
    expect(unexpectedNames).toBe(0);
    expect(droppedLines).toEqual([{ file: 'x.env', line: 2, reason: 'not-an-assignment' }]);
    expect(JSON.stringify({ values, droppedLines })).not.toContain(CANARY);
  });

  it.runIf(!SWALLOWING_PARSER)('keeps an unterminated quote at end of file as a value', () => {
    const { values, droppedLines } = parseEnvContent(`A=1\nK="${CANARY}\n`, 'x.env');

    // Nothing is dropped, so nothing is reported. The value carries the
    // opening quote, which surfaces as a wrong value rather than a missing one.
    expect(values['K']).toBe(`"${CANARY}`);
    expect(droppedLines).toEqual([]);
  });
});

/**
 * The filter, fed what the swallowing parsers returned.
 *
 * Every input here is a recorded `util.parseEnv` result, with the releases that
 * produced it. They run on every runtime, because CI's runtimes have the
 * rewritten parser and would otherwise never hand the filter a name to drop.
 */
describe('the filter over a swallowing parser', () => {
  it("drops the name a line with no = builds out of the next line's", () => {
    // 22.12.0 to 22.15.0, 23.0.0 to 23.11.0. A newline in a variable name is
    // impossible through every real exporter, so the name is dropped. Either
    // way `B` is gone. The difference is that the mangled name does not become
    // an unclassified variable holding part of a value.
    const { values, unexpectedNames, droppedLines } = reportParsedEnv(
      { 'KEY\nB': '2' },
      'KEY\nB=2\n',
      'x.env'
    );

    expect(values).toEqual({});
    expect(unexpectedNames).toBe(1);
    // Two entries for one mistake, and both are wanted: line 1 is the stray
    // line, and line 2 is the variable that went missing because of it.
    expect(droppedLines).toEqual([
      { file: 'x.env', line: 1, reason: 'not-an-assignment' },
      { file: 'x.env', line: 2, reason: 'unparsed-assignment' },
    ]);
  });

  it('drops a mangled name rather than classifying a secret fragment as plain', () => {
    // The shape that made this a fix rather than a tidy-up: a stray line above
    // a credential makes the credential's own name unmatchable by any rule, so
    // it would have landed in the plain half while the report said nothing was
    // wrapped. Same releases as above.
    const { values, unexpectedNames, droppedLines } = reportParsedEnv(
      { A: '1', [`${CANARY}\nTOKEN`]: 't' },
      `A=1\n${CANARY}\nTOKEN=t\n`,
      'x.env'
    );

    expect(values).toEqual({ A: '1' });
    expect(unexpectedNames).toBe(1);
    expect(droppedLines).toEqual([
      { file: 'x.env', line: 2, reason: 'not-an-assignment' },
      { file: 'x.env', line: 3, reason: 'unparsed-assignment' },
    ]);
    expect(JSON.stringify({ values, droppedLines })).not.toContain(CANARY);
  });

  it('drops a second name invented from a quoted value containing =', () => {
    // 22.15.0 and 23.11.0 with a trailing newline, and 22.13.0 and 22.14.0
    // without one. The invented name starts with a quote, which no exporter
    // can set, and its value is a slice of A's, so it is reported only as a
    // count.
    const { values, unexpectedNames } = reportParsedEnv(
      { A: `x=${CANARY}`, '"x': `${CANARY}"` },
      `A="x=${CANARY}"\n`,
      'x.env'
    );

    expect(values).toEqual({ A: `x=${CANARY}` });
    expect(unexpectedNames).toBe(1);
  });

  it('drops a name a whitespace-only line swallowed', () => {
    // 22.12.0 to 22.14.0 and 23.0.0. The blank line is not reported, because
    // the scanner skips it, but the variable it took is.
    const { values, unexpectedNames, droppedLines } = reportParsedEnv(
      { '\nA': '1' },
      '\n# comment\n\n   \nA=1\n',
      'x.env'
    );

    expect(values).toEqual({});
    expect(unexpectedNames).toBe(1);
    expect(droppedLines).toEqual([{ file: 'x.env', line: 5, reason: 'unparsed-assignment' }]);
  });

  it('reports an unterminated quote at end of file that the parser dropped, by line', () => {
    // 22.15.0 and 23.11.0.
    const { droppedLines } = reportParsedEnv({ A: '1' }, `A=1\nK="${CANARY}\n`, 'x.env');

    expect(droppedLines).toEqual([{ file: 'x.env', line: 2, reason: 'unparsed-assignment' }]);
    expect(JSON.stringify(droppedLines)).not.toContain(CANARY);
  });
});

describe('the dropped-line report', () => {
  it('reports a stray line, and on a swallowing parser the variable it took', () => {
    const { droppedLines } = parseEnvContent(`A=1\n${CANARY}\nB=2\n`, 'x.env');

    expect(JSON.stringify(droppedLines)).not.toContain(CANARY);
    expect(droppedLines).toEqual([
      { file: 'x.env', line: 2, reason: 'not-an-assignment' },
      ...(SWALLOWING_PARSER ? [{ file: 'x.env', line: 3, reason: 'unparsed-assignment' }] : []),
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
    // Through the filter with a clean parse, because some swallowing parsers
    // fold a whitespace-only line into the next name. That case is above.
    expect(reportParsedEnv({ A: '1' }, '\n# comment\n\n   \nA=1\n', 'x.env').droppedLines).toEqual(
      []
    );
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
