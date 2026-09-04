import { readFileSync } from 'node:fs';
import { parseEnv } from 'node:util';

import type { DroppedLine } from './types.js';

/**
 * `.env` parsing with no dependency, and a report of what the parser swallowed.
 *
 * `node:util`'s `parseEnv` parses `.env` content into a plain object without
 * touching `process.env`, so this package needs neither a parser nor dotenv.
 *
 * Never throwing is a security property: a parser that does not fail on content
 * cannot put content in an error. It is also a correctness hazard, and a worse
 * one than it looks. Measured on Node 22.15.0:
 *
 * | Input | Result |
 * |---|---|
 * | `export A=1` | `{ A: '1' }`, the `export` prefix stripped |
 * | `B='x\ny'` | `{ B: 'x\ny' }`, multi-line quoted values supported |
 * | `A=1\nA=2` | `{ A: '2' }`, last wins, silently |
 * | `KEY` alone at end of file | `{}`, the line dropped, silently |
 * | `KEY` followed by `B=2` | `{ 'KEY\nB': '2' }`, **`B` is gone** |
 * | `K="unterminated` alone | `{}`, the line dropped, silently |
 * | `K="unterminated` followed by `B=2` | `{ K: '"unterminated', B: '2' }` |
 * | `A="x=y"` | `{ A: 'x=y', '"x': 'y"' }`, **a second key invented from the value** |
 * | `A=b # c` followed by another line | `{ A: 'b' }`, the comment stripped |
 * | `A=b # c` as the last line | `{ A: 'b # c' }`, **the comment kept in the value** |
 * | Anything malformed | Never throws |
 *
 * The fifth row is why the dropped-line report exists rather than being a nice
 * extra: a stray line with no `=` does not lose itself, it eats the name of the
 * variable on the next line, and the service starts with that variable absent.
 *
 * The last-line comment row is not something this package can fix, and it is
 * why the README says to keep comments on their own lines: a credential written
 * as the last line of a `.env` file with a trailing comment silently carries
 * that comment into its value, and the failure surfaces as an authentication
 * error rather than as a parse error.
 *
 * The `A="x=y"` row is why `unexpectedNames` is a count and never a list. A quoted
 * value containing `=` is parsed a second time, and the extra key's *name* is a
 * slice of the *value*, so reporting the name would disclose part of a secret
 * through the very report that exists to avoid that.
 */

/**
 * Characters no exporter can put in a variable name.
 *
 * A control character (`\n` and `\r` above all), `=`, or a quote. Every one of
 * them is impossible through `export`, `docker run -e`, a Kubernetes `env:`
 * entry or a systemd `Environment=`, and every one of them is producible by
 * `util.parseEnv` from a *value*: the swallow case builds a name holding a
 * newline and the whole of the previous line, and the `A="x=y"` case builds a
 * name out of a slice of the value.
 */
// eslint-disable-next-line no-control-regex -- naming the impossible characters is the point
const IMPOSSIBLE_IN_A_NAME = /[\u0000-\u001f\u007f="'`]/;

/** What one `.env` file produced. */
export interface ParsedEnvFile {
  /** The parser's own output. Values are raw strings. */
  readonly values: Readonly<Record<string, string>>;
  /** Lines that produced no variable, by number and never by content. */
  readonly droppedLines: readonly DroppedLine[];
  /**
   * How many names the parser produced that no assignment-looking line
   * declared, plus how many it produced that no exporter could have set.
   *
   * A count, never a list: the second group's *names* are slices of *values*,
   * so listing one would disclose part of a secret through the report that
   * exists to prevent exactly that.
   */
  readonly unexpectedNames: number;
}

/** One assignment-looking line, by the name it declares and where it sits. */
interface Assignment {
  readonly name: string;
  readonly line: number;
}

const QUOTES = new Set(['"', "'", '`']);

/**
 * Scan the source for assignment-looking, non-comment lines.
 *
 * A heuristic, and the package says so. A quoted multi-line value spans lines
 * that are not assignments, so a naive count over-reports; this skips lines
 * inside a quoted continuation, which is enough for the common shapes and is
 * not a second parser. That it is a heuristic is why the result is a warning
 * through `onLoad` rather than a throw: a `.env` file with a stray line should
 * not stop a service that has the variable in its environment anyway, and a
 * heuristic should not be able to stop one at all.
 */
function scanAssignments(content: string): {
  assignments: Assignment[];
  notAssignments: number[];
} {
  const assignments: Assignment[] = [];
  const notAssignments: number[] = [];
  const lines = content.split(/\r?\n/);

  let openQuote: string | undefined;

  for (let index = 0; index < lines.length; index++) {
    const raw = lines[index] ?? '';
    const lineNumber = index + 1;

    if (openQuote !== undefined) {
      if (raw.includes(openQuote)) {
        openQuote = undefined;
      }
      continue;
    }

    const trimmed = raw.trim();
    if (trimmed === '' || trimmed.startsWith('#')) {
      continue;
    }

    const match = /^\s*(?:export\s+)?([^=]+?)\s*=(.*)$/.exec(raw);
    if (match === null) {
      notAssignments.push(lineNumber);
      continue;
    }

    const name = match[1] ?? '';
    const value = (match[2] ?? '').trimStart();
    assignments.push({ name, line: lineNumber });

    const first = value.charAt(0);
    if (QUOTES.has(first) && !value.slice(1).includes(first)) {
      openQuote = first;
    }
  }

  return { assignments, notAssignments };
}

/**
 * Parse `.env` content and report what the parser did not turn into a variable.
 *
 * @param content - The file's text.
 * @param file - The path, used only to label a report. Never read here.
 */
export function parseEnvContent(content: string, file: string): ParsedEnvFile {
  const parsed = parseEnv(content) as Record<string, string>;
  const { assignments, notAssignments } = scanAssignments(content);

  // Drop the names that cannot have come from an assignment. This is not
  // tidiness. A stray line makes `parseEnv` fold it into the *next* variable's
  // name, so `TOKEN=...` two lines below a typo arrives under a name that ends
  // in `TOKEN` but does not match a rule anchored on `_`, and the credential
  // lands in the plain half with the report saying nothing was wrapped. The
  // filter is structural rather than a comparison against the scanned
  // assignments, so a disagreement between the scanner and `parseEnv` can never
  // drop a variable that a real exporter could have set.
  const values: Record<string, string> = {};
  let impossibleNames = 0;

  for (const name of Object.keys(parsed)) {
    if (IMPOSSIBLE_IN_A_NAME.test(name)) {
      impossibleNames++;
      continue;
    }
    values[name] = parsed[name] as string;
  }

  const droppedLines: DroppedLine[] = notAssignments.map((line) => ({
    file,
    line,
    reason: 'not-an-assignment' as const,
  }));

  const declared = new Set<string>();
  for (const assignment of assignments) {
    declared.add(assignment.name);
    if (!Object.hasOwn(values, assignment.name)) {
      droppedLines.push({ file, line: assignment.line, reason: 'unparsed-assignment' });
    }
  }

  let unexpectedNames = impossibleNames;
  for (const name of Object.keys(values)) {
    if (!declared.has(name)) {
      unexpectedNames++;
    }
  }

  droppedLines.sort((a, b) => a.line - b.line);

  return { values, droppedLines, unexpectedNames };
}

/**
 * Read and parse one `.env` file.
 *
 * @returns `undefined` when the file does not exist, which every loader in this
 *   row treats as "not configured" rather than as an error.
 * @throws Error when the file exists and cannot be read. The message carries
 *   the path and the errno and nothing else, and there is no `cause`: the
 *   underlying error is not chained anywhere in this package, so a contributor
 *   who adds one here has to add it deliberately.
 */
export function readEnvFile(file: string): ParsedEnvFile | undefined {
  let content: string;

  try {
    content = readFileSync(file, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException | undefined)?.code;
    if (code === 'ENOENT') {
      return undefined;
    }
    throw new Error(`Cannot read env file '${file}': ${code ?? 'unknown error'}`);
  }

  return parseEnvContent(content, file);
}
