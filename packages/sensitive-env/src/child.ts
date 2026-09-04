import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { RevealContext } from '@platform-sec/sensitive-string-core';

import { ChildEnvRefusedError } from './types.js';
import type { EnvRecord } from './types.js';

/**
 * Handing a credential back out to a child process.
 *
 * Anything assigned into an environment object is coerced with `String()`, so
 * the naive version fails silently and late. Measured on Node 22.15.0:
 *
 * | Path | What arrives |
 * |---|---|
 * | `process.env.API_KEY = wrapped` | `"[REDACTED:credential]"`, typed `string` |
 * | `spawn(cmd, { env: { API_KEY: wrapped } })` | the child reads `[REDACTED:credential]` |
 * | `{ ...process.env }` after either | the marker, copied onward |
 *
 * The parent starts, the child starts, the child authenticates with the literal
 * string `[REDACTED:credential]`, and the first sign is an authentication
 * failure in a process that is not the one holding the bug.
 */

/** The prefix every redaction marker starts with. */
const MARKER = '[REDACTED:';

/**
 * Reveal exactly the named variables into a plain environment object.
 *
 * @param record - The load to read from.
 * @param names - The variables to reveal. Nothing else is included.
 * @param ctx - An explicit audit context. Required, and never taken from the
 *   ambient `AsyncLocalStorage` context: handing a credential to another
 *   process is the kind of reveal that has to name itself.
 *
 * @returns Only what was asked for. It does **not** spread `process.env` into
 *   the result, because the default that spreads is the default that
 *   re-exports every credential the caller just removed to every child the
 *   service starts. Composing is the caller's line:
 *
 * @example
 * ```ts
 * const childEnv = { PATH: process.env.PATH, ...toChildEnv(record, ['DB_PASSWORD'], ctx) };
 * spawn('pg_dump', args, { env: childEnv });
 * ```
 *
 * The child receives a plain string, and the exec-time copy in the child's
 * `/proc/<pid>/environ` is now the child's problem. A package cannot hand a
 * credential to another process without giving it a credential.
 *
 * @throws ChildEnvRefusedError before any of the result is returned, when a
 *   name is in neither map, when no context was supplied, or when a produced
 *   value contains a redaction marker. The marker check is a heuristic: a
 *   genuine secret could contain `[REDACTED:`, and the odds are low enough that
 *   a guard which names the fix earns its place. The error says which variable
 *   and what to do, and never prints the value that tripped it.
 */
export function toChildEnv(
  record: EnvRecord,
  names: readonly string[],
  ctx: RevealContext
): Record<string, string> {
  if (ctx === null || typeof ctx !== 'object') {
    throw new ChildEnvRefusedError(
      'no-context',
      'toChildEnv requires an explicit RevealContext. Revealing a credential for a child ' +
        'process must not inherit an ambient context, because the audit record would not say ' +
        'which process received it.'
    );
  }

  const result: Record<string, string> = Object.create(null) as Record<string, string>;

  for (const name of names) {
    const wrapped = record.fields.get(name);

    if (wrapped !== undefined) {
      result[name] = wrapped.reveal(ctx);
      continue;
    }

    const plain = record.plain.get(name);

    if (plain !== undefined) {
      result[name] = plain;
      continue;
    }

    throw new ChildEnvRefusedError(
      'unknown-name',
      `Cannot build a child environment: '${name}' is in neither the wrapped nor the plain ` +
        `half of the record. Check the name, and check that the load's spec classified it.`,
      name
    );
  }

  // Every value is checked before any of them is returned, so a caller cannot
  // hold a half-built environment whose first entries were fine.
  for (const [name, value] of Object.entries(result)) {
    if (value.includes(MARKER)) {
      throw new ChildEnvRefusedError(
        'marker',
        `Refusing to put '${name}' into a child environment: its value contains a redaction ` +
          `marker, so a SensitiveString was stringified somewhere upstream instead of being ` +
          `revealed. Find the interpolation or assignment that coerced it and use reveal(), or ` +
          `pass the instance to toChildEnv() through the record.`,
        name
      );
    }
  }

  return { ...result };
}

/**
 * Whether a value would be refused by `toChildEnv`.
 *
 * Exported so a caller building an environment by hand can run the same check
 * on the parts this package did not produce.
 */
export function carriesRedactionMarker(value: unknown): boolean {
  if (value instanceof SensitiveString) {
    return true;
  }

  return typeof value === 'string' && value.includes(MARKER);
}
