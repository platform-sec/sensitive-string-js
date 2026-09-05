import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { COVERED_SEAMS, EXCLUDED_SEAMS } from '../install.js';

/**
 * The seam inventory, checked against the declarations `rollbar` ships.
 *
 * The other vendor packages do this at the type level with `expectTypeOf`,
 * which is worth more because it fails at `pnpm typecheck` rather than at
 * `pnpm test`. That does not work here: `keyof Rollbar.Configuration` widens to
 * `string` in this program, so a mapped type over it yields `string` too and
 * every check against it passes vacuously. A check that cannot fail is worse
 * than one that fails late.
 *
 * So this reads the shipped `index.d.ts` and finds every option in
 * `interface Configuration` whose declared type is a function, which is the
 * form the design's section 2.5 describes for this vendor. A new callback
 * option in a future release fails here with its name in the message.
 */
/**
 * The shipped declarations.
 *
 * Read from the installed path rather than resolved as a module specifier, for
 * two reasons. `rollbar`'s `exports` map does not publish `./index.d.ts` as a
 * subpath, so a deep import of it fails even though the file is right there.
 * And `import.meta` is unavailable in this program, which type-checks these
 * files against a CommonJS-capable target, so there is no module URL to resolve
 * relative to. Vitest runs from the repository root.
 */
const DECLARATIONS = resolve(
  process.cwd(),
  'packages/sensitive-rollbar/node_modules/rollbar/index.d.ts'
);

function readDeclarations(): string {
  return readFileSync(DECLARATIONS, 'utf8');
}

/** Every option in `interface Configuration` whose type is a function. */
function callbackOptions(declarations: string): string[] {
  const start = declarations.indexOf('export interface Configuration {');

  if (start === -1) {
    throw new Error('the shipped declarations no longer declare interface Configuration');
  }

  // The interface ends at the first line that closes it at its own indent,
  // which for this file is two spaces. Nested object literals in the body are
  // indented further, so they do not terminate the slice.
  const end = declarations.indexOf('\n  }', start);
  const body = declarations.slice(start, end === -1 ? undefined : end);

  const found: string[] = [];

  // `name?: ( ... ) => ...;`, with the parameter list allowed to run onto the
  // following lines, which several of them do. The arrow is what tells a
  // function type from a parenthesised union: `ignoredMessages?: (string |
  // RegExp)[]` opens the same way and is not a seam.
  for (const match of body.matchAll(/^ {4}(\w+)\?:\s*\(([^;]*?)\)\s*=>/gm)) {
    const name = match[1];

    if (name !== undefined) {
      found.push(name);
    }
  }

  return found;
}

describe('seam inventory', () => {
  const declared = callbackOptions(readDeclarations());

  // TEST-ROLLBAR-SEAMS
  it('accounts for every callback option the SDK declares', () => {
    const accounted = new Set<string>([...COVERED_SEAMS, ...EXCLUDED_SEAMS]);
    const unaccounted = declared.filter((name) => !accounted.has(name));

    expect(unaccounted, 'a callback option this package neither composes nor excuses').toEqual([]);
  });

  it('names no option the SDK does not declare', () => {
    const present = new Set(declared);
    const phantom = [...COVERED_SEAMS, ...EXCLUDED_SEAMS].filter((name) => !present.has(name));

    expect(phantom, 'a seam this package claims and the SDK has removed').toEqual([]);
  });

  it('actually finds the options it is checking, so an empty pass is impossible', () => {
    // The reason this file needs a self-check and the `expectTypeOf` ones do
    // not: a regular expression over a declaration file can silently match
    // nothing after a formatting change, and the two assertions above would
    // both pass on an empty list.
    expect(declared).toContain('transform');
    expect(declared).toContain('checkIgnore');
    expect(declared.length).toBeGreaterThanOrEqual(COVERED_SEAMS.length + EXCLUDED_SEAMS.length);
  });
});
