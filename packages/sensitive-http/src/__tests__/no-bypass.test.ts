import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

/**
 * Only two modules in this row may produce a raw value.
 *
 * `reveal.ts` and `auth.ts` in the shared package call `reveal()`. Nothing else
 * does, in any of the six packages. That is the property a reviewer needs to be
 * able to check by reading two files rather than sixty, and a source scan is
 * the only thing that keeps it true as the row grows.
 *
 * `serialize()` is on the list for a different reason: its result is the
 * sanctioned wire format between two services that both use this library, so a
 * caller may put one in a body, but no package here should be producing one.
 */

const PACKAGES = [
  'sensitive-http',
  'sensitive-axios',
  'sensitive-got',
  'sensitive-ky',
  'sensitive-fetch',
  'sensitive-undici',
];

const ALLOWED = new Set(['sensitive-http/src/reveal.ts', 'sensitive-http/src/auth.ts']);

const FORBIDDEN = ['.reveal(', '.serialize('];

/**
 * The `packages` directory.
 *
 * Resolved from the working directory rather than from `import.meta.url`,
 * because the repository program type-checks these files against a
 * `NodeNext`/CommonJS-capable target where `import.meta` is not available.
 * Vitest runs from the repository root.
 */
const root = resolve(process.cwd(), 'packages');

function sources(pkg: string): string[] {
  const dir = join(root, pkg, 'src');
  const out: string[] = [];

  const walk = (current: string, prefix: string): void => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const relative = `${prefix}${entry.name}`;

      if (entry.isDirectory()) {
        walk(join(current, entry.name), `${relative}/`);
        continue;
      }

      if (!entry.name.endsWith('.ts') || entry.name.endsWith('.test.ts')) {
        continue;
      }

      // Fixtures and the recording server are test scaffolding, not shipped
      // surface, and the harness has to build canaries.
      if (relative.startsWith('__tests__/') || entry.name === 'testing.ts') {
        continue;
      }

      out.push(`${pkg}/src/${relative}`);
    }
  };

  walk(dir, '');

  return out;
}

describe('no bypass', () => {
  it('finds sources to scan, so a broken path fails loudly rather than passing', () => {
    expect(PACKAGES.flatMap(sources).length).toBeGreaterThan(20);
  });

  it.each(PACKAGES)('%s produces a raw value only in reveal.ts and auth.ts', (pkg) => {
    const offenders: string[] = [];

    for (const file of sources(pkg)) {
      if (ALLOWED.has(file)) {
        continue;
      }

      const text = readFileSync(join(root, file), 'utf8');

      for (const needle of FORBIDDEN) {
        if (text.includes(needle)) {
          offenders.push(`${file} calls ${needle}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });
});
