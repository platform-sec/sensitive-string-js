import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { findCoreImports } from '../testing.js';

/**
 * Invariant 12: nothing in these packages reveals.
 *
 * The import surface is what makes that checkable. A grep for `reveal` cannot
 * tell `SensitiveString.prototype.map` from `Array.prototype.map`, and a
 * scrubbing package that reaches a raw value has inverted its own purpose, so
 * the check is on what comes in rather than on what is called.
 *
 * `SensitivityClass` is the only type on the list; the rest are the four
 * values the walk needs. A new name here is a deliberate decision and this
 * test is where it gets made.
 */
const ALLOWED = new Set([
  'SensitiveString',
  'redactCopy',
  'containsSensitive',
  'sensitiveClassesIn',
  'SensitivityClass',
]);

const PACKAGES = ['sensitive-scrub', 'sensitive-sentry'];

/**
 * The `packages` directory.
 *
 * Resolved from the working directory rather than from `import.meta.url`,
 * because the repository program type-checks these files against a
 * `NodeNext`/CommonJS-capable target where `import.meta` is not available.
 * Vitest runs from the repository root.
 */
const packagesDir = resolve(process.cwd(), 'packages');

describe('core import surface', () => {
  for (const name of PACKAGES) {
    // TEST-SCRUB-IMPORTS
    it(`${name} imports only what the invariant allows`, () => {
      const imports = findCoreImports(`${packagesDir}/${name}/src`);
      const offending = imports.filter((entry) => !ALLOWED.has(entry.name));

      expect(
        offending.map((entry) => `${entry.file}: ${entry.name}`),
        'a name outside the allowed set reached shipped source'
      ).toEqual([]);
    });
  }

  it('actually finds the imports it is checking, so an empty pass is impossible', () => {
    const imports = findCoreImports(`${packagesDir}/sensitive-scrub/src`);

    expect(imports.map((entry) => entry.name)).toContain('redactCopy');
    expect(imports.map((entry) => entry.name)).toContain('SensitiveString');
  });

  it('skips tests, which may import what shipped source may not', () => {
    const imports = findCoreImports(`${packagesDir}/sensitive-sentry/src`);

    // The Sentry suite imports redactInStructure to pin how it corrupts a
    // shared reference. That is a test doing its job and reaches no artifact.
    expect(imports.map((entry) => entry.name)).not.toContain('redactInStructure');
  });
});
