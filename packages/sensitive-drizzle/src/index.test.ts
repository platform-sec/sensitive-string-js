import { access } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import * as index from './index.js';

const exists = (at: string): Promise<boolean> =>
  access(at).then(
    () => true,
    () => false
  );

describe('the public surface', () => {
  it('exports everything the README uses', () => {
    for (const name of [
      'sensitiveLogger',
      'checkSchema',
      'classifiedColumns',
      'classificationOf',
      'sanitizeQueryError',
      'hydrateRawRows',
      'drizzleScrubFragment',
      'assertParametersSafe',
      'touchesClassifiedColumn',
      'redactParameters',
      'loggerBrand',
      'containsRedactionMarker',
      'redactionMatchers',
      'resetRedactionMarkerCache',
    ]) {
      expect(index).toHaveProperty(name);
    }
  });

  it('exports every error class, and each carries a code', () => {
    const errors = [
      index.DrizzleCacheRefusedError,
      index.DrizzleConfigError,
      index.DrizzleDriftError,
      index.DrizzleGuardMissingError,
      index.DrizzleMarkerReadError,
      index.DrizzleParameterRefusedError,
      index.DrizzleWriteRefusedError,
    ];
    for (const Ctor of errors) expect(typeof Ctor).toBe('function');
    expect(new index.DrizzleConfigError('x').code).toBe('DRIZZLE_INVALID_CONFIG');
    expect(new index.DrizzleMarkerReadError('users.email').code).toBe('DRIZZLE_MARKER_IN_COLUMN');
    expect(new index.DrizzleGuardMissingError([]).code).toBe('DRIZZLE_GUARD_MISSING');
    expect(new index.DrizzleCacheRefusedError([], 'X').code).toBe('DRIZZLE_QUERY_CACHE');
    expect(new index.DrizzleDriftError([]).code).toBe('DRIZZLE_SCHEMA_DRIFT');
    expect(new index.DrizzleWriteRefusedError('p', 'x').code).toBe('DRIZZLE_WRITE_REFUSED');
    expect(new index.DrizzleParameterRefusedError(0, 'instance', 's').code).toBe(
      'DRIZZLE_SENSITIVE_PARAMETER'
    );
  });

  it('does not export the column factories, which live in the dialect entry points', () => {
    // A single `sensitiveText` at the root would have to pick a dialect, and
    // importing all three would pull every `drizzle-orm` dialect module into a
    // process that installed one.
    expect(index).not.toHaveProperty('sensitiveText');
    expect(index).not.toHaveProperty('credentialText');
  });

  it('reaches no drizzle-orm module from the root entry point', async () => {
    // The root restates Drizzle's Logger, Column and Table structurally rather
    // than importing them, so it works in a process that installed one dialect
    // and in one that has two copies of the ORM. Only `pg.ts`, `mysql.ts` and
    // `sqlite.ts` import the ORM, and each imports exactly its own dialect.
    const fs = await import('node:fs/promises');
    const path = await import('node:path');
    // Found by walking up from the working directory rather than from
    // `import.meta.url`, which is unavailable here: the package has no
    // `"type": "module"`, so the repository typecheck compiles this file as
    // CommonJS. The suite runs from the workspace root and from the package.
    const SRC = 'packages/sensitive-drizzle/src';
    let here = path.resolve(process.cwd(), SRC);
    for (let up = process.cwd(); !(await exists(here)); up = path.dirname(up)) {
      if (up === path.dirname(up)) throw new Error(`could not locate ${SRC}`);
      here = path.resolve(path.dirname(up), SRC);
    }
    const dialects = new Set(['pg.ts', 'mysql.ts', 'sqlite.ts']);
    const IMPORT = /^\s*(?:import|export)\s[^;]*?from\s+'(drizzle-orm[^']*)'/gm;

    const offenders: string[] = [];
    for (const file of await fs.readdir(here)) {
      if (!file.endsWith('.ts') || file.endsWith('.test.ts') || file.endsWith('.test-d.ts'))
        continue;
      if (dialects.has(file)) continue;
      const source = await fs.readFile(path.join(here, file), 'utf8');
      for (const match of source.matchAll(IMPORT)) offenders.push(`${file} -> ${match[1]}`);
    }
    expect(offenders).toEqual([]);
  });
});
