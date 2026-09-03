import { defineConfig } from 'vitest/config';

/**
 * Timing analysis, run with `pnpm test:timing`.
 *
 * Separate from the default suite because these tests measure the wall clock:
 * their verdict depends on what else the machine is doing, so they inform a
 * developer rather than gate a release. They run single threaded, so the
 * measurement does not compete with another test file for a core.
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['packages/*/src/**/*.timing.test.ts'],
    testTimeout: 120000,
    pool: 'forks',
    poolOptions: {
      forks: { singleFork: true },
    },
  },
});
