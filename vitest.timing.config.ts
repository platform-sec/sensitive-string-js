import { defineConfig } from 'vitest/config';

/**
 * Timing analysis, run with `pnpm test:timing`.
 *
 * Separate from the default suite because these tests measure the wall clock:
 * their verdict depends on what else the machine is doing, so they inform a
 * developer rather than gate a release.
 *
 * Files run one at a time, so a measurement does not compete with another test
 * file for a core. That is load bearing rather than decorative: two files match
 * the include glob, the core comparison analysis and the fastify wrapping one,
 * and running them together is the interference the core file's noise floor is
 * built to detect.
 *
 * `fileParallelism: false` is how Vitest 4 spells it. It replaces the
 * `poolOptions.forks.singleFork` this config used to carry, which Vitest 4
 * removed: the option was accepted and ignored, so the two files had been
 * running in parallel while the config said they did not.
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['packages/*/src/**/*.timing.test.ts'],
    testTimeout: 120000,
    pool: 'forks',
    fileParallelism: false,
  },
});
