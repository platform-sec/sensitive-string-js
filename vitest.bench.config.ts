import { defineConfig } from 'vitest/config';

/**
 * Performance benchmarks, run with `pnpm bench`.
 *
 * Separate from the default suite for the same reason the timing analysis is:
 * these measure the wall clock, so their numbers describe the machine that
 * produced them as much as the code, and a release must not hang on one. They
 * inform a developer about the cost of an operation and about the gap between
 * two operations, which is the part that survives being measured on a busy
 * laptop.
 *
 * Files run one at a time, so a benchmark is not competing with another file
 * for a core while it is being timed. `fileParallelism: false` is the Vitest 4
 * spelling of that; it overrides `maxWorkers` to 1 on its own.
 *
 * Benchmarks are grouped so that the members of a `describe` are worth
 * comparing against each other. Vitest ranks within a group and prints the
 * slowest as a multiple of the fastest, and that ratio holds up far better
 * across machines than any absolute figure does.
 *
 * `vitest bench --outputJson <file>` records a run, and `--compare <file>`
 * reports a later run against it, which is the way to use these for a
 * before-and-after on one machine.
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    benchmark: {
      include: ['packages/*/src/**/*.bench.ts'],
      exclude: ['**/node_modules/**', '**/dist/**'],
    },
    fileParallelism: false,
  },
});
