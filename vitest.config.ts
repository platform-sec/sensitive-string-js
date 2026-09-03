import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['packages/*/src/**/*.test.ts'],
    // Wall clock measurements are opt-in, through `pnpm test:timing`. Their
    // verdict depends on how busy the machine is, which is not something a
    // release should hang on.
    exclude: ['**/node_modules/**', '**/dist/**', '**/*.timing.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['packages/*/src/**/*.ts'],
      exclude: ['**/*.test.ts', '**/*.d.ts'],
    },
    testTimeout: 10000,
  },
});
