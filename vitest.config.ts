import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

/**
 * Two projects, because one of the packages needs a different TypeScript
 * transform than the rest of the repository.
 *
 * Vitest compiles TypeScript with esbuild, which implements
 * `experimentalDecorators` but not `emitDecoratorMetadata`. NestJS reads
 * `design:paramtypes` to learn which DTO class a `@Body()` parameter has, and
 * hands that class to a pipe as `ArgumentMetadata.metatype`. Under esbuild the
 * metadata is absent, the metatype arrives as `undefined`, and
 * `SensitiveTransformPipe` has nothing to key off: the suite would pass on a
 * pipe that never wrapped anything. `sensitive-nestjs` therefore compiles
 * through swc, which emits the metadata, matching what `tsc` produces for the
 * published build.
 *
 * The rest of the repository keeps the esbuild path, `sensitive-decorators`
 * included: its decorators are Stage 3, which esbuild implements, and it reads
 * no metadata, so it wants the transform the root `tsconfig.json` describes
 * rather than the legacy one.
 */
const NESTJS_TESTS = 'packages/sensitive-nestjs/src/**/*.test.ts';

const shared = {
  globals: true,
  environment: 'node' as const,
  testTimeout: 10000,
  // Wall clock measurements are opt-in, through `pnpm test:timing`. Their
  // verdict depends on how busy the machine is, which is not something a
  // release should hang on.
  exclude: ['**/node_modules/**', '**/dist/**', '**/*.timing.test.ts'],
};

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          ...shared,
          name: 'default',
          include: ['packages/*/src/**/*.test.ts'],
          exclude: [...shared.exclude, NESTJS_TESTS],
        },
      },
      {
        plugins: [
          swc.vite({
            module: { type: 'es6' },
            jsc: {
              target: 'es2022',
              parser: { syntax: 'typescript', decorators: true },
              transform: { legacyDecorator: true, decoratorMetadata: true },
            },
          }),
        ],
        test: {
          ...shared,
          name: 'nestjs',
          include: [NESTJS_TESTS],
        },
      },
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['packages/*/src/**/*.ts'],
      // Benchmarks are source under `src`, so coverage would count them as
      // uncovered library code. They are measured by `pnpm bench`, never run
      // by `pnpm test`, and ship in no package.
      exclude: ['**/*.test.ts', '**/*.d.ts', '**/__benchmarks__/**'],
    },
  },
});
