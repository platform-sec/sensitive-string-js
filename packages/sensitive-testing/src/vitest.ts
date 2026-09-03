/* eslint-disable @typescript-eslint/no-empty-interface, @typescript-eslint/no-explicit-any */
import type { Assertion as VitestAssertion, expect as vitestExpect } from 'vitest';
import type { SensitiveMatchers } from './matchers.js';
import type { SnapshotSerializerPlugin } from './serializer.js';

/**
 * Ready-made Vitest type augmentation.
 *
 * Import it once, from a setup file or from a `.d.ts` in the consuming project:
 *
 * ```ts
 * import '@platform-sec/sensitive-string-testing/vitest';
 * ```
 *
 * Registering the matchers is separate and still required; see
 * `setupSensitiveMatchers`. This module only teaches TypeScript about them, and
 * emits nothing at runtime.
 *
 * The type parameter list has to match Vitest's own declaration exactly for the
 * interfaces to merge, which is where `T = any` comes from.
 *
 * @packageDocumentation
 */
declare module 'vitest' {
  interface Assertion<T = any> extends SensitiveMatchers<T> {}
  interface AsymmetricMatchersContaining extends SensitiveMatchers {}
}

/**
 * Vitest's assertion type, re-exported.
 *
 * The re-export is what puts Vitest's own declarations into the program. Under
 * CommonJS resolution, `vitest` resolves to a re-export barrel that carries no
 * declarations of its own, and an augmentation of a module nothing else pulls
 * in fails to resolve. A consumer whose project is CommonJS therefore needs
 * this import as much as this package's own build does.
 */
export type SensitiveAssertion<T> = VitestAssertion<T>;

/**
 * The plugin type Vitest's `expect.addSnapshotSerializer` accepts, which is
 * `pretty-format`'s own.
 */
type VitestSnapshotSerializer = Parameters<typeof vitestExpect.addSnapshotSerializer>[0];

/** Fails to compile unless `T` is `true`. */
type Assert<T extends true> = T;

/**
 * A compile-time proof that `sensitiveSerializer` is the shape Vitest accepts.
 *
 * `SnapshotSerializerPlugin` is declared structurally in `serializer.ts` rather
 * than imported from `pretty-format`, which is what keeps this package free of
 * a dependency on a test framework. The cost of writing a type out by hand is
 * that it can drift from the one it is meant to match, and nothing would say
 * so: the test suite runs through esbuild, which strips types without checking
 * them, so a serializer Vitest rejects would still pass every test in this
 * repository. This alias is checked by `tsc` during the build, so the drift is
 * a failed build instead.
 */
export type SensitiveSerializerFitsVitest = Assert<
  SnapshotSerializerPlugin extends VitestSnapshotSerializer ? true : false
>;
