/* eslint-disable @typescript-eslint/no-empty-interface, @typescript-eslint/no-explicit-any */
import type { Assertion as VitestAssertion } from 'vitest';
import type { SensitiveMatchers } from './matchers.js';

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
