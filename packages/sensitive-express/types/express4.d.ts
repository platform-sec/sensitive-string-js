/**
 * Typings for the `express4` alias in devDependencies, which resolves to
 * Express 4 alongside the Express 5 the rest of the suite runs on.
 *
 * The alias carries no typings of its own, and `@types/express` describes only
 * the package named `express`. The middleware surface this package touches is
 * identical across the two majors, so pointing the alias at the same types is
 * accurate for what the smoke test does with it.
 *
 * It lives outside `src` on purpose. `.gitignore` excludes every declaration
 * file under a package's `src`, so that generated declarations stay out of the
 * tree, and `pnpm clean` deletes them; a hand-written one in `src` would be
 * untracked and then silently removed on the next clean. The package's build
 * tsconfig includes only `src`, so nothing here reaches the published `dist`
 * either.
 */
declare module 'express4' {
  import type express from 'express';

  const factory: typeof express;

  export = factory;
}

declare module 'express4/package.json' {
  const manifest: { version: string };

  export = manifest;
}
