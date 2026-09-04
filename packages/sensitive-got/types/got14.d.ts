/**
 * Typings for the `got14` alias in devDependencies, which resolves to got 14
 * alongside the got 16 the rest of the suite runs on.
 *
 * The alias carries no typings of its own, and got's own declarations describe
 * only the package named `got`. The surface this package touches, the callable
 * instance plus `extend`, `defaults.options.prefixUrl` and the hooks, is the
 * same shape across the two majors, so pointing the alias at got 16's types is
 * accurate for what the compatibility test does with it.
 *
 * It lives outside `src` on purpose, matching `sensitive-express`: `.gitignore`
 * excludes every declaration file under a package's `src` so that generated
 * declarations stay out of the tree, and `pnpm clean` deletes them, so a
 * hand-written one there would be untracked and then silently removed. The
 * build tsconfig includes only `src`, so nothing here reaches `dist` either.
 */
declare module 'got14' {
  import type { Got } from 'got';

  const got: Got;

  export default got;
}
