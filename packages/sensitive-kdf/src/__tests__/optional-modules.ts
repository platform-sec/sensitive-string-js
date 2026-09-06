import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

/**
 * Whether an optional native module is actually loadable.
 *
 * `argon2` and `bcrypt` are devDependencies here, so normally both are
 * present and every test runs. They are still checked, because
 * `pnpm install --ignore-scripts` leaves the native binding unbuilt and a
 * suite that fails on a deliberate install choice is a suite people stop
 * running.
 *
 * Synchronous on purpose. The alternative is a top-level `await`, which the
 * CommonJS build these files typecheck under does not allow, and the answer
 * has to exist at collection time for `describe.skipIf`.
 */
const packageRoot = join(process.cwd(), 'packages', 'sensitive-kdf');

if (!existsSync(join(packageRoot, 'package.json'))) {
  // Loudly, rather than by reporting both modules as missing and skipping
  // most of the suite, which is the failure mode this whole file exists to
  // avoid.
  throw new Error(
    `The kdf tests resolve optional modules from ${packageRoot}, which does not exist. ` +
      'Run them from the repository root.'
  );
}

const requireFromPackage = createRequire(join(packageRoot, 'package.json'));

export function moduleInstalled(specifier: string): boolean {
  try {
    requireFromPackage(specifier);
    return true;
  } catch {
    return false;
  }
}

export const hasArgon2 = moduleInstalled('argon2');
export const hasBcrypt = moduleInstalled('bcrypt');
