/**
 * The release allowlist: the packages that may be on npm.
 *
 * The list is cumulative. A package joins it in the wave that first publishes
 * it and stays on it afterwards, so "allowlisted" means "released or releasing
 * now" and never "releasing this time only". That is what lets the closure rule
 * below be checked offline: a package's internal runtime dependencies must be
 * on the list too, because a published package whose peer was never published
 * cannot be installed.
 *
 * A package that is not named is held. Changesets still versions it and still
 * rewrites its internal ranges, so it stays release-consistent on `main`; the
 * release workflow only declines to publish it.
 */
import { readFile } from 'node:fs/promises';
import path from 'node:path';

export const allowlistFilename = 'release-allowlist.json';

const runtimeDependencyFields = ['dependencies', 'optionalDependencies', 'peerDependencies'];

/**
 * Read and shape-check the allowlist. A missing or malformed file is an error,
 * never an empty list: the safe reading of "no list" is "publish nothing", and
 * the caller should hear about it rather than receive that silently.
 */
export async function readAllowlist(repoRoot, filename = allowlistFilename) {
  const absolute = path.resolve(repoRoot, filename);
  let document;
  try {
    document = JSON.parse(await readFile(absolute, 'utf8'));
  } catch (error) {
    throw new Error(`cannot read release allowlist ${filename}: ${error.message}`);
  }

  if (
    document === null ||
    typeof document !== 'object' ||
    !Array.isArray(document.packages) ||
    !document.packages.every((name) => typeof name === 'string' && name.length > 0)
  ) {
    throw new Error(`${filename} must be an object whose "packages" is an array of package names`);
  }

  return document.packages;
}

/**
 * Check the allowlist against the workspace. Returns problem strings in the
 * same form as the other release checks.
 */
export function checkAllowlist(names, packagesByName, filename = allowlistFilename) {
  const problems = [];
  const seen = new Set();

  for (const name of names) {
    if (seen.has(name)) problems.push(`${filename} names ${name} more than once`);
    seen.add(name);

    const pkg = packagesByName.get(name);
    if (pkg === undefined) {
      problems.push(`${filename} names ${name}, which is not a workspace package`);
    } else if (pkg.manifest.private === true) {
      problems.push(`${filename} names ${name}, which is private`);
    }
  }

  for (const name of seen) {
    const pkg = packagesByName.get(name);
    if (pkg === undefined) continue;

    for (const field of runtimeDependencyFields) {
      for (const dependencyName of Object.keys(pkg.manifest[field] ?? {})) {
        if (!packagesByName.has(dependencyName)) continue;
        if (!seen.has(dependencyName)) {
          problems.push(
            `${filename} names ${name} but not its ${field} entry ${dependencyName}, so ` +
              `${name} could be published depending on a package that never is`
          );
        }
      }
    }
  }

  return problems;
}
