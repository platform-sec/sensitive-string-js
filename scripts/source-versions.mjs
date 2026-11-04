#!/usr/bin/env node
/**
 * Keep the package versions written into source in step with the manifests.
 *
 * The ESLint plugin declares `meta.version` by hand, because importing its
 * `package.json` from `src` would pull a file outside `rootDir` into the build.
 * `changeset version` rewrites the manifest and knows nothing about the source
 * file, so a Version Packages pull request ships the old version in
 * `meta` until something notices. The first one did exactly that, and only the
 * plugin's own test caught it: ESLint reads the field in its config inspector
 * and in the cache key it derives, both of them quiet failures.
 *
 * `pnpm release:version` runs this with `--write` straight after
 * `changeset version`, and `pnpm release:check` runs the same comparison
 * without writing, so a hand edit to either side fails the check.
 */
import { realpathSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Every source file that states its own package's version.
 *
 * `pattern` must match exactly once, and its single capture group is the
 * version. Matching more than once means the file grew a second declaration
 * that the pattern cannot tell apart from the first, and that is refused rather
 * than guessed at.
 */
export const sourceVersionTargets = [
  {
    packageDir: 'packages/sensitive-eslint-plugin',
    file: 'src/index.ts',
    pattern: /(?<=export const meta = \{\n\s+name: '[^']+',\n\s+version: ')([^']+)(?=')/g,
  },
];

async function inspect(repoRoot, target) {
  const manifestPath = path.join(repoRoot, target.packageDir, 'package.json');
  const sourcePath = path.join(repoRoot, target.packageDir, target.file);
  const { name, version } = JSON.parse(await readFile(manifestPath, 'utf8'));
  const source = await readFile(sourcePath, 'utf8');
  const matches = [...source.matchAll(target.pattern)];
  const relative = path.join(target.packageDir, target.file);

  if (matches.length !== 1) {
    return {
      problem: `${relative} must declare ${name}'s version exactly once; found ${matches.length}`,
    };
  }

  return { name, version, source, sourcePath, relative, declared: matches[0][1] };
}

/** One problem per source file whose declared version is not its manifest's. */
export async function checkSourceVersions(repoRoot) {
  const problems = [];

  for (const target of sourceVersionTargets) {
    const result = await inspect(repoRoot, target);
    if (result.problem !== undefined) {
      problems.push(result.problem);
    } else if (result.declared !== result.version) {
      problems.push(
        `${result.relative} declares ${result.name}@${result.declared}, but its manifest is at ` +
          `${result.version}; run node scripts/source-versions.mjs --write`
      );
    }
  }

  return problems;
}

/** Rewrite every declared version to its manifest's. Returns what changed. */
export async function writeSourceVersions(repoRoot) {
  const changed = [];

  for (const target of sourceVersionTargets) {
    const result = await inspect(repoRoot, target);
    if (result.problem !== undefined) {
      throw new Error(result.problem);
    }
    if (result.declared === result.version) continue;

    await writeFile(result.sourcePath, result.source.replace(target.pattern, result.version));
    changed.push(`${result.relative}: ${result.declared} -> ${result.version}`);
  }

  return changed;
}

// Compared through `realpathSync`, because `import.meta.url` is already
// resolved: run through a symlinked path, a plain comparison would skip the
// body and exit 0 having written nothing.
if (
  process.argv[1] !== undefined &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const repoRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));

  if (process.argv.includes('--write')) {
    const changed = await writeSourceVersions(repoRoot);
    for (const line of changed) console.log(`wrote ${line}`);
    if (changed.length === 0) console.log('ok    every source version matches its manifest');
  } else {
    const problems = await checkSourceVersions(repoRoot);
    for (const problem of problems) console.error(`FAIL  ${problem}`);
    if (problems.length > 0) process.exitCode = 1;
    else console.log('ok    every source version matches its manifest');
  }
}
