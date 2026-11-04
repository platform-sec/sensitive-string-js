#!/usr/bin/env node
/**
 * Check the invariants that make independent package releases safe.
 *
 * With no arguments this checks package versions, every internal dependency
 * range, and the release allowlist (`release-allowlist.json`, described in
 * `release-allowlist.mjs`). A release workflow can additionally pass a
 * Changesets publish plan, every entry of which must be allowlisted:
 *
 *   pnpm release:check -- --plan path/to/publish-plan.json --require-releases
 *   pnpm release:check -- --plan path/to/publish-plan.json --require-tarballs
 *   pnpm release:check -- --require-no-changesets
 */
import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import semver from 'semver';
import { allowlistFilename, checkAllowlist, readAllowlist } from './release-allowlist.mjs';

const repoRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const packagesDir = path.join(repoRoot, 'packages');
const runtimeDependencyFields = ['dependencies', 'optionalDependencies', 'peerDependencies'];

function parseArguments(argv) {
  const options = {
    plan: null,
    requireReleases: false,
    requireTarballs: false,
    requireNoChangesets: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--') {
      continue;
    } else if (argument === '--plan') {
      options.plan = argv[index + 1] ?? null;
      index += 1;
    } else if (argument === '--require-releases') {
      options.requireReleases = true;
    } else if (argument === '--require-tarballs') {
      options.requireTarballs = true;
    } else if (argument === '--require-no-changesets') {
      options.requireNoChangesets = true;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }

  if (options.requireTarballs && options.plan === null) {
    throw new Error('--require-tarballs requires --plan');
  }

  if (options.requireReleases && options.plan === null) {
    throw new Error('--require-releases requires --plan');
  }

  return options;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function readPackages() {
  const entries = await readdir(packagesDir, { withFileTypes: true });
  const packages = [];

  for (const entry of entries.toSorted((left, right) => left.name.localeCompare(right.name))) {
    if (!entry.isDirectory()) continue;

    const dir = path.join(packagesDir, entry.name);
    const manifestPath = path.join(dir, 'package.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    packages.push({ dir, manifestPath, manifest });
  }

  return packages;
}

function checkPackageGraph(packages) {
  const problems = [];
  const packagesByName = new Map();

  for (const pkg of packages) {
    const { name, version } = pkg.manifest;
    if (typeof name !== 'string' || name.length === 0) {
      problems.push(`${path.relative(repoRoot, pkg.manifestPath)} has no package name`);
      continue;
    }

    if (packagesByName.has(name)) {
      problems.push(`duplicate workspace package name: ${name}`);
    }
    packagesByName.set(name, pkg);

    if (semver.valid(version) === null) {
      problems.push(`${name} has invalid version ${JSON.stringify(version)}`);
    }
  }

  for (const pkg of packages) {
    const name = pkg.manifest.name;

    for (const field of runtimeDependencyFields) {
      for (const [dependencyName, range] of Object.entries(pkg.manifest[field] ?? {})) {
        const dependency = packagesByName.get(dependencyName);
        if (dependency === undefined) continue;

        if (typeof range !== 'string' || semver.validRange(range) === null) {
          problems.push(`${name} has invalid internal ${field} range ${dependencyName}@${range}`);
        } else if (
          !semver.satisfies(dependency.manifest.version, range, { includePrerelease: true })
        ) {
          problems.push(
            `${name} declares ${field} ${dependencyName}@${range}, which excludes the committed ` +
              `workspace version ${dependency.manifest.version}`
          );
        }
      }
    }

    for (const [dependencyName, range] of Object.entries(pkg.manifest.devDependencies ?? {})) {
      if (!packagesByName.has(dependencyName)) continue;
      if (typeof range !== 'string' || !range.startsWith('workspace:')) {
        problems.push(
          `${name} must use the workspace protocol for internal devDependency ` +
            `${dependencyName}; found ${range}`
        );
      }
    }
  }

  return { packagesByName, problems };
}

async function fileExists(filename) {
  try {
    return (await stat(filename)).isFile();
  } catch {
    return false;
  }
}

async function checkPublishPlan(
  planFilename,
  packagesByName,
  allowlisted,
  requireReleases,
  requireTarballs
) {
  const problems = [];
  const absolutePlan = path.resolve(repoRoot, planFilename);
  const planDocument = JSON.parse(await readFile(absolutePlan, 'utf8'));

  if (planDocument.version !== 1 || !Array.isArray(planDocument.plan)) {
    return { entries: [], problems: [`${planFilename} is not a Changesets publish plan v1`] };
  }

  const entries = planDocument.plan.flat();
  const seen = new Set();
  if (requireReleases && entries.length === 0) {
    problems.push('the publish plan contains no releases');
  }

  for (const entry of entries) {
    if (entry === null || typeof entry !== 'object') {
      problems.push('the publish plan contains a non-object entry');
      continue;
    }

    const key = `${entry.name}@${entry.version}`;
    if (seen.has(key)) problems.push(`the publish plan contains ${key} more than once`);
    seen.add(key);

    if (entry.kind !== 'publish' && entry.kind !== 'tag-only') {
      problems.push(`${key} has unknown publish-plan kind ${JSON.stringify(entry.kind)}`);
    }

    const pkg = packagesByName.get(entry.name);
    if (pkg === undefined) {
      problems.push(`${key} is not a workspace package`);
      continue;
    }

    if (!allowlisted.has(entry.name)) {
      problems.push(`${key} is in the publish plan but not in ${allowlistFilename}`);
    }

    if (pkg.manifest.version !== entry.version) {
      problems.push(`${key} does not match the committed manifest version ${pkg.manifest.version}`);
    }

    const changelogPath = path.join(pkg.dir, 'CHANGELOG.md');
    if (!(await fileExists(changelogPath))) {
      problems.push(`${key} has no committed package CHANGELOG.md`);
    } else {
      const changelog = await readFile(changelogPath, 'utf8');
      const heading = new RegExp(`^## ${escapeRegExp(entry.version)}(?:\\s|$)`, 'm');
      if (!heading.test(changelog)) {
        problems.push(`${key} has no ## ${entry.version} entry in its package changelog`);
      }
    }

    if (entry.kind !== 'publish' || !requireTarballs) continue;
    if (entry.tarball === null || typeof entry.tarball !== 'object') {
      problems.push(`${key} has no packed tarball metadata`);
      continue;
    }

    const planDir = path.dirname(absolutePlan);
    const tarballPath = path.resolve(planDir, entry.tarball.path ?? '');
    const relativeTarball = path.relative(planDir, tarballPath);
    if (relativeTarball.startsWith('..') || path.isAbsolute(relativeTarball)) {
      problems.push(`${key} tarball path escapes the pack directory`);
      continue;
    }

    if (!(await fileExists(tarballPath))) {
      problems.push(`${key} tarball does not exist at ${entry.tarball.path}`);
      continue;
    }

    const tarball = await readFile(tarballPath);
    const integrity = `sha256-${createHash('sha256').update(tarball).digest('base64')}`;
    if (entry.tarball.integrity !== integrity) {
      problems.push(`${key} tarball integrity does not match its publish plan`);
    }
  }

  return { entries, problems };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const packages = await readPackages();
  const { packagesByName, problems } = checkPackageGraph(packages);
  const allowlist = await readAllowlist(repoRoot);
  problems.push(...checkAllowlist(allowlist, packagesByName));
  let releaseCount = null;

  if (options.requireNoChangesets) {
    const changesetFiles = await readdir(path.join(repoRoot, '.changeset'));
    const pendingChangesets = changesetFiles.filter(
      (filename) => filename.endsWith('.md') && filename !== 'README.md'
    );
    if (pendingChangesets.length > 0) {
      problems.push(
        `pending changesets must be consumed by the Version Packages pull request: ` +
          pendingChangesets.join(', ')
      );
    }
  }

  if (options.plan !== null) {
    const planResult = await checkPublishPlan(
      options.plan,
      packagesByName,
      new Set(allowlist),
      options.requireReleases,
      options.requireTarballs
    );
    releaseCount = planResult.entries.length;
    problems.push(...planResult.problems);
  }

  if (problems.length > 0) {
    for (const problem of problems) console.error(`FAIL  ${problem}`);
    process.exitCode = 1;
    return;
  }

  const planResult = releaseCount === null ? '' : ` and ${releaseCount} planned release(s)`;
  console.log(
    `ok    ${packages.length} package manifests${planResult} are release-consistent; ` +
      `${allowlist.length} allowlisted for npm`
  );
}

await main();
