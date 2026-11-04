#!/usr/bin/env node
/**
 * Narrow a Changesets publish plan to the release allowlist.
 *
 *   pnpm release:filter -- --plan publish-plan.full.json --output publish-plan.json \
 *     [--held held.txt]
 *
 * `changeset publish-plan` lists every committed version npm does not have. This
 * keeps the entries whose package is allowlisted, preserves the dependency-order
 * chunks (dropping any left empty), and reports every entry it held back, one
 * `name@version` per line, on stdout and optionally in a file.
 *
 * Filtering is the convenience; `release:check --plan` is the enforcement. It
 * refuses a plan entry that is not allowlisted, and the publish job runs it
 * again on the signed bundle, so a plan that skipped this step still cannot
 * publish a held package.
 */
import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkAllowlist, readAllowlist } from './release-allowlist.mjs';

const repoRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));

function parseArguments(argv) {
  const options = { plan: null, output: null, held: null };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--') {
      continue;
    } else if (argument === '--plan' || argument === '--output' || argument === '--held') {
      const value = argv[index + 1];
      if (value === undefined) throw new Error(`${argument} requires a value`);
      options[argument.slice(2)] = value;
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }

  if (options.plan === null || options.output === null) {
    throw new Error('Usage: filter-publish-plan.mjs --plan <file> --output <file> [--held <file>]');
  }

  if (path.resolve(options.plan) === path.resolve(options.output)) {
    throw new Error('--output must differ from --plan, so the unfiltered plan survives');
  }

  return options;
}

async function readPackagesByName() {
  const packagesDir = path.join(repoRoot, 'packages');
  const entries = await readdir(packagesDir, { withFileTypes: true });
  const packagesByName = new Map();

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const manifest = JSON.parse(
      await readFile(path.join(packagesDir, entry.name, 'package.json'), 'utf8')
    );
    packagesByName.set(manifest.name, { manifest });
  }

  return packagesByName;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const allowlist = await readAllowlist(repoRoot);
  const problems = checkAllowlist(allowlist, await readPackagesByName());
  if (problems.length > 0) {
    for (const problem of problems) console.error(`FAIL  ${problem}`);
    process.exitCode = 1;
    return;
  }

  const document = JSON.parse(await readFile(path.resolve(repoRoot, options.plan), 'utf8'));
  if (document?.version !== 1 || !Array.isArray(document.plan)) {
    throw new Error(`${options.plan} is not a Changesets publish plan v1`);
  }

  const allowlisted = new Set(allowlist);
  const kept = [];
  const held = [];
  for (const chunk of document.plan) {
    if (!Array.isArray(chunk)) throw new Error(`${options.plan} has a chunk that is not an array`);
    const keptChunk = [];
    for (const entry of chunk) {
      if (allowlisted.has(entry?.name)) keptChunk.push(entry);
      else held.push(`${entry?.name}@${entry?.version}`);
    }
    if (keptChunk.length > 0) kept.push(keptChunk);
  }

  await writeFile(
    path.resolve(repoRoot, options.output),
    `${JSON.stringify({ ...document, plan: kept }, null, 2)}\n`
  );

  held.sort();
  if (options.held !== null) {
    await writeFile(
      path.resolve(repoRoot, options.held),
      held.length > 0 ? `${held.join('\n')}\n` : ''
    );
  }

  for (const release of held) console.log(`held  ${release}`);
  console.log(
    `ok    kept ${kept.flat().length} release(s) from ${allowlist.length} allowlisted ` +
      `package(s); held ${held.length}`
  );
}

await main();
