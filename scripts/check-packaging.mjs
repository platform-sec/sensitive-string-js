#!/usr/bin/env node
/**
 * Verify that every workspace package can actually be loaded the way a
 * consumer loads it.
 *
 * The unit suite imports modules by relative path, which never touches a
 * package manifest. That gap let every package in this repository ship an
 * `exports` map whose `require` condition named a `dist/index.cjs` that `tsc`
 * does not emit: `require()` of any package failed, and so did importing a
 * package that reaches another through a dependency, because the compiled
 * output is CommonJS and its internal `require` fails the same way.
 *
 * Two checks per package:
 *
 * 1. Every path named by `main`, `module`, `types`, or a leaf of `exports`
 *    exists on disk, and falls inside the `files` allowlist so it survives
 *    packing.
 * 2. The package loads by its own name, once through `require` and once
 *    through `import`. Node resolves a package's own name from inside it when
 *    the manifest has an `exports` field, so this exercises the real map with
 *    no linking or publishing.
 *
 * Run it after `pnpm build`. Node built-ins only, like the packages it checks.
 */
import { execFile } from 'node:child_process';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);

const repoRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const packagesDir = path.join(repoRoot, 'packages');

/** Every `./`-relative path a manifest field names, with where it was found. */
function collectReferences(value, trail, found = []) {
  if (typeof value === 'string') {
    if (value.startsWith('./')) {
      found.push({ target: value, field: trail });
    }
    return found;
  }

  if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      collectReferences(child, `${trail}.${key}`, found);
    }
  }

  return found;
}

async function isFile(absolute) {
  try {
    return (await stat(absolute)).isFile();
  } catch {
    return false;
  }
}

/**
 * Whether a packed tarball would contain the path.
 *
 * A manifest with no `files` publishes everything, so only an explicit
 * allowlist can exclude something a manifest also points at.
 */
function isPacked(target, files) {
  if (!Array.isArray(files)) {
    return true;
  }

  const [head] = target.replace(/^\.\//, '').split('/');

  return files.some((entry) => entry.replace(/^\.\//, '').split('/')[0] === head);
}

async function loadsByName(dir, name, mode) {
  const source =
    mode === 'require'
      ? `require(${JSON.stringify(name)})`
      : `await import(${JSON.stringify(name)})`;
  const args = mode === 'require' ? ['-e', source] : ['--input-type=module', '-e', source];

  try {
    await execFileAsync(process.execPath, args, { cwd: dir });
    return null;
  } catch (error) {
    return firstErrorLine(String(error.stderr ?? error.message));
  }
}

/**
 * The line naming the error, skipping the source excerpt Node prints above it.
 * That excerpt contains the word "Error" too, so matching on the word alone
 * reports the throw site rather than what went wrong.
 */
function firstErrorLine(stderr) {
  const lines = stderr.split('\n').map((line) => line.trim());
  const named = lines.find((line) => /^(?:[A-Za-z]+ )?[A-Za-z]*Error(?: \[[^\]]+\])?:/.test(line));

  return named ?? lines.find((line) => line.length > 0) ?? 'failed';
}

async function checkPackage(dir) {
  const manifest = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8'));
  const problems = [];

  const references = [
    ...collectReferences(manifest.main, 'main'),
    ...collectReferences(manifest.module, 'module'),
    ...collectReferences(manifest.types, 'types'),
    ...collectReferences(manifest.exports, 'exports'),
  ];

  for (const { target, field } of references) {
    if (!(await isFile(path.join(dir, target)))) {
      problems.push(`${field} names ${target}, which the build does not produce`);
      continue;
    }

    if (!isPacked(target, manifest.files)) {
      problems.push(`${field} names ${target}, which "files" leaves out of the tarball`);
    }
  }

  // Only worth loading once the manifest points at files that exist.
  if (problems.length === 0) {
    for (const mode of ['require', 'import']) {
      const failure = await loadsByName(dir, manifest.name, mode);
      if (failure !== null) {
        problems.push(`${mode}('${manifest.name}') failed: ${failure}`);
      }
    }
  }

  return { name: manifest.name, problems };
}

async function main() {
  const entries = await readdir(packagesDir, { withFileTypes: true });
  const directories = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(packagesDir, entry.name));

  const results = [];
  for (const dir of directories) {
    results.push(await checkPackage(dir));
  }

  let failed = false;
  for (const { name, problems } of results) {
    if (problems.length === 0) {
      console.log(`ok    ${name}`);
      continue;
    }

    failed = true;
    console.log(`FAIL  ${name}`);
    for (const problem of problems) {
      console.log(`        ${problem}`);
    }
  }

  if (failed) {
    console.log('\nRun `pnpm build` first if this is a fresh checkout.');
    process.exitCode = 1;
  }
}

await main();
