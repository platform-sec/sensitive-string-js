#!/usr/bin/env node
/**
 * Pack the exact packages in a Changesets v3 publish plan with pnpm 9.
 *
 * Changesets v3's experimental pack command uses newer pnpm flags. This small
 * compatibility boundary produces the same v1 packed-plan shape that
 * `changeset publish --from-pack-dir` consumes, while keeping pnpm 9 as the
 * repository's declared package manager.
 */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));

function parseArguments(argv) {
  const options = { plan: null, outDir: null };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--') {
      continue;
    } else if (argument === '--plan') {
      options.plan = argv[index + 1] ?? null;
      index += 1;
    } else if (argument === '--out-dir') {
      options.outDir = argv[index + 1] ?? null;
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }

  if (options.plan === null || options.outDir === null) {
    throw new Error('Usage: pack-release-plan.mjs --plan <file> --out-dir <directory>');
  }

  return options;
}

function tarballFilename(name, version) {
  return `${name.replace(/^@/, '').replace('/', '-')}-${version}.tgz`;
}

async function packageDirectory(name) {
  const packagesDir = path.join(repoRoot, 'packages');
  const entries = await readdir(packagesDir, { withFileTypes: true });

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(packagesDir, entry.name);
    const manifest = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8'));
    if (manifest.name === name) return { dir, manifest };
  }

  return null;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const planPath = path.resolve(repoRoot, options.plan);
  const outDir = path.resolve(repoRoot, options.outDir);
  const packagesOutDir = path.join(outDir, 'packages');
  const document = JSON.parse(await readFile(planPath, 'utf8'));

  if (document.version !== 1 || !Array.isArray(document.plan)) {
    throw new Error(`${options.plan} is not a Changesets publish plan v1`);
  }

  try {
    await mkdir(outDir, { recursive: false });
  } catch (error) {
    if (error?.code === 'EEXIST') {
      throw new Error(`Refusing to pack into existing directory ${options.outDir}`);
    }
    throw error;
  }
  await mkdir(packagesOutDir);

  const packedPlan = [];
  for (const group of document.plan) {
    const packedGroup = [];
    for (const release of group) {
      if (release.kind !== 'publish') {
        packedGroup.push(release);
        continue;
      }

      const pkg = await packageDirectory(release.name);
      if (pkg === null) throw new Error(`Package not found: ${release.name}`);
      if (pkg.manifest.version !== release.version) {
        throw new Error(
          `${release.name}@${release.version} does not match manifest ${pkg.manifest.version}`
        );
      }

      await execFileAsync('pnpm', ['pack', '--pack-destination', packagesOutDir], {
        cwd: pkg.dir,
        maxBuffer: 10 * 1024 * 1024,
      });

      const filename = tarballFilename(release.name, release.version);
      const absoluteTarball = path.join(packagesOutDir, filename);
      const tarball = await readFile(absoluteTarball);
      const integrity = `sha256-${createHash('sha256').update(tarball).digest('base64')}`;
      packedGroup.push({
        ...release,
        tarball: {
          path: path.posix.join('packages', filename),
          integrity,
        },
      });
      console.log(`packed ${release.name}@${release.version}`);
    }
    packedPlan.push(packedGroup);
  }

  await writeFile(
    path.join(outDir, 'publish-plan.json'),
    `${JSON.stringify({ version: 1, plan: packedPlan }, null, 2)}\n`
  );
}

await main();
