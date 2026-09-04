#!/usr/bin/env node
/**
 * A stand-in for the `sops` binary.
 *
 * It is not a SOPS implementation. It does the one thing the unit suite needs
 * to observe: read an encrypted document, replace every `ENC[...]` marker with
 * the plaintext encoded in it, and write the result as JSON, exactly as
 * `--output-type json` does. That exercises the whole path this package owns,
 * which is the argv, the child environment, the exit code handling, and the
 * JSON guard on stdout.
 *
 * What it cannot test is SOPS itself, so `src/__tests__/live.test.ts` runs the
 * same cases against the real binary and skips itself when it is not installed.
 * The rule this row works to is that a fixture written from a design document
 * tests the document, and this file is a fixture.
 *
 * It reports what it saw into `FAKE_SOPS_REPORT`, so the suite can assert that
 * the age key reached the child and never the parent.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { parse } from 'yaml';

const args = process.argv.slice(2);
const report = process.env.FAKE_SOPS_REPORT;

if (report !== undefined) {
  writeFileSync(
    report,
    JSON.stringify({
      argv: args,
      sawAgeKey: typeof process.env.SOPS_AGE_KEY === 'string',
      ageKey: process.env.SOPS_AGE_KEY ?? null,
      extraEnv: process.env.FAKE_SOPS_EXTRA ?? null,
    })
  );
}

if (args.includes('--version')) {
  process.stdout.write('sops 3.9.4 (latest)\n');
  process.exit(0);
}

// Hangs on a decrypt while still answering `--version`, which is what a large
// document, a hardware token waiting for a touch, or an unreachable KMS
// endpoint looks like from the outside.
if (process.env.FAKE_SOPS_HANG === '1') {
  setTimeout(() => undefined, 60_000);
}

if (process.env.FAKE_SOPS_VERSION_FAILS === '1') {
  process.stderr.write('fake sops: version check refused\n');
  process.exit(3);
}

const path = args[args.length - 1];

let source;

try {
  source = readFileSync(path, 'utf8');
} catch {
  // The wording and the exit code real sops uses, measured on 3.13.3. An
  // earlier version of this file invented `no such file or directory`, and the
  // package matched on the invention rather than on what sops says.
  process.stderr.write(`Error: cannot operate on non-existent file "${path}"\n`);
  process.exit(100);
}

if (process.env.FAKE_SOPS_FAIL === '1') {
  // What sops 3.13.3 prints for a key that matches no recipient, exit code
  // included. It names the recipient's public key and the local paths it
  // probed for identities, and no plaintext.
  process.stderr.write('Failed to get the data key required to decrypt the SOPS file.\n');
  process.stderr.write('\nGroup 0: FAILED\n');
  process.stderr.write('  age1example: FAILED\n');
  process.stderr.write('    - | age: identity did not match any of the recipients\n');
  process.exit(128);
}

if (process.env.FAKE_SOPS_BAD_OUTPUT === '1') {
  process.stdout.write('not json at all\n');
  process.exit(0);
}

const document = path.endsWith('.json') ? JSON.parse(source) : parse(source);

/** `ENC[AES256_GCM,data:<base64>,iv:...,tag:...,type:str]` back to its plaintext. */
function decrypt(value) {
  if (typeof value !== 'string') {
    return value;
  }

  const match = /^ENC\[[A-Za-z0-9_]+,data:([^,\]]*)/.exec(value);

  return match === null ? value : Buffer.from(match[1], 'base64').toString('utf8');
}

function walk(value) {
  if (Array.isArray(value)) {
    return value.map(walk);
  }

  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, walk(entry)]));
  }

  return decrypt(value);
}

const { sops: _metadata, ...payload } = document ?? {};

process.stdout.write(JSON.stringify(walk(payload)));
