/**
 * The subprocess boundary.
 *
 * This package shells out to the `sops` binary and does not implement SOPS. A
 * pure-JavaScript implementation would be a security-critical reimplementation
 * of a format with five key backends, and getting the AES-GCM handling or the
 * MAC verification subtly wrong is a failure this library would be actively
 * responsible for. Shelling out means the decryption is done by the tool the
 * file was produced with.
 */

import { spawn } from 'node:child_process';
import { createChildContext } from '@platform-sec/sensitive-string-core';
import type { RevealContext, SensitiveString } from '@platform-sec/sensitive-string-core';
import { SecretError } from '@platform-sec/sensitive-string-secrets';

export interface SpawnResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  /**
   * Whether the child was killed for running past `timeoutMs`.
   *
   * Without it a timeout is indistinguishable from any other signal death: the
   * exit code is `null` and stderr is empty, because the process never got to
   * write anything. A caller that reported that as an ordinary decrypt failure
   * would tell an operator to check their key while the actual problem was that
   * the decrypt did not finish.
   */
  readonly timedOut: boolean;
}

/** A `sops` invocation that failed. */
export class SopsError extends SecretError {
  override readonly name = 'SopsError';

  constructor(
    message: string,
    path: string,
    /** The binary's own stderr, when `includeStderr` is on. See the note below. */
    readonly stderr: string | undefined
  ) {
    super(message, path);
  }
}

export interface RunOptions {
  /** The binary. A name is resolved on PATH; an absolute path is used as given. */
  readonly binary: string;
  readonly args: readonly string[];
  /** Revealed into the child's environment, and never into the parent's. */
  readonly ageKey?: SensitiveString<'credential'> | undefined;
  readonly context: RevealContext;
  readonly timeoutMs: number;
  /** Extra environment for the child only. */
  readonly env?: Readonly<Record<string, string>> | undefined;
}

/**
 * The environment the child gets.
 *
 * The age identity is a credential, so it is revealed here, per decrypt, under
 * this package's own context, and placed in the **child's** environment
 * specifically rather than the parent's:
 *
 * - The parent's environment is visible in `/proc/<pid>/environ` for the life
 *   of the process, is copied into every other child it spawns, and is what an
 *   error tracker collects when it captures the environment.
 * - The child's is visible in `/proc/<child pid>/environ` to the same user, for
 *   as long as the decrypt takes, and then the process is gone.
 *
 * Neither is private against a local attacker with the same uid. The child's is
 * the better of the two because it is bounded in time and never touches disk.
 * Writing the key to a `0600` temp file for `SOPS_AGE_KEY_FILE` was rejected:
 * it trades a short-lived memory exposure for a filesystem artifact that
 * survives a crash.
 */
export function childEnv(options: RunOptions): NodeJS.ProcessEnv {
  const base: NodeJS.ProcessEnv = { ...process.env, ...options.env };

  if (options.ageKey === undefined) {
    // No key at all, which is the KMS case: ambient cloud credentials do the
    // work and this package holds one fewer secret.
    return base;
  }

  return { ...base, SOPS_AGE_KEY: options.ageKey.reveal(options.context) };
}

/** The context every reveal of the age identity happens under. */
export function decryptContext(): RevealContext {
  return createChildContext({ name: 'sops-decrypt', reason: 'decrypting a SOPS document' });
}

/**
 * Run the binary and collect its output.
 *
 * `shell: false`, which is the default for an argv array and is stated here
 * because it is the property that matters: a file path never reaches a shell,
 * so a path with a space or a semicolon in it is a path and not an injection.
 *
 * stdout is captured into a buffer, which is a copy of the whole decrypted
 * document that this package cannot clear. It is the largest uncollectable copy
 * in this row and the README says so.
 */
export function run(options: RunOptions): Promise<SpawnResult> {
  return new Promise<SpawnResult>((resolve, reject) => {
    const child = spawn(options.binary, [...options.args], {
      shell: false,
      env: childEnv(options),
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, options.timeoutMs);
    timer.unref?.();

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });

    child.on('error', (error) => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timer);
      reject(error);
    });

    child.on('close', (code) => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut });
    });
  });
}

/**
 * The argv for a decrypt.
 *
 * `--output-type json`, so the decrypted document arrives as JSON and is
 * decoded by the shared guard. That is what keeps the YAML parser on the
 * ciphertext side of this package: a YAML parser reports the offending line in
 * its errors, which is safe for ciphertext and is exactly the leak this row
 * exists to prevent for plaintext.
 */
export function decryptArgs(path: string): string[] {
  return ['--decrypt', '--output-type', 'json', path];
}

/**
 * Check the binary once, so a missing or too-old `sops` fails where it can be
 * read rather than at the first decrypt in the middle of a request.
 */
export async function checkVersion(binary: string, timeoutMs: number): Promise<string> {
  let result: SpawnResult;

  try {
    result = await run({
      binary,
      args: ['--version', '--disable-version-check'],
      context: decryptContext(),
      timeoutMs,
    });
  } catch {
    throw new SopsError(
      `The '${binary}' binary could not be run. This package shells out to sops rather than ` +
        `reimplementing it, so the binary has to be installed and on PATH.`,
      binary,
      undefined
    );
  }

  if (result.timedOut) {
    throw new SopsError(
      `'${binary} --version' did not finish within ${String(timeoutMs)}ms.`,
      binary,
      undefined
    );
  }

  if (result.code !== 0) {
    throw new SopsError(
      `'${binary} --version' exited with code ${String(result.code)}.`,
      binary,
      result.stderr.trim() === '' ? undefined : result.stderr.trim()
    );
  }

  return result.stdout.trim();
}
