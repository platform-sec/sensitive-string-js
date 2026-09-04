import { readFileSync } from 'node:fs';

/**
 * Deletion from `process.env`, and an honest report of what deletion misses.
 *
 * **Deleting a variable from `process.env` removes the copy JavaScript can see.
 * It does not remove the copy the kernel made at exec time.** Measured on Linux
 * 6.18.33.1 under WSL2, Node 22.15.0:
 *
 * | How the value reached the process | `process.env` | `/proc/self/environ` | After `delete` |
 * |---|---|---|---|
 * | Exported by the parent before exec | yes | yes | gone from `process.env`, still in `/proc/self/environ` |
 * | `node --env-file=.env` | yes | no | gone, and there was no kernel copy |
 * | `process.loadEnvFile()`, or dotenv writing to `process.env` | yes | no | gone, and there was no kernel copy |
 *
 * Overwriting behaves the same way: `process.env.X = 'redacted'` leaves the
 * original bytes in `/proc/self/environ` for the life of the process.
 *
 * The first row is the production case. Kubernetes `env:` and `envFrom:`,
 * `docker run -e`, systemd `Environment=`, and a CI runner injecting repository
 * secrets all export before exec. So this option protects the JavaScript copy,
 * the copy a spread hands to a child process, and the copy a crash handler
 * serializes. It cannot protect the copy a debugger, a core dump, or anything
 * running as the same user reads out of `/proc`.
 */

/** The path holding this process's exec-time environment on Linux. */
const ENVIRON = '/proc/self/environ';

/** The byte value of `=`. */
const EQUALS = 0x3d;

/**
 * Delete the named variables from `process.env`.
 *
 * @returns The names that were actually deleted, so a caller can report them.
 *
 * What this breaks, and the README says it plainly: any library that reads
 * `process.env` lazily stops finding the variable. That includes an SDK reading
 * `AWS_SECRET_ACCESS_KEY` on first call, a driver reading `PGPASSWORD`, and
 * anything that re-reads on reconnect. The failure is loud, and it arrives
 * later than startup, which is why the option is off by default and the
 * recommended order is to adopt classification first and removal second.
 */
export function removeFromProcessEnv(names: readonly string[]): string[] {
  const removed: string[] = [];

  for (const name of names) {
    if (Object.hasOwn(process.env, name)) {
      delete process.env[name];
      removed.push(name);
    }
  }

  return removed;
}

/**
 * Which of the given names are still in the kernel's copy of the environment.
 *
 * A non-empty result means those variables were exported before this process
 * was executed, so `/proc/<pid>/environ` holds them for the life of the process
 * whatever was deleted from `process.env`. A deployment that wants the
 * guarantee has to stop exporting them at exec time and load them from a file
 * or a secrets manager instead; this is how an operator learns which variables
 * are in that position.
 *
 * @returns `'unknown'` on a platform where the check cannot run. Never an empty
 *   array there, which would be a false all-clear.
 *
 * The cost is a transient copy of the whole environment, values included, which
 * is why the option that calls this is off by default. The cost is narrowed as
 * far as it can be: the file is read as a `Buffer`, only the name slices are
 * decoded into JavaScript strings, and the buffer is zeroed before it is
 * dropped. No value is ever materialized as a string. The bytes still existed.
 *
 * `/proc/<pid>/environ` is mode 0400, owned by the process owner, so its
 * readers are that user, root, and anything with `CAP_SYS_PTRACE`, subject to
 * the host's `ptrace_scope` and `hidepid` settings. In a container that is
 * normally every other process in the container, a shell someone `exec`s into
 * it included. That is a smaller set than can read `/proc/<pid>/cmdline`, which
 * is mode 0444 and world readable. It is not a small enough set to skip this.
 */
export function kernelCopyNames(names: readonly string[]): readonly string[] | 'unknown' {
  const present = kernelEnvironNames();

  if (present === undefined) {
    return 'unknown';
  }

  return names.filter((name) => present.has(name));
}

/** Every variable name in `/proc/self/environ`, or `undefined` if it cannot be read. */
function kernelEnvironNames(): Set<string> | undefined {
  let buffer: Buffer;

  try {
    buffer = readFileSync(ENVIRON);
  } catch {
    return undefined;
  }

  const names = new Set<string>();

  try {
    let start = 0;

    for (let index = 0; index <= buffer.length; index++) {
      if (index !== buffer.length && buffer[index] !== 0) {
        continue;
      }

      if (index > start) {
        const equals = buffer.indexOf(EQUALS, start);
        if (equals !== -1 && equals < index) {
          names.add(buffer.toString('utf8', start, equals));
        }
      }

      start = index + 1;
    }
  } finally {
    // Best effort, and not a claim that the read is undone: the bytes were in
    // this process's heap for the duration. Zeroing keeps them from sitting
    // there until the buffer is collected, which is the only part still under
    // this function's control.
    buffer.fill(0);
  }

  return names;
}
