import { compileEnvSpec } from './classify.js';
import type { EnvSpec } from './types.js';

/**
 * Test helpers, behind their own entry point.
 *
 * `import { findCrossContamination } from '@platform-sec/sensitive-string-env/testing'`
 *
 * A subpath rather than a main export, so nothing here is reachable from a
 * production import by accident. The reason is in the function below: it
 * compares raw values against raw values, which is the one operation this
 * package otherwise never performs.
 */

/**
 * Find secrets that a `.env` expansion copied into an unclassified variable.
 *
 * `dotenv-expand` resolves `${VAR}` references, and a reference to a secret
 * inlines the secret:
 *
 * ```
 * DB_PASSWORD=s3cr3t
 * DATABASE_URL=postgres://app:${DB_PASSWORD}@db:5432/app
 * ```
 *
 * Measured: the expanded record holds the full secret in `DATABASE_URL`. A
 * specification that classifies `DB_PASSWORD` and not `DATABASE_URL` has
 * wrapped one of the two copies and reports success.
 *
 * `explainEnv` cannot see this, because expansion happens before the loader
 * runs and the result is just another string. This can, because it is allowed
 * to read values.
 *
 * **Run it in a test, not at startup.** It holds every value in a comparison
 * loop, it is O(names squared) in the worst case, and the condition it checks
 * changes only when the `.env` file does.
 *
 * @param source - The raw values, before wrapping.
 * @param spec - The specification to check them against.
 * @returns One entry per contaminated variable, naming both variables and
 *   neither value. Empty when nothing is contaminated, so a test reads
 *   `expect(findCrossContamination(source, spec)).toEqual([])`.
 *
 * @example
 * ```ts
 * it('leaves no secret inlined into a plain variable', () => {
 *   const { parsed } = dotenv.config({ processEnv: {} });
 *   expect(findCrossContamination(expand({ parsed }).parsed ?? {}, spec)).toEqual([]);
 * });
 * ```
 */
export function findCrossContamination(
  source: Readonly<Record<string, string>>,
  spec: EnvSpec
): string[] {
  const compiled = compileEnvSpec(spec);
  const classified: [string, string][] = [];
  const plain: [string, string][] = [];

  for (const name of Object.keys(source)) {
    const value = source[name];

    if (typeof value !== 'string' || value === '') {
      continue;
    }

    const klass = compiled.classify(name) ?? spec.fallback;

    if (klass === 'plain') {
      plain.push([name, value]);
    } else {
      classified.push([name, value]);
    }
  }

  const findings: string[] = [];

  for (const [plainName, plainValue] of plain) {
    for (const [secretName, secretValue] of classified) {
      if (plainValue.includes(secretValue)) {
        findings.push(`${plainName} contains the value of ${secretName}`);
      }
    }
  }

  return findings.sort();
}

/**
 * The canary and marker harness, shared with the packages built on this one.
 *
 * Framework-free: plain functions that throw an ordinary `Error`, so a suite
 * can run them under Vitest, Jest, or `node --test` without any of them
 * becoming a dependency of this package. The same arrangement `sensitive-scrub`
 * and `sensitive-secrets` use for their own vendor suites.
 */

/** Every string an error can be rendered as, including its whole cause chain. */
export function errorText(error: unknown): string {
  const parts: string[] = [];
  const seen = new Set<unknown>();
  let current: unknown = error;

  while (current !== null && current !== undefined && !seen.has(current)) {
    seen.add(current);

    if (current instanceof Error) {
      parts.push(current.message, current.stack ?? '', String(current));
      current = (current as { cause?: unknown }).cause;
    } else {
      parts.push(safeJson(current));
      current = undefined;
    }
  }

  parts.push(safeJson(error));

  return parts.join('\n');
}

/** `JSON.stringify` that survives a cycle, a BigInt, and a throwing getter. */
export function safeJson(value: unknown): string {
  const seen = new WeakSet<object>();

  try {
    return (
      JSON.stringify(value, (_key, entry: unknown) => {
        if (typeof entry === 'bigint') {
          return entry.toString();
        }

        if (typeof entry === 'object' && entry !== null) {
          if (seen.has(entry)) {
            return '[Circular]';
          }
          seen.add(entry);

          if (entry instanceof Error) {
            return {
              name: entry.name,
              message: entry.message,
              stack: entry.stack,
              cause: (entry as { cause?: unknown }).cause,
            };
          }
        }

        return entry;
      }) ?? String(value)
    );
  } catch {
    return String(value);
  }
}

/** Every string reachable in a value, so a canary cannot hide in a nested field. */
export function allStrings(value: unknown, depth = 0): string[] {
  if (depth > 12) {
    return [];
  }

  if (typeof value === 'string') {
    return [value];
  }

  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return [String(value)];
  }

  if (value instanceof Error) {
    return [errorText(value)];
  }

  if (value instanceof Map) {
    return [...value.entries()].flatMap(([key, entry]) => [
      ...allStrings(key, depth + 1),
      ...allStrings(entry, depth + 1),
    ]);
  }

  if (value instanceof Set || Array.isArray(value)) {
    return [...(value as Iterable<unknown>)].flatMap((entry) => allStrings(entry, depth + 1));
  }

  if (typeof value === 'object' && value !== null) {
    let entries: [string, unknown][];

    try {
      entries = Object.entries(value);
    } catch {
      return [];
    }

    return entries.flatMap(([key, entry]) => [key, ...allStrings(entry, depth + 1)]);
  }

  return [];
}

export class CanaryLeakError extends Error {
  override readonly name: string = 'CanaryLeakError';
}

/** Assert a canary appears nowhere in a value, however deeply nested. */
export function assertNoCanary(canary: string, value: unknown, where: string): void {
  for (const text of allStrings(value)) {
    if (text.includes(canary)) {
      throw new CanaryLeakError(`Canary leaked in ${where}.`);
    }
  }
}

/**
 * Assert a canary appears in no rendering of a thrown error.
 *
 * Kept separate from `assertNoCanary` because an error's `stack` and `cause`
 * chain are not reachable by walking own properties, and the cause chain is the
 * half this package's error rule exists to keep empty.
 */
export function assertNoCanaryInError(canary: string, error: unknown, where: string): void {
  if (errorText(error).includes(canary)) {
    throw new CanaryLeakError(`Canary leaked in the error thrown by ${where}.`);
  }
}

/** One entry point, driven with a canary in every position it accepts. */
export interface SweepCase {
  readonly name: string;
  run(): unknown;
  /**
   * This entry point returns raw values by contract, so only its error path is
   * swept.
   *
   * Two kinds of function qualify, and no others. The `.env` parser, which is
   * the layer *below* classification and whose whole job is to hand back the
   * values a file held. And the guarded property read, which returns whatever
   * the caller's own object holds at a name the caller chose. Asserting a
   * canary never appears in either result would be asserting that the parser
   * does not parse and the read does not read. Their errors are still swept,
   * and so is every consumer of them.
   */
  readonly rawResult?: boolean;
  /**
   * The public export names this case exercises.
   *
   * The registration check reads these, so a new entry point cannot land
   * unswept. A case that drives a private path leaves it empty.
   */
  readonly covers?: readonly string[];
}

export interface SweepResult {
  readonly name: string;
  /** Whether the case threw. Both outcomes are swept; neither is required. */
  readonly threw: boolean;
}

/**
 * Run every case and assert the canary reached neither the value nor the error.
 *
 * A case is allowed to resolve and allowed to throw. The sweep does not assert
 * which, because the cases that matter most are the failure paths and pinning
 * them here would duplicate the functional suite.
 */
export async function sweep(canary: string, cases: readonly SweepCase[]): Promise<SweepResult[]> {
  const results: SweepResult[] = [];

  for (const testCase of cases) {
    try {
      const value = await testCase.run();

      if (testCase.rawResult !== true) {
        assertNoCanary(canary, value, `the result of ${testCase.name}`);
      }

      results.push({ name: testCase.name, threw: false });
    } catch (error) {
      if (error instanceof CanaryLeakError) {
        throw error;
      }

      assertNoCanaryInError(canary, error, testCase.name);
      results.push({ name: testCase.name, threw: true });
    }
  }

  return results;
}

/**
 * Assert every exported entry point of a module has a sweep entry.
 *
 * Error classes are not entry points: nothing in the package builds one from
 * caller data, and the sweep already asserts the message of every error it can
 * actually produce. They are excluded rather than listed, so a new error type
 * does not need a line in two places.
 */
export function assertEveryExportSwept(
  moduleExports: Readonly<Record<string, unknown>>,
  cases: readonly SweepCase[]
): void {
  const swept = new Set(cases.flatMap((sweepCase) => sweepCase.covers ?? []));

  const missing = Object.entries(moduleExports)
    .filter(([, value]) => typeof value === 'function' && !isErrorClass(value))
    .map(([name]) => name)
    .filter((name) => !swept.has(name))
    .sort();

  if (missing.length > 0) {
    throw new Error(`Public exports with no sweep entry: ${missing.join(', ')}.`);
  }
}

function isErrorClass(value: unknown): boolean {
  return typeof value === 'function' && Object.prototype.isPrototypeOf.call(Error, value);
}

/** Objects that refuse to answer, for the hostile-object sweep. */
export function hostileObjects(): Record<string, object> {
  return {
    /** envalid's own shape: a Proxy that throws for any name it was not given. */
    strictProxy: new Proxy(
      { KNOWN: 'known' },
      {
        get(target, name): unknown {
          if (!Object.hasOwn(target, name)) {
            throw new ReferenceError(`[test] Env var not found: ${String(name)}`);
          }
          return (target as Record<string | symbol, unknown>)[name];
        },
      }
    ),
    /** A trap on the path `Object.hasOwn` and `Object.keys` take. */
    throwingDescriptor: new Proxy(
      { KNOWN: 'known' },
      {
        getOwnPropertyDescriptor(): PropertyDescriptor {
          throw new Error('[test] getOwnPropertyDescriptor refused');
        },
        ownKeys(): string[] {
          throw new Error('[test] ownKeys refused');
        },
      }
    ),
    /** Not a Proxy: an ORM's unloaded relation, which `Object.entries` invokes. */
    throwingGetter: Object.defineProperty({ KNOWN: 'known' }, 'lazy', {
      enumerable: true,
      get(): never {
        throw new Error('[test] getter refused');
      },
    }),
    /** Every `instanceof` in a walk goes through this trap. */
    throwingGetPrototypeOf: new Proxy(
      { KNOWN: 'known' },
      {
        getPrototypeOf(): never {
          throw new Error('[test] getPrototypeOf refused');
        },
      }
    ),
    /** A getter on the prototype that throws for anything inherited. */
    throwingPrototype: Object.create(
      new Proxy(
        {},
        {
          get(): unknown {
            throw new Error('[test] prototype refused');
          },
        }
      ),
      { KNOWN: { value: 'known', enumerable: true } }
    ) as object,
    /** No prototype at all, so every `Object.prototype` method is absent. */
    nullPrototype: Object.assign(Object.create(null) as object, { KNOWN: 'known' }),
  };
}
