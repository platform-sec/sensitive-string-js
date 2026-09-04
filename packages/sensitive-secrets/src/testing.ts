import { BaseSecretSource } from './source.js';

/**
 * The canary and marker harness provider suites import.
 *
 * Framework-free: these are plain functions that throw an ordinary `Error`, so
 * a suite can run them under Vitest, Jest, or `node --test` without any of them
 * being a dependency of this package.
 *
 * The sweep is the test this layer exists for. It drives every entry point with
 * a canary in every position the provider accepts, forces each failure mode the
 * package can produce, and asserts the canary appears in no `error.message`, no
 * `JSON.stringify(error)`, no `error.stack`, and no `cause` chain at any depth.
 *
 * The `cause` check is not incidental. The decode guard turns on not chaining
 * an error that would otherwise be chained by reflex, and a later contributor
 * restoring `cause` for good reasons must see a test fail.
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
    return Object.entries(value).flatMap(([key, entry]) => [key, ...allStrings(entry, depth + 1)]);
  }

  return [];
}

export class CanaryLeakError extends Error {
  override readonly name = 'CanaryLeakError';
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
 * half the decode guard exists to keep empty.
 */
export function assertNoCanaryInError(canary: string, error: unknown, where: string): void {
  if (errorText(error).includes(canary)) {
    throw new CanaryLeakError(`Canary leaked in the error thrown by ${where}.`);
  }
}

/** One entry point, driven with a canary in every position the provider accepts. */
export interface SweepCase {
  readonly name: string;
  run(): unknown;
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
 * them here would duplicate the provider suite.
 */
export async function sweep(canary: string, cases: readonly SweepCase[]): Promise<SweepResult[]> {
  const results: SweepResult[] = [];

  for (const testCase of cases) {
    try {
      const value = await testCase.run();
      assertNoCanary(canary, value, `the result of ${testCase.name}`);
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
 * The names of every `BaseSecretSource` subclass a module exports.
 *
 * The registration test uses it: a ninth provider whose source has no sweep
 * entry should not be able to land, and asking the module what sources it
 * exports is more durable than a hand-maintained list.
 */
export function sourceClassesIn(moduleExports: Readonly<Record<string, unknown>>): string[] {
  return Object.entries(moduleExports)
    .filter(
      ([, value]) =>
        typeof value === 'function' && Object.prototype.isPrototypeOf.call(BaseSecretSource, value)
    )
    .map(([name]) => name)
    .sort();
}

/** Assert every exported source class has a sweep entry. */
export function assertEverySourceSwept(
  moduleExports: Readonly<Record<string, unknown>>,
  swept: readonly string[]
): void {
  const missing = sourceClassesIn(moduleExports).filter((name) => !swept.includes(name));

  if (missing.length > 0) {
    throw new Error(`Source implementations with no sweep entry: ${missing.join(', ')}.`);
  }
}

/**
 * A transport that records what it was asked to send and never sends it.
 *
 * The marker test asserts a refused write reached no transport, which needs
 * something that can prove it was not called.
 */
export interface RecordingCalls<T> {
  readonly calls: readonly T[];
  record(call: T): void;
  reset(): void;
}

export function recorder<T>(): RecordingCalls<T> {
  const calls: T[] = [];

  return {
    get calls(): readonly T[] {
      return calls;
    },
    record(call: T): void {
      calls.push(call);
    },
    reset(): void {
      calls.length = 0;
    },
  };
}
