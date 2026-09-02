const GLOBAL_STATE_PREFIX = '@platform-sec/sensitive-string-core';

/**
 * Return process-global state shared by every loaded copy of core.
 *
 * Symbol.for() is required here: module-local state is duplicated when an
 * application resolves more than one physical installation of this package.
 */
export function getGlobalSingleton<T>(name: string, initialize: () => T): T {
  const key = Symbol.for(`${GLOBAL_STATE_PREFIX}/${name}`);
  const globals = globalThis as typeof globalThis & { [key: symbol]: unknown };
  const existing = globals[key];

  if (existing !== undefined) {
    return existing as T;
  }

  const value = initialize();
  globals[key] = value;
  return value;
}
