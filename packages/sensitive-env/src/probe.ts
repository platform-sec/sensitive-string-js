/**
 * Property reads against objects this package did not create.
 *
 * A caller hands `loadEnv` a source, `assertSensitiveFlags` a convict schema,
 * and `wrapTree` a configuration document. Reading a property of one of those
 * is not universally safe: a Proxy may throw for a name it was not given
 * rather than answering `undefined`, and envalid's own `cleanEnv` result is
 * exactly such an object.
 *
 * `core` carries the same guard for the redaction walks. This one is a local
 * copy rather than an import because `core` does not export it, and four lines
 * of `try`/`catch` is a smaller commitment than widening another package's
 * public surface.
 */

/** Read a named property, treating a refusal as absence. */
export function probeProperty(value: object, name: string): unknown {
  try {
    return (value as Record<string, unknown>)[name];
  } catch {
    return undefined;
  }
}

/**
 * Own enumerable string keys, treating a refusal as an empty object.
 *
 * `Object.keys` goes through the `ownKeys` and `getOwnPropertyDescriptor`
 * traps, either of which a hostile or merely strict object can throw from.
 */
export function probeKeys(value: object): string[] {
  try {
    return Object.keys(value);
  } catch {
    return [];
  }
}
