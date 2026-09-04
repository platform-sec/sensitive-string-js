/**
 * Property reads against objects the library did not create.
 *
 * A walk has to ask an arbitrary object a few duck-type questions: is this a
 * `serialize()` result, is this a stream. Reading an absent property is not
 * universally safe, because a Proxy may throw for an unknown name rather than
 * answering `undefined`.
 */

/**
 * Read a named property, treating a refusal as absence.
 *
 * envalid's `cleanEnv()` result is the case this was found on: it is a Proxy
 * that throws `ReferenceError` for any variable that was not declared, so the
 * unguarded probes took out `redactInStructure`, `containsSensitive`,
 * `safeStringify`, `sensitiveClassesIn` and `redactCopy` alike, including when
 * the object was merely nested inside a logged one.
 *
 * Reporting absence is the safe answer for every caller here. Neither probe
 * decides whether a value is redacted; they decide whether the walk replaces
 * the object wholesale or descends into it, and descending still redacts every
 * `SensitiveString` it finds. So an object that refuses to answer is walked
 * like any other object rather than failing the whole redaction.
 */
export function probeProperty(value: object, name: string): unknown {
  try {
    return (value as Record<string, unknown>)[name];
  } catch {
    return undefined;
  }
}
