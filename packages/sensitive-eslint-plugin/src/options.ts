/**
 * Reading a rule's options.
 *
 * ESLint validates options against each rule's `meta.schema` before `create` is
 * called, so these readers are not the enforcement point. They exist because
 * the options arrive as `unknown` and a rule should not cast its way out of
 * that: a schema can be edited into disagreement with the code it guards, and
 * on that day a wrong option should fall back to a safe default rather than
 * reach a rule as a string where a list belongs.
 */

/**
 * One positional option, as an object, or an empty one when it is absent or is
 * not an object. Every reader below then falls back to its default, which is
 * what an omitted option should do.
 */
export function optionObject(
  options: readonly unknown[],
  index: number
): Readonly<Record<string, unknown>> {
  const value = options[index];
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    return value as Readonly<Record<string, unknown>>;
  }
  return {};
}

/** A boolean field of an options object, or `fallback` when it is absent. */
export function readBoolean(
  option: Readonly<Record<string, unknown>>,
  key: string,
  fallback: boolean
): boolean {
  const value = option[key];
  return typeof value === 'boolean' ? value : fallback;
}

/**
 * A list-of-strings field of an options object, as a set, or `fallback` when it
 * is absent.
 *
 * A configured list replaces the default rather than extending it. That is the
 * ESLint convention, and for these rules it is also the useful behaviour: a
 * project that names its logger `report` wants `report` recognised, and a
 * project that has deliberately narrowed the list wants the entries it removed
 * to stay removed.
 */
export function readNameSet(
  option: Readonly<Record<string, unknown>>,
  key: string,
  fallback: readonly string[]
): ReadonlySet<string> {
  const value = option[key];
  if (Array.isArray(value)) {
    const names = value.filter((entry): entry is string => typeof entry === 'string');
    return new Set(names);
  }
  return new Set(fallback);
}

/** The JSON Schema for an option that is a list of names. */
export function nameListSchema(): Readonly<Record<string, unknown>> {
  return { type: 'array', items: { type: 'string' }, uniqueItems: true };
}
