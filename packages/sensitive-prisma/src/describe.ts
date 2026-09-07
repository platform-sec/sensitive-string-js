/** `a` or `an`, so a refusal that names a type reads as a sentence. */
function article(noun: string): string {
  return /^[aeiou]/i.test(noun) ? 'an' : 'a';
}

/**
 * Name the type of a value for a refusal message.
 *
 * Every refusal this package raises travels the same paths a leak would: a
 * thrown error is logged, reported to an error tracker, and often echoed to a
 * client. So the messages say what kind of thing arrived and never what it was.
 *
 * The whole body is guarded because this runs on the way to throwing, and an
 * object that refuses to describe itself must not replace the refusal that
 * names the real problem with a `TypeError` from inside the message. Three
 * separate reads can throw on a hostile or revoked `Proxy`: `Array.isArray`,
 * `getPrototypeOf` and any property access. `wrapRows` takes its rows from the
 * caller, so this is reachable with an object this package did not create.
 */
export function describeValue(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value !== 'object') return `${article(typeof value)} ${typeof value}`;

  try {
    if (Array.isArray(value)) return 'an array';

    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype === Object.prototype || prototype === null) return 'a plain object';

    const name: unknown = (value as { constructor?: { name?: unknown } }).constructor?.name;
    return typeof name === 'string' && name !== '' ? `${article(name)} ${name}` : 'an object';
  } catch {
    return 'an object';
  }
}
