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
 */
export function describeValue(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';

  if (typeof value === 'object') {
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype === Object.prototype || prototype === null) return 'a plain object';

    const name: unknown = (value as { constructor?: { name?: unknown } }).constructor?.name;
    return typeof name === 'string' && name !== '' ? `${article(name)} ${name}` : 'an object';
  }

  return `${article(typeof value)} ${typeof value}`;
}
