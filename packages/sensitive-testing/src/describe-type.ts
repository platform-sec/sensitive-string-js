/**
 * Name a value by its type, never by its content.
 *
 * Every message this package produces runs through here rather than through
 * template interpolation of the value itself. What reaches an assertion or a
 * serializer may be a raw copy of a secret, and the string built from it ends
 * up in a CI log, so the type is the most a message may say about it.
 *
 * It answers for any value, including the awkward ones. A message that explains
 * what went wrong must not be the thing that throws: replacing a clear
 * complaint about a bad argument with `Cannot read properties of undefined`
 * loses the complaint and points the reader at this package instead of at their
 * own call.
 */
export function describeType(received: unknown): string {
  if (received === null) {
    return 'null';
  }

  if (typeof received !== 'object') {
    return typeof received;
  }

  if (Object.getPrototypeOf(received) === null) {
    return 'an object with no prototype';
  }

  // `constructor` is an ordinary inherited property, so an object can reach
  // here without one, or with one that is not a function: `Object.create` of a
  // null-prototype object is the everyday way to get the first.
  const constructor: unknown = (received as { constructor?: unknown }).constructor;
  const name: unknown = typeof constructor === 'function' ? constructor.name : undefined;

  return typeof name === 'string' && name !== '' ? name : 'an object';
}
