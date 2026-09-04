/**
 * Assign a value under a key that came from data the library did not create.
 *
 * `JSON.parse('{"__proto__": {"isAdmin": true}}')` yields an object with an
 * own property named `__proto__`, inert on that object. Copying it with
 * `target[key] = value` does not create the same property on the target: the
 * key reaches the `__proto__` accessor on `Object.prototype`, which replaces
 * the target's prototype with the attacker's object, and every property in it
 * becomes inherited. A webhook body wrapped by `wrapSensitiveByPath` then
 * answered `wrapped.isAdmin === true` where the input answered `undefined`,
 * and a shadowed `hasOwnProperty` turned the next call on it into a
 * `TypeError`. The path helpers already refused the name; the copies did not.
 *
 * A defined own data property is what the source had, so it is what the copy
 * gets, and the key survives a round trip through `JSON.stringify` as the key
 * it was. Every other key is assigned as before, so a setter a class declares
 * still runs, which `redactCopy` relies on.
 */
export function assignOwn(target: object, key: string, value: unknown): void {
  if (key === '__proto__') {
    Object.defineProperty(target, key, {
      value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
    return;
  }

  (target as Record<string, unknown>)[key] = value;
}
