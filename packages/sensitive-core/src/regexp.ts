/* eslint-disable @typescript-eslint/unbound-method --
   Detaching these getters from RegExp.prototype is the point: a subclass or an
   instance with an overridden `source` cannot influence what is read. Each is
   annotated `this: RegExp` and invoked through .call() with the pattern as the
   receiver, which is the binding the rule asks for. */
const REGEXP_SOURCE_GETTER = Object.getOwnPropertyDescriptor(RegExp.prototype, 'source')?.get as (
  this: RegExp
) => string;
const REGEXP_FLAGS_GETTER = Object.getOwnPropertyDescriptor(RegExp.prototype, 'flags')?.get as (
  this: RegExp
) => string;
/* eslint-enable @typescript-eslint/unbound-method */

/**
 * The pattern's own source and flags, read through the intrinsic getters.
 *
 * Calling them verifies the RegExp internal slots, works across realms, and
 * bypasses an instance's overridden `source` or `flags`, which could otherwise
 * report one pattern to the library and match another.
 */
function readPattern(pattern: RegExp, operation: string): { source: string; flags: string } {
  try {
    return {
      source: REGEXP_SOURCE_GETTER.call(pattern),
      flags: REGEXP_FLAGS_GETTER.call(pattern),
    };
  } catch {
    throw new TypeError(`${operation} requires a regular expression`);
  }
}

/**
 * Copy a caller-provided regular expression into a plain RegExp.
 *
 * RegExp subclasses and instances with overridden `exec` or symbol methods must
 * not receive a sensitive value, so the pattern is rebuilt from its own source
 * and flags rather than used directly. The copy also keeps a match from moving
 * the caller's `lastIndex`.
 *
 * @param operation - The fully qualified name to name in a rejection, such as
 *   `'SensitiveString.test'`. It is the whole message, not a suffix, so a
 *   caller reads back the function they actually called.
 */
export function snapshotRegExp(pattern: RegExp, operation: string): RegExp {
  const { source, flags } = readPattern(pattern, operation);
  return new RegExp(source, flags);
}

/**
 * The same, without the flags that make `test()` stateful.
 *
 * A stored pattern is tested repeatedly against different strings. `g` and `y`
 * make `test()` advance `lastIndex` and answer differently on each call, so a
 * pattern kept for the life of a process would match every other time it was
 * consulted. Dropping them is not a restriction on what a caller may express:
 * neither flag changes which strings the pattern matches, only where the next
 * search resumes.
 */
export function snapshotStatelessRegExp(pattern: RegExp, operation: string): RegExp {
  const { source, flags } = readPattern(pattern, operation);
  return new RegExp(source, flags.replace(/[gy]/g, ''));
}
