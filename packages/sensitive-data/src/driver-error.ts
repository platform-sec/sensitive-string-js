/**
 * Taking the revealed parameters back out of a query error.
 *
 * By the time an ORM throws, the bound parameters are the plaintext that was
 * sent. Every ORM measured carries them on the error as an own enumerable
 * property, which is exactly what an error tracker serialises, and some also
 * interpolate them into `message`, which puts them in the header of `stack` as
 * well. This runs on the error itself rather than on a tracker's payload,
 * because by the time an event exists the value is a substring of a message
 * with no structure left to walk, which is why `sensitive-scrub` cannot help.
 *
 * Three properties of the implementation are load bearing and were each learned
 * from a driver rather than reasoned out.
 *
 * Descriptors throughout, never a plain read. Reading `error.params` invokes a
 * getter, and an error captured from somewhere unusual can have one that
 * throws.
 *
 * In place when the property allows it. The error is a control-flow object: the
 * ORM above reads `code` to decide whether to retry, and application code runs
 * `instanceof` on it. A frozen error is the case that falls back to a copy with
 * the same prototype.
 *
 * `stack` whenever `message`, and `stack` read through its getter.
 * `Error.captureStackTrace` installs `stack` as an own accessor and it stays
 * one, so a sanitizer looking for `descriptor.value` finds nothing and rewrites
 * nothing. Its tests still pass, because V8 formats the stack at first access
 * from whatever `message` says by then; that only holds while nothing read the
 * stack first. One `console.error` between the throw and the catch materialises
 * it with the plaintext in the header, and from then on the string is fixed.
 */

/** What a censored parameter is replaced with, per consumer. */
export interface SanitizeShape {
  /**
   * The error's class name, matched without `instanceof`.
   *
   * Structural because a shared layer imports no ORM, and because an
   * application with two copies of one in its graph would fail an `instanceof`
   * against the wrong one at exactly the moment it mattered.
   */
  readonly name: string;
  /**
   * Own property names that together identify this error when `name` has been
   * changed or lost. All of them must be present.
   */
  readonly identifyBy?: readonly string[];
  /** Own properties holding the bound parameters. Censored element by element. */
  readonly parameterKeys: readonly string[];
  /**
   * Own properties holding a nested error whose own `parameterKeys` are
   * censored too. TypeORM's `driverError` is the case.
   */
  readonly nestedKeys?: readonly string[];
  /** What one censored parameter becomes. */
  readonly censor: string;
  /**
   * Rewrite the message, or return `undefined` to leave it alone.
   *
   * Only some ORMs interpolate the parameters into the message. A consumer
   * whose message is clean omits this and nothing touches `message` or `stack`.
   * A consumer that supplies it must return a string that no longer holds a
   * value, and the stack is rewritten from the pair.
   */
  readonly sanitizeMessage?: (message: string) => string | undefined;
  /**
   * A marker whose presence in a stack means the parameters are in it, used
   * when the message no longer matches what the stack was built from. Required
   * for the fallback path of a consumer that supplies `sanitizeMessage`.
   */
  readonly stackMarker?: string;
  /** What replaces the frames when the header cannot be bounded. */
  readonly stackWithheld?: string;
  /** The message a total failure yields. It must name no value. */
  readonly fallbackMessage: string;
}

function ownValue(target: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  return descriptor !== undefined && 'value' in descriptor ? descriptor.value : undefined;
}

function looksLike(error: object, shape: SanitizeShape): boolean {
  const named: unknown = Object.getOwnPropertyDescriptor(error, 'name')?.value;
  const name = named ?? (error as { constructor?: { name?: string } }).constructor?.name;
  if (name === shape.name) return true;

  const identifyBy = shape.identifyBy;
  if (identifyBy === undefined || identifyBy.length === 0) return false;
  return identifyBy.every((key) => Object.getOwnPropertyDescriptor(error, key) !== undefined);
}

/** Replace one parameter array with censors, preserving its length. */
function censorArray(value: unknown, censor: string): unknown {
  if (!Array.isArray(value)) return value;
  return value.map(() => censor);
}

/** What a parameter property should become, whether it is data or an accessor. */
function replacementFor(target: object, key: string, censor: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  // An accessor. The getter is never called, so there is no way to know how
  // many parameters it would have produced, and leaving it in place would let
  // whatever it returns out. The count is lost and the value is gone, which is
  // the right way round.
  if (descriptor === undefined || !('value' in descriptor)) return [censor];
  if (!Array.isArray(descriptor.value)) return [censor];
  return censorArray(descriptor.value, censor);
}

/**
 * Write a replacement back, or report that the property would not move.
 *
 * `false` means the caller must fall back to a copy: a frozen error, or one
 * whose property is neither writable nor configurable.
 */
function tryWriteInPlace(target: object, key: string, replacement: unknown): boolean {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  if (descriptor === undefined) return true;

  if (!('value' in descriptor)) {
    if (descriptor.configurable !== true) return false;
    try {
      Object.defineProperty(target, key, {
        value: replacement,
        writable: true,
        enumerable: descriptor.enumerable ?? true,
        configurable: true,
      });
      return true;
    } catch {
      return false;
    }
  }

  if (descriptor.writable !== true && descriptor.configurable !== true) return false;
  try {
    Object.defineProperty(target, key, { ...descriptor, value: replacement });
    return true;
  } catch {
    return false;
  }
}

/**
 * Read `stack` through the getter, because on a real error that is what it is.
 *
 * Read before `message` moves, which makes the outcome the same either way: the
 * already-materialised string when there is one, and otherwise one formatted
 * from the message the parameters are still in.
 */
function readStack(error: object): string | undefined {
  try {
    const value: unknown = (error as { stack?: unknown }).stack;
    return typeof value === 'string' ? value : undefined;
  } catch {
    // An exotic object whose getter throws. Nothing to sanitize.
    return undefined;
  }
}

/**
 * The stack with the parameters taken out of the header it was built with.
 *
 * The header is found by the message the error carries rather than by looking
 * for where the frames begin. Both were written; the frame-boundary version is
 * the one that can be fooled. A parameter value holding a newline and an
 * indented `at ` splits the header inside the parameters, and the tail is then
 * spliced back on, which produces a stack that reads as censored and carries
 * the value. Replacing the message text cannot do that, because whatever is
 * inside the message goes with it.
 *
 * When the message no longer matches, something rewrote it between the throw
 * and here and there is no reference text left to bound the parameters with.
 * The frames are dropped rather than guessed at.
 */
function sanitizedStack(
  stack: string | undefined,
  original: unknown,
  cleaned: string | undefined,
  name: string,
  shape: SanitizeShape
): string | undefined {
  if (stack === undefined) return undefined;

  if (
    cleaned !== undefined &&
    typeof original === 'string' &&
    original !== '' &&
    stack.includes(original)
  ) {
    return stack.replace(original, cleaned);
  }

  const marker = shape.stackMarker;
  // Nothing of this ORM's shape in it, so nothing to bound and nothing to fix.
  if (marker === undefined || !stack.includes(marker)) return undefined;

  const header = cleaned ?? (typeof original === 'string' ? original : shape.fallbackMessage);
  const withheld =
    shape.stackWithheld ?? '    at <stack withheld: it carried the query parameters>';
  return `${name}: ${header}\n${withheld}`;
}

/** A copy with the same prototype, own descriptors, and censored properties. */
function redactedCopy(error: object, replacements: ReadonlyMap<string, unknown>): object {
  const copy = Object.create(Object.getPrototypeOf(error) as object | null) as object;

  for (const key of Reflect.ownKeys(error)) {
    const descriptor = Object.getOwnPropertyDescriptor(error, key);
    if (descriptor === undefined) continue;

    if (typeof key === 'string' && replacements.has(key)) {
      // Including an accessor, which is copied as a censored data property
      // rather than carried across: copying the getter would copy the leak.
      Object.defineProperty(copy, key, {
        enumerable: descriptor.enumerable ?? true,
        writable: true,
        configurable: true,
        value: replacements.get(key),
      });
      continue;
    }

    Object.defineProperty(copy, key, descriptor);
  }

  return copy;
}

/**
 * Remove the revealed parameters from a query error.
 *
 * Never throws. Sanitising happens while an error is already in flight, and
 * throwing from here destroys the error the user needed to see. On internal
 * failure the error is replaced by a minimal one carrying the name and nothing
 * else: an error whose parameters could not be removed is not one to hand
 * onwards, and its stack begins with the message they were in.
 *
 * It has to be called. A `catch` block, or a framework's error filter, is where
 * it goes.
 */
export function sanitizeQueryError(error: unknown, shape: SanitizeShape): unknown {
  if (typeof error !== 'object' || error === null) return error;

  try {
    if (!looksLike(error, shape)) return error;

    const replacements = new Map<string, unknown>();
    for (const key of shape.parameterKeys) {
      replacements.set(key, replacementFor(error, key, shape.censor));
    }

    let message: string | undefined;
    let stack: string | undefined;

    if (shape.sanitizeMessage !== undefined) {
      const original: unknown = ownValue(error, 'message');
      message = typeof original === 'string' ? shape.sanitizeMessage(original) : undefined;

      const name: unknown = (error as { name?: unknown }).name;
      stack = sanitizedStack(
        readStack(error),
        original,
        message,
        typeof name === 'string' ? name : 'Error',
        shape
      );

      if (message !== undefined) replacements.set('message', message);
      if (stack !== undefined) replacements.set('stack', stack);
    }

    let ok = true;
    for (const [key, replacement] of replacements) {
      if (!tryWriteInPlace(error, key, replacement)) ok = false;
    }

    for (const key of shape.nestedKeys ?? []) {
      const nested: unknown = ownValue(error, key);
      if (typeof nested !== 'object' || nested === null || nested === error) continue;

      const nestedReplacements = new Map<string, unknown>();
      for (const parameterKey of shape.parameterKeys) {
        nestedReplacements.set(parameterKey, replacementFor(nested, parameterKey, shape.censor));
      }

      let nestedOk = true;
      for (const [parameterKey, replacement] of nestedReplacements) {
        if (!tryWriteInPlace(nested, parameterKey, replacement)) nestedOk = false;
      }

      if (nestedOk) continue;

      // A nested error that would not take the censor in place has to be
      // replaced on the copy, not merely reported. Copying it across by
      // descriptor hands back the original object with the plaintext still on
      // it, under an outer error that otherwise reads as sanitized, which is
      // the worst of the three possible outcomes: it looks like success.
      ok = false;
      replacements.set(key, redactedCopy(nested, nestedReplacements));
    }

    if (ok) return error;

    return redactedCopy(error, replacements);
  } catch {
    return fallbackFor(error, shape);
  }
}

/** Read one property without letting a throwing getter escape. */
function safeString(target: unknown, key: string): string | undefined {
  try {
    const value: unknown = (target as Record<string, unknown>)[key];
    return typeof value === 'string' ? value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The minimal error returned when sanitising failed outright.
 *
 * Every read in here goes through {@link safeString}, and the whole body is
 * guarded, because this runs inside the `catch` that exists to keep
 * `sanitizeQueryError` from throwing. A property read here is exactly as
 * capable of invoking a throwing getter as the ones in the main path, and an
 * exception escaping from the recovery path would defeat the contract at the
 * one moment it is being relied on.
 *
 * A shape with no `sanitizeMessage` is one whose message carries no value,
 * which is a measurement about that ORM rather than a default. For it the
 * message and the stack are the diagnosis and both are carried across. For a
 * shape that does rewrite the message, neither is: the stack's header is the
 * original message, which is where the parameters were.
 */
function fallbackFor(error: unknown, shape: SanitizeShape): Error {
  try {
    const safeText = shape.sanitizeMessage === undefined;
    const originalMessage = safeText ? safeString(error, 'message') : undefined;

    const fallback = new Error(originalMessage ?? shape.fallbackMessage);
    fallback.name = safeString(error, 'name') ?? 'Error';

    if (safeText) {
      const originalStack = safeString(error, 'stack');
      if (originalStack !== undefined) fallback.stack = originalStack;
    }
    return fallback;
  } catch {
    return new Error(shape.fallbackMessage);
  }
}
