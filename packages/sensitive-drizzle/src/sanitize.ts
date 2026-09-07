/** What a redacted parameter is replaced with on an error object. */
export const ERROR_PARAMETER_CENSOR = '[REDACTED:drizzle-parameter]';

/** What the rebuilt message says in place of the parameters. */
const MESSAGE_CENSOR = '[REDACTED:drizzle-parameters]';

/**
 * Recognise Drizzle's query error by shape rather than by class.
 *
 * Structural because the root entry point of this package imports no
 * `drizzle-orm` at runtime, and because an application with two copies of the
 * ORM in its graph would fail an `instanceof` against the wrong one at exactly
 * the moment it mattered.
 */
function looksLikeQueryError(error: object): boolean {
  const named: unknown = Object.getOwnPropertyDescriptor(error, 'name')?.value;
  const name = named ?? (error as { constructor?: { name?: string } }).constructor?.name;
  if (name === 'DrizzleQueryError') return true;
  return (
    Object.getOwnPropertyDescriptor(error, 'query') !== undefined &&
    Object.getOwnPropertyDescriptor(error, 'params') !== undefined
  );
}

/** Replace one parameter array with censors, preserving its length. */
function censor(value: unknown): unknown {
  if (!Array.isArray(value)) return value;
  return value.map(() => ERROR_PARAMETER_CENSOR);
}

/**
 * The message Drizzle built, with the parameters taken back out.
 *
 * `DrizzleQueryError` composes its message as `Failed query: ${query}\nparams:
 * ${params}`, and template interpolation of an array is `Array.prototype.join`,
 * so a one-parameter statement puts the bare revealed value in the message.
 * This is the difference from the equivalent problem in TypeORM, where the
 * plaintext is only a structured property: here it is in the string that goes
 * into every stack trace, every `console.error` and every error tracker that
 * only reads `message`.
 *
 * The query half is kept. It is the statement Drizzle built, with `$1`
 * placeholders rather than values, and it is what makes the error useful.
 */
function sanitizedMessage(message: unknown): string | undefined {
  if (typeof message !== 'string') return undefined;
  const at = message.indexOf('\nparams: ');
  if (at === -1) return undefined;
  return `${message.slice(0, at)}\nparams: ${MESSAGE_CENSOR}`;
}

/**
 * Write the censored value back, or report that the property would not move.
 *
 * Descriptors throughout: reading `error.params` would invoke a getter, and an
 * error captured from somewhere unusual can have one that throws. A frozen
 * error is the case this returns `false` for, and the caller falls back to a
 * copy.
 */
function tryRedactInPlace(target: object, key: string, replacement: unknown): boolean {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  if (descriptor === undefined) return true;

  // An accessor. The getter is never called, so there is no way to know what it
  // would have produced, and leaving it in place would let whatever it returns
  // out.
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
 * The stack with the parameters taken out of the header it was built with.
 *
 * V8 composes `stack` once, at construction, as the name and message followed
 * by the frames, so reassigning `message` afterwards leaves the plaintext in
 * the stack. Sanitizing the message alone would move the leak rather than
 * remove it, and the stack is the copy an error tracker is most likely to
 * keep.
 */
function sanitizedStack(
  stack: unknown,
  original: string | undefined,
  replacement: string | undefined
): string | undefined {
  if (typeof stack !== 'string') return undefined;
  if (original === undefined || replacement === undefined) return undefined;
  if (!stack.includes(original)) return undefined;
  return stack.replace(original, replacement);
}

/** A copy with the same prototype, own descriptors, and censored parameters. */
function redactedCopy(
  error: object,
  message: string | undefined,
  stack: string | undefined
): object {
  const copy = Object.create(Object.getPrototypeOf(error) as object | null) as object;
  for (const key of Reflect.ownKeys(error)) {
    const descriptor = Object.getOwnPropertyDescriptor(error, key);
    if (descriptor === undefined) continue;
    if (key === 'params') {
      const value =
        'value' in descriptor && Array.isArray(descriptor.value)
          ? censor(descriptor.value)
          : [ERROR_PARAMETER_CENSOR];
      Object.defineProperty(copy, key, {
        enumerable: descriptor.enumerable ?? true,
        writable: true,
        configurable: true,
        value,
      });
      continue;
    }
    if (key === 'message' && message !== undefined) {
      Object.defineProperty(copy, key, {
        enumerable: descriptor.enumerable ?? false,
        writable: true,
        configurable: true,
        value: message,
      });
      continue;
    }
    if (key === 'stack' && stack !== undefined) {
      Object.defineProperty(copy, key, {
        enumerable: descriptor.enumerable ?? false,
        writable: true,
        configurable: true,
        value: stack,
      });
      continue;
    }
    Object.defineProperty(copy, key, descriptor);
  }
  return copy;
}

/**
 * Remove the revealed parameters from a Drizzle query error.
 *
 * `DrizzleQueryError` is thrown for every failing statement on every dialect,
 * and it carries the bound parameters three times: as `params`, an own
 * enumerable property; interpolated into `message`; and in the header of
 * `stack`, which V8 composes once at construction so that reassigning the
 * message afterwards does not move it. By the time the error exists the
 * parameters are the revealed plaintext, because that is what was sent. All
 * three copies are removed; `query`, `cause`, `name` and the frames are kept.
 *
 * A `cause` is left alone. It is the driver's own error, and what a driver puts
 * in it varies: Postgres reports the conflicting value in `detail` for several
 * constraint classes. That is what the scrub fragment covers, on the way out to
 * an error tracker, rather than being guessed at here.
 *
 * Never throws. It works through property descriptors so a getter that throws
 * is never invoked, redacts in place where the property allows it, and falls
 * back to a copy with the same prototype where it does not, so `instanceof`,
 * `name` and the frames of the stack all survive. If even that fails, a bare
 * `Error` carrying only the name is returned rather than the original: an error
 * whose parameters could not be removed is not one to hand onwards, and its
 * stack begins with the message they were in.
 *
 * It has to be called. A `catch` block, or a framework's error filter, is where
 * it goes.
 *
 * @example
 * ```ts
 * try {
 *   await db.insert(users).values(row);
 * } catch (error) {
 *   throw sanitizeQueryError(error);
 * }
 * ```
 */
export function sanitizeQueryError(error: unknown): unknown {
  if (typeof error !== 'object' || error === null) return error;

  try {
    if (!looksLikeQueryError(error)) return error;

    const descriptor = Object.getOwnPropertyDescriptor(error, 'params');
    const replacement =
      descriptor !== undefined && 'value' in descriptor && Array.isArray(descriptor.value)
        ? censor(descriptor.value)
        : [ERROR_PARAMETER_CENSOR];

    const messageDescriptor = Object.getOwnPropertyDescriptor(error, 'message');
    const original: unknown =
      messageDescriptor !== undefined && 'value' in messageDescriptor
        ? messageDescriptor.value
        : undefined;
    const message = sanitizedMessage(original);
    const stackDescriptor = Object.getOwnPropertyDescriptor(error, 'stack');
    const stack = sanitizedStack(
      stackDescriptor !== undefined && 'value' in stackDescriptor
        ? stackDescriptor.value
        : undefined,
      typeof original === 'string' ? original : undefined,
      message
    );

    let ok = tryRedactInPlace(error, 'params', replacement);
    if (message !== undefined && !tryRedactInPlace(error, 'message', message)) ok = false;
    if (stack !== undefined && !tryRedactInPlace(error, 'stack', stack)) ok = false;
    if (ok) return error;

    return redactedCopy(error, message, stack);
  } catch {
    const fallback = new Error(
      'A Drizzle query failed and its error could not be sanitized, so neither its message nor ' +
        'its parameters are reproduced here.'
    );
    fallback.name =
      typeof (error as { name?: unknown }).name === 'string'
        ? (error as { name: string }).name
        : 'Error';
    // The original stack is not carried across. Its header is the original
    // message, which is where the parameters were.
    return fallback;
  }
}
