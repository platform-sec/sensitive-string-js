/** What a redacted parameter is replaced with on an error object. */
export const ERROR_PARAMETER_CENSOR = '[REDACTED:typeorm-parameter]';

/** Own properties that hold bound parameters, on the error and on its driver error. */
const PARAMETER_KEYS = ['parameters'];

/**
 * Recognise a TypeORM query error by shape rather than by class.
 *
 * Structural because this package imports no `typeorm` at runtime, and because
 * an application with two copies of the ORM in its graph would fail an
 * `instanceof` against the wrong one at exactly the moment it mattered.
 */
function looksLikeQueryError(error: object): boolean {
  const named: unknown = Object.getOwnPropertyDescriptor(error, 'name')?.value;
  const name = named ?? (error as { constructor?: { name?: string } }).constructor?.name;
  if (name === 'QueryFailedError') return true;
  return (
    Object.getOwnPropertyDescriptor(error, 'query') !== undefined &&
    Object.getOwnPropertyDescriptor(error, 'parameters') !== undefined
  );
}

/** Replace one parameter array with censors, preserving its length. */
function censor(value: unknown): unknown {
  if (!Array.isArray(value)) return value;
  return value.map(() => ERROR_PARAMETER_CENSOR);
}

/**
 * Write the censored array back, or report that the property would not move.
 *
 * Descriptors throughout: reading `error.parameters` would invoke a getter, and
 * an error captured from somewhere unusual can have one that throws. A frozen
 * error is the case this returns `false` for, and the caller falls back to a
 * copy.
 */
function tryRedactInPlace(target: object, key: string): boolean {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  if (descriptor === undefined) return true;

  // An accessor. The getter is never called, so there is no way to know how
  // many parameters it would have produced, and leaving it in place would let
  // whatever it returns out. It is replaced by a single censor entry: the count
  // is lost and the value is gone, which is the right way round.
  if (!('value' in descriptor)) {
    if (descriptor.configurable !== true) return false;
    try {
      Object.defineProperty(target, key, {
        value: [ERROR_PARAMETER_CENSOR],
        writable: true,
        enumerable: descriptor.enumerable ?? true,
        configurable: true,
      });
      return true;
    } catch {
      return false;
    }
  }

  if (!Array.isArray(descriptor.value)) return true;
  if (descriptor.writable !== true && descriptor.configurable !== true) return false;
  try {
    Object.defineProperty(target, key, { ...descriptor, value: censor(descriptor.value) });
    return true;
  } catch {
    return false;
  }
}

/** A copy with the same prototype, own descriptors, and censored parameters. */
function redactedCopy(error: object): object {
  const copy = Object.create(Object.getPrototypeOf(error) as object | null) as object;
  for (const key of Reflect.ownKeys(error)) {
    const descriptor = Object.getOwnPropertyDescriptor(error, key);
    if (descriptor === undefined) continue;
    if (typeof key === 'string' && PARAMETER_KEYS.includes(key)) {
      // Including an accessor, which is copied as a censored data property
      // rather than carried across: copying the getter would copy the leak.
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
    Object.defineProperty(copy, key, descriptor);
  }
  return copy;
}

/**
 * Remove the revealed parameters from a TypeORM query error.
 *
 * `QueryFailedError` carries `parameters` as an own enumerable property holding
 * the bound values, which by then are the revealed plaintext, on every failing
 * statement on every driver. That is exactly what an error tracker serialises,
 * and it is a structured property rather than a message substring, which makes
 * it both easy to remove and easy to ship by accident.
 *
 * The message is left alone. On SQLite it is clean, which is a property of
 * SQLite's message rather than a guarantee: Postgres puts the conflicting value
 * in the driver error's `detail` for several constraint classes, and that is
 * what the scrub fragment covers.
 *
 * Never throws. It works through property descriptors so a getter that throws
 * is never invoked, redacts in place where the property allows it, and falls
 * back to a copy with the same prototype where it does not, so `instanceof`,
 * `name`, `message` and the stack all survive. If even that fails, a bare
 * `Error` carrying the name, message and stack is returned rather than the
 * original: an error whose parameters could not be removed is not one to hand
 * onwards.
 *
 * It has to be called. A `catch` block, or a NestJS exception filter, is where
 * it goes.
 *
 * @example
 * ```ts
 * try {
 *   await repo.insert(row);
 * } catch (error) {
 *   throw sanitizeQueryFailedError(error);
 * }
 * ```
 */
export function sanitizeQueryFailedError(error: unknown): unknown {
  if (typeof error !== 'object' || error === null) return error;

  try {
    if (!looksLikeQueryError(error)) return error;

    const driverDescriptor = Object.getOwnPropertyDescriptor(error, 'driverError');
    const driverError: unknown =
      driverDescriptor !== undefined && 'value' in driverDescriptor
        ? driverDescriptor.value
        : undefined;

    let ok = true;
    for (const key of PARAMETER_KEYS) {
      if (!tryRedactInPlace(error, key)) ok = false;
    }
    if (typeof driverError === 'object' && driverError !== null && driverError !== error) {
      for (const key of PARAMETER_KEYS) {
        if (!tryRedactInPlace(driverError, key)) ok = false;
      }
    }
    if (ok) return error;

    return redactedCopy(error);
  } catch {
    const fallback = new Error(
      typeof (error as { message?: unknown }).message === 'string'
        ? (error as { message: string }).message
        : 'A TypeORM query failed and its error could not be sanitized.'
    );
    fallback.name =
      typeof (error as { name?: unknown }).name === 'string'
        ? (error as { name: string }).name
        : 'Error';
    if (typeof (error as { stack?: unknown }).stack === 'string') {
      fallback.stack = (error as { stack: string }).stack;
    }
    return fallback;
  }
}
