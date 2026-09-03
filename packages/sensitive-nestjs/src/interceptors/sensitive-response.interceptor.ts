import {
  Injectable,
  StreamableFile,
  type CallHandler,
  type ExecutionContext,
  type NestInterceptor,
} from '@nestjs/common';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { map, type Observable } from 'rxjs';

/**
 * Replace every `SensitiveString` in a response body with its redacted form.
 *
 * This is defense in depth, not the primary guarantee: `toJSON()` already
 * redacts whenever the body reaches `JSON.stringify`. It earns its place when
 * something serializes the body another way, most often
 * `ClassSerializerInterceptor`, whose `instanceToPlain` copies the public
 * `klass` and `label` of a `SensitiveString` and drops the redaction marker
 * entirely.
 *
 * Register it after any serializer. Interceptors process responses innermost
 * first and later registration is inner, so this ordering redacts before
 * `instanceToPlain` runs:
 *
 * ```ts
 * { provide: APP_INTERCEPTOR, useClass: ClassSerializerInterceptor },
 * { provide: APP_INTERCEPTOR, useClass: SensitiveResponseInterceptor },
 * ```
 */
@Injectable()
export class SensitiveResponseInterceptor implements NestInterceptor {
  intercept(_context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next.handle().pipe(map((body: unknown) => redactResponse(body, new WeakMap())));
  }
}

/**
 * Copy a response body with every `SensitiveString` redacted.
 *
 * `redactInStructure` from core is not used here: for an object that is
 * neither plain nor carrying `toJSON()` it falls back to `String(obj)`, which
 * turns an entity instance into `"[object Object]"`.
 *
 * The walk never mutates its input. An entity may be shared with an ORM
 * identity map or a cache, and redacting it in place would corrupt the value
 * the application still holds. Copies keep the original prototype so entity
 * `toJSON()` methods and `ClassSerializerInterceptor` still see class
 * instances.
 *
 * `copies` maps each visited object to its copy, which is what stops a cycle
 * from recursing forever. A set of "objects seen anywhere in the walk" would
 * also stop it, but it cannot tell a cycle from an object that legitimately
 * appears twice: `{ author: user, reviewer: user }` would lose the second
 * reference. Memoizing instead preserves shared references, and a genuine
 * cycle produces a cyclic copy that fails at `JSON.stringify` exactly as the
 * original body would have.
 *
 * Values reachable only through prototype getters are not visited, since the
 * walk reads own enumerable properties. Those are still redacted by `toJSON()`
 * during JSON serialization.
 */
function redactResponse(value: unknown, copies: WeakMap<object, unknown>): unknown {
  if (value === null || typeof value !== 'object') {
    return value;
  }

  if (value instanceof SensitiveString) {
    return value.toString();
  }

  // Bodies that are not JSON trees: copying them would break the response.
  // A Date is passed through for the same reason, its own toJSON() already
  // producing the wire form.
  //
  // Map, Set, RegExp, and URL are here because their contents live in internal
  // slots rather than own properties. Copying the prototype and the own
  // properties would produce something that answers `instanceof Map` and
  // throws on `.get()`. They serialize the same either way, and a
  // SensitiveString inside one is not reachable by JSON.stringify, so passing
  // them through neither leaks nor loses anything.
  if (
    value instanceof StreamableFile ||
    value instanceof Date ||
    value instanceof Map ||
    value instanceof Set ||
    value instanceof RegExp ||
    value instanceof URL ||
    Buffer.isBuffer(value) ||
    typeof (value as { pipe?: unknown }).pipe === 'function'
  ) {
    return value;
  }

  const existing = copies.get(value);

  if (existing !== undefined) {
    return existing;
  }

  if (Array.isArray(value)) {
    const copy: unknown[] = [];

    copies.set(value, copy);

    for (const item of value) {
      copy.push(redactResponse(item, copies));
    }

    return copy;
  }

  // Plain objects and class instances alike, the prototype carried over so a
  // serializer downstream still sees the class it expects.
  const copy: Record<string, unknown> = Object.create(
    Object.getPrototypeOf(value) as object | null
  ) as Record<string, unknown>;

  copies.set(value, copy);

  for (const [key, child] of Object.entries(value)) {
    copy[key] = redactResponse(child, copies);
  }

  return copy;
}
