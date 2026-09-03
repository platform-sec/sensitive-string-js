import { Injectable, type ArgumentMetadata, type PipeTransform } from '@nestjs/common';
import { SensitiveString, type SensitivityClass } from '@platform-sec/sensitive-string-core';
import { getSensitiveFields, type SensitiveFieldMap } from '../decorators/sensitive.decorator.js';

/**
 * Wrap the `@Sensitive` properties of a DTO in `SensitiveString` instances.
 *
 * Register it after `ValidationPipe`, through the same mechanism, so the order
 * is deterministic:
 *
 * ```ts
 * app.useGlobalPipes(
 *   new ValidationPipe({
 *     transform: true,
 *     whitelist: true,
 *     validationError: { target: false, value: false },
 *   }),
 *   new SensitiveTransformPipe(),
 * );
 * ```
 *
 * class-validator decorators must see plain strings: a wrapped value fails
 * `@IsEmail()` and `@MinLength()`. Running this pipe first would break
 * validation rather than tighten it.
 *
 * The pipe applies to every parameter whose `metatype` is a user-defined
 * class, which covers `@Body()`, `@Query()`, and `@Param()` DTOs as well as
 * GraphQL `@Args()`. It deliberately does not gate on
 * `metadata.type === 'body'`.
 */
@Injectable()
export class SensitiveTransformPipe implements PipeTransform {
  transform(value: unknown, metadata: ArgumentMetadata): unknown {
    if (!isCandidate(metadata.metatype)) {
      return value;
    }

    // The declared class is passed in as the fallback for the root, because
    // the root is not always an instance of it: with `transform: false`, or
    // with no `ValidationPipe` at all, the parameter is the parsed body, a
    // plain object whose constructor carries no metadata.
    wrapTree(value, new WeakSet(), getSensitiveFields(metadata.metatype));

    return value;
  }
}

const BUILT_IN_METATYPES: readonly unknown[] = [String, Boolean, Number, Array, Object];

/**
 * Whether a parameter is worth walking.
 *
 * The test is the one `ValidationPipe` applies before it validates: a
 * user-defined class, rather than a built-in that NestJS uses as the metatype
 * for an untyped or primitive parameter. A `@Param('id') id: string` reflects
 * as `String` and is skipped; a `@SensitiveHeader()` parameter reflects as
 * `Object` and is skipped, which is also what keeps the pipe off values the
 * parameter decorators already wrapped.
 *
 * Gating instead on "does this exact class carry `@Sensitive` metadata" would
 * be cheaper and wrong: a DTO whose only sensitive data sits in a nested DTO
 * carries none of its own, so the payload it guards would pass through
 * unwrapped. Nested classes cannot be discovered from the outer class without
 * `design:type`, which does not survive an array-typed property, so the outer
 * gate has to be this loose and the walk decides per object.
 */
function isCandidate(metatype: unknown): boolean {
  return typeof metatype === 'function' && !BUILT_IN_METATYPES.includes(metatype);
}

/**
 * Wrap in place, depth first.
 *
 * In place rather than by copying, because `ValidationPipe({ transform: true })`
 * has just produced a DTO instance and spreading it into a new object would
 * drop the prototype that `ClassSerializerInterceptor` and the DTO's own
 * methods depend on.
 *
 * Nested DTOs are found by the runtime class of the value, which is how
 * class-validator's `@ValidateNested()` already works: it needs
 * `@Type(() => Nested)` and `transform: true` so class-transformer
 * instantiates the nested class. Without those the nested value is a plain
 * object, carries no metadata, and is left alone.
 *
 * `fallback` is the declared class's field map, and applies to the root and to
 * the elements of a root array only. Passing it further down would classify a
 * nested plain object by its parent's field names, which is a different object
 * wearing the same keys.
 */
function wrapTree(value: unknown, seen: WeakSet<object>, fallback?: SensitiveFieldMap): void {
  if (value === null || typeof value !== 'object') {
    return;
  }

  // An already-wrapped value is a leaf. Recursing into one would find only its
  // public `klass` and `label`, and `#value` is unreachable from here anyway.
  if (value instanceof SensitiveString || seen.has(value)) {
    return;
  }

  seen.add(value);

  if (Array.isArray(value)) {
    for (const item of value) {
      wrapTree(item, seen, fallback);
    }

    return;
  }

  const fields = getSensitiveFields(value.constructor) ?? fallback;

  if (fields) {
    wrapFields(value as Record<string, unknown>, fields);
  }

  for (const child of Object.values(value)) {
    wrapTree(child, seen);
  }
}

/**
 * Wrap the classified properties of one object.
 *
 * Only strings and arrays of strings are wrapped. Coercing with `String(value)`
 * would turn an object into a `"[object Object]"` credential and a number into
 * a credential that was never validated as one; rejecting the wrong type is
 * `ValidationPipe`'s job, and a value it let through unwrapped is visibly wrong
 * rather than silently mislabelled.
 *
 * Values that are already `SensitiveString` instances are left alone, so
 * running the pipe twice does not double-wrap.
 */
function wrapFields(target: Record<string, unknown>, fields: SensitiveFieldMap): void {
  for (const [key, { klass, label }] of fields) {
    const current = target[key];
    const wrap = (raw: string): SensitiveString<SensitivityClass> =>
      new SensitiveString(raw, klass, label ?? key);

    if (typeof current === 'string') {
      target[key] = wrap(current);
    } else if (Array.isArray(current)) {
      target[key] = current.map((item: unknown) => (typeof item === 'string' ? wrap(item) : item));
    }
  }
}
