import 'reflect-metadata';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { SENSITIVE_FIELDS_KEY } from '../constants.js';

/** How one DTO property is classified. */
export interface SensitiveFieldMetadata {
  /** Sensitivity class the wrapped value receives. */
  klass: SensitivityClass;
  /** Label the wrapped value receives; the property name when omitted. */
  label: string | undefined;
}

/** Every classified property of a DTO class, keyed by property name. */
export type SensitiveFieldMap = ReadonlyMap<string, SensitiveFieldMetadata>;

/**
 * Mark a DTO property as sensitive.
 *
 * The decorator records metadata and nothing else; `SensitiveTransformPipe`
 * does the wrapping, after `ValidationPipe` has validated the plain string.
 *
 * A subclass starts from its parent's map, because `Reflect.getMetadata` walks
 * the prototype chain, and re-decorating a property overrides the parent's
 * classification for that property alone.
 *
 * `@Sensitive` registers no class-validator metadata. Under
 * `ValidationPipe({ whitelist: true })` a property carrying only `@Sensitive`
 * is stripped from the payload before the pipe ever sees it, so give every
 * sensitive property at least one class-validator decorator, or `@Allow()`.
 *
 * @param klass - Sensitivity class for the wrapped value
 * @param label - Audit label; defaults to the property name
 * @throws If applied to a static or symbol-keyed property, neither of which
 *   the pipe could ever wrap
 */
export function Sensitive(klass: SensitivityClass, label?: string): PropertyDecorator {
  return (target, propertyKey) => {
    // A static property decorator receives the constructor rather than the
    // prototype, so `target.constructor` would be `Function` itself: the map
    // would land on a global object and the DTO would carry nothing. A payload
    // cannot populate a static property anyway, so this is always a mistake,
    // and one whose only other symptom is a field that is quietly never
    // wrapped.
    if (typeof target === 'function') {
      throw new TypeError(
        `@Sensitive cannot mark the static property '${String(propertyKey)}'. It marks instance properties of a DTO.`
      );
    }

    // Same reasoning: the pipe looks properties up by string key, so a
    // symbol-keyed field would record metadata that nothing ever matches. No
    // JSON payload can populate one either.
    if (typeof propertyKey === 'symbol') {
      throw new TypeError(
        `@Sensitive cannot mark the symbol-keyed property '${String(propertyKey)}'. Only string-keyed properties can arrive in a payload.`
      );
    }

    const ctor = target.constructor;
    const inherited = getSensitiveFields(ctor) ?? new Map<string, SensitiveFieldMetadata>();
    // Copy rather than mutate: the inherited map may be the parent's own, and
    // defining a field on a subclass must not reach back into the parent.
    const fields = new Map(inherited);

    fields.set(propertyKey, { klass, label });
    Reflect.defineMetadata(SENSITIVE_FIELDS_KEY, fields, ctor);
  };
}

/**
 * The sensitive-field map of a class, or `undefined` when it has none.
 *
 * Accepts `unknown` because its callers pass `ArgumentMetadata.metatype` and
 * `value.constructor`, neither of which is typed as a constructor.
 */
export function getSensitiveFields(ctor: unknown): SensitiveFieldMap | undefined {
  if (typeof ctor !== 'function') {
    return undefined;
  }

  const fields: unknown = Reflect.getMetadata(SENSITIVE_FIELDS_KEY, ctor);

  return fields instanceof Map ? (fields as SensitiveFieldMap) : undefined;
}
