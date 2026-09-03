import {
  SENSITIVITY_PRECEDENCE,
  SensitiveString,
  defaultCombineClasses,
  type SensitivityClass,
  type SensitiveStringOptions,
} from '@platform-sec/sensitive-string-core';
import { describeType } from './describe-type.js';

/**
 * What an `@Sensitive` accessor may hold.
 *
 * A `SensitiveString` is stored as it is, a string is wrapped, and nullish
 * passes through: an auto-accessor with no initializer is initialized with
 * `undefined`, and wrapping that would produce a protected value holding the
 * text "undefined".
 */
export type SensitiveAccessorValue<C extends SensitivityClass> =
  SensitiveString<C> | string | null | undefined;

/**
 * Reject an accessor whose declared type cannot hold what a read returns.
 *
 * `SensitiveAccessorValue` has to admit `string`, because
 * `accessor email!: string | SensitiveString<'sensitive'>` is a supported
 * declaration: it is what lets a raw string be assigned under TypeScript as
 * well as at runtime. On its own that constraint would also admit a bare
 * `string` accessor, which reads back as a `SensitiveString` while TypeScript
 * still believes it is a string, so `const raw: string = user.email` would
 * compile and a reviewer would believe it.
 *
 * Requiring the declared type to be a supertype of `SensitiveString<C>` rules
 * that one out and leaves the honest declarations alone. The message is a
 * tuple rather than `never` so the compiler prints the fix inside the
 * assignability error.
 */
type AcceptsWrappedValue<C extends SensitivityClass, Value, T> =
  SensitiveString<C> extends Value
    ? T
    : [
        "@Sensitive: this accessor's declared type cannot hold the SensitiveString a read returns. Declare it as SensitiveString<C>, or as string | SensitiveString<C> to also assign raw strings",
      ];

/**
 * Recognized sensitivity classes, so an unrecognized one is named at
 * decoration time rather than reaching `getPolicy` on first assignment.
 */
function isSensitivityClass(value: unknown): value is SensitivityClass {
  return (SENSITIVITY_PRECEDENCE as readonly unknown[]).includes(value);
}

/**
 * Whether a value is already protected, stated at the class-agnostic type.
 *
 * `value instanceof SensitiveString` narrows to `SensitiveString<'sensitive'>`,
 * because that is the class parameter's default, which would have the class
 * check comparing against a type that says the answer in advance.
 */
function isWrapped(value: unknown): value is SensitiveString<SensitivityClass> {
  return value instanceof SensitiveString;
}

/**
 * How an error message names the decorated accessor.
 */
function describeAccessor(name: string | symbol, isStatic: boolean): string {
  return `${isStatic ? 'static accessor' : 'accessor'} '${String(name)}'`;
}

/**
 * The label a wrapped value carries when the decorator was not given one.
 *
 * The property name is already visible in the source, so using it as the audit
 * label discloses nothing and makes redacted output name the field it came
 * from: `SensitiveString<credential:apiKey>`.
 */
function defaultLabel(name: string | symbol): string | undefined {
  return typeof name === 'string' ? name : name.description;
}

/**
 * Mark a class field sensitive, so every value it receives is protected.
 *
 * Applies to Stage 3 auto-accessors, which is the only field form whose
 * assignments a decorator can intercept: a plain field decorator sees the
 * initializer and nothing after it, so a later `user.email = raw` would store a
 * bare string that `JSON.stringify` prints in full. Both the initializer and
 * every later assignment go through this decorator.
 *
 * ```ts
 * class User {
 *   \@Sensitive('sensitive', 'email') accessor email!: SensitiveString<'sensitive'>;
 *   \@Sensitive('credential') accessor passwordHash!: SensitiveString<'credential'>;
 * }
 * ```
 *
 * Declaring the accessor as `string | SensitiveString<C>` instead lets a raw
 * string be assigned under TypeScript as well as at runtime, at the cost of
 * having to narrow on every read. Either declaration wraps.
 *
 * What arrives decides what is stored:
 *
 * - A string is wrapped with this decorator's class, label, and options.
 * - A `SensitiveString` of the same or a more restrictive class is stored as
 *   it is, keeping its own label and options. The decorator's options apply to
 *   values it constructs; tightening an already-wrapped value would mean
 *   reading it, which only `reveal()` may do.
 * - A `SensitiveString` of a less restrictive class is refused, because the
 *   field would then advertise protections its contents do not have. Rule R5:
 *   `reclassify()` is the one audited way to change a class.
 * - `null` and `undefined` pass through.
 * - Anything else is refused rather than coerced, so a mis-shaped payload
 *   fails at the assignment instead of storing `[object Object]`.
 *
 * @param klass - Sensitivity class for values this decorator wraps
 * @param label - Audit label; defaults to the property name
 * @param options - Constructor options for values this decorator wraps, copied
 *   once at decoration time
 * @throws TypeError If `klass` is not a sensitivity class, or if the decorator
 *   is applied to anything but an auto-accessor.
 */
export function Sensitive<C extends SensitivityClass>(
  klass: C,
  label?: string,
  options?: SensitiveStringOptions
) {
  if (!isSensitivityClass(klass)) {
    // Narrowed to `never` here, since the guard above excluded every member of
    // the declared type. The check exists for a caller arriving from JavaScript
    // or through `any`, so the value is inspected as the unknown it actually is
    // at runtime.
    const raw: unknown = klass;
    const received = typeof raw === 'string' ? `'${raw}'` : describeType(raw);

    throw new TypeError(
      `@Sensitive: klass ${received} is not a sensitivity class; expected ` +
        SENSITIVITY_PRECEDENCE.map((name) => `'${name}'`).join(' or ')
    );
  }

  // Copied so a caller that keeps and later mutates the object it passed does
  // not change the constraints of values wrapped after the mutation.
  const wrapOptions = options === undefined ? undefined : { ...options };

  return function <This, Value extends SensitiveAccessorValue<C>>(
    target: AcceptsWrappedValue<C, Value, ClassAccessorDecoratorTarget<This, Value>>,
    context: ClassAccessorDecoratorContext<This, Value>
  ): ClassAccessorDecoratorResult<This, Value> {
    // The conditional above has already rejected every Value it would refuse,
    // so inside the body the target is the accessor pair it always was.
    const pair = target as ClassAccessorDecoratorTarget<This, Value>;

    // Widened, because TypeScript has already narrowed `kind` to 'accessor'
    // from the parameter type. The check is here for JavaScript callers and
    // for a build whose decorator types do not line up, where the failure
    // would otherwise be a field that is quietly never wrapped.
    const kind: string = context.kind;
    if (kind !== 'accessor') {
      throw new TypeError(
        `@Sensitive cannot decorate a ${kind}; it decorates an auto-accessor, ` +
          `declared with the 'accessor' keyword, because that is the only field ` +
          `form whose assignments a decorator can intercept`
      );
    }

    const accessor = describeAccessor(context.name, context.static);
    const wrapLabel = label ?? defaultLabel(context.name);

    const protect = (value: Value): Value =>
      wrapValue(value, klass, wrapLabel, wrapOptions, accessor);

    return {
      // Auto-accessor initializers do not go through `set`: the initial value
      // is passed to `init` and stored directly. Without this hook,
      // `accessor email = 'jane@example.com'` would hold a bare string.
      init(value: Value): Value {
        return protect(value);
      },

      set(this: This, value: Value): void {
        pair.set.call(this, protect(value));
      },

      get(this: This): Value {
        return pair.get.call(this);
      },
    };
  };
}

/**
 * Decide what an assignment actually stores.
 */
function wrapValue<C extends SensitivityClass, Value extends SensitiveAccessorValue<C>>(
  value: Value,
  klass: C,
  label: string | undefined,
  options: SensitiveStringOptions | undefined,
  accessor: string
): Value {
  if (value === undefined || value === null) {
    return value;
  }

  if (isWrapped(value)) {
    // Precedence order decides this, not a policy hook, for the same reason
    // the template tag does not let one relax rule R5.
    if (defaultCombineClasses(value.klass, klass) !== value.klass) {
      throw new TypeError(
        `@Sensitive: ${accessor} is declared '${klass}' but was assigned a ` +
          `'${value.klass}' value, which is less restrictive; use reclassify() ` +
          `to lower a class deliberately and under audit`
      );
    }

    return value;
  }

  if (typeof value !== 'string') {
    throw new TypeError(
      `@Sensitive: ${accessor} was assigned ${describeType(value)}; ` +
        `expected a string, a SensitiveString, or nullish`
    );
  }

  return new SensitiveString(value, klass, label, options) as Value;
}
