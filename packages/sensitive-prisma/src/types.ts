import type { SensitiveString, SensitivityClass } from '@platform-sec/sensitive-string-core';
import { revealArgs, type RevealAttribution } from './args.js';
import type { ModelFieldConfig, SensitiveExtensionConfig, SensitiveFieldSpec } from './config.js';

/** The sensitivity class a field spec names, in either of its two forms. */
export type ClassOf<S> = S extends SensitivityClass
  ? S
  : S extends { readonly klass: infer K extends SensitivityClass }
    ? K
    : never;

/**
 * The type a configured field reads back as.
 *
 * `list` and `nullable` in the spec are what widen it; they describe the
 * column, and the computed field's declared return type is what Prisma
 * publishes as the field's type.
 */
export type WrappedField<S> =
  | (S extends { readonly list: true }
      ? SensitiveString<ClassOf<S>>[]
      : SensitiveString<ClassOf<S>>)
  | (S extends { readonly nullable: true } ? null : never);

/**
 * The `result` component `sensitiveExtension()` hands to Prisma, as a type.
 *
 * Prisma's `$extends` inference reads the declared return type of each
 * `compute` and republishes it as the field's type, including through `select`,
 * `include` and `omit`. That is the whole read-side type strategy: there is no
 * parallel type layer over Prisma's output, so narrowing keeps working.
 */
export type SensitiveResultComponent<C extends SensitiveExtensionConfig> = {
  [M in keyof C['models'] & string as Uncapitalize<M>]: {
    [F in keyof C['models'][M] & string]: {
      readonly needs: { readonly [K in F]: true };
      readonly compute: (row: { [K in F]: unknown }) => WrappedField<C['models'][M][F]>;
    };
  };
};

/**
 * A write input with every `SensitiveString` replaced by `string`.
 *
 * Prisma's generated input types say `string`, and a query extension cannot
 * change them: the extension sees runtime values only. This is the type side of
 * that gap, and `sensitiveInput()` is the one place the cast lives so
 * application code never writes `as unknown as string`.
 *
 * Everything that is not a plain object or an array is returned by identity, so
 * `Date`, `Uint8Array`, `Decimal` and the other column types Prisma accepts
 * survive: mapping over a class would produce a structural copy that no longer
 * matches it.
 */
export type UnwrapSensitive<T> =
  T extends SensitiveString<SensitivityClass>
    ? string
    : T extends string | number | boolean | bigint | symbol | null | undefined
      ? T
      : T extends (...args: never[]) => unknown
        ? T
        : T extends Date | RegExp | Uint8Array | ArrayBuffer
          ? T
          : T extends readonly (infer U)[]
            ? UnwrapSensitive<U>[]
            : T extends { readonly d: unknown; readonly e: unknown; readonly s: unknown }
              ? T
              : T extends object
                ? { [K in keyof T]: UnwrapSensitive<T[K]> }
                : T;

/**
 * Unwrap every `SensitiveString` in a Prisma argument, through an audited reveal.
 *
 * This is where a write is unwrapped, and it has to be, because it is the last
 * point at which the value still exists. Prisma copies query arguments before
 * any extension hook runs, and the copy cannot reach an ES `#private` field: by
 * the time the extension's query hook is called, a `SensitiveString` in `data`
 * has already been flattened to its class and label with no value behind it.
 * The extension recognises that wreckage and refuses the query, so a forgotten
 * call here fails loudly rather than persisting a redaction marker, but only a
 * call at the call site can succeed.
 *
 * Types line up as a consequence rather than as the point: Prisma's generated
 * input types say `string`, `UnwrapSensitive<T>` says the same, so the result
 * is assignable and no application ever writes `as unknown as string`.
 *
 * Each replacement is one `reveal()` and one audit entry. An ambient context
 * from `withRevealContext()` is inherited, including its `auditReveal` hook,
 * and each reveal runs under a child context tagged with the argument path.
 *
 * Plain values, `Date`, `Uint8Array`, `Decimal` and every other class instance
 * pass through untouched, and any subtree with nothing wrapped in it is
 * returned by identity.
 *
 * @param value - The argument to prepare: `data`, `where`, `create`, `update`,
 * or an array of them for `createMany`.
 * @param attribution - Optional `model`, `operation`, `name` and `reason` for
 * the audit tags. An ambient context's own `name` and `reason` still win.
 *
 * @example
 * ```ts
 * await prisma.user.update({
 *   where: { id: 1 },
 *   data: sensitiveInput(
 *     { passwordHash: new SensitiveString(hash, 'credential') },
 *     { model: 'User', operation: 'update' }
 *   ),
 * });
 * ```
 */
export function sensitiveInput<T>(value: T, attribution?: RevealAttribution): UnwrapSensitive<T> {
  return revealArgs(value, attribution) as UnwrapSensitive<T>;
}

/** One column of a raw row, wrapped according to its field spec. */
export type WrapValue<V, S extends SensitiveFieldSpec> = V extends null
  ? null
  : V extends undefined
    ? undefined
    : V extends readonly string[]
      ? SensitiveString<ClassOf<S>>[]
      : V extends string
        ? SensitiveString<ClassOf<S>>
        : V;

/**
 * A raw query row with its configured columns wrapped.
 *
 * Driven by the row type the caller gave `$queryRaw`, so a nullable column
 * declared `string | null` reads back as `SensitiveString<C> | null` without
 * the spec having to repeat it.
 */
export type WrapRow<Row, Fields extends ModelFieldConfig> = {
  [K in keyof Row]: K extends keyof Fields ? WrapValue<Row[K], Fields[K]> : Row[K];
};
