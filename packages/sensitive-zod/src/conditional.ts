/**
 * Sensitivity that depends on a sibling field.
 *
 * Some payloads carry a value whose classification is decided by another field
 * in the same object: a settings row that is a secret only when its `type` says
 * so. Wrapping that after the parse means the raw string exists, unwrapped, for
 * as long as it takes to look at the discriminator. This builds the decision
 * into the schema instead.
 *
 * @packageDocumentation
 */

import { z } from 'zod';
import type { SensitiveString, SensitivityClass } from '@platform-sec/sensitive-string-core';
import { zSensitiveString } from './base.js';

/**
 * How to classify the value for one discriminator case. `null` leaves the
 * value a plain string.
 */
export interface ConditionalSensitivity {
  /** The sensitivity classification to apply for this case. */
  klass: SensitivityClass;
  /** Optional label for audit/compliance. */
  label?: string;
}

/**
 * The map from discriminator value to classification.
 */
export type ConditionalConditions = Readonly<Record<string, ConditionalSensitivity | null>>;

/**
 * The value type produced for one case: wrapped when the case names a class,
 * a plain string when it is `null`.
 */
type ConditionalValue<T> = T extends { klass: infer C extends SensitivityClass }
  ? SensitiveString<C>
  : string;

/**
 * The discriminated union produced by {@link zConditionalSensitive}.
 */
export type ConditionalSensitiveOutput<
  D extends string,
  V extends string,
  M extends ConditionalConditions,
> = {
  [K in keyof M & string]: { [P in D]: K } & { [P in V]: ConditionalValue<M[K]> };
}[keyof M & string];

/**
 * The accepted input: the discriminator plus a string value.
 */
export type ConditionalSensitiveInput<
  D extends string,
  V extends string,
  M extends ConditionalConditions,
> = { [P in D]: keyof M & string } & { [P in V]: string };

/**
 * Configuration for {@link zConditionalSensitive}.
 */
export interface ConditionalSensitiveConfig<
  D extends string,
  V extends string,
  M extends ConditionalConditions,
> {
  /** The field naming the case. */
  discriminator: D;
  /** The field holding the value to classify. */
  valueField: V;
  /** One entry per accepted discriminator value. */
  conditions: M;
}

/**
 * Build a discriminated union that classifies one field according to another.
 *
 * The result is a plain `z.discriminatedUnion`, so an unknown discriminator is
 * rejected before the value is looked at, and the value never exists unwrapped
 * on a case that classifies it.
 *
 * The generated objects hold exactly the two fields. A payload with more
 * fields than that is better written as a `z.discriminatedUnion` over
 * hand-written branches; `zSensitive` and `zCredential` work as object fields
 * there with nothing extra.
 *
 * @typeParam D - The discriminator field name
 * @typeParam V - The value field name
 * @typeParam M - The conditions map
 * @param config - Discriminator, value field, and one entry per case
 * @returns A discriminated union schema
 * @throws TypeError If `conditions` is empty, or the two field names are the same.
 *
 * @example
 * ```ts
 * const Setting = zConditionalSensitive({
 *   discriminator: 'type',
 *   valueField: 'value',
 *   conditions: {
 *     secret: { klass: 'credential', label: 'secret_data' },
 *     private: { klass: 'sensitive', label: 'private_data' },
 *     public: null,
 *   },
 * });
 *
 * Setting.parse({ type: 'secret', value: 'sk-live-x' });  // value is SensitiveString
 * Setting.parse({ type: 'public', value: 'motd' });       // value is a string
 * ```
 */
export function zConditionalSensitive<
  D extends string,
  V extends string,
  M extends ConditionalConditions,
>(
  config: ConditionalSensitiveConfig<D, V, M>
): z.ZodType<
  ConditionalSensitiveOutput<D, V, M>,
  z.ZodTypeDef,
  ConditionalSensitiveInput<D, V, M>
> {
  // Compared as plain strings: inside the function `D` and `V` are unresolved
  // type parameters, and tsc reads a direct comparison of two of those as
  // having no overlap.
  const discriminator: string = config.discriminator;
  const valueField: string = config.valueField;

  if (discriminator === valueField) {
    // The two names become keys of the same object literal, so the second
    // would overwrite the first and the value field would vanish without a
    // word. A schema that silently stops classifying anything is the worst
    // failure mode this helper has.
    throw new TypeError(
      'zConditionalSensitive requires distinct discriminator and valueField names'
    );
  }

  const entries = Object.entries(config.conditions);
  if (entries.length === 0) {
    throw new TypeError('zConditionalSensitive requires at least one condition');
  }

  const options = entries.map(([discriminatorValue, sensitivity]) =>
    z.object({
      [config.discriminator]: z.literal(discriminatorValue),
      [config.valueField]:
        sensitivity == null ? z.string() : zSensitiveString(sensitivity.klass, sensitivity.label),
    })
  );

  // The branches are built from a runtime map, so their literal types are not
  // recoverable by inference. The declared return type states the union those
  // branches produce; the cast on `options` is the seam between the two.
  return z.discriminatedUnion(
    config.discriminator,
    options as unknown as [z.ZodDiscriminatedUnionOption<D>, ...z.ZodDiscriminatedUnionOption<D>[]]
  );
}
