import { hasPolicy } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { PrismaConfigError } from './errors.js';

/**
 * How one column is classified.
 *
 * The bare class is the common case and reads well in a table of fields; the
 * object form adds the label and the two shape flags. `nullable` and `list`
 * exist because the computed field's declared return type is what Prisma
 * publishes as the field's type, and a required-scalar type on a nullable
 * column would be a lie the compiler propagates. They describe the column, so
 * they must match the schema.
 */
export type SensitiveFieldSpec =
  | SensitivityClass
  | {
      /** Sensitivity class; must be registered with core's policy registry. */
      readonly klass: SensitivityClass;
      /** Audit label. Defaults to the field name. */
      readonly label?: string;
      /** The column is nullable (`String?`). Widens the read type with `null`. */
      readonly nullable?: boolean;
      /** The column is a scalar list (`String[]`). Wraps each element. */
      readonly list?: boolean;
    };

/** The classified fields of one model, keyed by field name. */
export type ModelFieldConfig = { readonly [field: string]: SensitiveFieldSpec };

/**
 * The configuration `sensitiveExtension()` takes.
 *
 * Model keys use the schema's casing (`User`, `PaymentMethod`); the extension
 * maps them to Prisma's client casing when it builds the result component.
 */
export interface SensitiveExtensionConfig {
  /** Models to classify, keyed by schema model name. */
  readonly models: { readonly [model: string]: ModelFieldConfig };
  /**
   * Name and reason used for writes when no ambient reveal context supplies
   * them. An ambient context set with `withRevealContext()` takes precedence,
   * so a request-scoped audit trail is not replaced by a static string.
   */
  readonly writeContext?: {
    readonly name?: string;
    readonly reason?: string;
  };
  /**
   * Refuse an operation whose arguments still carry a `SensitiveString` that
   * `sensitiveInput()` never unwrapped. On by default.
   *
   * The check recognises the exact wreckage Prisma's argument copy leaves: a
   * plain object whose only keys are `klass` and `label`, with a registered
   * sensitivity class. Turn it off only for a schema that has two columns named
   * `klass` and `label` where the first holds a class name, which is the one
   * shape that can be mistaken for it.
   */
  readonly detectUnwrapped?: boolean;
}

/** One field after defaults are filled in. */
export interface NormalizedField {
  readonly klass: SensitivityClass;
  readonly label: string;
  readonly nullable: boolean;
  readonly list: boolean;
}

/** One model's fields, keyed for O(1) lookup. */
export interface NormalizedModel {
  /**
   * The model name as the configuration spelled it.
   *
   * Kept alongside the client key because a refusal has to name what the
   * author wrote: `User.email`, not the `user.email` the extension derived.
   */
  readonly name: string;
  readonly fields: ReadonlyMap<string, NormalizedField>;
}

/** The whole configuration after validation. */
export interface NormalizedConfig {
  /** Keyed by Prisma's client property name (`user`), not the schema name. */
  readonly models: ReadonlyMap<string, NormalizedModel>;
  readonly writeContext: { readonly name?: string; readonly reason?: string };
  readonly detectUnwrapped: boolean;
}

/**
 * Prisma's schema-name to client-property mapping: lowercase the first
 * character and leave the rest alone. `PaymentMethod` becomes `paymentMethod`.
 * Idempotent, so a configuration already written in client casing still works.
 */
export function clientKey(model: string): string {
  return model.charAt(0).toLowerCase() + model.slice(1);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  return `a ${typeof value}`;
}

/**
 * Validate one field spec and fill in its defaults.
 *
 * `location` is the human name the refusals use, so the same routine serves the
 * extension configuration (`User.email`) and `wrapRows` (`column 'email'`).
 */
export function normalizeField(location: string, field: string, spec: unknown): NormalizedField {
  if (typeof spec === 'string') {
    assertKnownClass(location, spec);
    return { klass: spec, label: field, nullable: false, list: false };
  }

  if (!isPlainObject(spec)) {
    throw new PrismaConfigError(
      `${location} must be a sensitivity class or { klass, label?, nullable?, list? }; received ${describe(spec)}.`
    );
  }

  const { klass, label, nullable, list, ...rest } = spec;

  // An unknown key is almost always a misspelling of one of the four that
  // matter, and silently ignoring it means the field ships without the
  // behaviour the author asked for.
  const extra = Object.keys(rest);
  if (extra.length > 0) {
    throw new PrismaConfigError(
      `${location} has ${extra.length === 1 ? 'an unknown key' : 'unknown keys'} ${extra
        .map((key) => `'${key}'`)
        .join(', ')}. Valid keys are klass, label, nullable and list.`
    );
  }

  if (typeof klass !== 'string') {
    throw new PrismaConfigError(
      `${location} is missing 'klass', or it is not a string; received ${describe(klass)}.`
    );
  }
  assertKnownClass(location, klass);

  if (label !== undefined && typeof label !== 'string') {
    throw new PrismaConfigError(
      `${location} has a non-string 'label'; received ${describe(label)}.`
    );
  }
  if (nullable !== undefined && typeof nullable !== 'boolean') {
    throw new PrismaConfigError(
      `${location} has a non-boolean 'nullable'; received ${describe(nullable)}.`
    );
  }
  if (list !== undefined && typeof list !== 'boolean') {
    throw new PrismaConfigError(
      `${location} has a non-boolean 'list'; received ${describe(list)}.`
    );
  }

  return {
    klass,
    label: label ?? field,
    nullable: nullable ?? false,
    list: list ?? false,
  };
}

/**
 * Validate and index the classified fields of one model.
 *
 * Exported because `wrapRows` takes the same per-model shape and must reject
 * the same mistakes; a raw row wrapped from an unvalidated spec would carry a
 * class with no policy behind it.
 */
export function normalizeModelFields(model: string, fields: ModelFieldConfig): NormalizedModel {
  if (!isPlainObject(fields)) {
    throw new PrismaConfigError(
      `Model '${model}' must map field names to sensitivity classes; received ${describe(fields)}.`
    );
  }

  const normalized = new Map<string, NormalizedField>();
  for (const [field, spec] of Object.entries(fields)) {
    if (field === '') {
      throw new PrismaConfigError(`Model '${model}' has a field with an empty name.`);
    }
    normalized.set(field, normalizeField(`${model}.${field}`, field, spec));
  }
  return { name: model, fields: normalized };
}

function assertKnownClass(location: string, klass: string): asserts klass is SensitivityClass {
  if (!hasPolicy(klass as SensitivityClass)) {
    throw new PrismaConfigError(
      `${location} names sensitivity class '${klass}', which is not registered. ` +
        `Register it with registerPolicy() before building the extension, or correct the spelling.`
    );
  }
}

/**
 * Validate a configuration and index it for lookup.
 *
 * Runs once, when `sensitiveExtension()` is called, so a bad class or a
 * malformed field entry fails at startup rather than on the first query that
 * happens to touch it.
 *
 * @throws PrismaConfigError If the shape is wrong or a class is unregistered.
 */
export function normalizeConfig(config: SensitiveExtensionConfig): NormalizedConfig {
  if (!isPlainObject(config)) {
    throw new PrismaConfigError(
      `sensitiveExtension() expects a configuration object; received ${describe(config)}.`
    );
  }
  if (!isPlainObject(config.models)) {
    throw new PrismaConfigError(
      `sensitiveExtension() expects 'models' to be an object of model names; received ${describe(
        config.models
      )}.`
    );
  }

  const models = new Map<string, NormalizedModel>();

  for (const [model, fields] of Object.entries(config.models)) {
    // An empty model name produces a `result` component keyed `''`, which
    // Prisma matches against no model and ignores. The configuration would
    // then classify nothing while reporting no problem, which is the failure
    // this package exists to prevent.
    if (model === '') {
      throw new PrismaConfigError(
        `A model is configured under an empty name. Use the model's name as the schema spells it.`
      );
    }

    const key = clientKey(model);
    // Two schema names cannot collide after uncapitalising unless the
    // configuration lists the same model twice in different casing, which
    // would silently drop one of the two field sets.
    if (models.has(key)) {
      throw new PrismaConfigError(
        `Model '${model}' is configured twice (it resolves to the client property '${key}').`
      );
    }

    models.set(key, normalizeModelFields(model, fields));
  }

  const writeContext = config.writeContext;
  if (writeContext !== undefined && !isPlainObject(writeContext)) {
    throw new PrismaConfigError(
      `'writeContext' must be an object with optional 'name' and 'reason'; received ${describe(
        writeContext
      )}.`
    );
  }
  if (writeContext?.name !== undefined && typeof writeContext.name !== 'string') {
    throw new PrismaConfigError(
      `'writeContext.name' must be a string; received ${describe(writeContext.name)}.`
    );
  }
  if (writeContext?.reason !== undefined && typeof writeContext.reason !== 'string') {
    throw new PrismaConfigError(
      `'writeContext.reason' must be a string; received ${describe(writeContext.reason)}.`
    );
  }

  const { detectUnwrapped } = config;
  if (detectUnwrapped !== undefined && typeof detectUnwrapped !== 'boolean') {
    throw new PrismaConfigError(
      `'detectUnwrapped' must be a boolean; received ${describe(detectUnwrapped)}.`
    );
  }

  return {
    models,
    detectUnwrapped: detectUnwrapped ?? true,
    writeContext: {
      ...(writeContext?.name !== undefined ? { name: writeContext.name } : {}),
      ...(writeContext?.reason !== undefined ? { reason: writeContext.reason } : {}),
    },
  };
}
