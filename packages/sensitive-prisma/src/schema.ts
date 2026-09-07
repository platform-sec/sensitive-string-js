import { clientKey } from './config.js';
import type { NormalizedConfig } from './config.js';
import { PrismaUnknownFieldError, PrismaUnknownModelError } from './errors.js';

/**
 * Read the schema Prisma keeps on the client, if it is where it has been.
 *
 * `_runtimeDataModel` is internal, so this is written to come back empty rather
 * than to throw when Prisma moves it. What keeps that from turning into a
 * silently skipped check is `schema.test.ts`, which asserts this finds the test
 * schema's models and fields: a Prisma release that changes the shape fails the
 * suite rather than quietly disabling validation.
 */
export function readSchemaModels(client: unknown): Map<string, SchemaModel> | undefined {
  if (typeof client !== 'object' || client === null) return undefined;

  const runtime = (client as { _runtimeDataModel?: unknown })._runtimeDataModel;
  if (typeof runtime !== 'object' || runtime === null) return undefined;

  const models = (runtime as { models?: unknown }).models;
  if (typeof models !== 'object' || models === null) return undefined;

  // Keyed by the client property rather than the schema name, so a
  // configuration written in either casing resolves the same way. `clientKey`
  // is idempotent, which is what makes that safe.
  const found = new Map<string, SchemaModel>();
  for (const [name, model] of Object.entries(models)) {
    const fields: unknown = (model as { fields?: unknown })?.fields;
    if (!Array.isArray(fields)) continue;

    // Read field by field rather than trusting a declared element type. This is
    // undeclared internal data, so the only thing worth assuming about it is
    // that it might not be what it was last release. Anything unrecognised is
    // skipped, and a model that yields no scalars still registers, so a
    // configuration naming a column of it is refused rather than waved through.
    const scalars = new Set<string>();
    for (const field of fields as unknown[]) {
      if (typeof field !== 'object' || field === null) continue;
      const { name: fieldName, kind } = field as { name?: unknown; kind?: unknown };
      if (kind === 'scalar' && typeof fieldName === 'string') {
        scalars.add(fieldName);
      }
    }

    found.set(clientKey(name), { name, scalars });
  }

  return found.size === 0 ? undefined : found;
}

/** One model of the schema, as this package needs it. */
export interface SchemaModel {
  /** The model name as the schema spells it. */
  readonly name: string;
  /** Names of its scalar fields. Relations and composites are not here. */
  readonly scalars: ReadonlySet<string>;
}

function suggest(name: string, candidates: Iterable<string>): string {
  const lowered = name.toLowerCase();
  for (const candidate of candidates) {
    if (candidate.toLowerCase() === lowered) return ` Did you mean '${candidate}'?`;
  }
  return '';
}

/**
 * Refuse a configuration that names a model or a column the schema does not have.
 *
 * This is the check the design assumed TypeScript and Prisma would provide, and
 * neither does. Measured on Prisma 6.19.3 and 7.10.0: a `result` component
 * keyed by a model that does not exist is ignored, a computed field whose name
 * is misspelled is added alongside the real column rather than replacing it,
 * and a `needs` entry for a column that does not exist does not throw. In all
 * three the configured column reads back as a plain string, which is the exact
 * failure this package exists to prevent, arriving silently.
 *
 * The model check runs against the client's own properties, which are public.
 * The field check needs the schema, so it runs only when `readSchemaModels`
 * found one.
 *
 * @throws PrismaUnknownModelError If a configured model is not on the client.
 * @throws PrismaUnknownFieldError If a configured field is not a scalar column.
 */
export function assertConfigMatchesSchema(client: unknown, config: NormalizedConfig): void {
  if (typeof client !== 'object' || client === null) return;

  const schema = readSchemaModels(client);
  const clientObject = client as Record<string, unknown>;

  for (const [key, model] of config.models) {
    if (!(key in clientObject) || typeof clientObject[key] !== 'object') {
      throw new PrismaUnknownModelError(
        model.name,
        key,
        suggest(
          key,
          Object.keys(clientObject).filter((name) => !name.startsWith('$') && !name.startsWith('_'))
        )
      );
    }

    const found = schema?.get(key);
    if (found === undefined) continue;

    for (const field of model.fields.keys()) {
      if (!found.scalars.has(field)) {
        throw new PrismaUnknownFieldError(found.name, field, suggest(field, found.scalars));
      }
    }
  }
}
