import { SensitiveString, type SensitivityClass } from '@platform-sec/sensitive-string-core';

/** The value a `sensitive` keyword takes in a schema. */
export interface SensitiveKeywordSchema {
  /** Sensitivity class for the wrapped value. */
  klass: SensitivityClass;
  /** Audit label. Defaults to the property name. */
  label?: string;
}

/**
 * The part of Ajv's data context this keyword reads.
 *
 * Restated structurally so the published declaration names no Ajv type: a
 * consumer needs Ajv on disk (Fastify's validator compiler brings it) but not
 * in its own type graph.
 */
export interface SensitiveKeywordContext {
  /** The object or array holding the validated value, absent at the root. */
  parentData?: Record<string, unknown> | unknown[] | undefined;
  /** The key or index the value sits at in `parentData`. */
  parentDataProperty?: string | number | undefined;
}

/**
 * An Ajv user-defined keyword, shaped so no Ajv type appears in this package's
 * public declaration.
 */
export interface SensitiveKeywordDefinition {
  keyword: 'sensitive';
  type: 'string';
  schemaType: 'object';
  modifying: true;
  errors: false;
  metaSchema: Record<string, unknown>;
  validate(
    schema: SensitiveKeywordSchema,
    data: string,
    parentSchema?: unknown,
    context?: SensitiveKeywordContext
  ): boolean;
}

/** The keyword name, so a schema walk does not have to spell it twice. */
export const SENSITIVE_KEYWORD = 'sensitive';

/**
 * Ajv keyword that replaces a validated string with a `SensitiveString`.
 *
 * Ajv is configured when the Fastify instance is created, so this goes into the
 * constructor options rather than into a plugin. Fastify's Ajv runs in strict
 * mode: a schema using `sensitive` without the keyword registered fails at
 * route registration with `FST_ERR_SCH_VALIDATION_BUILD`.
 *
 * ```ts
 * const fastify = Fastify({ ajv: { customOptions: { keywords: [sensitiveKeyword] } } });
 * ```
 *
 * What it does, and where:
 *
 * - It applies to string values only, so `type`, `minLength`, `format`, and the
 *   property's other keywords all run on the raw string first. A failing check
 *   produces the usual 400 with no value in the message, and the keyword never
 *   runs for that property.
 * - It reaches nested objects, array items, `$ref` to schemas added with
 *   `fastify.addSchema`, and the querystring and params schemas, because
 *   `request.query` and `request.params` are plain mutable objects in Fastify.
 * - The label defaults to the property name. An array item has an index rather
 *   than a name, so it takes the label the schema gives it, or none.
 * - The keyword's own schema is checked at startup by `metaSchema`, so a typo
 *   fails at route registration rather than at the first request.
 *
 * Two places it must not be used:
 *
 * - A **headers schema**. The value it would replace lives in the raw Node
 *   headers object, which Fastify itself reads as strings. `sensitivePlugin`
 *   refuses such a route; use the plugin's `headers` option instead.
 * - A **response schema**, where it is simply inert: `fast-json-stringify`
 *   ignores it. Use the plugin's `responseFilter` option.
 *
 * Under a custom validator compiler (`setValidatorCompiler`, a TypeBox or Zod
 * type provider) the keyword is absent and nothing is wrapped. Those
 * applications use the plugin's `body` option, or a schema library that
 * transforms during validation, such as sensitive-zod.
 *
 * @example
 * ```ts
 * fastify.post('/login', {
 *   schema: {
 *     body: {
 *       type: 'object',
 *       properties: {
 *         email: { type: 'string', format: 'email', sensitive: { klass: 'sensitive' } },
 *         password: { type: 'string', minLength: 8, sensitive: { klass: 'credential' } },
 *       },
 *     },
 *   },
 * }, async (request) => {
 *   // request.body.password is a SensitiveString<'credential'> labelled 'password'
 * });
 * ```
 */
export const sensitiveKeyword: SensitiveKeywordDefinition = {
  keyword: SENSITIVE_KEYWORD,
  type: 'string',
  schemaType: 'object',
  modifying: true,
  errors: false,
  metaSchema: {
    type: 'object',
    required: ['klass'],
    additionalProperties: false,
    properties: {
      klass: { enum: ['sensitive', 'credential'] },
      label: { type: 'string' },
    },
  },

  validate(schema, data, _parentSchema, context) {
    const parent = context?.parentData;

    // The root of a validated part is a string only when the schema says the
    // whole body is one. There is nothing to assign into, and Fastify would
    // read the replacement back as `request.body` anyway.
    if (parent === undefined || parent === null) {
      return true;
    }

    const property = context?.parentDataProperty;

    if (property === undefined) {
      return true;
    }

    // An array item is addressed by index, and an index is a useless audit
    // label, so only a property name becomes one by default.
    const label = schema.label ?? (typeof property === 'string' ? property : undefined);

    (parent as Record<string | number, unknown>)[property] = new SensitiveString(
      data,
      schema.klass,
      label
    );

    return true;
  },
};

/**
 * Does a schema use the `sensitive` keyword anywhere inside it?
 *
 * Used to refuse a headers schema before it can corrupt the raw headers object.
 * Plain objects and arrays are walked; a `$ref` is followed through `resolve`,
 * which the caller backs with `fastify.getSchema`, and a schema already visited
 * is not visited again, so a recursive `$ref` terminates.
 *
 * @param schema - The schema to inspect, of any shape
 * @param resolve - Looks up a schema by `$ref`, typically `fastify.getSchema`
 * @returns True when some subschema carries a `sensitive` key
 */
export function schemaUsesKeyword(
  schema: unknown,
  resolve: (ref: string) => unknown = () => undefined
): boolean {
  return walk(schema, resolve, new Set<unknown>(), new Set<string>());
}

function walk(
  node: unknown,
  resolve: (ref: string) => unknown,
  seen: Set<unknown>,
  refs: Set<string>
): boolean {
  if (node === null || typeof node !== 'object') {
    return false;
  }

  if (seen.has(node)) {
    return false;
  }

  seen.add(node);

  if (Array.isArray(node)) {
    return node.some((item) => walk(item, resolve, seen, refs));
  }

  const record = node as Record<string, unknown>;

  if (SENSITIVE_KEYWORD in record) {
    return true;
  }

  const ref = record['$ref'];

  if (typeof ref === 'string' && !refs.has(ref)) {
    refs.add(ref);

    // `fastify.getSchema` keys on the bare `$id`, so a JSON Pointer suffix is
    // dropped. A pointer into a shared schema therefore over-reports rather
    // than under-reports, which is the safe direction for a guard.
    const resolved = resolve(ref.split('#')[0] ?? ref);

    if (walk(resolved, resolve, seen, refs)) {
      return true;
    }
  }

  return Object.values(record).some((value) => walk(value, resolve, seen, refs));
}
