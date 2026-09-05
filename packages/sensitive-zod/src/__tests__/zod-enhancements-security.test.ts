/**
 * Zod Enhancement Security Tests
 *
 * Three guarantees, checked against every schema the package builds.
 *
 * A parsed value never renders its input. That is the core library's promise,
 * and it holds here because everything ends up inside a SensitiveString.
 *
 * A rejected value never renders its input either. That one is not free. Zod 4
 * puts input-derived data in `unrecognized_keys.keys`, in `custom.params`, in
 * `invalid_element.key`, and in `issue.input`, so the sweep below feeds a canary
 * into each schema, in every shape it will accept, and scans the whole error:
 * the message, the issue objects, and every shape Zod formats them into.
 *
 * A *published* schema never renders it either. `z.toJSONSchema` is new in v4
 * and turns a schema definition into a document, calling function defaults to
 * do it. Anything this package puts in a definition is therefore a publication
 * surface, which is why `zSensitiveDefault` holds its fallback in a closure.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { z } from 'zod';
import {
  installSensitiveErrorMap,
  redactZodError,
  safeLog,
  sensitiveSafeParse,
  zConditionalSensitive,
  zCredential,
  zCredentialArray,
  zCredentialPreprocess,
  zCredentialRecord,
  zSensitive,
  zSensitiveArray,
  zSensitiveDefault,
  zSensitiveDeserialize,
  zSensitiveOptional,
  zSensitivePreprocess,
  zSensitiveRecord,
  zSensitiveString,
  zSensitiveStringArray,
  zSensitiveStringPreprocess,
  zSensitiveStringRecord,
  zSensitiveWithValidation,
} from '../index.js';

const CANARY = 'LEAKED_SECRET_zod_abc123xyz';

const previousCustomError = z.config().customError;

afterEach(() => {
  z.config({ customError: previousCustomError });
});

/**
 * Everything a caller could reasonably read off a failed parse.
 *
 * `.format()` and `.flatten()` are deprecated in v4 in favour of
 * `z.treeifyError` and `z.prettifyError`, so both generations are scanned: a
 * caller who has not migrated still reads the old ones.
 */
function renderError(error: unknown): string {
  if (!(error instanceof z.ZodError)) {
    return String(error);
  }

  return [
    error.message,
    JSON.stringify(error),
    JSON.stringify(error.issues),
    JSON.stringify(z.treeifyError(error)),
    JSON.stringify(z.flattenError(error)),
    JSON.stringify(z.formatError(error)),
    z.prettifyError(error),
    error.issues.map((issue) => issue.message).join('\n'),
  ].join('\n');
}

/**
 * Everything a caller could reasonably read off a parsed value.
 */
function renderValue(value: unknown): string {
  return [JSON.stringify(value), String(value), JSON.stringify(safeLog(value))].join('\n');
}

/**
 * Every schema the package builds, with inputs that put the canary in a
 * position the schema is supposed to classify.
 *
 * Adding a factory to the package without adding it here leaves it unswept,
 * which the export-coverage test below turns into a failure.
 */
const SCHEMAS: ReadonlyArray<{
  name: string;
  schema: z.ZodType<unknown, unknown>;
  inputs: readonly unknown[];
  /**
   * Set where the entry is an object a caller composes around the package's
   * schemas, so it can reach the leaking issue codes. Those entries are clean
   * only through the redaction helpers, which is what the leak-and-fix test
   * below pins.
   */
  composedByCaller?: true;
}> = [
  {
    name: 'zSensitiveString',
    schema: zSensitiveString('credential', 'token'),
    inputs: [CANARY, ''],
  },
  { name: 'zSensitive', schema: zSensitive('email'), inputs: [CANARY] },
  { name: 'zCredential', schema: zCredential('password'), inputs: [CANARY] },
  {
    name: 'zSensitiveWithValidation',
    schema: zSensitiveWithValidation(
      'credential',
      z
        .string()
        .min(50)
        .max(60)
        .startsWith('sk_')
        .regex(/^never$/),
      'password'
    ),
    inputs: [CANARY],
  },
  {
    // The widened parameter: a v4 format constructor is not a `z.ZodString`.
    name: 'zSensitiveWithValidation',
    schema: zSensitiveWithValidation('sensitive', z.email(), 'email'),
    inputs: [CANARY],
  },
  {
    name: 'zSensitiveOptional',
    schema: zSensitiveOptional('credential', 'token'),
    inputs: [CANARY],
  },
  {
    name: 'zSensitiveDeserialize',
    schema: zSensitiveDeserialize('credential'),
    inputs: [
      { __sensitive: true, klass: 'credential', value: CANARY },
      // A wrong literal, a wrong class, and a missing field, each carrying the canary.
      { __sensitive: false, klass: 'credential', value: CANARY },
      { __sensitive: true, klass: 'sensitive', value: CANARY },
      { __sensitive: true, value: CANARY },
      { __sensitive: true, klass: 'credential', value: CANARY, label: 7 },
    ],
  },
  {
    name: 'zSensitiveStringArray',
    schema: zSensitiveStringArray('credential', 'token'),
    inputs: [[CANARY]],
  },
  { name: 'zSensitiveArray', schema: zSensitiveArray('email').min(5), inputs: [[CANARY]] },
  { name: 'zCredentialArray', schema: zCredentialArray('secret').min(5), inputs: [[CANARY]] },
  {
    name: 'zSensitiveStringRecord',
    schema: zSensitiveStringRecord('credential', 'secret'),
    inputs: [{ key: CANARY }],
  },
  { name: 'zSensitiveRecord', schema: zSensitiveRecord('secret'), inputs: [{ key: CANARY }] },
  { name: 'zCredentialRecord', schema: zCredentialRecord('secret'), inputs: [{ key: CANARY }] },
  {
    name: 'zSensitiveStringPreprocess',
    schema: zSensitiveStringPreprocess('credential', { trim: true }, 'token', z.uuid()),
    inputs: [CANARY],
  },
  {
    name: 'zSensitivePreprocess',
    schema: zSensitivePreprocess({ trim: true, lowercase: true }, 'email', z.email()),
    inputs: [CANARY, `  ${CANARY}  `],
  },
  {
    name: 'zCredentialPreprocess',
    schema: zCredentialPreprocess({ stripWhitespace: true }, 'api_key', z.uuid()),
    inputs: [CANARY],
  },
  {
    name: 'refineSensitive',
    schema: zCredential('password')
      .refineSensitive((raw) => raw.length >= 200, { message: 'too short' })
      .refineSensitive(() => false),
    inputs: [CANARY],
  },
  {
    name: 'zSensitiveDefault',
    schema: zSensitiveDefault('credential', 'token', CANARY),
    inputs: [undefined, CANARY],
  },
  {
    name: 'zSensitiveDefault',
    schema: zSensitiveDefault('credential', 'token', () => CANARY),
    inputs: [undefined, CANARY],
  },
  {
    name: 'zConditionalSensitive',
    schema: zConditionalSensitive({
      discriminator: 'type',
      valueField: 'value',
      conditions: { secret: { klass: 'credential' }, other: { klass: 'sensitive' } },
    }),
    inputs: [{ type: 'secret', value: CANARY }, { type: 'nope', value: CANARY }, { value: CANARY }],
  },
  {
    name: 'composed object',
    composedByCaller: true,
    schema: z
      .object({
        role: z.enum(['admin', 'user']),
        kind: z.literal('user'),
        password: zCredential('password'),
        keys: zCredentialArray('api_key'),
      })
      .strict(),
    inputs: [
      { role: CANARY, kind: CANARY, password: CANARY, keys: [CANARY], [CANARY]: 1 },
      { role: 'admin', kind: 'user', password: CANARY, keys: [CANARY] },
    ],
  },
];

describe('Zod Enhancement Security', () => {
  describe('CANARY: no schema in the package renders its input', () => {
    for (const { name, schema, inputs } of SCHEMAS) {
      inputs.forEach((input, index) => {
        it(`${name} keeps the canary out of input ${index}`, () => {
          const result = sensitiveSafeParse(schema, input);

          const rendered = result.success ? renderValue(result.data) : renderError(result.error);

          expect(rendered).not.toContain(CANARY);
        });
      });
    }
  });

  describe('CANARY: every schema the package builds is clean without the helpers', () => {
    for (const { name, schema, inputs, composedByCaller } of SCHEMAS) {
      if (composedByCaller) {
        continue;
      }

      it(`${name} keeps the canary out of a plain safeParse`, () => {
        for (const input of inputs) {
          let rendered: string;
          try {
            const result = schema.safeParse(input);
            rendered = result.success ? renderValue(result.data) : renderError(result.error);
          } catch (error) {
            // Nothing the package builds should land here. A throw from inside
            // a transform escapes safeParse and never reaches the redaction
            // path, so it is scanned rather than allowed to pass unchecked.
            rendered = String(error);
          }

          expect(rendered).not.toContain(CANARY);
        }
      });
    }
  });

  describe('CANARY: no schema the package builds publishes its input as JSON Schema', () => {
    // `z.toJSONSchema` is what every OpenAPI generator calls, and `io: 'input'`
    // is what a request-body generator passes.
    //
    // The two sides are asserted separately rather than as "throws or is
    // clean". Every factory here emits on the input side and refuses on the
    // output side, so accepting either would let a future Zod turn this sweep
    // into a no-op: a version that started throwing on the input side, or one
    // that started emitting something for a SensitiveString, would both pass a
    // test that treats a throw as success.
    for (const { name, schema, composedByCaller } of SCHEMAS) {
      if (composedByCaller) {
        continue;
      }

      it(`${name} emits a canary-free input schema and refuses the output side`, () => {
        const input = JSON.stringify(z.toJSONSchema(schema, { io: 'input' }));

        expect(input).not.toContain(CANARY);
        expect(input).toContain('$schema');

        expect(() => z.toJSONSchema(schema, { io: 'output' })).toThrow(
          /cannot be represented in JSON Schema/
        );
      });
    }
  });

  it('CANARY: a function default is not invoked while generating a JSON Schema', () => {
    // The failure this prevents is the documented example: a default that reads
    // `process.env.API_KEY` at generation time embeds the live key in the
    // document. A value-only assertion would miss a call whose result happened
    // not to match, so the call itself is what is asserted.
    const factory = vi.fn(() => CANARY);
    const Config = z.object({ apiKey: zSensitiveDefault('credential', 'api_key', factory) });

    const schema = JSON.stringify(z.toJSONSchema(Config, { io: 'input' }));

    expect(factory).not.toHaveBeenCalled();
    expect(schema).not.toContain(CANARY);
    expect(schema).not.toContain('default');

    // The default still works, and still runs once per parse that needs it.
    expect(Config.parse({}).apiKey.reveal()).toBe(CANARY);
    expect(factory).toHaveBeenCalledTimes(1);
  });

  it('CANARY: the output side of toJSONSchema refuses rather than emitting', () => {
    // Pins the safe-by-default behaviour, so a future Zod that starts emitting
    // something for a SensitiveString is caught here.
    const Config = z.object({ token: zCredential('token') });

    expect(() => z.toJSONSchema(Config)).toThrow(/cannot be represented in JSON Schema/);
  });

  it('no schema the package builds throws out of safeParse', () => {
    for (const { schema, inputs, composedByCaller } of SCHEMAS) {
      if (composedByCaller) {
        continue;
      }
      for (const input of inputs) {
        expect(() => schema.safeParse(input)).not.toThrow();
      }
    }
  });

  it('CANARY: a length check on the raw value does not echo it', () => {
    const schema = zSensitiveWithValidation('credential', z.string().min(200), 'password');
    const result = schema.safeParse(CANARY);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(renderError(result.error)).not.toContain(CANARY);
      expect(result.error.issues[0]?.message).toBe(
        'Too small: expected string to have >=200 characters'
      );
    }
  });

  it('CANARY: an array length check does not echo the elements', () => {
    const result = zCredentialArray('secret').min(5).safeParse([CANARY]);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(renderError(result.error)).not.toContain(CANARY);
    }
  });

  it('CANARY: a refinement failure does not echo the value', () => {
    const schema = zCredential('token').refineSensitive((raw) => raw.startsWith('sk_'), {
      message: 'token must start with sk_',
    });

    const result = schema.safeParse(CANARY);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(renderError(result.error)).not.toContain(CANARY);
    }
  });

  it('CANARY: a sibling enum no longer leaks, and an unknown key still does', () => {
    // This case pins the gap as well as the fix, and v4 moved the gap.
    //
    // The enum half asserts an upstream fix rather than one of ours:
    // `invalid_enum_value` became `invalid_value`, which carries the allowed
    // set instead of what arrived. If a future Zod puts the input back there,
    // this fails and the enum branch of `sensitiveErrorMap` comes back.
    const withEnum = z.object({
      role: z.enum(['admin', 'user']),
      password: zCredential('password'),
    });

    const enumResult = withEnum.safeParse({ role: CANARY, password: 'pw' });
    expect(enumResult.success).toBe(false);
    if (!enumResult.success) {
      expect(enumResult.error.issues[0]?.code).toBe('invalid_value');
      expect(renderError(enumResult.error)).not.toContain(CANARY);
    }

    // `unrecognized_keys` is the surviving instance of the gap the module
    // exists to close: it leaks under the default configuration, in both the
    // message and the structured field.
    const strict = withEnum.strict();

    const unprotected = strict.safeParse({ role: 'admin', password: 'pw', [CANARY]: 1 });
    expect(unprotected.success).toBe(false);
    if (!unprotected.success) {
      expect(renderError(unprotected.error)).toContain(CANARY);
      expect(renderError(redactZodError(unprotected.error))).not.toContain(CANARY);
    }

    installSensitiveErrorMap();
    const withMap = strict.safeParse({ role: 'admin', password: 'pw', [CANARY]: 1 });
    expect(withMap.success).toBe(false);
    if (!withMap.success) {
      // The message is clean, but `keys` survives an error map, so the
      // structured issue still needs redacting.
      expect(withMap.error.issues[0]?.message).not.toContain(CANARY);
      expect(JSON.stringify(withMap.error.issues)).toContain(CANARY);
      expect(renderError(redactZodError(withMap.error))).not.toContain(CANARY);
    }
  });

  it('CANARY: a parsed collection redacts every element', () => {
    const schema = z.object({
      keys: zCredentialArray('api_key'),
      secrets: zCredentialRecord('secret'),
    });

    const parsed = schema.parse({ keys: [CANARY, CANARY], secrets: { a: CANARY } });

    expect(renderValue(parsed)).not.toContain(CANARY);
    expect(parsed.keys[0]?.reveal()).toBe(CANARY);
  });

  it('every schema factory the package exports is covered by the sweep', async () => {
    const exports = await import('../index.js');
    const factories = Object.keys(exports).filter((name) => name.startsWith('z') && name !== 'z');
    const swept = new Set(SCHEMAS.map(({ name }) => name));

    expect(factories.filter((name) => !swept.has(name))).toEqual([]);
  });
});
