import { describe, it, expect, afterEach } from 'vitest';
import { z } from 'zod';
import {
  REDACTED_ISSUE_VALUE,
  installSensitiveErrorMap,
  redactZodError,
  redactZodIssues,
  sensitiveErrorMap,
  sensitiveParse,
  sensitiveSafeParse,
  sensitiveSafeParseAsync,
  zCredential,
  zSensitive,
} from './index.js';
import type { SensitiveParseOptions } from './index.js';

const CANARY = 'CANARY-ERRORMAP-VALUE-58';

/**
 * v4 has no `z.defaultErrorMap` to reinstall, so the previous configuration is
 * captured and put back. `z.config()` reads the live global config, and
 * assigning `undefined` clears the entry rather than being ignored.
 */
const previousCustomError = z.config().customError;

afterEach(() => {
  z.config({ customError: previousCustomError });
});

/** A strict object is the surviving source of a leaking built-in issue. */
const Strict = z.object({ a: z.string() }).strict();
const strictInput = { a: 'x', [CANARY]: 1 };

/**
 * Render an issue tree with every `path` removed.
 *
 * `path` is the one channel the module deliberately does not redact, so a
 * blanket canary scan over a redacted issue would report the documented
 * limitation as a failure. Stripping it leaves exactly the fields the module
 * does claim to cover.
 */
function renderExceptPath(issues: readonly z.core.$ZodIssue[]): string {
  const strip = (value: unknown): unknown => {
    if (Array.isArray(value)) {
      return value.map(strip);
    }
    if (value !== null && typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>)
          .filter(([key]) => key !== 'path')
          .map(([key, nested]) => [key, strip(nested)])
      );
    }
    return value;
  };

  return JSON.stringify(strip(issues));
}

/**
 * One producer per issue code Zod 4 can emit, each fed the canary where the
 * code's input position accepts a string.
 *
 * This is the evidence for the module's central claim, which is about Zod's
 * whole issue surface rather than about the codes that happened to leak in v3.
 * The completeness test below ties the table to `z.ZodIssueCode`, so a code
 * added by a future Zod fails here rather than going unswept.
 */
const ISSUE_CODES: ReadonlyArray<{
  code: string;
  schema: z.ZodType<unknown, unknown>;
  input: unknown;
  /** Set where the raw issue echoes the input before any redaction. */
  leaksRaw?: true;
}> = [
  { code: 'invalid_type', schema: z.number(), input: CANARY },
  { code: 'too_big', schema: z.string().max(2), input: CANARY },
  { code: 'too_small', schema: z.string().min(200), input: CANARY },
  { code: 'invalid_format', schema: z.email(), input: CANARY },
  // The canary has no numeric spelling, so this row exists for the
  // completeness check rather than to carry one.
  { code: 'not_multiple_of', schema: z.number().multipleOf(7), input: 3 },
  { code: 'unrecognized_keys', schema: Strict, input: strictInput, leaksRaw: true },
  {
    code: 'invalid_union',
    schema: z.union([Strict, z.number()]),
    input: { a: 1, [CANARY]: 1 },
    leaksRaw: true,
  },
  {
    code: 'invalid_key',
    schema: z.record(
      z.string().superRefine((value, ctx) => {
        ctx.addIssue({ code: 'custom', message: 'bad key', params: { value } });
      }),
      z.string()
    ),
    input: { [CANARY]: 'v' },
    leaksRaw: true,
  },
  {
    code: 'invalid_element',
    schema: z.map(z.object({ id: z.string() }), Strict),
    input: new Map([[{ id: 'k' }, strictInput]]),
    leaksRaw: true,
  },
  { code: 'invalid_value', schema: z.enum(['a', 'b']), input: CANARY },
  {
    code: 'custom',
    schema: z.string().superRefine((value, ctx) => {
      ctx.addIssue({ code: 'custom', message: 'bad', params: { value } });
    }),
    input: CANARY,
    leaksRaw: true,
  },
];

describe('the whole v4 issue surface', () => {
  for (const { code, schema, input, leaksRaw } of ISSUE_CODES) {
    it(`${code} is clean after redaction, and leaks beforehand only where recorded`, () => {
      const result = schema.safeParse(input);

      expect(result.success).toBe(false);
      if (result.success) {
        return;
      }

      expect(result.error.issues[0]?.code).toBe(code);
      expect(JSON.stringify(result.error.issues).includes(CANARY)).toBe(leaksRaw === true);
      expect(renderExceptPath(redactZodIssues(result.error.issues))).not.toContain(CANARY);
    });
  }

  it('covers every issue code this Zod can emit', () => {
    // `z.ZodIssueCode` is a runtime object whose members are exactly the codes
    // v4 emits. Tying the table to it means a code added upstream fails this
    // test instead of quietly going unredacted: the same reason the enum
    // gap-pinning case exists.
    const emitted = Object.keys(z.ZodIssueCode);
    const covered = new Set(ISSUE_CODES.map(({ code }) => code));

    expect(emitted.filter((code) => !covered.has(code))).toEqual([]);
    expect([...covered].filter((code) => !emitted.includes(code))).toEqual([]);
  });
});

describe('sensitiveErrorMap', () => {
  it('test_error_map_keeps_unknown_key_names_out_of_the_message', () => {
    const result = Strict.safeParse(strictInput, { error: sensitiveErrorMap });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).not.toContain(CANARY);
      expect(result.error.issues[0]?.message).toContain('1 not allowed');
    }
  });

  it('test_error_map_declines_rather_than_rewriting_other_messages', () => {
    // A v4 error map returns nothing to hand the issue back to Zod, and there
    // is no `ctx.defaultError` to echo.
    const result = z.string().min(50).safeParse('x', { error: sensitiveErrorMap });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe(
        'Too small: expected string to have >=50 characters'
      );
    }
  });

  it('test_error_map_never_reads_the_input_off_the_raw_issue', () => {
    // Invariant S3. The raw issue an error function sees carries the value in
    // full, which is the hazard: reading it here would put the secret in every
    // message. This pins the hazard as well as the fix.
    let sawInput: unknown;
    Strict.safeParse(strictInput, {
      error: (issue) => {
        sawInput = issue.input;
        return sensitiveErrorMap(issue);
      },
    });

    expect(sawInput).toEqual(strictInput);
    expect(JSON.stringify(sawInput)).toContain(CANARY);

    const result = Strict.safeParse(strictInput, { error: sensitiveErrorMap });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).not.toContain(CANARY);
    }
  });

  it('test_install_sets_the_global_map', () => {
    installSensitiveErrorMap();

    const result = Strict.safeParse(strictInput);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).not.toContain(CANARY);
      expect(result.error.issues[0]?.message).toContain('1 not allowed');
    }
  });

  it('test_the_map_is_not_installed_merely_by_importing_the_package', () => {
    // The default map is still in place, which is exactly why the message half
    // of the fix has to be opted into.
    const result = Strict.safeParse(strictInput);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toContain(CANARY);
    }
  });

  it('test_v4_closed_the_enum_and_literal_leaks_this_module_used_to_patch', () => {
    // Both codes became `invalid_value`, which carries the allowed set rather
    // than what arrived. If a future Zod reintroduces a `received` field here,
    // this fails and the enum branch comes back.
    for (const schema of [z.enum(['a', 'b']), z.literal('a')]) {
      const result = schema.safeParse(CANARY);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0]?.code).toBe('invalid_value');
        expect(JSON.stringify(result.error.issues)).not.toContain(CANARY);
        expect(result.error.issues[0]?.message).not.toContain(CANARY);
      }
    }
  });
});

describe('redactZodIssues', () => {
  it('test_redacts_unknown_key_names', () => {
    const error = Strict.safeParse(strictInput);

    expect(error.success).toBe(false);
    if (!error.success) {
      const redacted = redactZodIssues(error.error.issues);

      expect(JSON.stringify(redacted)).not.toContain(CANARY);
      // The count survives, so a caller still knows how many keys were refused.
      expect((redacted[0] as { keys: string[] }).keys).toEqual([REDACTED_ISSUE_VALUE]);
    }
  });

  it('test_drops_custom_issue_params', () => {
    const schema = z.string().superRefine((value, ctx) => {
      ctx.addIssue({ code: 'custom', message: 'bad', params: { value } });
    });
    const error = schema.safeParse(CANARY);

    expect(error.success).toBe(false);
    if (!error.success) {
      const redacted = redactZodIssues(error.error.issues);

      expect(JSON.stringify(redacted)).not.toContain(CANARY);
      expect(redacted[0]).not.toHaveProperty('params');
      expect(redacted[0]?.message).toBe('bad');
    }
  });

  it('test_recurses_into_the_raw_issue_arrays_of_a_union', () => {
    // v4 nests `$ZodIssue[][]` under `errors`, not `ZodError[]` under
    // `unionErrors`. Both branches have to fail with issues of their own for
    // Zod to report the union rather than collapsing to the closest branch.
    const schema = z.union([Strict, z.number()]);
    const error = schema.safeParse({ a: 1, [CANARY]: 1 });

    expect(error.success).toBe(false);
    if (!error.success) {
      expect(error.error.issues[0]?.code).toBe('invalid_union');
      expect(JSON.stringify(error.error.issues)).toContain(CANARY);
      expect(JSON.stringify(redactZodIssues(error.error.issues))).not.toContain(CANARY);
    }
  });

  it('test_leaves_a_multiple_match_union_alone', () => {
    // `z.xor` produces the other member of the `invalid_union` union:
    // `errors: []` plus the indices that matched. It carries nothing derived
    // from the input, and mapping over `errors` would not type-check against
    // it, which is why the branch narrows past the code first.
    const error = z.xor([z.string(), z.string()]).safeParse(CANARY);

    expect(error.success).toBe(false);
    if (!error.success) {
      expect(error.error.issues[0]).toMatchObject({ code: 'invalid_union', matches: [0, 1] });

      const redacted = redactZodIssues(error.error.issues);
      expect(redacted[0]).toMatchObject({ matches: [0, 1], errors: [] });
      expect(JSON.stringify(redacted)).not.toContain(CANARY);
    }
  });

  it('test_recurses_into_the_nested_issues_of_an_invalid_key', () => {
    // A record key rejected by its own refinement. The nested issue is about
    // the key, so `params` there holds the key itself.
    const schema = z.record(
      z.string().superRefine((value, ctx) => {
        ctx.addIssue({ code: 'custom', message: 'bad key', params: { key: value } });
      }),
      z.string()
    );
    const error = schema.safeParse({ [CANARY]: 'v' });

    expect(error.success).toBe(false);
    if (!error.success) {
      expect(error.error.issues[0]?.code).toBe('invalid_key');
      expect(JSON.stringify(error.error.issues)).toContain(CANARY);

      const redacted = redactZodIssues(error.error.issues);
      expect(renderExceptPath(redacted)).not.toContain(CANARY);
      // `path` is the documented exception: it still carries the key, and the
      // whole point of leaving it alone is that it stays useful.
      expect(redacted[0]?.path).toEqual([CANARY]);
    }
  });

  it('test_redacts_the_key_and_nested_issues_of_an_invalid_element', () => {
    // Zod reports a map value under a non-primitive key this way, and puts the
    // key on the issue verbatim.
    const schema = z.map(z.object({ id: z.string() }), Strict);
    const error = schema.safeParse(new Map([[{ id: 'k' }, strictInput]]));

    expect(error.success).toBe(false);
    if (!error.success) {
      expect(error.error.issues[0]?.code).toBe('invalid_element');
      expect(JSON.stringify(error.error.issues)).toContain(CANARY);

      const redacted = redactZodIssues(error.error.issues);
      expect(JSON.stringify(redacted)).not.toContain(CANARY);
      expect((redacted[0] as { key: unknown }).key).toBe(REDACTED_ISSUE_VALUE);
    }
  });

  it('test_strips_the_input_a_caller_asked_zod_to_report', () => {
    // Zod drops `input` during finalization by default, but `reportInput` puts
    // it back on every issue, and `$ZodIssueBase` declares the field either
    // way. Invariant S4: this does not depend on which the caller got.
    const error = Strict.safeParse(strictInput, { reportInput: true });

    expect(error.success).toBe(false);
    if (!error.success) {
      expect('input' in (error.error.issues[0] ?? {})).toBe(true);
      expect(JSON.stringify(error.error.issues)).toContain(CANARY);

      const redacted = redactZodIssues(error.error.issues);
      expect('input' in (redacted[0] ?? {})).toBe(false);
      expect(JSON.stringify(redacted)).not.toContain(CANARY);
    }
  });

  it('test_finalized_issues_carry_no_input_under_the_default_options', () => {
    // If Zod ever stops stripping, this fails on its own rather than every
    // canary assertion in the suite failing at once.
    const error = Strict.safeParse(strictInput);

    expect(error.success).toBe(false);
    if (!error.success) {
      for (const issue of error.error.issues) {
        expect('input' in issue).toBe(false);
      }
    }
  });

  it('test_leaves_the_expected_type_name_of_an_invalid_type_issue_alone', () => {
    const error = z.number().safeParse('x');

    expect(error.success).toBe(false);
    if (!error.success) {
      expect(redactZodIssues(error.error.issues)[0]).toMatchObject({
        code: 'invalid_type',
        expected: 'number',
      });
    }
  });

  it('test_does_not_mutate_the_issues_it_is_given', () => {
    const error = Strict.safeParse(strictInput);

    expect(error.success).toBe(false);
    if (!error.success) {
      redactZodIssues(error.error.issues);

      expect(JSON.stringify(error.error.issues)).toContain(CANARY);
    }
  });

  it('test_redactZodError_returns_a_usable_ZodError', () => {
    const error = z.object({ nested: Strict }).safeParse({ nested: strictInput });

    expect(error.success).toBe(false);
    if (!error.success) {
      const redacted = redactZodError(error.error);

      expect(redacted).toBeInstanceOf(z.ZodError);
      expect(redacted.issues[0]?.path).toEqual(['nested']);
      expect(JSON.stringify(z.treeifyError(redacted))).not.toContain(CANARY);
      expect(z.prettifyError(redacted)).not.toContain(CANARY);
    }
  });
});

describe('sensitiveSafeParse', () => {
  const Payload = z
    .object({
      role: z.enum(['admin', 'user']),
      password: zCredential('password'),
    })
    .strict();

  it('test_returns_the_parsed_value_on_success', () => {
    const result = sensitiveSafeParse(Payload, { role: 'admin', password: 'pw' });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.password.reveal()).toBe('pw');
    }
  });

  it('test_applies_both_halves_of_the_fix', () => {
    const result = sensitiveSafeParse(Payload, {
      role: 'admin',
      password: 'pw',
      [CANARY]: 1,
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(JSON.stringify(result.error)).not.toContain(CANARY);
      expect(result.error.issues[0]?.message).not.toContain(CANARY);
    }
  });

  it('test_applies_the_map_with_no_options_supplied', () => {
    // Under the v3 spelling with the key renamed away, this would silently
    // stop applying the map and the helper would become a pass-through. The
    // "not allowed" phrasing comes only from the map: the post-hoc scrub can
    // rewrite the value inside Zod's own message but cannot replace it.
    const result = sensitiveSafeParse(Strict, strictInput);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe('Unrecognized key(s) in object: 1 not allowed');
    }
  });

  it('test_an_explicit_undefined_error_map_does_not_disable_the_default', () => {
    // Spreading the caller's options over the default would leave Zod resolving
    // the global map here, which is a fail-open.
    //
    // `exactOptionalPropertyTypes` rejects a literal `error: undefined` against
    // `ParseContext`, so the assertion is what lets the test express it. It
    // models the callers who can actually reach this path: JavaScript, and
    // TypeScript without that flag.
    const params = { error: undefined } as unknown as SensitiveParseOptions;
    const result = sensitiveSafeParse(Strict, strictInput, params);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe('Unrecognized key(s) in object: 1 not allowed');
    }
  });

  it('test_a_supplied_error_map_wins', () => {
    const result = sensitiveSafeParse(z.string().min(50), 'x', {
      error: () => 'custom',
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe('custom');
    }
  });

  it('test_report_input_is_forced_off_even_when_the_caller_asks_for_it', () => {
    // `reportInput` is the one parse option that puts the raw value back on
    // every finalized issue. The redaction pass would strip it regardless; not
    // asking for it means the value is never assembled into the error at all.
    const result = sensitiveSafeParse(Strict, strictInput, { reportInput: true });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect('input' in (result.error.issues[0] ?? {})).toBe(false);
      expect(JSON.stringify(result.error)).not.toContain(CANARY);
    }
  });

  it('test_async_variant_returns_the_parsed_value_on_success', async () => {
    const schema = zSensitive('email').refineSensitive(() => Promise.resolve(true));

    const result = await sensitiveSafeParseAsync(schema, 'a@example.com');

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.reveal()).toBe('a@example.com');
    }
  });

  it('test_async_variant_covers_an_async_refinement', async () => {
    const schema = zSensitive('email').refineSensitive(() => Promise.resolve(false), {
      message: 'unknown domain',
    });

    const result = await sensitiveSafeParseAsync(schema, CANARY);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(JSON.stringify(result.error)).not.toContain(CANARY);
    }
  });

  it('test_async_variant_applies_the_map_and_forces_report_input_off', async () => {
    const result = await sensitiveSafeParseAsync(Strict, strictInput, { reportInput: true });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe('Unrecognized key(s) in object: 1 not allowed');
      expect(JSON.stringify(result.error)).not.toContain(CANARY);
    }
  });
});

describe('sensitiveParse', () => {
  it('test_returns_the_parsed_value_on_success', () => {
    expect(sensitiveParse(zCredential('password'), 'pw').reveal()).toBe('pw');
  });

  it('test_throws_a_redacted_zod_error', () => {
    try {
      sensitiveParse(Strict, strictInput);
      expect.unreachable('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(z.ZodError);
      expect(JSON.stringify(error)).not.toContain(CANARY);
    }
  });

  it('test_rethrows_a_non_zod_error_untouched', () => {
    const schema = z.string().transform(() => {
      throw new RangeError('boom');
    });

    expect(() => sensitiveParse(schema, 'x')).toThrow(RangeError);
  });
});
