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

const CANARY = 'CANARY-ERRORMAP-VALUE-58';

afterEach(() => {
  z.setErrorMap(z.defaultErrorMap);
});

describe('sensitiveErrorMap', () => {
  it('test_error_map_keeps_the_input_out_of_an_enum_message', () => {
    const result = z.enum(['a', 'b']).safeParse(CANARY, { errorMap: sensitiveErrorMap });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe(`Invalid enum value. Expected "a" | "b"`);
      expect(result.error.issues[0]?.message).not.toContain(CANARY);
    }
  });

  it('test_error_map_keeps_unknown_key_names_out_of_the_message', () => {
    const schema = z.object({ a: z.string() }).strict();
    const result = schema.safeParse({ a: 'x', [CANARY]: 1 }, { errorMap: sensitiveErrorMap });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).not.toContain(CANARY);
      expect(result.error.issues[0]?.message).toContain('1 not allowed');
    }
  });

  it('test_error_map_leaves_other_messages_alone', () => {
    const result = z.string().min(50).safeParse('x', { errorMap: sensitiveErrorMap });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe('String must contain at least 50 character(s)');
    }
  });

  it('test_install_sets_the_global_map', () => {
    installSensitiveErrorMap();

    const result = z.enum(['a', 'b']).safeParse(CANARY);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).not.toContain(CANARY);
    }
  });

  it('test_the_map_is_not_installed_merely_by_importing_the_package', () => {
    // The default map is still in place, which is exactly why the message half
    // of the fix has to be opted into.
    const result = z.enum(['a', 'b']).safeParse(CANARY);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toContain(CANARY);
    }
  });
});

describe('redactZodIssues', () => {
  it('test_redacts_the_received_value_of_an_enum_issue', () => {
    const error = z.enum(['a', 'b']).safeParse(CANARY);

    expect(error.success).toBe(false);
    if (!error.success) {
      const redacted = redactZodIssues(error.error.issues);

      expect(JSON.stringify(redacted)).not.toContain(CANARY);
      expect(JSON.stringify(redacted)).toContain(REDACTED_ISSUE_VALUE);
    }
  });

  it('test_redacts_the_received_value_of_a_literal_issue', () => {
    const error = z.literal('a').safeParse(CANARY);

    if (!error.success) {
      expect(JSON.stringify(redactZodIssues(error.error.issues))).not.toContain(CANARY);
    }
  });

  it('test_redacts_unknown_key_names', () => {
    const schema = z.object({ a: z.string() }).strict();
    const error = schema.safeParse({ a: 'x', [CANARY]: 1 });

    if (!error.success) {
      const redacted = redactZodIssues(error.error.issues);

      expect(JSON.stringify(redacted)).not.toContain(CANARY);
      // The count survives, so a caller still knows how many keys were refused.
      expect((redacted[0] as { keys: string[] }).keys).toEqual([REDACTED_ISSUE_VALUE]);
    }
  });

  it('test_drops_custom_issue_params', () => {
    const schema = z.string().superRefine((value, ctx) => {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'bad', params: { value } });
    });
    const error = schema.safeParse(CANARY);

    if (!error.success) {
      const redacted = redactZodIssues(error.error.issues);

      expect(JSON.stringify(redacted)).not.toContain(CANARY);
      expect(redacted[0]).not.toHaveProperty('params');
      expect(redacted[0]?.message).toBe('bad');
    }
  });

  it('test_recurses_into_union_errors', () => {
    const schema = z.union([z.literal('a'), z.number()]);
    const error = schema.safeParse(CANARY);

    if (!error.success) {
      expect(JSON.stringify(error.error.issues)).toContain(CANARY);
      expect(JSON.stringify(redactZodIssues(error.error.issues))).not.toContain(CANARY);
    }
  });

  it('test_leaves_the_received_type_name_of_an_invalid_type_issue_alone', () => {
    const error = z.number().safeParse('x');

    if (!error.success) {
      expect(redactZodIssues(error.error.issues)[0]).toMatchObject({
        code: 'invalid_type',
        received: 'string',
      });
    }
  });

  it('test_does_not_mutate_the_issues_it_is_given', () => {
    const error = z.enum(['a', 'b']).safeParse(CANARY);

    if (!error.success) {
      redactZodIssues(error.error.issues);

      expect(JSON.stringify(error.error.issues)).toContain(CANARY);
    }
  });

  it('test_redactZodError_returns_a_usable_ZodError', () => {
    const error = z.object({ role: z.enum(['a', 'b']) }).safeParse({ role: CANARY });

    if (!error.success) {
      const redacted = redactZodError(error.error);

      expect(redacted).toBeInstanceOf(z.ZodError);
      expect(redacted.issues[0]?.path).toEqual(['role']);
      expect(JSON.stringify(redacted.format())).not.toContain(CANARY);
      expect(JSON.stringify(redacted.flatten())).not.toContain(CANARY);
    }
  });
});

describe('sensitiveSafeParse', () => {
  const Payload = z.object({
    role: z.enum(['admin', 'user']),
    password: zCredential('password'),
  });

  it('test_returns_the_parsed_value_on_success', () => {
    const result = sensitiveSafeParse(Payload, { role: 'admin', password: 'pw' });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.password.reveal()).toBe('pw');
    }
  });

  it('test_applies_both_halves_of_the_fix', () => {
    const result = sensitiveSafeParse(Payload, { role: CANARY, password: 'pw' });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(JSON.stringify(result.error)).not.toContain(CANARY);
      expect(result.error.issues[0]?.message).not.toContain(CANARY);
    }
  });

  it('test_an_explicit_undefined_error_map_does_not_disable_the_default', () => {
    // Spreading the caller's params over the default would leave Zod resolving
    // the global map here, which is a fail-open.
    const result = sensitiveSafeParse(z.enum(['a', 'b']), CANARY, { errorMap: undefined });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).not.toContain(CANARY);
    }
  });

  it('test_a_supplied_error_map_wins', () => {
    const result = sensitiveSafeParse(z.string().min(50), 'x', {
      errorMap: () => ({ message: 'custom' }),
    });

    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe('custom');
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
});

describe('sensitiveParse', () => {
  it('test_returns_the_parsed_value_on_success', () => {
    expect(sensitiveParse(zCredential('password'), 'pw').reveal()).toBe('pw');
  });

  it('test_throws_a_redacted_zod_error', () => {
    try {
      sensitiveParse(z.enum(['a', 'b']), CANARY);
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
