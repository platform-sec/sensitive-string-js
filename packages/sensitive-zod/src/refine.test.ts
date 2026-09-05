import { describe, it, expect, afterEach } from 'vitest';
import { z } from 'zod';
import {
  SensitiveString,
  refineSensitive,
  withRevealContext,
  zCredential,
  zSensitive,
  zSensitiveWithValidation,
} from './index.js';
import { registerPolicy, resetPolicies } from '@platform-sec/sensitive-string-core';
import type { ISensitiveString, RevealDetails } from '@platform-sec/sensitive-string-core';

const CANARY = 'CANARY-REFINE-VALUE-77';

describe('refineSensitive', () => {
  afterEach(() => {
    resetPolicies();
  });

  it('test_refine_accepts_a_value_that_passes', () => {
    const schema = zCredential('password').refineSensitive((raw) => raw.length >= 12, {
      message: 'Password must be at least 12 characters',
    });

    const result = schema.parse('correct-horse-battery');

    expect(result).toBeInstanceOf(SensitiveString);
    expect(result.klass).toBe('credential');
  });

  it('test_refine_rejects_a_value_that_fails', () => {
    const schema = zCredential('password').refineSensitive((raw) => raw.length >= 12, {
      message: 'Password must be at least 12 characters',
    });

    const result = schema.safeParse('short');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe('Password must be at least 12 characters');
    }
  });

  it('test_refine_uses_a_value_free_default_message', () => {
    const result = zCredential()
      .refineSensitive(() => false)
      .safeParse(CANARY);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe('Invalid value');
    }
  });

  it('test_refine_chains', () => {
    const schema = zCredential('password')
      .refineSensitive((raw) => /[A-Z]/.test(raw), { message: 'needs an uppercase letter' })
      .refineSensitive((raw) => /[0-9]/.test(raw), { message: 'needs a digit' });

    expect(schema.safeParse('Abcdefgh').success).toBe(false);
    expect(schema.safeParse('abcdefg1').success).toBe(false);
    expect(schema.safeParse('Abcdefg1').success).toBe(true);
  });

  it('test_refine_runs_after_the_inner_string_validation', () => {
    const schema = zSensitiveWithValidation(
      'credential',
      z.string().min(8, 'at least 8'),
      'password'
    ).refineSensitive((raw) => /[A-Z]/.test(raw), { message: 'needs an uppercase letter' });

    const tooShort = schema.safeParse('short');
    expect(tooShort.success).toBe(false);
    if (!tooShort.success) {
      // The length check fails first, so the refinement never sees the value.
      expect(tooShort.error.issues.map((issue) => issue.message)).toEqual(['at least 8']);
    }

    expect(schema.safeParse('lowercaseonly').success).toBe(false);
    expect(schema.safeParse('ValidPassword').success).toBe(true);
  });

  it('test_refine_places_the_issue_at_the_field_path', () => {
    const schema = z.object({
      password: zCredential('password').refineSensitive(() => false, { message: 'nope' }),
    });

    const result = schema.safeParse({ password: 'x' });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.path).toEqual(['password']);
    }
  });

  it('test_refine_fatal_stops_the_chain', () => {
    // Zod 4 spells this `continue: false` and keeps `fatal` as a documented v3
    // compatibility path. An option that quietly stops being read is the exact
    // failure this migration turned up elsewhere, so it is pinned here.
    const stopping = zCredential('password')
      .refineSensitive(() => false, { message: 'first', fatal: true })
      .refineSensitive(() => false, { message: 'second' });

    const stopped = stopping.safeParse('x');
    expect(stopped.success).toBe(false);
    if (!stopped.success) {
      expect(stopped.error.issues.map((issue) => issue.message)).toEqual(['first']);
    }

    const collecting = zCredential('password')
      .refineSensitive(() => false, { message: 'first' })
      .refineSensitive(() => false, { message: 'second' });

    const collected = collecting.safeParse('x');
    expect(collected.success).toBe(false);
    if (!collected.success) {
      expect(collected.error.issues.map((issue) => issue.message)).toEqual(['first', 'second']);
    }
  });

  it('test_refine_appends_a_supplied_path', () => {
    const result = zCredential()
      .refineSensitive(() => false, { message: 'nope', path: ['confirm'] })
      .safeParse('x');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.path).toEqual(['confirm']);
    }
  });

  describe('auditing', () => {
    it('test_refine_is_audited_as_a_reveal', () => {
      const audited: Array<{ klass: string; operation: string }> = [];

      const schema = zCredential('password').refineSensitive((raw) => raw.length >= 4);

      withRevealContext(
        {
          name: 'signup-handler',
          auditReveal(value: ISensitiveString, details: RevealDetails) {
            audited.push({ klass: value.klass, operation: details.operation });
          },
        },
        () => schema.parse('longenough')
      );

      expect(audited).toEqual([{ klass: 'credential', operation: 'reveal' }]);
    });

    it('test_refine_audits_once_per_check_in_a_chain', () => {
      let reveals = 0;
      const schema = zCredential('password')
        .refineSensitive(() => true)
        .refineSensitive(() => true);

      withRevealContext(
        {
          name: 'signup-handler',
          auditReveal() {
            reveals += 1;
          },
        },
        () => schema.parse('value')
      );

      expect(reveals).toBe(2);
    });

    it('test_refine_uses_an_explicitly_supplied_context', () => {
      const seen: string[] = [];

      const schema = zSensitive('email').refineSensitive((raw) => raw.includes('@'), {
        context: {
          name: 'zod:email-shape',
          auditReveal(value: ISensitiveString) {
            seen.push(value.label ?? '');
          },
        },
      });

      schema.parse('a@example.com');

      expect(seen).toEqual(['email']);
    });

    it('test_refine_is_refused_by_a_policy_that_refuses_a_context_free_reveal', () => {
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: (ctx) => {
            if (!ctx) {
              throw new Error('credential reveals require a context');
            }
          },
        },
        { overwrite: true }
      );

      const schema = zCredential('password').refineSensitive(() => true);

      // The refinement manufactures no authority of its own: outside a context
      // it is refused exactly as a hand-written reveal would be.
      expect(() => schema.parse('value')).toThrow('credential reveals require a context');

      expect(withRevealContext({ name: 'signup' }, () => schema.parse('value'))).toBeInstanceOf(
        SensitiveString
      );
    });
  });

  describe('async checks', () => {
    it('test_async_check_passes_under_parse_async', async () => {
      const schema = zSensitive('email').refineSensitive(
        async (raw) => Promise.resolve(raw.endsWith('@example.com')),
        { message: 'unknown domain' }
      );

      await expect(schema.parseAsync('a@example.com')).resolves.toBeInstanceOf(SensitiveString);
      await expect(schema.safeParseAsync('a@elsewhere.com')).resolves.toMatchObject({
        success: false,
      });
    });

    it('test_async_check_is_refused_rather_than_skipped_under_sync_parse', () => {
      const schema = zSensitive('email').refineSensitive(() => Promise.resolve(false));

      // Zod throws rather than treating the pending promise as a pass. v4
      // raises `$ZodAsyncError` with a new message; the invariant is the same.
      expect(() => schema.parse('a@example.com')).toThrow(
        /Encountered Promise during synchronous parse/
      );
    });
  });

  describe('the standalone function', () => {
    it('test_standalone_refines_any_sensitive_schema', () => {
      const schema = refineSensitive(zCredential('token'), (raw) => raw.startsWith('sk_'), {
        message: 'token must start with sk_',
      });

      expect(schema.safeParse('pk_live').success).toBe(false);
      expect(schema.safeParse('sk_live').success).toBe(true);
    });

    it('test_standalone_does_not_mutate_the_schema_it_refines', () => {
      const base = zCredential('token');
      refineSensitive(base, () => false);

      expect(base.safeParse('anything').success).toBe(true);
    });
  });

  it('test_refine_survives_object_composition_and_partial', () => {
    const field = zCredential('password').refineSensitive((raw) => raw.length >= 8, {
      message: 'too short',
    });
    const schema = z.object({ password: field }).partial();

    expect(schema.safeParse({ password: 'short' }).success).toBe(false);
    expect(schema.safeParse({}).success).toBe(true);
  });
});
