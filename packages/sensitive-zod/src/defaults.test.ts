import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { SensitiveString, zSensitiveDefault } from './index.js';

describe('zSensitiveDefault', () => {
  it('test_default_fills_in_a_missing_field', () => {
    const schema = z.object({
      token: zSensitiveDefault('credential', 'token', () => 'default-token'),
    });

    const result = schema.parse({});

    expect(result.token).toBeInstanceOf(SensitiveString);
    expect(result.token.klass).toBe('credential');
    expect(result.token.reveal()).toBe('default-token');
  });

  it('test_default_accepts_a_literal_value', () => {
    const schema = zSensitiveDefault('sensitive', 'region', 'eu-west-1');

    expect(schema.parse(undefined).reveal()).toBe('eu-west-1');
  });

  it('test_default_yields_to_a_supplied_value', () => {
    const schema = zSensitiveDefault('credential', 'token', 'fallback');

    expect(schema.parse('supplied').reveal()).toBe('supplied');
  });

  it('test_default_factory_runs_once_per_parse_that_needs_it', () => {
    let calls = 0;
    const schema = zSensitiveDefault('credential', 'token', () => `token-${(calls += 1)}`);

    expect(schema.parse(undefined).reveal()).toBe('token-1');
    expect(schema.parse(undefined).reveal()).toBe('token-2');
    expect(schema.parse('given').reveal()).toBe('given');
    expect(calls).toBe(2);
  });

  it('test_default_does_not_substitute_for_null_or_empty_string', () => {
    const schema = zSensitiveDefault('credential', 'token', 'fallback');

    expect(schema.safeParse(null).success).toBe(false);
    expect(schema.parse('').reveal()).toBe('');
  });

  it('test_default_redacts_in_json', () => {
    const CANARY = 'CANARY-DEFAULT-VALUE-13';
    const schema = z.object({ token: zSensitiveDefault('credential', 'token', CANARY) });

    expect(JSON.stringify(schema.parse({}))).not.toContain(CANARY);
  });

  it('test_default_carries_refine_sensitive', () => {
    const schema = zSensitiveDefault('credential', 'token', 'short').refineSensitive(
      (raw) => raw.length >= 8,
      { message: 'too short' }
    );

    expect(schema.safeParse(undefined).success).toBe(false);
    expect(schema.safeParse('longenough').success).toBe(true);
  });
});
