import { afterEach, describe, expect, it } from 'vitest';
import {
  SensitiveString,
  deterministicRedaction,
  registerPolicy,
  resetPolicies,
} from '@platform-sec/sensitive-string-core';

import { MarkerLeakError } from './errors.js';
import { BASE64_NEEDLES, assertNoMarker, containsMarker, markerMatchers } from './marker.js';

describe('markerMatchers', () => {
  afterEach(() => {
    resetPolicies();
  });

  it('includes the literal prefix and every registered class marker', () => {
    const matchers = markerMatchers();

    expect(matchers).toContain('[REDACTED:');
    expect(matchers).toContain('[REDACTED:credential]');
    expect(matchers).toContain('[REDACTED:sensitive]');
  });

  it('picks up a custom redaction format registered after this module loaded', () => {
    registerPolicy(
      { name: 'credential', redact: () => '<<gone>>', requireConstantTimeEquals: true },
      { overwrite: true }
    );

    expect(markerMatchers()).toContain('<<gone>>');
    expect(() => assertNoMarker('token=<<gone>>', 'query string')).toThrow(MarkerLeakError);
  });

  it('derives no needle from a value-dependent redactor, and says so by omission', () => {
    registerPolicy(
      { name: 'sensitive', redact: (value: string) => `len:${value.length}` },
      { overwrite: true }
    );

    // The probe's length is the only thing such a policy would contribute, and
    // a needle of `len:29` would fire on unrelated traffic. The prefix still
    // covers the default format, and `markerPattern` is what closes the rest.
    expect(markerMatchers().some((m) => typeof m === 'string' && m.startsWith('len:'))).toBe(false);
  });

  it('consults a policy that declares its own markerPattern', () => {
    registerPolicy(
      {
        name: 'sensitive',
        redact: (value: string) => `##${value.length}##`,
        markerPattern: /##\d+##/,
      },
      { overwrite: true }
    );

    expect(() => assertNoMarker('body ##42##', 'request body')).toThrow(MarkerLeakError);
  });

  /**
   * Core's first value-dependent policy, end to end. Its default rendering
   * still starts with `[REDACTED:` and would be caught by the prefix alone; a
   * custom prefix would not, and before the policy declared a `markerPattern`
   * that request went out with the tag in it instead of being refused.
   */
  it.each([
    ['the default prefix', { key: new Uint8Array(32).fill(7) }],
    ['a custom prefix', { key: new Uint8Array(32).fill(7), prefix: 'PII' }],
  ])('catches a deterministic redaction under %s', (_label, options) => {
    registerPolicy(deterministicRedaction('sensitive', options), { overwrite: true });

    const body = JSON.stringify({ email: String(new SensitiveString('a@b.com', 'sensitive')) });

    expect(() => assertNoMarker(body, 'request body')).toThrow(MarkerLeakError);
  });
});

describe('assertNoMarker', () => {
  it('passes clean bytes', () => {
    expect(() => assertNoMarker('{"token":"sk_live_real"}', 'request body')).not.toThrow();
  });

  it('finds the literal marker in a JSON body', () => {
    expect(() => assertNoMarker('{"token":"[REDACTED:credential]"}', 'request body')).toThrow(
      /redaction marker \(literal encoding\)/
    );
  });

  it('finds the fully percent-encoded marker a form body carries', () => {
    expect(() => assertNoMarker('token=%5BREDACTED%3Acredential%5D', 'form body')).toThrow(
      /percent encoding/
    );
  });

  it("finds axios's partly encoded params form, which neither literal scan catches", () => {
    const wire = '?token=%5BREDACTED:credential%5D';

    expect(wire.includes('[REDACTED:')).toBe(false);
    expect(wire.includes('%5BREDACTED%3A')).toBe(false);
    expect(() => assertNoMarker(wire, 'query string')).toThrow(MarkerLeakError);
  });

  it('treats an undecodable body as itself rather than throwing URIError', () => {
    expect(() => assertNoMarker('%%%not-encoding%%%', 'request body')).not.toThrow();
  });

  it('leaves base64 alone by default and finds it when asked', () => {
    const wire = Buffer.from('user:[REDACTED:credential]').toString('base64');

    expect(() => assertNoMarker(wire, 'header')).not.toThrow();
    expect(() => assertNoMarker(wire, 'header', { base64: true })).toThrow(/base64 encoding/);
  });

  it('fires on all three base64 alignments', () => {
    for (let pad = 0; pad < 3; pad += 1) {
      const wire = Buffer.from(`${'X'.repeat(pad)}[REDACTED:credential]`).toString('base64');

      expect(BASE64_NEEDLES.some((needle) => wire.includes(needle))).toBe(true);
      expect(() => assertNoMarker(wire, 'header', { base64: true })).toThrow(MarkerLeakError);
    }
  });

  it('fires across 400 prefix offsets and both base64 flavours', () => {
    for (let length = 0; length < 400; length += 1) {
      for (const klass of ['credential', 'sensitive']) {
        const raw = `${'a'.repeat(length)}[REDACTED:${klass}]`;

        for (const encoding of ['base64', 'base64url'] as const) {
          const wire = Buffer.from(raw).toString(encoding);

          expect(BASE64_NEEDLES.some((needle) => wire.includes(needle))).toBe(true);
        }
      }
    }
  });

  it('says nothing about an empty representation', () => {
    expect(() => assertNoMarker('', 'request body')).not.toThrow();
  });

  it('names the position and the encoding without naming a value', () => {
    try {
      assertNoMarker('{"card":"[REDACTED:credential]"}', "body path 'card'");
      expect.unreachable();
    } catch (error) {
      expect((error as MarkerLeakError).where).toBe("body path 'card'");
      expect((error as MarkerLeakError).encoding).toBe('literal');
    }
  });
});

describe('containsMarker', () => {
  it('answers without throwing, for the undici interceptor', () => {
    expect(containsMarker('[REDACTED:credential]')).toBe(true);
    expect(containsMarker('sk_live_real')).toBe(false);
  });
});
