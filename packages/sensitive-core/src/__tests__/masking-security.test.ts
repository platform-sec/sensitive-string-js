/**
 * Partial Masking Security Tests
 *
 * `mask()` is a partial reveal. These tests verify that the policy gate, the
 * minMasked floor, and the audit trail cannot be worked around, and that a
 * rejected call discloses nothing.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SensitiveString, registerPolicy, resetPolicies, withRevealContext } from '../index.js';
import type { MaskOptions, RevealContext, RevealDetails } from '../index.js';

const CANARY = 'MASKING_SECURITY_CANARY_9f21c7';

/** A credential policy that permits masking, which the default one does not. */
function allowCredentialMasking(): void {
  registerPolicy(
    {
      name: 'credential',
      redact: () => '[REDACTED:credential]',
      requireConstantTimeEquals: true,
      allowPartialQueries: false,
      allowMask: true,
    },
    { overwrite: true }
  );
}

describe('partial masking security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('policy enforcement', () => {
    it('denies masking for credentials by default', () => {
      const credential = new SensitiveString(CANARY, 'credential', 'api_key');

      expect(() => credential.mask({ showLast: 4 })).toThrow(
        "Masking is not allowed for sensitivity class 'credential' (api_key)"
      );
    });

    it('names the class and label but never the value when it denies', () => {
      const credential = new SensitiveString(CANARY, 'credential', 'api_key');

      try {
        credential.mask({ showLast: 4 });
        expect.unreachable('expected masking to be denied');
      } catch (error) {
        expect(String(error)).not.toContain(CANARY);
        expect((error as Error).stack ?? '').not.toContain(CANARY);
      }
    });

    it('does not authorize or audit a denied mask', () => {
      const checkRevealAllowed = vi.fn();
      const auditReveal = vi.fn();
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          allowMask: false,
          checkRevealAllowed,
        },
        { overwrite: true }
      );

      const credential = new SensitiveString(CANARY, 'credential', 'api_key');

      expect(() => credential.mask({ showLast: 4 }, { name: 'probe', auditReveal })).toThrow(
        'Masking is not allowed'
      );
      expect(checkRevealAllowed).not.toHaveBeenCalled();
      expect(auditReveal).not.toHaveBeenCalled();
    });

    it('cannot be reached through a derived value', () => {
      const credential = new SensitiveString(`  ${CANARY}  `, 'credential', 'api_key');

      // Derivatives keep the class, so they keep the denial with it.
      expect(() => credential.trim().mask({ showLast: 4 })).toThrow('Masking is not allowed');
      expect(() => credential.slice(2).mask({ showLast: 4 })).toThrow('Masking is not allowed');
      expect(() => credential.map((value) => value).mask({ showLast: 4 })).toThrow(
        'Masking is not allowed'
      );
      expect(() => credential.concat('suffix').mask({ showLast: 4 })).toThrow(
        'Masking is not allowed'
      );
    });

    it('follows a value reclassified into a masking-denied class', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'note');

      expect(value.mask({ showLast: 4 })).not.toContain(CANARY);
      expect(() => value.reclassify('credential').mask({ showLast: 4 })).toThrow(
        'Masking is not allowed'
      );
    });

    it('lets a policy opt a credential in, under the higher credential floor', () => {
      allowCredentialMasking();

      expect(
        new SensitiveString(CANARY, 'credential', 'api_key').mask({ showLast: 4 })
      ).not.toContain(CANARY);

      // The BIN and the last four leave six of sixteen digits hidden, which is
      // below the floor of eight that the credential class carries.
      expect(
        new SensitiveString('4111111111111111', 'credential', 'card').mask({ strategy: 'card' })
      ).toBe('[REDACTED:credential]');
    });

    it('runs checkRevealAllowed exactly as reveal does', () => {
      const seen: (string | null)[] = [];
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          allowMask: true,
          checkRevealAllowed: (ctx) => {
            seen.push(ctx?.name ?? null);
            if (ctx?.name !== 'approved') {
              throw new Error('Reveal denied');
            }
          },
        },
        { overwrite: true }
      );

      const value = new SensitiveString(CANARY, 'sensitive');

      expect(() => value.mask({ showLast: 4 }, { name: 'denied' })).toThrow('Reveal denied');
      expect(value.mask({ showLast: 4 }, { name: 'approved' })).not.toContain(CANARY);
      expect(seen).toEqual(['denied', 'approved']);
    });
  });

  describe('the minMasked floor', () => {
    it('cannot be lowered by the caller', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'note');

      for (const minMasked of [0, 1, 3]) {
        expect(() => value.mask({ showFirst: CANARY.length, minMasked })).toThrow(RangeError);
      }
    });

    it('cannot be lowered by asking for more than the value holds', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'note');
      const masked = value.mask({ showFirst: 1000, showLast: 1000 });

      expect(masked).not.toContain(CANARY);
      expect(masked.split('*').length - 1).toBe(4);
    });

    it('holds for every built-in strategy', () => {
      const cases: { value: string; options: MaskOptions }[] = [
        { value: 'jane@example.com', options: { strategy: 'email' } },
        { value: '+1-555-123-4567', options: { strategy: 'phone' } },
        { value: '4111111111111111', options: { strategy: 'card' } },
        { value: '123-45-6789', options: { strategy: 'ssn' } },
        { value: '550e8400-e29b-41d4-a716-446655440000', options: { strategy: 'uuid' } },
        { value: 'sk_live_abc123xyz9', options: { showFirst: 2, showLast: 4 } },
      ];

      for (const { value, options } of cases) {
        const masked = new SensitiveString(value, 'sensitive').mask(options);
        const hidden = [...masked].filter((char) => char === '*').length;

        expect(hidden).toBeGreaterThanOrEqual(4);
        expect(masked).not.toBe(value);
      }
    });

    it('redacts rather than showing most of a short value', () => {
      for (const value of ['', 'a', 'ab', 'abc']) {
        expect(new SensitiveString(value, 'sensitive').mask({ showFirst: 4 })).toBe(
          '[REDACTED:sensitive]'
        );
      }
    });

    it('uses the class policy for the fallback redaction', () => {
      registerPolicy(
        { name: 'sensitive', redact: () => '[HIDDEN]', allowMask: true },
        { overwrite: true }
      );

      expect(new SensitiveString('abc', 'sensitive').mask({ showFirst: 1 })).toBe('[HIDDEN]');
    });
  });

  describe('the masked rendering', () => {
    it('never contains the whole value', () => {
      const email = new SensitiveString(`${CANARY}@example.com`, 'sensitive', 'email');
      const positional = new SensitiveString(CANARY, 'sensitive', 'note');

      expect(email.mask({ strategy: 'email' })).not.toContain(CANARY);
      expect(positional.mask({ showFirst: 4, showLast: 4 })).not.toContain(CANARY);
      expect(positional.mask()).not.toContain(CANARY);
    });

    it('shows no more than the caller asked for', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'note');
      const masked = value.mask({ showFirst: 2, showLast: 3 });

      expect(masked.startsWith(CANARY.slice(0, 2))).toBe(true);
      expect(masked.endsWith(CANARY.slice(-3))).toBe(true);
      expect(masked).not.toContain(CANARY.slice(0, 3));
      expect(masked).not.toContain(CANARY.slice(-4));
    });

    it('leaves the protected value untouched', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'note');

      value.mask({ showFirst: 2 });

      expect(value.reveal()).toBe(CANARY);
      expect(String(value)).toBe('[REDACTED:sensitive]');
      expect(JSON.stringify({ value })).not.toContain(CANARY);
    });

    it('is a plain string, so it carries no protection of its own', () => {
      const masked = new SensitiveString(CANARY, 'sensitive', 'note').mask({ showLast: 4 });

      expect(typeof masked).toBe('string');
      expect(masked).not.toBeInstanceOf(SensitiveString);
    });
  });

  describe('option validation', () => {
    it('rejects a mask character that is not exactly one character', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'note');

      // An empty mask would drop hidden characters and shorten the rendering;
      // a multi-character one would pad it into a different shape.
      expect(() => value.mask({ maskChar: '' })).toThrow('exactly one character');
      expect(() => value.mask({ maskChar: '**' })).toThrow('exactly one character');
      expect(() => value.mask({ maskChar: 'ab' })).toThrow('exactly one character');
    });

    it('rejects a custom formatter attached to a built-in strategy', () => {
      const value = new SensitiveString(`${CANARY}@example.com`, 'sensitive', 'email');
      const exfiltrated: string[] = [];

      // A formatter is handed the raw value and its output is not measured
      // against the floor, so it may only run when the caller names it.
      expect(() =>
        value.mask({
          strategy: 'email',
          customStrategy: (raw) => {
            exfiltrated.push(raw);
            return raw;
          },
        })
      ).toThrow("customStrategy requires strategy: 'custom'");
      expect(exfiltrated).toEqual([]);
    });

    it('does not read the value when options are rejected', () => {
      const auditReveal = vi.fn();
      const value = new SensitiveString(CANARY, 'sensitive', 'note');
      const ctx: RevealContext = { name: 'invalid', auditReveal };

      const invalid: MaskOptions[] = [
        { maskChar: '' },
        { showFirst: -1 },
        { minMasked: 1 },
        { strategy: 'passport' as never },
        { strategy: 'custom' },
        { strategy: 'email', showFirst: 1 },
      ];

      for (const options of invalid) {
        expect(() => value.mask(options, ctx)).toThrow();
      }

      expect(auditReveal).not.toHaveBeenCalled();
    });

    it('keeps the value out of validation errors', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'note');

      try {
        value.mask({ maskChar: '' });
        expect.unreachable('expected the mask character to be rejected');
      } catch (error) {
        expect(String(error)).not.toContain(CANARY);
        expect((error as Error).stack ?? '').not.toContain(CANARY);
      }
    });

    it('does not invoke a caller-supplied toString when naming a bad strategy', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'note');
      const hostile = {
        toString: () => {
          throw new Error('toString invoked');
        },
      };

      expect(() => value.mask({ strategy: hostile as never })).toThrow('is not a masking strategy');
    });
  });

  describe('audit trail', () => {
    it('records the operation and the options that produced the rendering', () => {
      const records: RevealDetails[] = [];
      const value = new SensitiveString('4111111111111111', 'sensitive', 'card');

      withRevealContext(
        {
          name: 'support-console',
          auditReveal: (_value, details) => {
            records.push(details);
          },
        },
        () => {
          value.mask({ strategy: 'card' });
          value.mask({ showLast: 4, maskChar: '#', minMasked: 6 });
        }
      );

      expect(records).toEqual([
        {
          operation: 'mask',
          strategy: 'card',
          showFirst: 0,
          showLast: 0,
          minMasked: 4,
          maskChar: '*',
        },
        {
          operation: 'mask',
          strategy: 'positional',
          showFirst: 0,
          showLast: 4,
          minMasked: 6,
          maskChar: '#',
        },
      ]);
    });

    it('never puts the value or the formatter in the audit record', () => {
      const records: RevealDetails[] = [];
      const value = new SensitiveString(CANARY, 'sensitive', 'note');

      value.mask(
        { strategy: 'custom', customStrategy: (raw) => raw.slice(0, 2) },
        {
          name: 'custom-mask',
          auditReveal: (_value, details) => {
            records.push(details);
          },
        }
      );

      expect(JSON.stringify(records)).not.toContain(CANARY);
      expect(records[0]).not.toHaveProperty('customStrategy');
      expect(records[0]).toMatchObject({ operation: 'mask', strategy: 'custom' });
    });

    it('audits a rendering that fell back to full redaction', () => {
      const auditReveal = vi.fn();
      const value = new SensitiveString('abc', 'sensitive', 'note');

      expect(value.mask({ showFirst: 2 }, { name: 'fallback', auditReveal })).toBe(
        '[REDACTED:sensitive]'
      );
      expect(auditReveal).toHaveBeenCalledTimes(1);
    });

    it('hands out an audit record an audit hook cannot repurpose', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'note');
      const records: RevealDetails[] = [];
      const ctx: RevealContext = {
        name: 'mutating',
        auditReveal: (_value, details) => {
          // A sink that writes to the record must not corrupt the next one.
          Object.assign(details as unknown as Record<string, unknown>, { operation: 'reveal' });
          records.push(details);
        },
      };

      // Object.assign on a frozen object throws in strict mode, which is what
      // module code is. Either way the next record must be unaffected.
      expect(() => value.mask({ showLast: 4 }, ctx)).toThrow(TypeError);

      const clean: RevealDetails[] = [];
      value.mask({ showLast: 4 }, { name: 'clean', auditReveal: (_v, d) => clean.push(d) });
      value.reveal({ name: 'clean', auditReveal: (_v, d) => clean.push(d) });

      expect(clean.map((record) => record.operation)).toEqual(['mask', 'reveal']);
      expect(records).toHaveLength(0);
    });
  });

  describe('the strategy mismatch rule', () => {
    it('redacts rather than showing a prefix of a value it does not recognize', () => {
      // Each of these is a secret that is not of the requested format. A
      // strategy that degraded to positional masking would show a fixed prefix
      // of the secret instead.
      const token = new SensitiveString(`${CANARY}a1b2c3d4e5f6a7b8`, 'sensitive', 'token');

      for (const strategy of ['email', 'card', 'uuid'] as const) {
        expect(token.mask({ strategy })).toBe('[REDACTED:sensitive]');
      }
    });

    it('does not render a value as a card just because it holds enough digits', () => {
      const token = new SensitiveString('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', 'sensitive', 'token');

      expect(token.mask({ strategy: 'card' })).toBe('[REDACTED:sensitive]');
    });

    it('still audits a mask that the mismatch rule redacted', () => {
      const auditReveal = vi.fn();
      const token = new SensitiveString(CANARY, 'sensitive', 'token');

      expect(token.mask({ strategy: 'uuid' }, { name: 'mismatch', auditReveal })).toBe(
        '[REDACTED:sensitive]'
      );
      expect(auditReveal).toHaveBeenCalledTimes(1);
    });
  });

  describe('the floor holds for arbitrary inputs', () => {
    /** A seeded generator, so a failure names an input that reproduces. */
    function makeRandom(seed: number): () => number {
      let state = seed;
      return () => {
        // Numerical Recipes' LCG. Reproducibility is the only requirement.
        state = (state * 1664525 + 1013904223) % 0x100000000;
        return state / 0x100000000;
      };
    }

    it('never shows more than length minus minMasked characters', () => {
      const random = makeRandom(20260902);
      // No '*': the count below treats every rendered character that also
      // occurs in the value as one the caller can read, which is exact only
      // while the mask character cannot come from the value itself.
      const alphabet = [...'abcxyz019-+@. \u00e9\u{1f512}'];
      const strategies = [undefined, 'email', 'phone', 'card', 'ssn', 'uuid'] as const;

      for (let run = 0; run < 500; run += 1) {
        const length = Math.floor(random() * 24);
        const value = Array.from(
          { length },
          () => alphabet[Math.floor(random() * alphabet.length)] ?? 'a'
        ).join('');
        const strategy = strategies[Math.floor(random() * strategies.length)];
        const options: MaskOptions =
          strategy === undefined
            ? {
                showFirst: Math.floor(random() * 8),
                showLast: Math.floor(random() * 8),
                minMasked: 4 + Math.floor(random() * 4),
              }
            : { strategy };

        const protectedValue = new SensitiveString(value, 'sensitive', 'note');
        const masked = protectedValue.mask(options);
        const context = `run ${run}, value ${JSON.stringify(value)}, ${JSON.stringify(options)}`;

        if (masked === '[REDACTED:sensitive]') {
          continue;
        }

        // Every code point of the value that survives into the rendering is a
        // character the caller can read, so at most length minus the floor of
        // them may appear.
        const chars = [...value];
        const shown = [...masked].filter((char) => chars.includes(char)).length;

        expect(shown, context).toBeLessThanOrEqual(
          Math.max(0, chars.length - (options.minMasked ?? 4))
        );
        expect(masked, context).not.toBe(value);
      }
    });
  });

  describe('canary containment', () => {
    it('keeps the canary out of every masked rendering of a formatted value', () => {
      const cases: { value: string; options: MaskOptions }[] = [
        { value: `${CANARY}@example.com`, options: { strategy: 'email' } },
        { value: `+1-555-123-4567`, options: { strategy: 'phone' } },
        { value: `${CANARY}`, options: { showFirst: 2, showLast: 2 } },
        { value: `${CANARY}`, options: { minMasked: 20 } },
        { value: `${CANARY}`, options: {} },
      ];

      for (const { value, options } of cases) {
        const masked = new SensitiveString(value, 'sensitive', 'note').mask(options);

        expect(masked).not.toContain(CANARY);
      }
    });

    it('keeps the canary out of a rendering that a policy redacted', () => {
      const masked = new SensitiveString(CANARY.slice(0, 3), 'sensitive').mask({ showFirst: 2 });

      expect(masked).toBe('[REDACTED:sensitive]');
      expect(masked).not.toContain(CANARY.slice(0, 3));
    });
  });
});
