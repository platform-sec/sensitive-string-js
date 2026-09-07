import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SensitiveString, registerPolicy, resetPolicies, withRevealContext } from './index.js';
import type { RevealDetails } from './index.js';

const sensitive = (value: string, label?: string) => new SensitiveString(value, 'sensitive', label);

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

describe('SensitiveString.mask', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('positional masking', () => {
    it('shows leading characters', () => {
      expect(sensitive('sk_live_abc123xyz9').mask({ showFirst: 2 })).toBe('sk****************');
    });

    it('shows trailing characters', () => {
      expect(sensitive('abcdefghijkxyz9').mask({ showLast: 4 })).toBe('***********xyz9');
    });

    it('shows both ends', () => {
      expect(sensitive('sk_live_abc123xyz9').mask({ showFirst: 2, showLast: 4 })).toBe(
        'sk************xyz9'
      );
    });

    it('hides everything by default', () => {
      expect(sensitive('secretvalue').mask()).toBe('***********');
    });

    it('uses the requested mask character', () => {
      expect(sensitive('secretvalue').mask({ showLast: 3, maskChar: '#' })).toBe('########lue');
    });

    it('preserves the length of the value', () => {
      const value = 'a'.repeat(37);

      expect(sensitive(value).mask({ showFirst: 3 })).toHaveLength(37);
    });
  });

  describe('the minMasked floor', () => {
    it('clamps what positional masking shows', () => {
      // Six characters with a floor of four leaves two to show, not the six asked for.
      expect(sensitive('abcdef').mask({ showLast: 6 })).toBe('****ef');
    });

    it('splits the clamped allowance in favor of showFirst', () => {
      expect(sensitive('abcdef').mask({ showFirst: 2, showLast: 2 })).toBe('ab****');
    });

    it('falls back to full redaction when the value is shorter than the floor', () => {
      expect(sensitive('abc').mask({ showFirst: 1 })).toBe('[REDACTED:sensitive]');
    });

    it('accepts a raised floor', () => {
      expect(sensitive('abcdefghij').mask({ showLast: 4, minMasked: 8 })).toBe('********ij');
    });

    it('rejects a lowered floor', () => {
      expect(() => sensitive('abcdefghij').mask({ showLast: 4, minMasked: 1 })).toThrow(RangeError);
      expect(() => sensitive('abcdefghij').mask({ showLast: 4, minMasked: 1 })).toThrow(
        "minMasked 1 is below the floor of 4 for sensitivity class 'sensitive'"
      );
    });

    it('applies the higher credential floor', () => {
      allowCredentialMasking();
      const credential = new SensitiveString('abcdefghijkl', 'credential', 'token');

      expect(credential.mask({ showLast: 8 })).toBe('********ijkl');
      expect(() => credential.mask({ minMasked: 4 })).toThrow(
        "minMasked 4 is below the floor of 8 for sensitivity class 'credential'"
      );
    });

    it('falls back to full redaction when a strategy cannot reach the floor', () => {
      // Ten of thirteen digits shown leaves three hidden, one short of the floor.
      expect(sensitive('4111111111111').mask({ strategy: 'card' })).toBe('[REDACTED:sensitive]');
    });
  });

  describe('the email strategy', () => {
    it('masks the local part and the domain', () => {
      expect(sensitive('jane@example.com', 'email').mask({ strategy: 'email' })).toBe(
        'j***@e******.com'
      );
    });

    it('keeps only the final domain label', () => {
      expect(sensitive('bob@sub.example.co.uk').mask({ strategy: 'email' })).toBe(
        'b**@s*************.uk'
      );
    });

    it('hides a one-character local part completely', () => {
      expect(sensitive('a@example.com').mask({ strategy: 'email' })).toBe('*@e******.com');
    });

    it('splits on the last @, which a quoted local part may contain', () => {
      expect(sensitive('a@b@example.com').mask({ strategy: 'email' })).toBe('a**@e******.com');
    });

    it('masks a domain with no dot', () => {
      expect(sensitive('jane@localhost').mask({ strategy: 'email' })).toBe('j***@l********');
    });

    it('redacts fully when the value has no @', () => {
      expect(sensitive('not-an-email').mask({ strategy: 'email' })).toBe('[REDACTED:sensitive]');
    });

    it('redacts fully when the domain is empty', () => {
      // 'j***' hides three characters, one short of the floor.
      expect(sensitive('john@').mask({ strategy: 'email' })).toBe('[REDACTED:sensitive]');
    });
  });

  describe('the phone strategy', () => {
    it('keeps the last four digits and the formatting', () => {
      expect(sensitive('+1-555-123-4567', 'phone').mask({ strategy: 'phone' })).toBe(
        '+1-***-***-4567'
      );
    });

    it('keeps a multi-digit country code', () => {
      expect(sensitive('+44 20 7946 0958').mask({ strategy: 'phone' })).toBe('+44 ** **** 0958');
    });

    it('keeps no country code when nothing delimits it', () => {
      expect(sensitive('+15551234567').mask({ strategy: 'phone' })).toBe('+*******4567');
    });

    it('handles a number with no country code', () => {
      expect(sensitive('(555) 123-4567').mask({ strategy: 'phone' })).toBe('(***) ***-4567');
    });

    it('hides characters that are neither digits nor separators', () => {
      expect(sensitive('555-EXT-4567').mask({ strategy: 'phone' })).toBe('***-***-4567');
    });
  });

  describe('the card strategy', () => {
    it('shows the BIN and the last four digits', () => {
      expect(sensitive('4111111111111111', 'card').mask({ strategy: 'card' })).toBe(
        '411111******1111'
      );
    });

    it('normalizes separators away', () => {
      expect(sensitive('4111-1111-1111-1111').mask({ strategy: 'card' })).toBe('411111******1111');
      expect(sensitive('4111 1111 1111 1111').mask({ strategy: 'card' })).toBe('411111******1111');
    });

    it('handles a fifteen-digit card', () => {
      expect(sensitive('371449635398431').mask({ strategy: 'card' })).toBe('371449*****8431');
    });

    it('redacts fully when the value is not a plausible card number', () => {
      expect(sensitive('42').mask({ strategy: 'card' })).toBe('[REDACTED:sensitive]');
      expect(sensitive('4'.repeat(20)).mask({ strategy: 'card' })).toBe('[REDACTED:sensitive]');
    });

    it('redacts a value that merely contains enough digits', () => {
      // A hex token holds sixteen digits among its letters. Rendering those as
      // a card would show ten characters of a value that is not a card.
      expect(sensitive('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6').mask({ strategy: 'card' })).toBe(
        '[REDACTED:sensitive]'
      );
    });
  });

  describe('the ssn strategy', () => {
    it('shows the last four digits', () => {
      expect(sensitive('123-45-6789', 'ssn').mask({ strategy: 'ssn' })).toBe('***-**-6789');
    });

    it('works without separators', () => {
      expect(sensitive('123456789').mask({ strategy: 'ssn' })).toBe('*****6789');
    });
  });

  describe('the uuid strategy', () => {
    it('shows the first segment', () => {
      expect(
        sensitive('550e8400-e29b-41d4-a716-446655440000', 'request_id').mask({ strategy: 'uuid' })
      ).toBe('550e8400-****-****-****-************');
    });

    it('redacts fully when the value has the wrong segment count', () => {
      expect(sensitive('550e8400-e29b-41d4-a716').mask({ strategy: 'uuid' })).toBe(
        '[REDACTED:sensitive]'
      );
    });

    it('redacts fully when a segment is not hexadecimal', () => {
      expect(sensitive('550e8400-e29b-41d4-a716-4466554400zz').mask({ strategy: 'uuid' })).toBe(
        '[REDACTED:sensitive]'
      );
    });

    it('accepts an uppercase uuid', () => {
      expect(sensitive('550E8400-E29B-41D4-A716-446655440000').mask({ strategy: 'uuid' })).toBe(
        '550E8400-****-****-****-************'
      );
    });
  });

  describe('the custom strategy', () => {
    it('invokes the formatter with the raw value', () => {
      const customStrategy = vi.fn((value: string) => `${value.slice(0, 3)}...${value.slice(-3)}`);

      expect(sensitive('4111111111111111').mask({ strategy: 'custom', customStrategy })).toBe(
        '411...111'
      );
      expect(customStrategy).toHaveBeenCalledWith('4111111111111111');
    });

    it('rejects a formatter that returns the value unchanged', () => {
      expect(() =>
        sensitive('secretvalue').mask({ strategy: 'custom', customStrategy: (value) => value })
      ).toThrow('returned the value unmasked');
    });

    it('rejects a formatter that does not return a string', () => {
      expect(() =>
        sensitive('secretvalue').mask({
          strategy: 'custom',
          // Callers without type checking are the reason this is validated.
          customStrategy: (() => 42) as unknown as (value: string) => string,
        })
      ).toThrow(TypeError);
    });
  });

  describe('option validation', () => {
    it('rejects a mask character that is not exactly one character', () => {
      expect(() => sensitive('secretvalue').mask({ maskChar: '' })).toThrow(RangeError);
      expect(() => sensitive('secretvalue').mask({ maskChar: '**' })).toThrow(
        'maskChar must be exactly one character'
      );
    });

    it('rejects a mask character that is not a string', () => {
      expect(() => sensitive('secretvalue').mask({ maskChar: 0 as unknown as string })).toThrow(
        TypeError
      );
    });

    it('accepts a mask character outside the basic plane', () => {
      expect(sensitive('secretvalue').mask({ showLast: 3, maskChar: '🔒' })).toBe(
        '🔒🔒🔒🔒🔒🔒🔒🔒lue'
      );
    });

    it('rejects counts that are not whole numbers', () => {
      expect(() => sensitive('secretvalue').mask({ showFirst: -1 })).toThrow(RangeError);
      expect(() => sensitive('secretvalue').mask({ showLast: 1.5 })).toThrow(RangeError);
      expect(() => sensitive('secretvalue').mask({ showFirst: Number.NaN })).toThrow(RangeError);
      expect(() => sensitive('secretvalue').mask({ showFirst: '2' as unknown as number })).toThrow(
        TypeError
      );
    });

    it('rejects an unknown strategy', () => {
      expect(() => sensitive('secretvalue').mask({ strategy: 'passport' as never })).toThrow(
        "strategy 'passport' is not a masking strategy"
      );
    });

    it('rejects positional options combined with a strategy', () => {
      expect(() => sensitive('jane@example.com').mask({ strategy: 'email', showLast: 4 })).toThrow(
        "showFirst and showLast do not apply to strategy 'email'"
      );
    });

    it('rejects a custom formatter without the custom strategy', () => {
      expect(() =>
        sensitive('secretvalue').mask({ customStrategy: (value) => value.slice(0, 2) })
      ).toThrow("customStrategy requires strategy: 'custom'");

      expect(() =>
        sensitive('secretvalue').mask({
          strategy: 'email',
          customStrategy: (value) => value.slice(0, 2),
        })
      ).toThrow("customStrategy requires strategy: 'custom'");
    });

    it('rejects the custom strategy without a formatter', () => {
      expect(() => sensitive('secretvalue').mask({ strategy: 'custom' })).toThrow(
        "strategy 'custom' requires customStrategy"
      );
    });

    it('rejects a formatter that is not a function', () => {
      expect(() =>
        sensitive('secretvalue').mask({
          strategy: 'custom',
          customStrategy: 'slice' as unknown as (value: string) => string,
        })
      ).toThrow(TypeError);
    });
  });

  describe('auditing', () => {
    it('reports the operation and the options through the ambient context', () => {
      const auditReveal = vi.fn();
      const value = sensitive('jane@example.com', 'email');
      const ctx = { name: 'support-lookup', auditReveal };

      withRevealContext(ctx, () => {
        value.mask({ strategy: 'email' });
      });

      expect(auditReveal).toHaveBeenCalledTimes(1);
      expect(auditReveal).toHaveBeenCalledWith(
        value,
        {
          operation: 'mask',
          strategy: 'email',
          showFirst: 0,
          showLast: 0,
          minMasked: 4,
          maskChar: '*',
        },
        ctx
      );
    });

    it('reports positional options', () => {
      const auditReveal = vi.fn();
      const value = sensitive('sk_live_abc123xyz9', 'api_key');
      const ctx = { name: 'debug', auditReveal };

      value.mask({ showFirst: 2, showLast: 4, maskChar: '#' }, ctx);

      expect(auditReveal).toHaveBeenCalledWith(
        value,
        {
          operation: 'mask',
          strategy: 'positional',
          showFirst: 2,
          showLast: 4,
          minMasked: 4,
          maskChar: '#',
        },
        ctx
      );
    });

    it('distinguishes a mask from a full reveal', () => {
      const operations: RevealDetails['operation'][] = [];
      const value = sensitive('sk_live_abc123xyz9', 'api_key');
      const ctx = {
        name: 'mixed',
        auditReveal: (_value: unknown, details: RevealDetails) => {
          operations.push(details.operation);
        },
      };

      value.reveal(ctx);
      value.mask({ showLast: 4 }, ctx);

      expect(operations).toEqual(['reveal', 'mask']);
    });

    it('runs the policy check before rendering', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          allowMask: true,
          checkRevealAllowed: (ctx) => {
            if (!ctx) {
              throw new Error('Context required');
            }
          },
        },
        { overwrite: true }
      );

      expect(() => sensitive('jane@example.com').mask({ strategy: 'email' })).toThrow(
        'Context required'
      );
      expect(sensitive('jane@example.com').mask({ strategy: 'email' }, { name: 'approved' })).toBe(
        'j***@e******.com'
      );
    });
  });

  describe('edge cases', () => {
    it('redacts an empty value', () => {
      expect(sensitive('').mask({ showFirst: 2 })).toBe('[REDACTED:sensitive]');
    });

    it('redacts a single-character value', () => {
      expect(sensitive('x').mask()).toBe('[REDACTED:sensitive]');
    });

    it('handles a request to show more than the value holds', () => {
      expect(sensitive('abcdefgh').mask({ showFirst: 100, showLast: 100 })).toBe('abcd****');
    });

    it('counts code points rather than UTF-16 units', () => {
      // Showing two of each end must not split the astral character in the middle.
      const masked = sensitive('héllo🌍world').mask({ showFirst: 2, showLast: 2 });

      expect(masked).toBe('hé*******ld');
      expect(masked).not.toContain('�');
    });

    it('masks a very long value', () => {
      const masked = sensitive('x'.repeat(10_000)).mask({ showLast: 4 });

      expect(masked).toHaveLength(10_000);
      expect(masked.endsWith('xxxx')).toBe(true);
      expect(masked.slice(0, 9996)).toBe('*'.repeat(9996));
    });

    it('is deterministic for the same input', () => {
      const value = sensitive('4111111111111111');

      expect(value.mask({ strategy: 'card' })).toBe(value.mask({ strategy: 'card' }));
    });
  });
});
