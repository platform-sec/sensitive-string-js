/**
 * A `toJSON()` that reveals gets nothing from a redaction walk.
 *
 * `redactInStructure` calls an object's own `toJSON()` to learn its JSON form.
 * A DTO whose `toJSON()` called `reveal()` handed the walk a plain string it
 * could not tell from one that was always plain, and `safeLog` printed the raw
 * value. Skipping user `toJSON()` methods would be the wrong fix, because a
 * `toJSON()` that omits a raw field hides it. Instead the gate refuses to
 * disclose a value while a walk is running caller code: the refusal is a throw
 * inside the `toJSON()`, the walk absorbs it as it absorbs any other refusal,
 * and the instance is redacted as an instance in the own-property fallback.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  RevealDuringRedactionError,
  SensitiveString,
  createSensitiveSerializer,
  redactInStructure,
  registerPolicy,
  resetPolicies,
  safeLog,
  safeStringify,
  withRevealContext,
} from '../index.js';

const CANARY = 'REVEAL_IN_TOJSON_CANARY_3d7f';

/** A DTO whose wire form reveals, which is a leak on every JSON path by construction. */
class RevealingDto {
  constructor(readonly token: SensitiveString<'credential'>) {}

  toJSON(): Record<string, unknown> {
    return { token: this.token.reveal(), kind: 'dto' };
  }
}

const DISCLOSURES: Array<[string, (value: SensitiveString<'sensitive'>) => unknown]> = [
  ['reveal()', (value) => value.reveal()],
  ['mask()', (value) => value.mask({ showLast: 4 })],
  ['serialize()', (value) => value.serialize()],
  ['substring()', (value) => value.substring(0, 6)],
  ['concat()', (value) => value.concat('x')],
];

describe('a toJSON() that reveals, run by a redaction walk', () => {
  beforeEach(() => {
    resetPolicies();
  });

  it.each([
    ['redactInStructure', (value: unknown) => JSON.stringify(redactInStructure(value))],
    ['safeLog', (value: unknown) => JSON.stringify(safeLog(value))],
    ['safeStringify', (value: unknown) => safeStringify(value)],
    [
      'the logger serializer',
      (value: unknown) => JSON.stringify(createSensitiveSerializer()(value)),
    ],
  ])('CANARY: %s emits the redaction and never the revealed value', (_name, walk) => {
    const output = walk({ dto: new RevealingDto(new SensitiveString(CANARY, 'credential')) });

    expect(output).not.toContain(CANARY);
    expect(output).toContain('[REDACTED:credential]');
  });

  it('falls back to the own properties, where the instance is still an instance', () => {
    const redacted = redactInStructure(new RevealingDto(new SensitiveString(CANARY, 'credential')));

    expect(redacted).toEqual({ token: '[REDACTED:credential]' });
  });

  it('treats a plain object carrying its own toJSON the same way, and drops the method', () => {
    const payload = {
      token: new SensitiveString(CANARY, 'credential'),
      toJSON(): Record<string, unknown> {
        return { token: this.token.reveal() };
      },
    };

    expect(safeStringify(payload)).toBe('{"token":"[REDACTED:credential]"}');
  });

  it.each(DISCLOSURES)('refuses %s from inside the toJSON() as well', (_name, disclose) => {
    const payload = {
      value: new SensitiveString(CANARY, 'sensitive'),
      toJSON(): Record<string, unknown> {
        return { value: disclose(this.value) };
      },
    };

    const output = safeStringify(payload);

    expect(output).toBe('{"value":"[REDACTED:sensitive]"}');
    expect(output).not.toContain(CANARY.slice(-4));
  });

  it('names the refusal, for a toJSON() that catches it, without the value', () => {
    let caught: unknown;
    const payload = {
      token: new SensitiveString(CANARY, 'credential', 'api_key'),
      toJSON(): Record<string, unknown> {
        try {
          return { token: this.token.reveal() };
        } catch (error) {
          caught = error;
          throw error;
        }
      },
    };

    safeStringify(payload);

    expect(caught).toBeInstanceOf(RevealDuringRedactionError);
    expect(caught).toMatchObject({
      name: 'RevealDuringRedactionError',
      klass: 'credential',
      label: 'api_key',
    });
    expect(String(caught)).not.toContain(CANARY);
  });

  it('fires neither the policy hook nor the audit hook for a reveal that never happened', () => {
    const checkRevealAllowed = vi.fn();
    const auditReveal = vi.fn();

    registerPolicy(
      {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        requireConstantTimeEquals: true,
        checkRevealAllowed,
      },
      { overwrite: true }
    );

    withRevealContext({ name: 'log', auditReveal }, () => {
      safeLog(new RevealingDto(new SensitiveString(CANARY, 'credential')));
    });

    expect(checkRevealAllowed).not.toHaveBeenCalled();
    expect(auditReveal).not.toHaveBeenCalled();
  });

  it('still answers a comparison, which discloses nothing', () => {
    const payload = {
      token: new SensitiveString(CANARY, 'credential'),
      toJSON(): Record<string, unknown> {
        return { matches: this.token.equals(CANARY) };
      },
    };

    expect(safeStringify(payload)).toBe('{"matches":true}');
  });

  it('lets a toJSON() return the instance itself, which the walk redacts', () => {
    class WireDto {
      constructor(readonly token: SensitiveString<'credential'>) {}

      toJSON(): Record<string, unknown> {
        return { token: this.token, kind: 'wire' };
      }
    }

    expect(safeStringify(new WireDto(new SensitiveString(CANARY, 'credential')))).toBe(
      '{"token":"[REDACTED:credential]","kind":"wire"}'
    );
  });

  it('releases the mark when the walk returns, including after a refusal', () => {
    const token = new SensitiveString(CANARY, 'credential');

    safeStringify(new RevealingDto(token));

    expect(token.reveal()).toBe(CANARY);
  });

  it('releases the mark when a toJSON() throws for its own reasons', () => {
    const token = new SensitiveString(CANARY, 'credential');

    safeStringify({
      toJSON(): never {
        throw new Error('[test] refused');
      },
    });

    expect(token.reveal()).toBe(CANARY);
  });

  it('holds the mark through a nested walk started from inside a toJSON()', () => {
    const inner = new SensitiveString(CANARY, 'credential');
    const payload = {
      toJSON(): Record<string, unknown> {
        // A toJSON() that logs while being logged. The inner walk returns, and
        // the outer one is still running, so the reveal after it is refused.
        safeLog({ inner });
        return { leaked: inner.reveal() };
      },
    };

    expect(safeStringify(payload)).toBe('{}');
    expect(inner.reveal()).toBe(CANARY);
  });
});
