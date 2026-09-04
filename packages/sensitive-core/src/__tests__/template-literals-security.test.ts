import * as util from 'node:util';
import { runInNewContext } from 'node:vm';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { registerPolicy, resetPolicies, SensitiveString, sensitiveTemplate, st } from '../index.js';
import type { ISensitiveString, RevealContext } from '../index.js';

const CANARY = 'TEMPLATE_SECURITY_CANARY_5c31';

describe('sensitive template literal security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  it('redacts the assembled value everywhere it can be observed', () => {
    const secret = new SensitiveString(CANARY, 'credential', 'key');
    const result = st`API Key: ${secret}`;

    expect(String(result)).toBe('[REDACTED:credential]');
    expect(String(result)).not.toContain(CANARY);
    expect(JSON.stringify({ result })).not.toContain(CANARY);
    expect(JSON.stringify({ result })).toContain('[REDACTED:credential]');
    expect(util.inspect(result)).not.toContain(CANARY);
    // Implicit coercion is the case an untagged log line hits, so exercise it directly.
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    expect(`${result}`).not.toContain(CANARY);
  });

  it('protects the plain parts of the template as well', () => {
    const secret = new SensitiveString(CANARY, 'credential', 'token');
    const result = st`Public: ${'public-data'}, Secret: ${secret}`;

    expect(String(result)).toBe('[REDACTED:credential]');
    expect(String(result)).not.toContain(CANARY);
    expect(String(result)).not.toContain('public-data');
  });

  it('redacts every secret when several are interpolated', () => {
    const first = `${CANARY}_KEY1`;
    const second = `${CANARY}_KEY2`;
    const result = st`${new SensitiveString(first, 'credential', 'key1')} and ${new SensitiveString(
      second,
      'credential',
      'key2'
    )}`;

    expect(String(result)).not.toContain(first);
    expect(String(result)).not.toContain(second);
    expect(util.inspect(result)).not.toContain(CANARY);
  });

  it('rejects a klass that loosens the inherited class', () => {
    const credential = new SensitiveString(CANARY, 'credential', 'key');

    expect(() => sensitiveTemplate({ klass: 'sensitive' })`Value: ${credential}`).toThrow(
      "klass 'sensitive' is less restrictive than interpolated class 'credential'"
    );

    try {
      sensitiveTemplate({ klass: 'sensitive' })`Value: ${credential}`;
      expect.unreachable('expected the loosened class to be rejected');
    } catch (error) {
      expect(String(error)).not.toContain(CANARY);
      expect((error as Error).stack ?? '').not.toContain(CANARY);
    }
  });

  it('does not reveal or audit anything when the class is loosened', () => {
    const audited: ISensitiveString[] = [];
    const credential = new SensitiveString(CANARY, 'credential', 'key');

    expect(
      () =>
        sensitiveTemplate({
          klass: 'sensitive',
          ctx: { name: 'audit', auditReveal: (value) => audited.push(value) },
        })`Value: ${credential}`
    ).toThrow(Error);

    expect(audited).toHaveLength(0);
  });

  it('aborts the whole template when a policy denies a reveal', () => {
    registerPolicy(
      {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        requireConstantTimeEquals: true,
        checkRevealAllowed: (ctx) => {
          if (!ctx) {
            throw new Error('reveal requires a context');
          }
        },
      },
      { overwrite: true }
    );

    const secret = new SensitiveString(CANARY, 'credential', 'key');

    expect(() => st`key=${secret}`).toThrow('reveal requires a context');

    try {
      st`key=${secret}`;
      expect.unreachable('expected the denied reveal to throw');
    } catch (error) {
      expect(String(error)).not.toContain(CANARY);
    }

    const allowed = sensitiveTemplate({ ctx: { name: 'allowed' } })`key=${secret}`;
    expect(allowed.reveal({ name: 'test' })).toBe(`key=${CANARY}`);
  });

  it('stops at the first denied interpolation without assembling a result', () => {
    const checkRevealAllowed = vi.fn((ctx: RevealContext | null): undefined => {
      if (ctx?.name !== 'approved') {
        throw new Error('Template context denied');
      }
    });
    registerPolicy(
      {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        requireConstantTimeEquals: true,
        checkRevealAllowed,
      },
      { overwrite: true }
    );

    const first = new SensitiveString(CANARY, 'credential', 'first');
    const second = new SensitiveString(`${CANARY}_SECOND`, 'credential', 'second');

    expect(() => st`${first}:${second}`).toThrow('Template context denied');
    expect(checkRevealAllowed).toHaveBeenCalledTimes(1);
  });

  it('rejects unsupported interpolations before revealing anything', () => {
    const audited: ISensitiveString[] = [];
    const secret = new SensitiveString(CANARY, 'credential', 'key');
    const leaky = { toString: () => CANARY };

    const tag = sensitiveTemplate({
      ctx: { name: 'audit', auditReveal: (value) => audited.push(value) },
    });

    try {
      // @ts-expect-error objects are rejected at compile time as well
      tag`${secret} ${leaky}`;
      expect.unreachable('expected the object interpolation to be rejected');
    } catch (error) {
      expect(error).toBeInstanceOf(TypeError);
      expect(String(error)).toContain('index 1');
      expect(String(error)).not.toContain(CANARY);
    }

    expect(audited).toHaveLength(0);
  });

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['object', { key: 'value' }],
    ['array', [1, 2, 3]],
    ['function', () => 'x'],
    ['bigint', 10n],
    ['symbol', Symbol('s')],
  ])('rejects a %s interpolation', (_kind, value) => {
    // @ts-expect-error these are rejected at compile time as well
    expect(() => st`Value: ${value}`).toThrow(TypeError);
  });

  it('rejects a protected value from a duplicate copy of the class', () => {
    const foreign = runInNewContext(
      '({ klass: "credential", toString: () => canary, reveal: () => canary })',
      { canary: CANARY }
    ) as unknown;

    let error: unknown;
    try {
      st`key=${foreign as string}`;
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(TypeError);
    expect(String(error)).toContain('index 0');
    expect(String(error)).not.toContain(CANARY);
  });

  it('rejects an unrecognized klass without invoking its toString()', () => {
    const secret = new SensitiveString(CANARY, 'credential', 'key');
    const leakyClass = { toString: () => CANARY };

    expect(() => {
      // @ts-expect-error only a sensitivity class is accepted at compile time
      sensitiveTemplate({ klass: leakyClass })`key=${secret}`;
    }).toThrow("klass object is not a sensitivity class; expected 'sensitive' or 'credential'");

    expect(() => {
      // @ts-expect-error only a sensitivity class is accepted at compile time
      sensitiveTemplate({ klass: 'Credential' })`key=${secret}`;
    }).toThrow("klass 'Credential' is not a sensitivity class");

    try {
      // @ts-expect-error only a sensitivity class is accepted at compile time
      sensitiveTemplate({ klass: leakyClass })`key=${secret}`;
      expect.unreachable('expected the unrecognized klass to be rejected');
    } catch (error) {
      expect(error).toBeInstanceOf(TypeError);
      expect(String(error)).not.toContain(CANARY);
    }
  });

  it('rejects an argument that is neither a template literal nor options', () => {
    for (const argument of [null, undefined, 'options', 42]) {
      expect(() => {
        // @ts-expect-error only a template literal or an options object is accepted
        sensitiveTemplate(argument);
      }).toThrow('expected a template literal or an options object');
    }
  });

  it('rejects a template whose escape sequence has no cooked value', () => {
    const secret = new SensitiveString(CANARY, 'credential', 'key');

    // A cooked part is undefined here, so the literal text would silently
    // vanish from the credential if it were treated as empty.
    expect(() => st`\unicode ${secret}`).toThrow(
      'template part at index 0 has no cooked value, which means the template contains an ' +
        'invalid escape sequence'
    );

    try {
      st`\unicode ${secret}`;
      expect.unreachable('expected the uncooked template part to be rejected');
    } catch (error) {
      expect(error).toBeInstanceOf(TypeError);
      expect(String(error)).not.toContain(CANARY);
    }
  });

  it('does not let a forged template array drop or coerce parts', () => {
    const secret = new SensitiveString(CANARY, 'credential', 'key');
    const leakyPart = { toString: () => CANARY } as unknown as string;

    const forgedParts = Object.assign(['a', leakyPart], { raw: ['a', 'b'] });
    expect(() => sensitiveTemplate(forgedParts, secret)).toThrow(TypeError);

    const missingParts = Object.assign(['a'], { raw: ['a'] });
    expect(() => sensitiveTemplate(missingParts, secret, secret)).toThrow(TypeError);
  });

  it('keeps the raw value out of the result label and inspection header', () => {
    const secret = new SensitiveString(CANARY, 'credential', 'key');
    const result = sensitiveTemplate({ label: 'api_url' })`https://example.test/?key=${secret}`;

    expect(util.inspect(result)).toBe(
      'SensitiveString<credential:api_url> { [REDACTED:credential] }'
    );
    expect(util.inspect(result)).not.toContain(CANARY);
  });

  it('keeps the raw value out of a serialized structure until deserialized', () => {
    const secret = new SensitiveString(CANARY, 'credential', 'key');
    const result = st`key=${secret}`;
    const roundTripped = SensitiveString.deserialize(
      JSON.parse(JSON.stringify(result.serialize()))
    );

    expect(JSON.stringify(result)).not.toContain(CANARY);
    expect(roundTripped.klass).toBe('credential');
    expect(roundTripped.reveal()).toBe(`key=${CANARY}`);
    expect(String(roundTripped)).not.toContain(CANARY);
  });
});
