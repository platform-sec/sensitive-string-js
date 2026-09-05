import {
  getPolicy,
  registerPolicy,
  resetPolicies,
  SensitiveString,
  st,
  withRevealContext,
  type RevealContext,
  type RevealDetails,
  type SensitivityClass,
  type SensitivityPolicy,
} from '@platform-sec/sensitive-string-core';
import { beforeEach, describe, expect, it } from 'vitest';

import { ExternalSendNotAllowedError, RedactedMarkerError, sendToExternal } from './external.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function setAdvisory(klass: SensitivityClass, allowSendToExternal: unknown): void {
  const policy = getPolicy(klass);

  registerPolicy(
    {
      ...policy,
      advisory: { ...policy.advisory, allowSendToExternal },
    } as SensitivityPolicy,
    { overwrite: true }
  );
}

describe('sendToExternal', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('the advisory flag', () => {
    /**
     * This is the test that fails the day somebody flips a default, which is
     * exactly the point of writing it.
     */
    it('refuses both classes on a stock installation', () => {
      for (const klass of ['sensitive', 'credential'] as const) {
        const value = new SensitiveString(CANARY, klass);

        expect(() => sendToExternal(value, { sink: { name: 'anthropic' }, reason: 'r' })).toThrow(
          ExternalSendNotAllowedError
        );
      }
    });

    it('writes the flag explicitly on both default policies', () => {
      // Behaviourally identical to leaving it absent under the rule above, and
      // completely different to a reviewer: absent reads as an oversight.
      expect(getPolicy('sensitive').advisory?.allowSendToExternal).toBe(false);
      expect(getPolicy('credential').advisory?.allowSendToExternal).toBe(false);
    });

    /**
     * `undefined` and `false` must not diverge, and a truthy non-boolean must
     * not pass. Before this flag was written into the defaults, the two obvious
     * readings of it, `if (flag)` and `if (flag !== false)`, disagreed on every
     * value in a stock installation.
     */
    it.each([
      ['undefined', undefined, false],
      ['false', false, false],
      ['null', null, false],
      ['the string "true"', 'true', false],
      ['1', 1, false],
      ['true', true, true],
    ])('permits only a literal true: %s', (_label, flag, permitted) => {
      setAdvisory('sensitive', flag);

      const value = new SensitiveString(CANARY, 'sensitive');
      const send = () => sendToExternal(value, { sink: { name: 'anthropic' }, reason: 'r' });

      if (permitted) {
        expect(send()).toBe(CANARY);
      } else {
        expect(send).toThrow(ExternalSendNotAllowedError);
      }
    });

    it('permits one class without permitting the other', () => {
      setAdvisory('sensitive', true);

      expect(
        sendToExternal(new SensitiveString(CANARY, 'sensitive'), {
          sink: { name: 'anthropic' },
          reason: 'r',
        })
      ).toBe(CANARY);

      expect(() =>
        sendToExternal(new SensitiveString(CANARY, 'credential'), {
          sink: { name: 'anthropic' },
          reason: 'r',
        })
      ).toThrow(ExternalSendNotAllowedError);
    });

    it('checks the combined class of an st-built prompt, not the loosest input', () => {
      setAdvisory('sensitive', true);

      const email = new SensitiveString('a@b.test', 'sensitive');
      const key = new SensitiveString(CANARY, 'credential');
      const prompt = st`Summarize for ${email} using ${key}`;

      // A caller cannot dilute a credential by surrounding it with harmless
      // text: the tag combines by precedence and the check sees `credential`.
      expect(prompt.klass).toBe('credential');
      expect(() => sendToExternal(prompt, { sink: { name: 'anthropic' }, reason: 'r' })).toThrow(
        ExternalSendNotAllowedError
      );
    });
  });

  describe('the reveal', () => {
    beforeEach(() => {
      setAdvisory('sensitive', true);
    });

    it('audits with the sink in the context name and the tags', () => {
      const operations: string[] = [];
      let captured: RevealContext | undefined;

      const policy = getPolicy('sensitive');
      registerPolicy(
        {
          ...policy,
          checkRevealAllowed: (ctx) => {
            captured = ctx ?? undefined;
          },
        },
        { overwrite: true }
      );

      withRevealContext(
        {
          name: 'request',
          auditReveal: (_value, details: RevealDetails) => operations.push(details.operation),
          tags: { requestId: 'r-1' },
        },
        () =>
          sendToExternal(new SensitiveString(CANARY, 'sensitive'), {
            sink: { name: 'anthropic', detail: 'claude-opus-5' },
            reason: 'account summary',
            tags: { feature: 'support-summary' },
          })
      );

      expect(captured?.name).toBe('external:anthropic');
      expect(captured?.reason).toBe('account summary');
      expect(captured?.tags).toMatchObject({
        sink: 'anthropic',
        sinkDetail: 'claude-opus-5',
        feature: 'support-summary',
        // Inherited from the ambient context rather than replacing it.
        requestId: 'r-1',
      });
      expect(operations).toEqual(['reveal']);
    });

    it('inherits the ambient audit hook rather than silencing it', () => {
      const audited: string[] = [];

      withRevealContext({ name: 'request', auditReveal: (v) => audited.push(v.klass) }, () =>
        sendToExternal(new SensitiveString(CANARY, 'sensitive'), {
          sink: { name: 'anthropic' },
          reason: 'r',
        })
      );

      expect(audited).toEqual(['sensitive']);
    });

    it('runs the ordinary gate, so an expired value still refuses', () => {
      const value = new SensitiveString(CANARY, 'sensitive', undefined, { ttl: 0 });

      let thrown: unknown;
      try {
        sendToExternal(value, { sink: { name: 'anthropic' }, reason: 'r' });
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(Error);
      expect(thrown).not.toBeInstanceOf(ExternalSendNotAllowedError);
      expect(String(thrown)).not.toContain(CANARY);
    });

    it('refuses a revealed form carrying a redaction marker', () => {
      const value = new SensitiveString(`prefix [REDACTED:credential] suffix`, 'sensitive');

      expect(() => sendToExternal(value, { sink: { name: 'anthropic' }, reason: 'r' })).toThrow(
        RedactedMarkerError
      );
    });
  });

  describe('argument checking', () => {
    beforeEach(() => {
      setAdvisory('sensitive', true);
    });

    it('requires a SensitiveString', () => {
      expect(() =>
        sendToExternal(CANARY as unknown as SensitiveString<'sensitive'>, {
          sink: { name: 'a' },
          reason: 'r',
        })
      ).toThrow(TypeError);
    });

    it.each([
      ['an empty sink name', { sink: { name: '  ' }, reason: 'r' }],
      ['a missing sink', { reason: 'r' }],
      ['an empty reason', { sink: { name: 'a' }, reason: '   ' }],
      ['a missing reason', { sink: { name: 'a' } }],
    ])('refuses %s', (_label, options) => {
      expect(() =>
        sendToExternal(
          new SensitiveString(CANARY, 'sensitive'),
          options as Parameters<typeof sendToExternal>[1]
        )
      ).toThrow(TypeError);
    });
  });
});
