import {
  registerPolicy,
  resetPolicies,
  getPolicy,
  SensitiveString,
  st,
  type SensitivityClass,
} from '@platform-sec/sensitive-string-core';
import {
  createCanary,
  expectCanaryPresent,
  expectNoCanary,
} from '@platform-sec/sensitive-string-scrub/testing';
import { beforeEach, describe, expect, it } from 'vitest';

import * as llm from '../index.js';

/**
 * The canary suite, which is what decides whether this package ships.
 *
 * Three things are checked here that nowhere else checks:
 *
 * 1. The three positions of the design's section 2.1, with position 3
 *    asserted **present**. A test that documents a known gap is worth more
 *    than a gap nobody wrote down, and this one fails the day somebody
 *    quietly adds a content classifier without updating the README sentence
 *    that says there is none.
 * 2. Every export of the package driven with a wrapped canary, off the
 *    module's own export list, so a new export with no coverage fails rather
 *    than passing silently.
 * 3. That `sendToExternal` is the only export returning a raw value.
 */

const KEY = new Uint8Array(32).fill(7);

/** A policy that permits an external sink, for the one test that needs a value out. */
function permitExternal(klass: SensitivityClass): void {
  const policy = getPolicy(klass);

  registerPolicy(
    { ...policy, advisory: { ...policy.advisory, allowSendToExternal: true } },
    { overwrite: true }
  );
}

describe('LLM package security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('the three positions of a request body', () => {
    it('covers position 1: a wrapped value at a key', () => {
      const canary = createCanary();
      const body = {
        messages: [{ role: 'user', content: new SensitiveString(canary, 'credential') }],
        tool_result: new SensitiveString(canary, 'credential').serialize(),
      };

      expectCanaryPresent(body.tool_result, canary, 'the serialized form before scrubbing');

      const { prompt, removed } = llm.scrubForPrompt(body);

      expectNoCanary(prompt, canary, 'the scrubbed body');
      expect(removed.instances).toBe(2);
      expect([...removed.classes]).toEqual(['credential']);
    });

    it('covers position 2: an unwrapped value under a credential-shaped key', () => {
      const canary = createCanary();
      const body = { model: 'm', api_key: canary, headers: { authorization: `Bearer ${canary}` } };

      expectCanaryPresent(body, canary, 'the body before scrubbing');

      const { prompt, removed } = llm.scrubForPrompt(body);

      expectNoCanary(prompt, canary, 'the scrubbed body');
      expect(removed.deniedKeys).toContain('api_key');
      expect(removed.deniedKeys).toContain('authorization');
    });

    it('does NOT cover position 3: prose, and this assertion is the documented gap', () => {
      const canary = createCanary();
      const body = {
        system: `You are helpful. The key is ${canary}.`,
        messages: [{ role: 'user', content: [{ type: 'text', text: `and again ${canary}` }] }],
      };

      const { prompt, removed } = llm.scrubForPrompt(body);

      // Deliberately `Present`. Section 2.2: the key is `content`, the key is
      // always `content`, and denying it denies the request. This package
      // ships no content classifier and the README says so in one sentence.
      // If this ever fails, the README sentence is now false.
      expectCanaryPresent(prompt, canary, 'a prose position, which is the known gap');
      expect(removed.contentPositions).toBeGreaterThan(0);
    });

    it('hands prose to the caller-supplied hook, which is the only seam there is', () => {
      const canary = createCanary();
      const seen: string[] = [];

      const { prompt } = llm.scrubForPrompt(
        { system: `key is ${canary}` },
        {
          transformContent: (text, path) => {
            seen.push(path);
            return text.replaceAll(canary, '[CALLER-DLP]');
          },
        }
      );

      expect(seen).toEqual(['system']);
      expectNoCanary(prompt, canary, 'the body a caller-supplied classifier scrubbed');
    });
  });

  describe('every export', () => {
    /**
     * Drive each export with a wrapped canary, off the module's own list.
     *
     * The table names how to call each one; a name in the module that is not
     * in the table fails the completeness test below, which is what makes a
     * new export impossible to add without deciding what its canary coverage
     * is.
     */
    const DRIVERS: Record<string, (canary: string) => unknown> = {
      sendToExternal: (canary) => {
        permitExternal('sensitive');
        return llm.sendToExternal(new SensitiveString(canary, 'sensitive'), {
          sink: { name: 'anthropic' },
          reason: 'covered by the raw-value exception below',
        });
      },
      scrubForPrompt: (canary) =>
        llm.scrubForPrompt({ extra: new SensitiveString(canary, 'credential') }),
      createPromptScrubber: (canary) =>
        llm.createPromptScrubber()({ extra: new SensitiveString(canary, 'credential') }),
      entityHandle: (canary) =>
        llm.entityHandle(new SensitiveString(canary, 'sensitive'), { key: KEY, scope: 's' }),
      createHandleMap: (canary) => {
        const map = llm.createHandleMap();
        llm.entityHandle(new SensitiveString(canary, 'sensitive'), { key: KEY, record: map });
        return map;
      },
      rehydrate: (canary) => {
        const map = llm.createHandleMap();
        const value = new SensitiveString(canary, 'sensitive');
        const handle = llm.entityHandle(value, { key: KEY, record: map });
        return llm.rehydrate(`say ${handle}`, { map });
      },
      handlePattern: () => llm.handlePattern(),
      hasRedactionMarker: (canary) => llm.hasRedactionMarker(canary),
      ExternalSendNotAllowedError: (canary) => {
        try {
          return llm.sendToExternal(new SensitiveString(canary, 'credential'), {
            sink: { name: 'anthropic' },
            reason: 'refused by the default policy',
          });
        } catch (error) {
          return { error, message: String(error), stack: (error as Error).stack };
        }
      },
      RedactedMarkerError: (canary) => {
        permitExternal('sensitive');
        try {
          return llm.sendToExternal(
            new SensitiveString(`${canary} [REDACTED:credential]`, 'sensitive'),
            { sink: { name: 'anthropic' }, reason: 'refused for carrying a marker' }
          );
        } catch (error) {
          return { error, message: String(error), stack: (error as Error).stack };
        }
      },
      HandleNotAllowedError: (canary) => {
        try {
          return llm.entityHandle(new SensitiveString(canary, 'credential'), { key: KEY });
        } catch (error) {
          return { error, message: String(error), stack: (error as Error).stack };
        }
      },
      PromptScrubFailedError: (canary) => {
        try {
          return llm.scrubForPrompt(
            { system: `key is ${canary}` },
            {
              transformContent: () => {
                throw new Error(`hook blew up holding ${canary}`);
              },
            }
          );
        } catch (error) {
          return { error, message: String(error), stack: (error as Error).stack };
        }
      },
      ANTHROPIC_MESSAGES: () => llm.ANTHROPIC_MESSAGES,
      OPENAI_CHAT_COMPLETIONS: () => llm.OPENAI_CHAT_COMPLETIONS,
      OPENAI_RESPONSES: () => llm.OPENAI_RESPONSES,
      CONTENT_PATH_SHAPES: () => llm.CONTENT_PATH_SHAPES,
      DEFAULT_CONTENT_PATHS: () => llm.DEFAULT_CONTENT_PATHS,
      LLM_DENY_KEYS: () => llm.LLM_DENY_KEYS,
    };

    /**
     * The one export allowed to return the canary.
     *
     * Success criterion 4: the package has exactly one export that returns a
     * raw string. A handle is a derived token rather than the value and does
     * not count against this, which is why the derivation is constrained
     * separately.
     */
    const RAW_VALUE_EXPORTS = new Set(['sendToExternal']);

    it('is covered by the table, so a new export cannot arrive untested', () => {
      const exported = Object.keys(llm).sort();
      const covered = Object.keys(DRIVERS).sort();

      expect(exported, 'every export needs a canary driver in this file').toEqual(covered);
    });

    it('leaks no canary, except through the one export that is meant to', () => {
      for (const [name, drive] of Object.entries(DRIVERS)) {
        resetPolicies();

        const canary = createCanary(name);
        const result = drive(canary);

        if (RAW_VALUE_EXPORTS.has(name)) {
          expectCanaryPresent(result, canary, `${name}, which is the authorized disclosure`);
          continue;
        }

        expectNoCanary(result, canary, name);
      }
    });
  });

  describe('errors', () => {
    it('carry no part of a value and chain no cause that could', () => {
      const canary = createCanary();

      let thrown: unknown;
      try {
        llm.sendToExternal(new SensitiveString(canary, 'credential', 'api_key'), {
          sink: { name: 'anthropic' },
          reason: 'refused by the default policy',
        });
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(llm.ExternalSendNotAllowedError);
      expectNoCanary(
        {
          message: (thrown as Error).message,
          stack: (thrown as Error).stack,
          fields: thrown,
        },
        canary,
        'the refusal'
      );
      expect((thrown as Error & { cause?: unknown }).cause).toBeUndefined();

      // The class, the label and the sink name are metadata the caller chose
      // and an operator has to read to act on the refusal, so they are quoted
      // deliberately. The value is what is absent.
      const error = thrown as llm.ExternalSendNotAllowedError;
      expect(error.klass).toBe('credential');
      expect(error.label).toBe('api_key');
      expect(error.sink).toBe('anthropic');
      expect(error.message).toContain('allowSendToExternal');
    });

    it('does not chain a cause out of a failed scrub', () => {
      const canary = createCanary();

      let thrown: unknown;
      try {
        llm.scrubForPrompt(
          { system: 'x' },
          {
            transformContent: () => {
              throw new Error(`the hook was holding ${canary}`);
            },
          }
        );
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(llm.PromptScrubFailedError);
      expect((thrown as Error).message).not.toContain(canary);
      expect((thrown as Error).stack ?? '').not.toContain(canary);
      expect((thrown as Error & { cause?: unknown }).cause).toBeUndefined();
    });
  });

  describe('the marker rule, in its strictest form', () => {
    it('refuses to send a value that is already a marker', () => {
      permitExternal('credential');

      const value = new SensitiveString('[REDACTED:credential]', 'credential');

      expect(() => llm.sendToExternal(value, { sink: { name: 'anthropic' }, reason: 'r' })).toThrow(
        llm.RedactedMarkerError
      );
    });

    it('counts a marker in the input rather than throwing on it', () => {
      const { removed } = llm.scrubForPrompt({
        messages: [{ role: 'user', content: 'the token was [REDACTED:credential]' }],
      });

      expect(removed.markersSeen).toBe(1);
      expect([...removed.markerClasses]).toEqual(['credential']);
    });

    it('never hands a marker back through an st-built prompt that was scrubbed upstream', () => {
      permitExternal('sensitive');

      const canary = createCanary();
      const upstream = new SensitiveString(canary, 'sensitive');
      const prompt = st`Summarize ${upstream}`;

      // The whole prompt reveals to the canary, not to a marker, which is the
      // shape the README recommends: a prompt built with the tag is itself a
      // wrapped value and `sendToExternal` is the one call that turns it into
      // bytes.
      const raw = llm.sendToExternal(prompt, { sink: { name: 'anthropic' }, reason: 'r' });

      expect(raw).toContain(canary);
      expect(llm.hasRedactionMarker(raw)).toBe(false);
    });
  });
});
