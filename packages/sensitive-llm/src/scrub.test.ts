import { resetPolicies, SensitiveString } from '@platform-sec/sensitive-string-core';
import type { ScrubReport } from '@platform-sec/sensitive-string-scrub';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { createPromptScrubber, PromptScrubFailedError, scrubForPrompt } from './scrub.js';
import { DEFAULT_CONTENT_PATHS } from './shapes.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('scrubForPrompt', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe("the walk is scrub's, not a second one", () => {
    /**
     * The cheapest proof available, and it is a real one: keeping an object
     * referenced at two paths as one shared reference is a property
     * `redactCopy` has and `redactInStructure` does not. A package that grew
     * its own walk would fail this without anybody noticing what else it had
     * lost.
     */
    it('keeps a shared reference shared', () => {
      const shared = { note: 'same object at two paths' };
      const { prompt } = scrubForPrompt({ a: shared, b: shared });

      const out = prompt as { a: unknown; b: unknown };

      expect(out.a).toBe(out.b);
      expect(out.a).not.toBe(shared);
    });

    it('counts a value held at two paths once', () => {
      const value = new SensitiveString(CANARY, 'credential');
      const { removed } = scrubForPrompt({ a: value, b: value });

      expect(removed.instances).toBe(1);
    });

    it('terminates on a cycle', () => {
      const body: Record<string, unknown> = { messages: [] };
      body['self'] = body;

      expect(() => scrubForPrompt(body)).not.toThrow();
    });

    /**
     * Inherited from `scrub`, and worth an assertion here because this package
     * adds a third traversal of its own and a naive one would take the scrub
     * down on the first hostile object it met.
     */
    it('survives a Proxy that throws on an unknown property read', () => {
      const hostile = new Proxy(
        { content: 'ordinary text' },
        {
          get(target, key) {
            if (!(key in target)) {
              throw new Error('no such property');
            }

            return Reflect.get(target, key) as unknown;
          },
        }
      );

      expect(() => scrubForPrompt({ messages: [hostile] })).not.toThrow();
    });

    it('does not modify the input at any depth, prose included', () => {
      const value = new SensitiveString(CANARY, 'credential');
      const body = {
        api_key: 'sk-secret',
        system: `key is ${CANARY}`,
        messages: [{ role: 'user', content: value }],
      };

      scrubForPrompt(body, { transformContent: () => 'REPLACED' });

      expect(body.api_key).toBe('sk-secret');
      expect(body.system).toBe(`key is ${CANARY}`);
      expect(body.messages[0]?.content).toBe(value);
    });

    it('round-trips a payload holding nothing sensitive', () => {
      const body = { model: 'm', max_tokens: 100, messages: [{ role: 'user', content: 'hello' }] };
      const { prompt, removed } = scrubForPrompt(body);

      expect(prompt).toEqual(body);
      expect(removed.instances).toBe(0);
      expect(removed.deniedKeys).toEqual([]);
    });
  });

  describe('the manifest', () => {
    it('reports classes, keys and counts, and never a value', () => {
      const body = {
        api_key: CANARY,
        messages: [{ role: 'user', content: new SensitiveString(CANARY, 'credential', 'token') }],
      };

      const { removed } = scrubForPrompt(body, { policy: { reportLabels: true } });

      expect(removed.instances).toBe(1);
      expect([...removed.classes]).toEqual(['credential']);
      expect(removed.labels).toEqual(['token']);
      expect(removed.deniedKeys).toEqual(['api_key']);
      expect(JSON.stringify({ ...removed, classes: [...removed.classes] })).not.toContain(CANARY);
    });

    it('counts prose positions whether or not a hook was supplied', () => {
      const body = {
        system: 'a',
        messages: [{ role: 'user', content: [{ type: 'text', text: 'b' }] }],
      };

      expect(scrubForPrompt(body).removed.contentPositions).toBe(2);
    });

    it('reports zero prose positions for a body whose shape moved', () => {
      // The one signal a caller gets that their SDK upgraded into a schema the
      // shipped content paths do not describe.
      const { removed } = scrubForPrompt({ turns: [{ say: 'hello' }] });

      expect(removed.contentPositions).toBe(0);
    });

    it('recognizes handle-shaped tokens in prose, by token only', () => {
      const { removed } = scrubForPrompt({
        system: 'write to <<E:0123456789ab>> and <<customer:ba9876543210>>',
      });

      expect(removed.handles).toEqual(['<<E:0123456789ab>>', '<<customer:ba9876543210>>']);
    });

    it('reads handles after the hook ran, because the manifest describes what goes out', () => {
      const { removed } = scrubForPrompt(
        { system: 'nothing here' },
        { transformContent: () => 'now with <<E:0123456789ab>>' }
      );

      expect(removed.handles).toEqual(['<<E:0123456789ab>>']);
    });

    /**
     * The mirror image of the marker rule, and the reason the README tells a
     * caller to read this field before sending. Structural redaction replaced
     * a wrapped value with a marker, which leaked nothing and left a
     * placeholder where a value belonged. A model accepts a placeholder and
     * answers as though it were real, so a caller needs to be able to tell
     * that it happened. `instances` is how.
     */
    it('counts a wrapped value that reached the body without sendToExternal', () => {
      const { prompt, removed } = scrubForPrompt({
        messages: [{ role: 'user', content: new SensitiveString(CANARY, 'credential') }],
      });

      expect(removed.instances).toBe(1);
      expect([...removed.classes]).toEqual(['credential']);
      expect(JSON.stringify(prompt)).toContain('[REDACTED:credential]');
    });

    it('stamps event, because PayloadKind has no prompt member yet', () => {
      expect(scrubForPrompt({}).removed.kind).toBe('event');
    });
  });

  describe('the content hook', () => {
    it('receives each prose position with its dotted path', () => {
      const seen: [string, string][] = [];

      scrubForPrompt(
        {
          system: 'sys',
          messages: [
            { role: 'user', content: 'first' },
            { role: 'user', content: [{ type: 'text', text: 'second' }] },
          ],
        },
        {
          transformContent: (text, path) => {
            seen.push([path, text]);
            return text;
          },
        }
      );

      expect(seen).toEqual([
        ['system', 'sys'],
        ['messages.0.content', 'first'],
        ['messages.1.content.0.text', 'second'],
      ]);
    });

    /**
     * A marker structural redaction just wrote is not prose, and the hook's
     * contract is that whatever it returns is trusted verbatim. A hook that
     * rewrote a marker into something value-shaped is the one failure this
     * package is strictest about, so it never sees one.
     */
    it('is not called on a marker that structural redaction wrote', () => {
      const seen: string[] = [];

      const { prompt } = scrubForPrompt(
        { messages: [{ role: 'user', content: new SensitiveString(CANARY, 'credential') }] },
        {
          transformContent: (text) => {
            seen.push(text);
            return 'REWRITTEN';
          },
        }
      );

      expect(seen).toEqual([]);
      expect((prompt as unknown as { messages: { content: string }[] }).messages[0]?.content).toBe(
        '[REDACTED:credential]'
      );
    });

    it('honours caller-supplied content paths instead of the shipped shapes', () => {
      const seen: string[] = [];

      scrubForPrompt(
        { turns: [{ say: 'hello' }], system: 'ignored' },
        {
          contentPaths: ['turns.*.say'],
          transformContent: (text, path) => {
            seen.push(path);
            return text;
          },
        }
      );

      expect(seen).toEqual(['turns.0.say']);
    });
  });

  describe('failure is fail closed', () => {
    /**
     * `scrub` ships `guardedScrub`, which never throws and swaps in a stub.
     * That is correct for an error tracker, whose stub preserves the signal
     * that an error occurred while dropping the payload. A prompt has no
     * equivalent: a stub prompt is a request that costs money and answers a
     * question nobody asked, and the caller cannot tell it from a real one.
     */
    it('throws rather than returning a stub', () => {
      expect(() =>
        scrubForPrompt(
          { system: 'x' },
          {
            transformContent: () => {
              throw new Error('classifier is down');
            },
          }
        )
      ).toThrow(PromptScrubFailedError);
    });

    /**
     * The structural walk, rather than the prose pass. `scrub`'s walk guards
     * every enumeration it attempts, so the one unguarded thing left in a
     * resolved policy is a caller's own `denyValues` `RegExp`, which is what
     * this reaches through.
     */
    it('throws from the structural stage too, naming that stage', () => {
      class Hostile extends RegExp {
        override exec(): RegExpExecArray | null {
          throw new Error('the caller pattern is broken');
        }
      }

      let thrown: unknown;

      try {
        scrubForPrompt(
          { messages: [{ role: 'user', content: 'text' }] },
          { policy: { denyValues: [new Hostile('x')] } }
        );
      } catch (error) {
        thrown = error;
      }

      const error = thrown as PromptScrubFailedError;

      expect(error).toBeInstanceOf(PromptScrubFailedError);
      expect(error.message).toContain('the structural walk');
      expect(error.path).toBeUndefined();
    });

    it('reports with failed: true before it throws', () => {
      const reports: ScrubReport[] = [];

      expect(() =>
        scrubForPrompt(
          { system: 'x' },
          {
            policy: { onScrub: (report) => reports.push(report) },
            transformContent: () => {
              throw new Error('classifier is down');
            },
          }
        )
      ).toThrow(PromptScrubFailedError);

      // An operator needs to see a scrubber failing on every request of one
      // shape, and a thrown error the caller catches and retries is not that
      // signal.
      expect(reports).toHaveLength(1);
      expect(reports[0]?.failed).toBe(true);
    });

    it('names the stage, the path and the exception type, and nothing else', () => {
      let thrown: unknown;

      try {
        scrubForPrompt(
          { messages: [{ role: 'user', content: `holding ${CANARY}` }] },
          {
            transformContent: () => {
              throw new TypeError(`the classifier saw ${CANARY}`);
            },
          }
        );
      } catch (error) {
        thrown = error;
      }

      const error = thrown as PromptScrubFailedError;

      expect(error).toBeInstanceOf(PromptScrubFailedError);
      expect(error.path).toBe('messages.0.content');
      expect(error.thrown).toBe('TypeError');
      expect(error.message).not.toContain(CANARY);
      expect((error as Error & { cause?: unknown }).cause).toBeUndefined();
    });

    it('refuses a hook that returns something other than a string', () => {
      expect(() =>
        scrubForPrompt({ system: 'x' }, { transformContent: () => 42 as unknown as string })
      ).toThrow(PromptScrubFailedError);
    });

    it('reports on success too, with the manifest', () => {
      const reports: ScrubReport[] = [];

      scrubForPrompt({ system: 'x' }, { policy: { onScrub: (report) => reports.push(report) } });

      expect(reports).toHaveLength(1);
      expect(reports[0]?.failed).toBe(false);
    });

    it('swallows what onScrub throws, the way scrub does', () => {
      expect(() =>
        scrubForPrompt(
          { system: 'x' },
          {
            policy: {
              onScrub: () => {
                throw new Error('the reporter is down');
              },
            },
          }
        )
      ).not.toThrow();
    });
  });

  describe('resolution', () => {
    it('resolves once in the factory and not per call', async () => {
      const scrubModule = await import('@platform-sec/sensitive-string-scrub');
      const spy = vi.spyOn(scrubModule, 'resolveScrubPolicy');

      try {
        spy.mockClear();

        const scrubber = createPromptScrubber();
        const afterFactory = spy.mock.calls.length;

        scrubber({ system: 'a' });
        scrubber({ system: 'b' });

        // One call, in the factory. Resolution walks and lowercases every
        // denied key and path, and an LLM caller has no install moment, so the
        // factory is where the moment goes.
        expect(afterFactory).toBe(1);
        expect(spy.mock.calls.length).toBe(afterFactory);
      } finally {
        spy.mockRestore();
      }
    });

    it('resolves per call in the convenience form, which is what it is documented as', async () => {
      const scrubModule = await import('@platform-sec/sensitive-string-scrub');
      const spy = vi.spyOn(scrubModule, 'resolveScrubPolicy');

      try {
        spy.mockClear();

        scrubForPrompt({ system: 'a' });
        scrubForPrompt({ system: 'b' });

        expect(spy.mock.calls.length).toBe(2);
      } finally {
        spy.mockRestore();
      }
    });

    it('gives two calls of one scrubber the same answer', () => {
      const scrubber = createPromptScrubber();
      const build = () => ({ api_key: CANARY, system: 'hello' });

      expect(scrubber(build()).prompt).toEqual(scrubber(build()).prompt);
    });

    it('fails at setup on an unusable policy, not on a request', () => {
      expect(() =>
        createPromptScrubber({ policy: { allowKeys: [{ key: 'token', reason: '' }] } })
      ).toThrow();
    });

    it('merges the caller policy over this package envelope keys', () => {
      const { prompt } = scrubForPrompt(
        { anthropic_api_key: CANARY, x_custom_secret: CANARY },
        { policy: { denyKeys: ['x_custom_secret'] } }
      );

      expect(prompt).toEqual({ anthropic_api_key: '[SCRUBBED]', x_custom_secret: '[SCRUBBED]' });
    });
  });

  describe('shipped content paths', () => {
    it('cover the message content of every shape they claim to', () => {
      expect(DEFAULT_CONTENT_PATHS).toContain('messages.*.content');
      expect(DEFAULT_CONTENT_PATHS).toContain('input.*.content.*.text');
      expect(DEFAULT_CONTENT_PATHS).toContain('instructions');
      expect(DEFAULT_CONTENT_PATHS).toContain('system');
    });

    it('reach a tool result nested inside a message content block', () => {
      const seen: string[] = [];

      scrubForPrompt(
        {
          messages: [
            {
              role: 'user',
              content: [
                { type: 'tool_result', content: [{ type: 'text', text: 'the tool said this' }] },
              ],
            },
          ],
        },
        {
          transformContent: (text, path) => {
            seen.push(path);
            return text;
          },
        }
      );

      expect(seen).toEqual(['messages.0.content.0.content.0.text']);
    });
  });
});
