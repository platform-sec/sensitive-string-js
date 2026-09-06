import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  getDevModeConfig,
  SensitiveString,
  setDevMode,
  withDevMode,
  withRevealContext,
} from './index.js';
import type { DevModeConfig } from './index.js';

const START = new Date('2026-01-01T00:00:00.000Z');

/** Collect what a configured logger was handed. */
function collector(): { lines: string[]; logger: (message: string) => void } {
  const lines: string[] = [];
  return { lines, logger: (message: string) => lines.push(message) };
}

/** Development mode with a logger attached, since most cases assert on output. */
function logging(overrides: Partial<DevModeConfig> = {}): {
  lines: string[];
  config: DevModeConfig;
} {
  const { lines, logger } = collector();

  return {
    lines,
    config: {
      enabled: true,
      logReveals: { enabled: true, logger },
      ...overrides,
    },
  };
}

describe('development mode', () => {
  beforeEach(() => {
    setDevMode({ enabled: false });
  });

  afterEach(() => {
    setDevMode({ enabled: false });
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('configuration', () => {
    it('is off until it is turned on', () => {
      expect(getDevModeConfig().enabled).toBe(false);
    });

    it('resolves defaults for every option', () => {
      setDevMode({ enabled: true });

      expect(getDevModeConfig()).toEqual({
        enabled: true,
        captureStackTraces: false,
        captureCreationStack: false,
        warnOnMissingContext: false,
        warnOnRepeatedReveal: false,
        logReveals: { enabled: false, showPartialValue: false, partialLength: 4 },
      });
    });

    it('returns a configuration that can be handed back to setDevMode', () => {
      setDevMode({
        enabled: true,
        captureStackTraces: true,
        warnOnRepeatedReveal: { threshold: 3, window: 1000 },
        logReveals: { enabled: true, showPartialValue: true, partialLength: 2 },
      });

      const saved = getDevModeConfig();
      setDevMode({ enabled: false });
      setDevMode(saved);

      expect(getDevModeConfig()).toEqual(saved);
    });

    it('freezes what it returns, so the live configuration cannot be edited through it', () => {
      setDevMode({ enabled: true });
      const config = getDevModeConfig();

      expect(() => {
        (config as { enabled: boolean }).enabled = false;
      }).toThrow(TypeError);
      expect(getDevModeConfig().enabled).toBe(true);
    });

    it('restores the previous configuration after withDevMode', () => {
      setDevMode({ enabled: true, captureStackTraces: true });

      const inner = withDevMode({ enabled: false }, () => getDevModeConfig().enabled);

      expect(inner).toBe(false);
      expect(getDevModeConfig()).toMatchObject({ enabled: true, captureStackTraces: true });
    });

    it('restores the previous configuration when the body throws', () => {
      setDevMode({ enabled: true });

      expect(() =>
        withDevMode({ enabled: false }, () => {
          throw new Error('boom');
        })
      ).toThrow('boom');
      expect(getDevModeConfig().enabled).toBe(true);
    });

    it('rejects a configuration that is not an object', () => {
      expect(() => setDevMode(null as unknown as DevModeConfig)).toThrow(TypeError);
      expect(() => setDevMode(undefined as unknown as DevModeConfig)).toThrow(TypeError);
    });

    it('requires enabled to be a boolean', () => {
      expect(() => setDevMode({} as DevModeConfig)).toThrow(/enabled must be a boolean/);
      expect(() => setDevMode({ enabled: 1 } as unknown as DevModeConfig)).toThrow(TypeError);
    });

    it('rejects a non-boolean flag', () => {
      expect(() =>
        setDevMode({ enabled: true, captureStackTraces: 'yes' } as unknown as DevModeConfig)
      ).toThrow(/captureStackTraces must be a boolean/);
    });

    it('rejects a repeated-reveal window that cannot hold anything', () => {
      expect(() =>
        setDevMode({ enabled: true, warnOnRepeatedReveal: { threshold: 2, window: 0 } })
      ).toThrow(RangeError);
      expect(() =>
        setDevMode({ enabled: true, warnOnRepeatedReveal: { threshold: 0, window: 100 } })
      ).toThrow(RangeError);
      expect(() =>
        setDevMode({
          enabled: true,
          warnOnRepeatedReveal: { threshold: 1.5, window: 100 },
        })
      ).toThrow(RangeError);
    });

    it('rejects a partial length beyond the cap', () => {
      expect(() =>
        setDevMode({
          enabled: true,
          logReveals: { enabled: true, showPartialValue: true, partialLength: 9 },
        })
      ).toThrow(/exceeds the cap of 8/);
    });

    it('rejects a logger that is not a function', () => {
      expect(() =>
        setDevMode({
          enabled: true,
          logReveals: { enabled: true, logger: 'console' as unknown as () => void },
        })
      ).toThrow(/logger must be a function/);
    });

    it('leaves the previous configuration in place when a new one is rejected', () => {
      setDevMode({ enabled: true, captureStackTraces: true });

      expect(() => setDevMode({ enabled: true, warnOnMissingContext: 1 } as never)).toThrow(
        TypeError
      );
      expect(getDevModeConfig()).toMatchObject({ enabled: true, captureStackTraces: true });
    });

    it('DEV-T011: warns when enabled under NODE_ENV=production', () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      const previous = process.env['NODE_ENV'];
      process.env['NODE_ENV'] = 'production';

      try {
        setDevMode({ enabled: true });
        setDevMode({ enabled: false });
      } finally {
        if (previous === undefined) {
          delete process.env['NODE_ENV'];
        } else {
          process.env['NODE_ENV'] = previous;
        }
      }

      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls[0]?.[0]).toContain('Dev mode enabled in production');
    });
  });

  describe('recorded history', () => {
    it('DEV-T001: reports nothing while development mode is off', () => {
      const secret = new SensitiveString('value', 'sensitive', 'api_key');

      expect(secret.__devInfo).toBeUndefined();
    });

    it('reports nothing for a value constructed before it was turned on', () => {
      const secret = new SensitiveString('value', 'sensitive');
      setDevMode({ enabled: true });

      expect(secret.__devInfo).toBeUndefined();
    });

    it('stops reporting once development mode is turned off again', () => {
      setDevMode({ enabled: true });
      const secret = new SensitiveString('value', 'sensitive');
      expect(secret.__devInfo).toBeDefined();

      setDevMode({ enabled: false });
      expect(secret.__devInfo).toBeUndefined();
    });

    it('DEV-T002: records when the value was constructed', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);
      setDevMode({ enabled: true });

      const secret = new SensitiveString('value', 'sensitive');

      expect(secret.__devInfo?.createdAt).toEqual(START);
    });

    it('hands out a copy of the creation date, not the record', () => {
      setDevMode({ enabled: true });
      const secret = new SensitiveString('value', 'sensitive');

      const first = secret.__devInfo?.createdAt;
      first?.setFullYear(1999);

      expect(secret.__devInfo?.createdAt.getFullYear()).not.toBe(1999);
    });

    it('DEV-T003: captures the creation stack only when asked', () => {
      withDevMode({ enabled: true }, () => {
        expect(new SensitiveString('value', 'sensitive').__devInfo?.creationStack).toBeUndefined();
      });

      withDevMode({ enabled: true, captureCreationStack: true }, () => {
        const stack = new SensitiveString('value', 'sensitive').__devInfo?.creationStack;

        expect(stack).toContain('dev-mode.test.ts');
      });
    });

    it('DEV-T004: counts every exposure', () => {
      setDevMode({ enabled: true });
      const secret = new SensitiveString('value', 'sensitive', 'api_key');

      secret.reveal();
      secret.reveal();
      secret.mask({ showLast: 1 });

      expect(secret.__devInfo?.revealCount).toBe(3);
    });

    it('does not count a comparison, which discloses nothing', () => {
      setDevMode({ enabled: true });
      const secret = new SensitiveString('value', 'sensitive');

      secret.equals('value');
      String(secret);
      JSON.stringify(secret);
      expect(secret.length).toBe(5);

      expect(secret.__devInfo?.revealCount).toBe(0);
    });

    it('does not count a reveal a policy refused', () => {
      setDevMode({ enabled: true });
      const secret = new SensitiveString('value', 'sensitive', 'expiring', { ttl: 0 });

      expect(() => secret.reveal()).toThrow();

      expect(secret.__devInfo?.revealCount).toBe(0);
    });

    it('does not count a reveal an audit hook stopped', () => {
      setDevMode({ enabled: true });
      const secret = new SensitiveString('value', 'sensitive');

      expect(() =>
        withRevealContext(
          {
            name: 'refusing',
            auditReveal: () => {
              throw new Error('denied');
            },
          },
          () => secret.reveal()
        )
      ).toThrow('denied');

      expect(secret.__devInfo?.revealCount).toBe(0);
    });

    it('tracks a derived value in its own right', () => {
      setDevMode({ enabled: true });
      const secret = new SensitiveString('value', 'sensitive');

      const derived = secret.substring(0, 3);
      derived.reveal();

      expect(secret.__devInfo?.revealCount).toBe(1);
      expect(derived.__devInfo?.revealCount).toBe(1);
    });

    it('DEV-T005: records the time of each exposure', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);
      setDevMode({ enabled: true });
      const secret = new SensitiveString('value', 'sensitive');

      secret.reveal();
      vi.setSystemTime(new Date(START.getTime() + 50));
      secret.reveal();

      expect(secret.__devInfo?.revealTimestamps).toEqual([START.getTime(), START.getTime() + 50]);
    });

    it('DEV-P003: keeps the most recent 64 timestamps and forgets the rest', () => {
      setDevMode({ enabled: true });
      const secret = new SensitiveString('value', 'sensitive');

      for (let i = 0; i < 500; i += 1) {
        secret.reveal();
      }

      const info = secret.__devInfo;
      expect(info?.revealCount).toBe(500);
      expect(info?.revealTimestamps).toHaveLength(64);
      expect([...(info?.revealTimestamps ?? [])]).toEqual(
        [...(info?.revealTimestamps ?? [])].sort((a, b) => a - b)
      );
    });

    it('DEV-T006: captures the stack of the most recent exposure only when asked', () => {
      withDevMode({ enabled: true }, () => {
        const secret = new SensitiveString('value', 'sensitive');
        secret.reveal();

        expect(secret.__devInfo?.lastRevealStack).toBeUndefined();
      });

      withDevMode({ enabled: true, captureStackTraces: true }, () => {
        const secret = new SensitiveString('value', 'sensitive');
        secret.reveal();
        const first = secret.__devInfo?.lastRevealStack;

        secret.mask({ showLast: 1 });

        expect(first).toContain('dev-mode.test.ts');
        expect(secret.__devInfo?.lastRevealStack).not.toBe(first);
      });
    });

    it('names the caller in a captured stack, not the library', () => {
      withDevMode({ enabled: true, captureStackTraces: true }, () => {
        const secret = new SensitiveString('value', 'sensitive');
        secret.reveal();

        const frames = (secret.__devInfo?.lastRevealStack ?? '').split('\n');

        expect(frames[0]).toContain('dev-mode.test.ts');
        expect(frames[0]).not.toContain('sensitive-string.ts');
        expect(frames[0]).not.toContain('dev-mode.ts:');
      });
    });
  });

  describe('logging', () => {
    it('DEV-T009: hands every line to the configured logger', () => {
      const { lines, config } = logging();

      withDevMode(config, () => {
        new SensitiveString('value', 'sensitive', 'api_key').reveal();
      });

      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain("[SensitiveString] Reveal of 'api_key'");
    });

    it('falls back to the class when the value has no label', () => {
      const { lines, config } = logging();

      withDevMode(config, () => {
        new SensitiveString('value', 'credential').reveal();
      });

      expect(lines[0]).toContain("Reveal of 'credential'");
    });

    it('names the operation that exposed the value', () => {
      const { lines, config } = logging();

      withDevMode(config, () => {
        new SensitiveString('value@example.com', 'sensitive', 'email').mask({ showLast: 4 });
      });

      expect(lines[0]).toContain("Mask of 'email'");
    });

    it('names a digest as a digest, not as a reveal', () => {
      const { lines, config } = logging();

      withDevMode(config, () => {
        const token = new SensitiveString('value', 'credential', 'api_key');

        token.hash('sha256');
        token.hmac('sha256', 'k'.repeat(32));
      });

      expect(lines[0]).toContain("Hash of 'api_key'");
      expect(lines[1]).toContain("HMAC of 'api_key'");
    });

    it('reports the context that explains the reveal', () => {
      const { lines, config } = logging();

      withDevMode(config, () => {
        const secret = new SensitiveString('value', 'sensitive', 'api_key');
        withRevealContext({ name: 'payment-processing' }, () => secret.reveal());
      });

      expect(lines[0]).toContain("with context 'payment-processing'");
    });

    it('DEV-T007: warns about a missing context even when full logging is off', () => {
      const { lines, logger } = collector();

      withDevMode(
        { enabled: true, warnOnMissingContext: true, logReveals: { enabled: false, logger } },
        () => {
          const secret = new SensitiveString('value', 'sensitive', 'api_key');
          secret.reveal();
          withRevealContext({ name: 'explained' }, () => secret.reveal());
        }
      );

      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain("Reveal of 'api_key' without context");
    });

    it('logs nothing at all when neither option asks for output', () => {
      const { lines, logger } = collector();

      withDevMode({ enabled: true, logReveals: { enabled: false, logger } }, () => {
        new SensitiveString('value', 'sensitive').reveal();
      });

      expect(lines).toEqual([]);
    });

    it('DEV-T010: shows a bounded prefix of the value when configured', () => {
      const { lines, logger } = collector();

      withDevMode(
        {
          enabled: true,
          logReveals: { enabled: true, logger, showPartialValue: true },
        },
        () => {
          new SensitiveString('sk_test_abcdefghijkl', 'sensitive', 'api_key').reveal();
        }
      );

      expect(lines[0]).toContain('(sk_t...)');
    });

    it('shows no prefix by default', () => {
      const { lines, config } = logging();

      withDevMode(config, () => {
        new SensitiveString('sk_test_abcdefghijkl', 'sensitive', 'api_key').reveal();
      });

      expect(lines[0]).not.toContain('sk_t');
    });

    it('appends the reveal stack and the creation stack when both were captured', () => {
      const { lines, logger } = collector();

      withDevMode(
        {
          enabled: true,
          captureStackTraces: true,
          captureCreationStack: true,
          logReveals: { enabled: true, logger },
        },
        () => {
          new SensitiveString('value', 'sensitive', 'api_key').reveal();
        }
      );

      expect(lines[0]).toContain('\nCreated at:\n');
      expect(lines[0]?.split('\n')[1]).toContain('    at ');
    });

    it('defaults to console.warn when no logger is configured', () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

      withDevMode({ enabled: true, warnOnMissingContext: true }, () => {
        new SensitiveString('value', 'sensitive', 'api_key').reveal();
      });

      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls[0]?.[0]).toContain("Reveal of 'api_key' without context");
    });
  });

  describe('repeated reveals', () => {
    it('DEV-T008: warns once the threshold is reached inside the window', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);
      const { lines, logger } = collector();

      withDevMode(
        {
          enabled: true,
          warnOnRepeatedReveal: { threshold: 3, window: 5000 },
          logReveals: { enabled: false, logger },
        },
        () => {
          const secret = new SensitiveString('value', 'credential', 'session_token');

          secret.reveal();
          secret.reveal();
          expect(lines).toEqual([]);

          secret.reveal();
          expect(lines).toHaveLength(1);
          expect(lines[0]).toContain("'session_token' revealed 3 times in 5000ms");
          expect(lines[0]).toContain('Consider caching the revealed value');
        }
      );
    });

    it('warns at most once per window, however hot the loop is', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);
      const { lines, logger } = collector();

      withDevMode(
        {
          enabled: true,
          warnOnRepeatedReveal: { threshold: 2, window: 1000 },
          logReveals: { enabled: false, logger },
        },
        () => {
          const secret = new SensitiveString('value', 'sensitive', 'token');

          for (let i = 0; i < 50; i += 1) {
            secret.reveal();
          }
          expect(lines).toHaveLength(1);

          vi.setSystemTime(new Date(START.getTime() + 1000));
          secret.reveal();
          secret.reveal();
          expect(lines).toHaveLength(2);
        }
      );
    });

    it('does not warn when the reveals are spread across windows', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);
      const { lines, logger } = collector();

      withDevMode(
        {
          enabled: true,
          warnOnRepeatedReveal: { threshold: 3, window: 1000 },
          logReveals: { enabled: false, logger },
        },
        () => {
          const secret = new SensitiveString('value', 'sensitive', 'token');

          for (let i = 0; i < 10; i += 1) {
            vi.setSystemTime(new Date(START.getTime() + i * 1000));
            secret.reveal();
          }

          expect(lines).toEqual([]);
        }
      );
    });

    it('includes the most recent reveal stack when one was captured', () => {
      const { lines, logger } = collector();

      withDevMode(
        {
          enabled: true,
          captureStackTraces: true,
          warnOnRepeatedReveal: { threshold: 2, window: 60_000 },
          logReveals: { enabled: false, logger },
        },
        () => {
          const secret = new SensitiveString('value', 'sensitive', 'token');
          secret.reveal();
          secret.reveal();
        }
      );

      expect(lines[0]).toContain('Most recent reveal at:');
      expect(lines[0]).toContain('dev-mode.test.ts');
    });

    it('counts each value separately', () => {
      const { lines, logger } = collector();

      withDevMode(
        {
          enabled: true,
          warnOnRepeatedReveal: { threshold: 2, window: 60_000 },
          logReveals: { enabled: false, logger },
        },
        () => {
          new SensitiveString('a', 'sensitive', 'first').reveal();
          new SensitiveString('b', 'sensitive', 'second').reveal();
        }
      );

      expect(lines).toEqual([]);
    });
  });

  describe('serialization', () => {
    it('DEV-T012: keeps the record out of toJSON', () => {
      setDevMode({ enabled: true, captureCreationStack: true });
      const secret = new SensitiveString('value', 'sensitive', 'api_key');
      secret.reveal();

      expect(JSON.stringify({ secret })).toBe('{"secret":"[REDACTED:sensitive]"}');
    });

    it('DEV-T013: keeps the record out of toString and inspection', () => {
      setDevMode({ enabled: true, captureCreationStack: true });
      const secret = new SensitiveString('value', 'sensitive', 'api_key');
      secret.reveal();

      expect(secret.toString()).toBe('[REDACTED:sensitive]');
      expect(util.inspect(secret)).toBe(
        'SensitiveString<sensitive:api_key> { [REDACTED:sensitive] }'
      );
      expect(Object.keys(secret)).not.toContain('__devInfo');
      expect(Object.getOwnPropertyNames(secret)).not.toContain('__devInfo');
    });
  });
});
