import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  safeStringify,
  SensitiveString,
  setDevMode,
  withDevMode,
  redactInStructure,
} from '../index.js';
import type { DevInfo } from '../index.js';

const CANARY = 'LEAKED_SECRET_dev_test_xyz789';

/** Collect what a configured logger was handed. */
function collector(): { lines: string[]; logger: (message: string) => void } {
  const lines: string[] = [];
  return { lines, logger: (message: string) => lines.push(message) };
}

/** Every string anywhere in a value, however nested. */
function strings(value: unknown, found: string[] = []): string[] {
  if (typeof value === 'string') {
    found.push(value);
  } else if (value instanceof Date) {
    found.push(value.toISOString());
  } else if (Array.isArray(value)) {
    for (const entry of value) {
      strings(entry, found);
    }
  } else if (typeof value === 'object' && value !== null) {
    for (const entry of Object.values(value)) {
      strings(entry, found);
    }
  }

  return found;
}

describe('development mode security', () => {
  beforeEach(() => {
    setDevMode({ enabled: false });
  });

  afterEach(() => {
    setDevMode({ enabled: false });
  });

  it('DEV-C001: never writes the full value to the log, partial rendering or not', () => {
    const { lines, logger } = collector();

    withDevMode(
      {
        enabled: true,
        captureStackTraces: true,
        captureCreationStack: true,
        warnOnMissingContext: true,
        warnOnRepeatedReveal: { threshold: 2, window: 60_000 },
        logReveals: { enabled: true, logger, showPartialValue: true },
      },
      () => {
        const secret = new SensitiveString(CANARY, 'credential', 'key');
        secret.reveal();
        secret.reveal();
      }
    );

    const output = lines.join('\n');
    expect(lines.length).toBeGreaterThan(0);
    expect(output).not.toContain(CANARY);
    expect(output).toContain('(LEAK...)');
  });

  it('DEV-C002: shows no more of the value than the configured length', () => {
    const { lines, logger } = collector();

    withDevMode(
      {
        enabled: true,
        logReveals: { enabled: true, logger, showPartialValue: true, partialLength: 2 },
      },
      () => {
        new SensitiveString('abcdefghij', 'sensitive').reveal();
      }
    );

    expect(lines[0]).toContain('(ab...)');
    expect(lines[0]).not.toContain('abc');
  });

  it('shows nothing at all when the class floor leaves no room', () => {
    const { lines, logger } = collector();

    withDevMode(
      { enabled: true, logReveals: { enabled: true, logger, showPartialValue: true } },
      () => {
        // A credential hides at least 8 characters, which is the whole of this one.
        new SensitiveString('pw123456', 'credential', 'password').reveal();
        // A sensitive value hides at least 4, leaving one of these five.
        new SensitiveString('abcde', 'sensitive', 'short').reveal();
      }
    );

    expect(lines[0]).toContain("Reveal of 'password' without context");
    expect(lines[0]).not.toContain('(');
    expect(lines[1]).toContain('(a...)');
    expect(lines[1]).not.toContain('ab');
  });

  it('holds the partial rendering to the same floor a mask of the class would', () => {
    const { lines, logger } = collector();

    withDevMode(
      {
        enabled: true,
        logReveals: { enabled: true, logger, showPartialValue: true, partialLength: 8 },
      },
      () => {
        // Ten code points, a floor of eight: two may be shown, not the eight asked for.
        new SensitiveString('0123456789', 'credential', 'token').reveal();
      }
    );

    expect(lines[0]).toContain('(01...)');
    expect(lines[0]).not.toContain('012');
  });

  it('shows nothing when the configured length is zero', () => {
    const { lines, logger } = collector();

    withDevMode(
      {
        enabled: true,
        logReveals: { enabled: true, logger, showPartialValue: true, partialLength: 0 },
      },
      () => {
        new SensitiveString(CANARY, 'sensitive', 'key').reveal();
      }
    );

    expect(lines[0]).not.toContain('(');
  });

  it('never splits a surrogate pair, which would render a lone half of one', () => {
    const { lines, logger } = collector();

    withDevMode(
      {
        enabled: true,
        logReveals: { enabled: true, logger, showPartialValue: true, partialLength: 2 },
      },
      () => {
        new SensitiveString('🔑🔒🗝️🧷🔐🪪', 'sensitive', 'emoji').reveal();
      }
    );

    expect(lines[0]).toContain('(🔑🔒...)');
    expect(lines[0]).not.toContain('🔑\uD83D)');
  });

  it('DEV-C003: keeps the value out of everything the record exposes', () => {
    withDevMode({ enabled: true, captureStackTraces: true, captureCreationStack: true }, () => {
      const secret = new SensitiveString(CANARY, 'credential', 'key');
      secret.reveal();

      const info = secret.__devInfo;
      expect(info).toBeDefined();
      expect(Object.keys(info as unknown as object).sort()).toEqual([
        'createdAt',
        'creationStack',
        'lastRevealStack',
        'revealCount',
        'revealTimestamps',
      ]);

      for (const value of strings(info)) {
        expect(value).not.toContain(CANARY);
      }

      expect(JSON.stringify(info)).not.toContain(CANARY);
      expect(util.inspect(info, { depth: null })).not.toContain(CANARY);
    });
  });

  it('DEV-C004: leaves every redacted rendering exactly as it was', () => {
    const withoutDevMode = {
      json: JSON.stringify({ secret: new SensitiveString(CANARY, 'credential', 'key') }),
      inspected: util.inspect(new SensitiveString(CANARY, 'credential', 'key')),
      redacted: redactInStructure({ secret: new SensitiveString(CANARY, 'credential', 'key') }),
      safe: safeStringify({ secret: new SensitiveString(CANARY, 'credential', 'key') }),
    };

    withDevMode({ enabled: true, captureStackTraces: true, captureCreationStack: true }, () => {
      const secret = new SensitiveString(CANARY, 'credential', 'key');
      secret.reveal();

      expect(JSON.stringify({ secret })).toBe(withoutDevMode.json);
      expect(util.inspect(secret)).toBe(withoutDevMode.inspected);
      expect(redactInStructure({ secret })).toEqual(withoutDevMode.redacted);
      expect(safeStringify({ secret })).toBe(withoutDevMode.safe);

      const serialized = secret.serialize();
      expect(Object.keys(serialized).sort()).toEqual(['__sensitive', 'klass', 'label', 'value']);
      expect(JSON.stringify(serialized).replaceAll(CANARY, '')).not.toContain('Stack');
    });
  });

  it('does not let a broken logger change what the program does', () => {
    withDevMode(
      {
        enabled: true,
        warnOnRepeatedReveal: { threshold: 1, window: 60_000 },
        logReveals: {
          enabled: true,
          logger: () => {
            throw new Error('the logger is broken');
          },
        },
      },
      () => {
        const secret = new SensitiveString(CANARY, 'sensitive', 'key');

        expect(secret.reveal()).toBe(CANARY);
        expect(secret.__devInfo?.revealCount).toBe(1);
      }
    );
  });

  it('records nothing at all while it is off', () => {
    const { lines, logger } = collector();

    setDevMode({
      enabled: false,
      captureStackTraces: true,
      captureCreationStack: true,
      warnOnMissingContext: true,
      logReveals: { enabled: true, logger, showPartialValue: true },
    });

    const secret = new SensitiveString(CANARY, 'credential', 'key');
    secret.reveal();
    new SensitiveString(CANARY, 'sensitive', 'other').mask({ showLast: 2 });

    expect(lines).toEqual([]);
    expect(secret.__devInfo).toBeUndefined();

    // Turning it on afterwards must not resurrect a history that was never kept.
    setDevMode({ enabled: true });
    expect(secret.__devInfo).toBeUndefined();
  });

  it('hands out a record that cannot be edited through', () => {
    withDevMode({ enabled: true, captureCreationStack: true }, () => {
      const secret = new SensitiveString(CANARY, 'sensitive', 'key');
      secret.reveal();

      const info = secret.__devInfo as DevInfo;

      expect(() => {
        (info as { revealCount: number }).revealCount = 99;
      }).toThrow(TypeError);
      expect(() => {
        (info.revealTimestamps as number[]).push(1);
      }).toThrow(TypeError);
      expect(secret.__devInfo?.revealCount).toBe(1);
    });
  });

  it('keeps a redaction walk from being reported as a reveal', () => {
    const { lines, logger } = collector();

    withDevMode(
      {
        enabled: true,
        warnOnMissingContext: true,
        logReveals: { enabled: true, logger, showPartialValue: true },
      },
      () => {
        const secret = new SensitiveString(CANARY, 'credential', 'key');

        redactInStructure({ secret });
        safeStringify({ secret });
        util.inspect(secret);
        JSON.stringify(secret);

        expect(lines).toEqual([]);
        expect(secret.__devInfo?.revealCount).toBe(0);
      }
    );
  });
});
