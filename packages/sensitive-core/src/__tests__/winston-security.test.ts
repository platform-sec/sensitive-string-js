import { Writable } from 'node:stream';
import winston from 'winston';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SensitiveString, sensitiveFormat, withRevealContext } from '../index.js';
import type { WinstonFormat, WinstonInfo } from '../index.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

/**
 * A payload deep enough to exhaust the stack during redaction.
 *
 * The redaction walk survives an object that refuses to answer any question:
 * a throwing `toJSON`, `toString`, `ownKeys` trap or enumerable getter all
 * degrade to walking what can be read. Depth is what is left, and the scrub
 * path still has to be reachable to be tested.
 */
function unredactablyDeep(): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  let node = root;

  for (let i = 0; i < 200_000; i++) {
    const child: Record<string, unknown> = {};
    node['n'] = child;
    node = child;
  }

  return root;
}

function sink(lines: string[], format?: WinstonFormat): winston.transport {
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      lines.push(String(chunk).trim());
      callback();
    },
  });

  return new winston.transports.Stream(format ? { stream, format } : { stream });
}

/** Capture the record objects a transport is handed, not just the written text. */
function captureRecords(records: WinstonInfo[]): WinstonFormat {
  return {
    transform(info: WinstonInfo) {
      records.push(info);
      return info;
    },
  };
}

describe('winston format security', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('leakage', () => {
    const terminalFormats = [
      ['json', () => winston.format.json()],
      ['simple', () => winston.format.simple()],
      ['prettyPrint', () => winston.format.prettyPrint()],
      ['logstash', () => winston.format.logstash()],
      ['printf', () => winston.format.printf((info) => JSON.stringify(info))],
    ] as const;

    it.each(terminalFormats)(
      'TST-WF-SEC-001: canary absent with %s as the terminal format',
      (_name, build) => {
        const lines: string[] = [];
        const logger = winston.createLogger({
          format: winston.format.combine(sensitiveFormat(), build()),
          transports: [sink(lines)],
        });

        logger.info('request', {
          token: new SensitiveString(CANARY, 'credential', 'api_key'),
          nested: { email: new SensitiveString(CANARY, 'sensitive', 'email') },
        });

        expect(lines).toHaveLength(1);
        expect(lines.join('')).not.toContain(CANARY);
      }
    );

    it('TST-WF-SEC-002: canary absent from the record object handed to the transport', () => {
      const records: WinstonInfo[] = [];
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines, captureRecords(records))],
      });

      logger.info('request', { token: new SensitiveString(CANARY, 'credential') });

      expect(records).toHaveLength(1);
      expect(JSON.stringify(records[0])).not.toContain(CANARY);
      expect(String(records[0]?.['token'])).not.toContain(CANARY);
    });

    it('TST-WF-SEC-003: no live instance reaches the transport', () => {
      const records: WinstonInfo[] = [];
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines, captureRecords(records))],
      });

      const secret = new SensitiveString(CANARY, 'credential');
      logger.info('request', { token: secret, list: [secret], deep: { deeper: secret } });

      const found: unknown[] = [];
      const walk = (value: unknown, seen = new WeakSet<object>()): void => {
        if (value === null || typeof value !== 'object') return;
        if (value instanceof SensitiveString) {
          found.push(value);
          return;
        }
        if (seen.has(value)) return;
        seen.add(value);
        for (const item of Object.values(value)) walk(item, seen);
      };
      walk(records[0]);

      expect(found).toEqual([]);
    });

    it('TST-WF-SEC-004: reveal() is never called', () => {
      const auditReveal = vi.fn();
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(
          sensitiveFormat({ stampClasses: true }),
          winston.format.json()
        ),
        transports: [sink(lines)],
      });

      withRevealContext({ name: 'test', auditReveal }, () => {
        logger.info('request', {
          token: new SensitiveString(CANARY, 'credential'),
          email: new SensitiveString(CANARY, 'sensitive'),
        });
      });

      expect(auditReveal).not.toHaveBeenCalled();
      expect(lines.join('')).not.toContain(CANARY);
    });

    it('TST-WF-SEC-005: a throwing toJSON is walked instead, and neither copy of the canary escapes', () => {
      // Two copies of the canary, reachable two different ways: one wrapped in
      // an own property, and one in the message of a `toJSON` that throws.
      class Exploding {
        readonly token = new SensitiveString(CANARY, 'credential');
        toJSON(): never {
          throw new Error(`boom ${CANARY}`);
        }
      }

      const onError = vi.fn();
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat({ onError }), winston.format.json()),
        transports: [sink(lines)],
      });

      logger.info('request', { payload: new Exploding() });

      // The walk discards the failed call and falls back to own properties,
      // which is the path an object with no `toJSON` already takes. The record
      // survives with its contents redacted rather than being dropped whole,
      // and the thrown message is never read.
      expect(onError).not.toHaveBeenCalled();
      expect(lines).toHaveLength(1);
      expect(lines.join('')).not.toContain(CANARY);
      expect(lines.join('')).toContain('[REDACTED:credential]');
    });

    it('TST-WF-SEC-008: a scrub at transport level reaches the written output', () => {
      // The transport writes Symbol.for('message'), not the record's fields, so
      // a scrub that only clears fields leaves the pre-error output in place.
      //
      // The trigger is depth rather than a throwing `toJSON`, which the walk now
      // survives. What is being tested is the scrub, not what provoked it.
      const onError = vi.fn();
      const lines: string[] = [];
      const logger = winston.createLogger({
        // printf does not call toJSON, so the failure happens in the
        // transport-level format rather than upstream.
        format: winston.format.printf((info) => `MSG:${String(info['message'])}`),
        transports: [sink(lines, sensitiveFormat({ onError, warnOnLateInstall: false }))],
      });

      logger.info('original output', { payload: unredactablyDeep() });

      expect(onError).toHaveBeenCalledTimes(1);
      expect(lines).toEqual(['[sensitive-format-error]']);
      expect(lines.join('')).not.toContain('original output');
    });

    it('TST-WF-SEC-006: canary absent from the late-install warning', () => {
      const emit = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.json(),
        transports: [sink(lines, sensitiveFormat())],
      });

      logger.info('request', { token: new SensitiveString(CANARY, 'credential') });

      expect(emit).toHaveBeenCalledTimes(1);
      expect(JSON.stringify(emit.mock.calls)).not.toContain(CANARY);
    });

    it('TST-WF-SEC-007: canary absent after an own-property walk of the record', () => {
      // Models a transport that serializes the record itself (BSON, protobuf,
      // structuredClone) instead of calling toJSON().
      const records: WinstonInfo[] = [];
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines, captureRecords(records))],
      });

      logger.info('request', { token: new SensitiveString(CANARY, 'credential') });

      expect(JSON.stringify(structuredClone(records[0]))).not.toContain(CANARY);
      expect(JSON.stringify(Object.entries(records[0] ?? {}))).not.toContain(CANARY);
    });
  });

  describe('adversarial', () => {
    it('TST-WF-ADV-001: a redaction that cannot finish scrubs the record and the logger survives', () => {
      const onError = vi.fn();
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat({ onError }), winston.format.json()),
        transports: [sink(lines)],
      });

      expect(() => logger.info('first', { payload: unredactablyDeep() })).not.toThrow();
      logger.info('second', { n: 2 });

      expect(lines).toHaveLength(2);
      expect(lines[0]).toContain('[sensitive-format-error]');
      expect(lines[1]).toContain('second');
    });

    it('TST-WF-ADV-005: an object that refuses every question is logged as unreadable', () => {
      const hostile = new Proxy(
        {},
        new Proxy(
          {},
          {
            get() {
              return (): never => {
                throw new Error('refused');
              };
            },
          }
        )
      );

      const onError = vi.fn();
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat({ onError }), winston.format.json()),
        transports: [sink(lines)],
      });

      expect(() =>
        logger.info('request', {
          hostile,
          token: new SensitiveString(CANARY, 'credential'),
        })
      ).not.toThrow();

      expect(onError).not.toHaveBeenCalled();
      expect(lines.join('')).not.toContain(CANARY);
      expect(lines.join('')).toContain('[Unreadable]');
      expect(lines.join('')).toContain('[REDACTED:credential]');
    });

    it('TST-WF-ADV-002: circular meta does not hang or throw', () => {
      const circular: Record<string, unknown> = {
        token: new SensitiveString(CANARY, 'credential'),
      };
      circular['self'] = circular;

      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      expect(() => logger.info('circular', { circular })).not.toThrow();
      expect(lines.join('')).not.toContain(CANARY);
      expect(lines.join('')).toContain('[Circular]');
    });

    it('TST-WF-ADV-003: deeply nested meta is redacted throughout', () => {
      const depth = 1000;
      let deep: Record<string, unknown> = { token: new SensitiveString(CANARY, 'credential') };
      for (let i = 0; i < depth; i++) {
        deep = { nested: deep };
      }

      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      expect(() => logger.info('deep', { deep })).not.toThrow();
      expect(lines.join('')).not.toContain(CANARY);
      expect(lines.join('')).toContain('[REDACTED:credential]');
    });

    it('TST-WF-ADV-004: null, undefined and empty meta are handled', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      expect(() => {
        logger.info('a', {});
        logger.info('b', { nil: null, undef: undefined });
        logger.info('c');
      }).not.toThrow();

      expect(lines).toHaveLength(3);
    });

    it('TST-WF-ADV-005: an instance under a symbol key is not walked and does not leak', () => {
      // Object.keys() does not see symbol keys, so the format leaves them alone.
      // Winston's serializers ignore them too, so nothing is written.
      const key = Symbol('secret');
      const meta = { [key]: new SensitiveString(CANARY, 'credential'), n: 1 };

      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      logger.info('symbol key', meta);

      expect(lines.join('')).not.toContain(CANARY);
    });

    it('TST-WF-ADV-006: frozen meta is not mutated', () => {
      const secret = new SensitiveString(CANARY, 'credential');
      const frozen = Object.freeze({ token: secret });

      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      expect(() => logger.info('frozen', { frozen })).not.toThrow();
      expect(frozen.token).toBe(secret);
      expect(lines.join('')).not.toContain(CANARY);
      expect(lines.join('')).toContain('[REDACTED:credential]');
    });

    it('TST-WF-ADV-007: an expired instance redacts without throwing', () => {
      const expired = new SensitiveString(CANARY, 'credential', 'otp', { ttl: 0 });

      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      expect(() => logger.info('expired', { otp: expired })).not.toThrow();
      expect(lines.join('')).not.toContain(CANARY);
    });

    it('TST-WF-ADV-008: an instance used as a Map key is redacted', () => {
      const map = new Map<unknown, unknown>([[new SensitiveString(CANARY, 'credential'), 'value']]);

      const lines: string[] = [];
      const records: WinstonInfo[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines, captureRecords(records))],
      });

      logger.info('map key', { map });

      expect(
        JSON.stringify([...((records[0]?.['map'] as Map<unknown, unknown>) ?? [])])
      ).not.toContain(CANARY);
      expect(lines.join('')).not.toContain(CANARY);
    });

    it('TST-WF-ADV-009: concurrent logging from overlapping async contexts stays clean', async () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      await Promise.all(
        Array.from({ length: 50 }, async (_unused, i) => {
          await Promise.resolve();
          logger.info(`n${i}`, { token: new SensitiveString(`${CANARY}_${i}`, 'credential') });
        })
      );

      expect(lines).toHaveLength(50);
      expect(lines.join('')).not.toContain(CANARY);
    });
  });
});
