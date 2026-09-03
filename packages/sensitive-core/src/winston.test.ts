import { Writable } from 'node:stream';
import winston from 'winston';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { redactInStructure, SensitiveString, sensitiveFormat } from './index.js';
import type { WinstonFormat, WinstonInfo } from './index.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

/** A transport that keeps every line it is asked to write. */
function sink(lines: string[], format?: WinstonFormat): winston.transport {
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      lines.push(String(chunk).trim());
      callback();
    },
  });

  return new winston.transports.Stream(format ? { stream, format } : { stream });
}

/** Parse the single JSON record a logger wrote. */
function record(lines: string[]): Record<string, unknown> {
  expect(lines).toHaveLength(1);
  return JSON.parse(lines[0] as string) as Record<string, unknown>;
}

describe('sensitiveFormat', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('redaction', () => {
    it('TST-WF-001: redacts an instance in top-level meta', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      logger.info('request', { token: new SensitiveString(CANARY, 'credential', 'api_key') });

      expect(record(lines)['token']).toBe('[REDACTED:credential]');
    });

    it('TST-WF-002: the record still reaches the transport', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      logger.info('one', { token: new SensitiveString(CANARY, 'credential') });
      logger.info('two');
      logger.info('three', { token: new SensitiveString(CANARY, 'sensitive') });

      expect(lines).toHaveLength(3);
      expect(lines.map((line) => (JSON.parse(line) as { message: string }).message)).toEqual([
        'one',
        'two',
        'three',
      ]);
    });

    it('TST-WF-003: redacts nested objects, arrays, Map and Set values', () => {
      const lines: string[] = [];
      const secret = new SensitiveString(CANARY, 'credential');
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      logger.info('nested', {
        deep: { deeper: { token: secret } },
        list: [1, secret, { token: secret }],
        map: new Map([['k', secret]]),
        set: new Set([secret]),
      });

      const written = lines.join('');
      expect(written).not.toContain(CANARY);
      const parsed = record(lines);
      expect(parsed['deep']).toEqual({ deeper: { token: '[REDACTED:credential]' } });
      expect(parsed['list']).toEqual([
        1,
        '[REDACTED:credential]',
        { token: '[REDACTED:credential]' },
      ]);
    });

    it('TST-WF-004: redacts when message is itself a SensitiveString', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      logger.info(new SensitiveString(CANARY, 'credential') as unknown as string);

      expect(lines.join('')).not.toContain(CANARY);
      expect(record(lines)['message']).toBe('[REDACTED:credential]');
    });

    it('TST-WF-005: redacts defaultMeta and child() meta', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        defaultMeta: { apiKey: new SensitiveString(CANARY, 'credential', 'api_key') },
        transports: [sink(lines)],
      });

      logger.child({ session: new SensitiveString(CANARY, 'sensitive', 'session') }).info('child');

      const parsed = record(lines);
      expect(parsed['apiKey']).toBe('[REDACTED:credential]');
      expect(parsed['session']).toBe('[REDACTED:sensitive]');
    });

    it('TST-WF-006: redacts the splat array', () => {
      const lines: string[] = [];
      let splat: unknown;
      const observe: WinstonFormat = {
        transform(info: WinstonInfo) {
          splat = (info as unknown as Record<symbol, unknown>)[Symbol.for('splat')];
          return info;
        },
      };
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), observe, winston.format.json()),
        transports: [sink(lines)],
      });

      logger.info('tok %s', new SensitiveString(CANARY, 'credential'));

      expect(splat).toEqual(['[REDACTED:credential]']);
    });

    it('TST-WF-007: redactSplat false leaves the splat array untouched', () => {
      const lines: string[] = [];
      let splat: unknown[] = [];
      const observe: WinstonFormat = {
        transform(info: WinstonInfo) {
          splat = (info as unknown as Record<symbol, unknown>)[Symbol.for('splat')] as unknown[];
          return info;
        },
      };
      const logger = winston.createLogger({
        format: winston.format.combine(
          sensitiveFormat({ redactSplat: false }),
          observe,
          winston.format.json()
        ),
        transports: [sink(lines)],
      });

      logger.info('tok %s', new SensitiveString(CANARY, 'credential'));

      expect(splat[0]).toBeInstanceOf(SensitiveString);
    });

    it('TST-WF-008: interpolation still works after splat redaction', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(
          sensitiveFormat(),
          winston.format.splat(),
          winston.format.simple()
        ),
        transports: [sink(lines)],
      });

      logger.info('tok %s n=%d', new SensitiveString(CANARY, 'credential'), 7);

      expect(lines.join('')).toBe('info: tok [REDACTED:credential] n=7');
    });

    it('TST-WF-009: non-sensitive fields pass through unchanged', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      logger.info('plain', { n: 1, s: 'text', b: true, nil: null, arr: [1, 2], obj: { a: 'b' } });

      const parsed = record(lines);
      expect(parsed).toMatchObject({
        message: 'plain',
        n: 1,
        s: 'text',
        b: true,
        nil: null,
        arr: [1, 2],
        obj: { a: 'b' },
      });
    });

    it('TST-WF-010: the caller meta object is unchanged after logging', () => {
      const lines: string[] = [];
      const secret = new SensitiveString(CANARY, 'credential');
      const meta = { nested: { token: secret }, list: [secret] };
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      logger.info('x', meta);

      expect(meta.nested.token).toBeInstanceOf(SensitiveString);
      expect(meta.list[0]).toBeInstanceOf(SensitiveString);
      expect(Object.keys(meta.nested)).toEqual(['token']);
    });
  });

  describe('winston integrity', () => {
    it('TST-WF-INT-001: preserves Symbol.for("level") on the transformed record', () => {
      const format = sensitiveFormat();
      const info = { level: 'info', message: 'x' } as WinstonInfo;
      (info as unknown as Record<symbol, unknown>)[Symbol.for('level')] = 'info';

      const out = format.transform(info);

      expect(out).not.toBe(false);
      expect((out as unknown as Record<symbol, unknown>)[Symbol.for('level')]).toBe('info');
      expect(out).toBe(info);
    });

    it('TST-WF-INT-002: level filtering still works at every configured level', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        level: 'warn',
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      logger.error('kept-error');
      logger.warn('kept-warn');
      logger.info('dropped-info');
      logger.debug('dropped-debug');

      expect(lines.map((line) => (JSON.parse(line) as { message: string }).message)).toEqual([
        'kept-error',
        'kept-warn',
      ]);
    });

    it('TST-WF-INT-003: every emitted record arrives at every transport', () => {
      const a: string[] = [];
      const b: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(a), sink(b)],
      });

      for (let i = 0; i < 5; i++) {
        logger.info(`n${i}`, { token: new SensitiveString(CANARY, 'credential') });
      }

      expect(a).toHaveLength(5);
      expect(b).toHaveLength(5);
      expect(a).toEqual(b);
    });

    it('TST-WF-INT-004: does not mutate nested state shared between transport clones', () => {
      // Winston hands each transport `Object.assign({}, info)`, a shallow copy,
      // so every nested object is shared. This models that exactly.
      const secret = new SensitiveString(CANARY, 'credential');
      const shared = { token: secret };
      const info = { level: 'info', message: 'x', nested: shared } as unknown as WinstonInfo;
      const format = sensitiveFormat();

      const a = format.transform(Object.assign({}, info)) as WinstonInfo;
      const b = format.transform(Object.assign({}, info)) as WinstonInfo;

      expect(a['nested']).toEqual({ token: '[REDACTED:credential]' });
      expect(b['nested']).toEqual({ token: '[REDACTED:credential]' });
      expect(a['nested']).not.toBe(shared);
      expect(a['nested']).not.toBe(b['nested']);
      expect(shared.token).toBeInstanceOf(SensitiveString);
    });

    it('TST-WF-INT-005: regression, returning redactInStructure(info) drops all output', () => {
      // Guards the failure this format exists to avoid. redactInStructure
      // rebuilds through Object.entries, which does not copy symbol keys, so
      // Symbol.for('level') is lost and every line is discarded in silence.
      // Object spread would have been safe: it does copy symbols.
      const rebuilt: string[] = [];
      const naive: WinstonFormat = {
        transform(info: WinstonInfo) {
          return redactInStructure(info) as WinstonInfo;
        },
      };
      winston
        .createLogger({
          format: winston.format.combine(naive, winston.format.json()),
          transports: [sink(rebuilt)],
        })
        .info('vanishes');

      expect(rebuilt).toEqual([]);

      const kept: string[] = [];
      winston
        .createLogger({
          format: winston.format.combine(sensitiveFormat(), winston.format.json()),
          transports: [sink(kept)],
        })
        .info('survives');

      expect(kept).toHaveLength(1);
    });
  });

  describe('policy', () => {
    it('TST-WF-POL-001: dropClasses discards a credential-bearing record', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(
          sensitiveFormat({ dropClasses: ['credential'] }),
          winston.format.json()
        ),
        transports: [sink(lines)],
      });

      logger.info('has credential', { token: new SensitiveString(CANARY, 'credential') });

      expect(lines).toEqual([]);
    });

    it('TST-WF-POL-002: records without that class still pass', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(
          sensitiveFormat({ dropClasses: ['credential'] }),
          winston.format.json()
        ),
        transports: [sink(lines)],
      });

      logger.info('clean', { n: 1 });
      logger.info('sensitive only', { email: new SensitiveString(CANARY, 'sensitive') });

      expect(lines).toHaveLength(2);
      expect(lines.join('')).not.toContain(CANARY);
    });

    it('TST-WF-POL-003: a transport-level drop affects only that transport', () => {
      const debug: string[] = [];
      const audit: string[] = [];
      const logger = winston.createLogger({
        // stampClasses is required here: the logger-level format redacts the
        // instances away, so the transport-level check has nothing left to see.
        format: winston.format.combine(
          sensitiveFormat({ stampClasses: true }),
          winston.format.json()
        ),
        transports: [sink(debug, sensitiveFormat({ dropClasses: ['credential'] })), sink(audit)],
      });

      logger.info('credential record', { token: new SensitiveString(CANARY, 'credential') });
      logger.info('clean record', { n: 1 });

      expect(debug).toHaveLength(1);
      expect(audit).toHaveLength(2);
      expect(debug.join('')).toContain('clean record');
    });

    it('TST-WF-POL-004: dropping still works after the output string is built', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.json(),
        transports: [sink(lines, sensitiveFormat({ dropClasses: ['credential'] }))],
      });

      logger.info('dropped', { token: new SensitiveString(CANARY, 'credential') });
      logger.info('kept', { n: 1 });

      expect(lines).toHaveLength(1);
      expect(lines.join('')).toContain('kept');
    });

    it('TST-WF-POL-007: drops a record whose only credential is a splat argument', () => {
      // `logger.info('%s', secret)` puts the value under Symbol.for('splat'),
      // where it never becomes a record field. A scan of the fields alone
      // misses it and the transport receives the record it was told to refuse.
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(
          sensitiveFormat({ dropClasses: ['credential'] }),
          winston.format.splat(),
          winston.format.simple()
        ),
        transports: [sink(lines)],
      });

      logger.info('tok %s', new SensitiveString(CANARY, 'credential'));
      logger.info('clean %s', 'value');

      expect(lines).toHaveLength(1);
      expect(lines.join('')).toContain('clean value');
    });

    it('TST-WF-POL-008: stamps classes found only in the splat array', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(
          sensitiveFormat({ stampClasses: true }),
          winston.format.splat(),
          winston.format.json()
        ),
        transports: [sink(lines, sensitiveFormat({ dropClasses: ['credential'] }))],
      });

      logger.info('tok %s', new SensitiveString(CANARY, 'credential'));

      expect(lines).toEqual([]);
    });

    it('TST-WF-POL-005: a late install warns exactly once', () => {
      const emit = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.json(),
        transports: [sink(lines, sensitiveFormat())],
      });

      logger.info('one', { token: new SensitiveString(CANARY, 'credential') });
      logger.info('two', { token: new SensitiveString(CANARY, 'credential') });
      logger.info('three');

      expect(emit).toHaveBeenCalledTimes(1);
      expect(emit.mock.calls[0]?.[1]).toBe('SensitiveStringWarning');
      expect(String(emit.mock.calls[0]?.[0])).toContain('format.combine()');
    });

    it('TST-WF-POL-006: a front install does not warn', () => {
      const emit = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      logger.info('x', { token: new SensitiveString(CANARY, 'credential') });

      expect(emit).not.toHaveBeenCalled();
      expect(lines).toHaveLength(1);
    });

    it('warnOnLateInstall false suppresses the warning', () => {
      const emit = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.json(),
        transports: [sink(lines, sensitiveFormat({ warnOnLateInstall: false }))],
      });

      logger.info('x');

      expect(emit).not.toHaveBeenCalled();
    });
  });
});
