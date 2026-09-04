import { Writable } from 'node:stream';
import winston from 'winston';
import { afterEach, describe, expect, it } from 'vitest';
import {
  SensitiveString,
  containsSensitive,
  createSensitiveSerializer,
  redactCopy,
  redactInStructure,
  registerPolicy,
  resetPolicies,
  safeLog,
  safeStringify,
  sensitiveClassesIn,
  sensitiveFormat,
} from './index.js';
import { carriesSerializedMarker } from './serialized.js';

const CANARY = 'LEAKED_SECRET_wire_4e2b';

const credential = () => new SensitiveString(CANARY, 'credential', 'token');
const sensitive = () => new SensitiveString(CANARY, 'sensitive', 'email');

/** A transport that keeps every line it is asked to write. */
function sink(lines: string[]): winston.transport {
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      lines.push(String(chunk).trim());
      callback();
    },
  });

  return new winston.transports.Stream({ stream });
}

/**
 * A Proxy that throws for any name it was not given, rather than answering
 * `undefined`. This is the shape envalid's `cleanEnv()` returns, and it is what
 * every walk in this library meets when a caller logs a validated config
 * object.
 */
function strictProxy<T extends object>(target: T): T {
  return new Proxy(target, {
    get(t, name, receiver): unknown {
      if (typeof name === 'string' && !Object.hasOwn(t, name)) {
        throw new ReferenceError(`Env var not found: ${name}`);
      }

      return Reflect.get(t, name, receiver);
    },
  });
}

/**
 * A serialize() result is a plain object holding the raw value, meant for a
 * service boundary. It is the one shape toJSON() cannot catch, so every walk
 * that feeds a log line has to catch it itself.
 */
describe('serialized values on the log path', () => {
  afterEach(() => {
    resetPolicies();
  });

  describe('redactInStructure', () => {
    it('replaces a serialized value at the root', () => {
      expect(redactInStructure(credential().serialize())).toBe('[REDACTED:credential]');
    });

    it('replaces serialized values wherever the walk reaches', () => {
      class Envelope {
        constructor(readonly wire: unknown) {}
      }

      const out = redactInStructure({
        nested: { wire: sensitive().serialize() },
        list: [credential().serialize()],
        map: new Map([['k', credential().serialize()]]),
        set: new Set([credential().serialize()]),
        entity: new Envelope(credential().serialize()),
        viaToJSON: { toJSON: () => ({ wire: credential().serialize() }) },
      }) as {
        nested: { wire: unknown };
        list: unknown[];
        map: Map<string, unknown>;
        set: Set<unknown>;
        entity: { wire: unknown };
        viaToJSON: { wire: unknown };
      };

      expect(out.nested.wire).toBe('[REDACTED:sensitive]');
      expect(out.list[0]).toBe('[REDACTED:credential]');
      expect(out.map.get('k')).toBe('[REDACTED:credential]');
      expect([...out.set][0]).toBe('[REDACTED:credential]');
      expect(out.entity.wire).toBe('[REDACTED:credential]');
      expect(out.viaToJSON.wire).toBe('[REDACTED:credential]');
    });

    it('honours the class policy', () => {
      registerPolicy(
        { name: 'credential', redact: () => '<hidden>', requireConstantTimeEquals: true },
        { overwrite: true }
      );

      expect(redactInStructure({ wire: credential().serialize() })).toEqual({ wire: '<hidden>' });
    });

    it('uses a generic marker for an unregistered class, and replaces a malformed marker', () => {
      expect(
        redactInStructure({
          unknown: { __sensitive: true, klass: 'made-up', value: CANARY },
          bare: { __sensitive: true, value: CANARY },
        })
      ).toEqual({ unknown: '[REDACTED]', bare: '[REDACTED]' });
    });

    it('agrees with redactCopy on the same value', () => {
      const wire = credential().serialize();

      expect(redactInStructure(wire)).toBe(redactCopy(wire));
    });

    it('does not mutate the serialized value it replaces', () => {
      const wire = credential().serialize();

      redactInStructure({ wire });

      expect(wire.value).toBe(CANARY);
    });
  });

  describe('the helpers built on it', () => {
    it('CANARY: safeLog, safeStringify, and the serializer emit the marker, never the value', () => {
      const payload = {
        wire: credential().serialize(),
        deeper: [{ wire: sensitive().serialize() }],
      };

      const logged = JSON.stringify(safeLog(payload));
      const stringified = safeStringify(payload);
      const serialized = JSON.stringify(createSensitiveSerializer()(payload));

      for (const output of [logged, stringified, serialized]) {
        expect(output).not.toContain(CANARY);
        expect(output).toContain('[REDACTED:credential]');
        expect(output).toContain('[REDACTED:sensitive]');
      }
    });
  });

  describe('detection', () => {
    it('containsSensitive reports a serialized value, at the root and nested', () => {
      expect(containsSensitive(credential().serialize())).toBe(true);
      expect(containsSensitive({ list: [{ wire: sensitive().serialize() }] })).toBe(true);
      expect(containsSensitive({ __sensitive: true, klass: 'made-up', value: CANARY })).toBe(true);
    });

    it('containsSensitive requires the marker to be the boolean true', () => {
      expect(containsSensitive({ __sensitive: 'true', value: 'plain' })).toBe(false);
    });

    it('sensitiveClassesIn counts the class a serialized value names', () => {
      const classes = sensitiveClassesIn({
        wire: credential().serialize(),
        list: [sensitive().serialize()],
      });

      expect([...classes].sort()).toEqual(['credential', 'sensitive']);
    });

    it('sensitiveClassesIn contributes nothing for an unregistered class', () => {
      const value = { wire: { __sensitive: true, klass: 'made-up', value: CANARY } };

      expect(sensitiveClassesIn(value).size).toBe(0);
      expect(containsSensitive(value)).toBe(true);
    });
  });

  /**
   * The marker probe reads a property that is absent from almost every object
   * it meets, and an object is allowed to throw on that read. Before the guard
   * in carriesSerializedMarker, each helper below died with the proxy's own
   * ReferenceError instead of redacting anything.
   */
  describe('objects that throw on an unknown property read', () => {
    it('CANARY: every walk redacts through a strict proxy instead of throwing', () => {
      const config = strictProxy({ token: credential(), host: 'db.internal' });

      expect(redactInStructure(config)).toEqual({
        token: '[REDACTED:credential]',
        host: 'db.internal',
      });
      expect(redactCopy(config)).toEqual({
        token: '[REDACTED:credential]',
        host: 'db.internal',
      });
      expect(containsSensitive(config)).toBe(true);
      expect([...sensitiveClassesIn(config)]).toEqual(['credential']);
      expect(safeStringify(config)).not.toContain(CANARY);
      expect(JSON.stringify(safeLog(config))).not.toContain(CANARY);
    });

    it('CANARY: reaches one nested inside an ordinary object, which is how it is logged', () => {
      const payload = { config: strictProxy({ token: credential() }), requestId: 'r-1' };

      const logged = JSON.stringify(safeLog(payload));

      expect(logged).not.toContain(CANARY);
      expect(logged).toContain('[REDACTED:credential]');
      expect(containsSensitive(payload)).toBe(true);
    });

    it('CANARY: still replaces a serialized value the proxy does answer for', () => {
      const wire = strictProxy(credential().serialize());

      expect(carriesSerializedMarker(wire)).toBe(true);
      expect(redactInStructure({ wire })).toEqual({ wire: '[REDACTED:credential]' });
      expect(JSON.stringify(redactInStructure({ wire }))).not.toContain(CANARY);
    });

    it('reports no marker for an object that refuses the probe', () => {
      expect(carriesSerializedMarker(strictProxy({ klass: 'credential' }))).toBe(false);
    });
  });

  describe('the winston format', () => {
    it('CANARY: redacts a serialized value in meta', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(sensitiveFormat(), winston.format.json()),
        transports: [sink(lines)],
      });

      logger.info('handoff', { wire: credential().serialize() });

      expect(lines).toHaveLength(1);
      expect(lines[0]).not.toContain(CANARY);
      expect((JSON.parse(lines[0] as string) as { wire: unknown }).wire).toBe(
        '[REDACTED:credential]'
      );
    });

    it('dropClasses refuses a record carrying a serialized credential', () => {
      const lines: string[] = [];
      const logger = winston.createLogger({
        format: winston.format.combine(
          sensitiveFormat({ dropClasses: ['credential'] }),
          winston.format.json()
        ),
        transports: [sink(lines)],
      });

      logger.info('handoff', { wire: credential().serialize() });
      logger.info('kept', { wire: sensitive().serialize() });

      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain('kept');
      expect(lines[0]).not.toContain(CANARY);
    });
  });
});
