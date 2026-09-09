import { inspect } from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  createSensitiveSerializer,
  observeRedactions,
  redactCopy,
  redactInStructure,
  registerPolicy,
  resetPolicies,
  safeStringify,
  sensitiveFormat,
} from '../index.js';
import type { RedactionEvent } from '../index.js';

const CANARY = 'LEAKED_SECRET_observer_sec_9c3d';

const stops: (() => void)[] = [];

function collect(): RedactionEvent[] {
  const events: RedactionEvent[] = [];
  stops.push(observeRedactions((event) => events.push(event)));
  return events;
}

/** Every way a rendering can be asked for, by name. */
function renderings(token: SensitiveString<'credential'>): readonly [string, () => unknown][] {
  return [
    ['toString()', () => token.toString()],
    ['toJSON()', () => token.toJSON()],
    ['template literal', () => `${String(token)}`],
    ['JSON.stringify', () => JSON.stringify({ token })],
    ['util.inspect', () => inspect(token)],
    ['redactInStructure', () => redactInStructure({ token })],
    ['redactCopy', () => redactCopy({ token })],
    ['safeStringify', () => safeStringify({ token })],
    ['pino serializer', () => createSensitiveSerializer()({ token })],
    ['winston format', () => sensitiveFormat().transform({ level: 'info', message: 'm', token })],
  ];
}

afterEach(() => {
  for (const stop of stops.splice(0)) {
    stop();
  }

  resetPolicies();
  vi.restoreAllMocks();
});

describe('redaction observer security', () => {
  describe('the event carries no value', () => {
    it('carries exactly klass, label and surface, frozen, on every surface and through every walker', () => {
      const events = collect();
      const token = new SensitiveString(CANARY, 'credential', 'api_key');

      for (const [, render] of renderings(token)) {
        render();
      }

      expect(events).toHaveLength(renderings(token).length);

      for (const event of events) {
        expect(Object.getOwnPropertyNames(event)).toEqual(['klass', 'label', 'surface']);
        expect(Object.getOwnPropertySymbols(event)).toEqual([]);
        expect(Object.getPrototypeOf(event)).toBe(Object.prototype);
        expect(Object.isFrozen(event)).toBe(true);
        expect(JSON.stringify(event)).not.toContain(CANARY);
        expect(inspect(event, { depth: null, showHidden: true })).not.toContain(CANARY);
      }
    });

    it('does not carry the rendering, even under a policy whose marker is derived from the value', () => {
      // Deterministic redaction renders a tag derived from the value, and a
      // tag is a pseudonym: an event carrying it would make a metric dimension
      // a table of every tag in the process. Registration refuses a renderer
      // that echoes its input outright, so this one reverses it, which is a
      // derivation the substring check cannot see and the event must not
      // carry either way.
      const reversed = [...CANARY].reverse().join('');
      registerPolicy(
        {
          name: 'sensitive',
          redact: (value) => `[REDACTED:sensitive:${[...value].reverse().join('')}]`,
        },
        { overwrite: true }
      );
      const events = collect();
      const value = new SensitiveString(CANARY, 'sensitive', 'email');

      expect(value.toString()).toContain(reversed);
      expect(JSON.stringify(events)).not.toContain(reversed);
      expect(events).toEqual([{ klass: 'sensitive', label: 'email', surface: 'toString' }]);
    });

    it('hands the observer one argument and no receiver', () => {
      let arity: number | undefined;
      let bareCall = false;
      stops.push(
        observeRedactions(function (this: unknown, ...args: unknown[]) {
          arity = args.length;
          bareCall = this === undefined;
        })
      );

      new SensitiveString(CANARY, 'credential').toString();

      expect(arity).toBe(1);
      expect(bareCall).toBe(true);
    });
  });

  describe('an observer cannot change what is rendered', () => {
    it('renders the marker on every surface when an observer throws', () => {
      vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
      stops.push(
        observeRedactions(() => {
          throw new Error('broken exporter');
        })
      );
      const token = new SensitiveString(CANARY, 'credential', 'api_key');

      for (const [name, render] of renderings(token)) {
        let output: unknown;

        expect(() => {
          output = render();
        }, name).not.toThrow();

        const text = typeof output === 'string' ? output : JSON.stringify(output);

        expect(text, name).not.toContain(CANARY);
        expect(text, name).toContain('[REDACTED:credential]');
      }
    });

    it('cannot mutate the event another observer receives', () => {
      vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
      stops.push(
        observeRedactions((event) => {
          // Throws in strict mode, since the event is frozen; the throw is
          // swallowed and warned about, and the point is what the next
          // observer sees.
          Object.assign(event, { klass: 'forged', extra: 'forged' });
        })
      );
      const later = collect();

      new SensitiveString(CANARY, 'credential', 'k').toString();

      expect(later).toEqual([{ klass: 'credential', label: 'k', surface: 'toString' }]);
      expect(Object.getOwnPropertyNames(later[0])).toEqual(['klass', 'label', 'surface']);
    });

    it('is not consulted: an observer has no return value that could alter or suppress a rendering', () => {
      stops.push(observeRedactions(() => false));
      stops.push(observeRedactions(() => CANARY));

      const token = new SensitiveString(CANARY, 'credential');

      expect(token.toString()).toBe('[REDACTED:credential]');
      expect(JSON.stringify({ token })).toBe('{"token":"[REDACTED:credential]"}');
    });
  });

  describe('reentrancy', () => {
    it('gives an observer that logs a wrapped value the marker, and no second event', () => {
      const inner = new SensitiveString(CANARY, 'sensitive', 'inner');
      const logged: string[] = [];
      const observer = vi.fn(() => {
        logged.push(safeStringify({ inner }));
      });
      stops.push(observeRedactions(observer));

      JSON.stringify({ token: new SensitiveString(CANARY, 'credential') });

      expect(observer).toHaveBeenCalledTimes(1);
      expect(logged).toEqual(['{"inner":"[REDACTED:sensitive]"}']);
    });

    it('does not let an observer subscribing or unsubscribing during a notification change that notification', () => {
      const late = vi.fn();
      const early = vi.fn();
      const stopEarly = observeRedactions(early);
      stops.push(stopEarly);
      stops.push(
        observeRedactions(() => {
          stops.push(observeRedactions(late));
          stopEarly();
        })
      );
      stops.push(observeRedactions(early));

      new SensitiveString(CANARY, 'credential').toString();

      // The first `early` was unsubscribed mid-notification and still received
      // this event; the second `early` is a separate subscription and got it
      // too. `late` was subscribed mid-notification and did not.
      expect(early).toHaveBeenCalledTimes(2);
      expect(late).not.toHaveBeenCalled();

      new SensitiveString(CANARY, 'credential').toString();

      expect(late).toHaveBeenCalledTimes(1);
    });
  });

  describe('the walkers render through the class, not through an overridable toString', () => {
    it('ignores an own toString on an unfrozen instance', () => {
      const token = new SensitiveString(CANARY, 'credential', 'api_key');
      (token as unknown as { toString: () => string }).toString = () => CANARY;

      // The coercion itself is the instance's own business and is what the
      // freezeInstances switch exists for. The walkers are not: a value they
      // were asked to clean must come out clean.
      expect(String(token)).toBe(CANARY);
      expect(JSON.stringify(redactInStructure({ token }))).not.toContain(CANARY);
      expect(JSON.stringify(redactCopy({ token }))).not.toContain(CANARY);
      expect(safeStringify({ token })).toBe('{"token":"[REDACTED:credential]"}');
    });

    it('ignores a subclass toString', () => {
      class Loud extends SensitiveString<'credential'> {
        override toString(): string {
          return this.reveal();
        }
      }
      const token = new Loud(CANARY, 'credential', 'api_key');

      expect(String(token)).toBe(CANARY);
      expect(safeStringify({ token })).toBe('{"token":"[REDACTED:credential]"}');
      expect(JSON.stringify(redactCopy({ token }))).toBe('{"token":"[REDACTED:credential]"}');
    });

    it('still substitutes the unreadable marker for a Proxy that fails the brand check', () => {
      const events = collect();
      const proxy = new Proxy(new SensitiveString(CANARY, 'credential'), {});

      const output = JSON.stringify(redactInStructure({ proxy }));

      expect(output).not.toContain(CANARY);
      expect(events).toEqual([]);
    });
  });

  describe('process-global under rule R6', () => {
    it('is reachable from globalThis under a Symbol.for key, which protects a dashboard and not a secret', () => {
      const key = Symbol.for('@platform-sec/sensitive-string-core/redaction-observers');
      const state = (globalThis as Record<symbol, unknown>)[key] as { observers: unknown[] };

      expect(Array.isArray(state.observers)).toBe(true);

      // What a hostile caller can do with it: stop the counting. What it
      // cannot do with it: reach a value, since no event ever carried one.
      const events = collect();
      const before = state.observers;
      state.observers = [];
      new SensitiveString(CANARY, 'credential').toString();
      state.observers = before;

      expect(events).toEqual([]);
    });
  });
});
