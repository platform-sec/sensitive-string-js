import { inspect } from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  containsSensitive,
  createSensitiveSerializer,
  observeRedactions,
  redactCopy,
  redactInStructure,
  registerPolicy,
  resetPolicies,
  resetSealing,
  safeLog,
  safeStringify,
  sensitiveClassesIn,
  sensitiveFormat,
} from './index.js';
import type { RedactionEvent } from './index.js';
import { redactionObservers } from './redaction-observer.js';

const CANARY = 'LEAKED_SECRET_observer_4f1a';

const stops: (() => void)[] = [];

/** Subscribe for the rest of the test, collecting what arrives. */
function collect(): RedactionEvent[] {
  const events: RedactionEvent[] = [];
  stops.push(observeRedactions((event) => events.push(event)));
  return events;
}

/** Subscribe a spy for the rest of the test. */
function spy(): ReturnType<typeof vi.fn<(event: RedactionEvent) => void>> {
  const observer = vi.fn<(event: RedactionEvent) => void>();
  stops.push(observeRedactions(observer));
  return observer;
}

afterEach(() => {
  for (const stop of stops.splice(0)) {
    stop();
  }

  resetPolicies();
  resetSealing();
  vi.restoreAllMocks();
});

describe('observeRedactions', () => {
  describe('surfaces', () => {
    it('reports toString(), toJSON() and the inspect hook each under its own surface', () => {
      const events = collect();
      const token = new SensitiveString(CANARY, 'credential', 'api_key');

      token.toString();
      token.toJSON();
      inspect(token);

      expect(events).toEqual([
        { klass: 'credential', label: 'api_key', surface: 'toString' },
        { klass: 'credential', label: 'api_key', surface: 'toJSON' },
        { klass: 'credential', label: 'api_key', surface: 'inspect' },
      ]);
    });

    it('reports a template literal, concatenation and String() as toString', () => {
      const events = collect();
      const token = new SensitiveString(CANARY, 'credential', 'api_key');

      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the coercion is the subject
      void `Bearer ${token}`;
      // eslint-disable-next-line @typescript-eslint/restrict-plus-operands -- the coercion is the subject
      void ('Bearer ' + token);
      void String(token);

      expect(events.map((event) => event.surface)).toEqual(['toString', 'toString', 'toString']);
    });

    it('reports JSON.stringify as toJSON, once per rendering', () => {
      const events = collect();
      const token = new SensitiveString(CANARY, 'credential', 'api_key');

      JSON.stringify({ a: token, b: [token] });

      expect(events.map((event) => event.surface)).toEqual(['toJSON', 'toJSON']);
    });

    it('reports a value nested in an inspected structure as inspect', () => {
      const events = collect();
      const token = new SensitiveString(CANARY, 'credential', 'api_key');

      inspect({ nested: { token } });

      expect(events.map((event) => event.surface)).toEqual(['inspect']);
    });

    it('reports every walker under structure', () => {
      const events = collect();
      const token = new SensitiveString(CANARY, 'credential', 'api_key');

      redactInStructure({ token });
      redactCopy({ token });
      safeStringify({ token });
      safeLog({ token });
      createSensitiveSerializer()({ token });
      sensitiveFormat().transform({ level: 'info', message: 'm', token });

      expect(events).toHaveLength(6);
      expect(new Set(events.map((event) => event.surface))).toEqual(new Set(['structure']));
    });

    it('reports a walker once per value, with no second event from the JSON it builds after', () => {
      const events = collect();
      const token = new SensitiveString(CANARY, 'credential', 'api_key');

      safeStringify({ token, again: token });

      expect(events.map((event) => event.surface)).toEqual(['structure', 'structure']);
    });

    it('reports a serialize() result a walker replaced, under structure and with no label', () => {
      const wire = new SensitiveString(CANARY, 'credential', 'tok').serialize();
      const events = collect();

      redactInStructure({ wire });
      redactCopy({ wire });

      expect(events).toEqual([
        { klass: 'credential', label: undefined, surface: 'structure' },
        { klass: 'credential', label: undefined, surface: 'structure' },
      ]);
    });

    it('does not report a wire shape naming no registered class', () => {
      const events = collect();

      redactInStructure({ x: { __sensitive: true, klass: 'nope', value: CANARY } });
      redactCopy({ x: { __sensitive: true, klass: 'nope', value: CANARY } });

      expect(events).toEqual([]);
    });

    it('does not report containsSensitive() or sensitiveClassesIn(), which render nothing', () => {
      const events = collect();
      const token = new SensitiveString(CANARY, 'credential', 'api_key');

      expect(containsSensitive({ token })).toBe(true);
      expect(sensitiveClassesIn({ token })).toEqual(new Set(['credential']));
      expect(events).toEqual([]);
    });
  });

  describe('what the event carries', () => {
    it('carries the class and the label, and undefined for a value with no label', () => {
      const events = collect();

      new SensitiveString(CANARY, 'sensitive').toString();
      new SensitiveString(CANARY, 'credential', 'db_password').toString();

      expect(events).toEqual([
        { klass: 'sensitive', label: undefined, surface: 'toString' },
        { klass: 'credential', label: 'db_password', surface: 'toString' },
      ]);
    });

    it('reports a cleared value from its snapshot', () => {
      const token = new SensitiveString(CANARY, 'credential', 'api_key');
      token.clear();
      const events = collect();

      expect(token.toString()).toBe('[REDACTED:credential]');
      expect(events).toEqual([{ klass: 'credential', label: 'api_key', surface: 'toString' }]);
    });

    it('reports a sealed value from its snapshot, without a decrypt', () => {
      const token = new SensitiveString(CANARY, 'credential', 'api_key', { sealed: true });
      const events = collect();

      // A sealed value has no live string, and a safe read that reached it
      // would throw. Rendering succeeding is the proof that it rendered from
      // the snapshot instead.
      expect(token.toString()).toBe('[REDACTED:credential]');
      expect(JSON.stringify({ token })).toBe('{"token":"[REDACTED:credential]"}');
      expect(events.map((event) => event.surface)).toEqual(['toString', 'toJSON']);
    });

    it('does not report the snapshot clear() takes, nor the one a sealed construction takes', () => {
      const events = collect();

      new SensitiveString(CANARY, 'credential', 'api_key', { sealed: true });
      new SensitiveString(CANARY, 'credential', 'api_key').clear();

      expect(events).toEqual([]);
    });

    it("reports nothing when the policy's redact throws, because nothing was rendered", () => {
      // Registration probes the renderer with its own canary and refuses one
      // that throws, so this one is healthy at registration and breaks on the
      // value the test then renders.
      registerPolicy(
        {
          name: 'sensitive',
          redact: (value) => {
            if (value === CANARY) {
              throw new Error('broken renderer');
            }

            return '[REDACTED:sensitive]';
          },
        },
        { overwrite: true }
      );
      const events = collect();
      const value = new SensitiveString(CANARY, 'sensitive', 'email');

      expect(() => value.toString()).toThrow('broken renderer');
      expect(events).toEqual([]);
    });
  });

  describe('subscription', () => {
    it('notifies every observer in subscription order, with the same event object', () => {
      const seen: [string, RedactionEvent][] = [];
      stops.push(observeRedactions((event) => seen.push(['first', event])));
      stops.push(observeRedactions((event) => seen.push(['second', event])));

      new SensitiveString(CANARY, 'credential').toString();

      expect(seen.map(([name]) => name)).toEqual(['first', 'second']);
      expect(seen[0]?.[1]).toBe(seen[1]?.[1]);
    });

    it('stops after unsubscribe, and a second unsubscribe is harmless', () => {
      const observer = vi.fn();
      const stop = observeRedactions(observer);
      const token = new SensitiveString(CANARY, 'credential');

      token.toString();
      stop();
      token.toString();
      stop();
      token.toString();

      expect(observer).toHaveBeenCalledTimes(1);
    });

    it('counts a function subscribed twice twice, and each unsubscribe removes one', () => {
      const observer = vi.fn();
      const stopFirst = observeRedactions(observer);
      const stopSecond = observeRedactions(observer);
      const token = new SensitiveString(CANARY, 'credential');

      token.toString();
      expect(observer).toHaveBeenCalledTimes(2);

      stopFirst();
      token.toString();
      expect(observer).toHaveBeenCalledTimes(3);

      stopSecond();
      token.toString();
      expect(observer).toHaveBeenCalledTimes(3);
    });

    it('refuses a non-function', () => {
      expect(() => observeRedactions(undefined as unknown as () => void)).toThrow(TypeError);
      expect(() => observeRedactions({} as unknown as () => void)).toThrow(TypeError);
    });

    it('does not report the redactions an observer performs itself', () => {
      const other = new SensitiveString(CANARY, 'sensitive', 'inner');
      const rendered: string[] = [];
      const observer = vi.fn(() => {
        rendered.push(String(other));
      });
      stops.push(observeRedactions(observer));

      new SensitiveString(CANARY, 'credential').toString();

      expect(observer).toHaveBeenCalledTimes(1);
      expect(rendered).toEqual(['[REDACTED:sensitive]']);
    });

    it('keeps rendering when an observer throws, and warns once per observer', () => {
      const emit = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
      const broken = vi.fn(() => {
        throw new Error('exporter down');
      });
      stops.push(observeRedactions(broken));
      const token = new SensitiveString(CANARY, 'credential');

      expect(token.toString()).toBe('[REDACTED:credential]');
      expect(token.toString()).toBe('[REDACTED:credential]');

      expect(broken).toHaveBeenCalledTimes(2);
      expect(emit).toHaveBeenCalledTimes(1);
      expect(emit.mock.calls[0]?.[1]).toBe('SensitiveStringWarning');
      expect(String(emit.mock.calls[0]?.[0])).toContain('exporter down');

      const alsoBroken = vi.fn(() => {
        throw new Error('second exporter down');
      });
      stops.push(observeRedactions(alsoBroken));
      token.toString();

      expect(emit).toHaveBeenCalledTimes(2);
      expect(String(emit.mock.calls[1]?.[0])).toContain('second exporter down');
    });

    it('gives a later observer the event even after an earlier one threw', () => {
      vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
      stops.push(
        observeRedactions(() => {
          throw new Error('first');
        })
      );
      const later = spy();

      new SensitiveString(CANARY, 'credential', 'k').toString();

      expect(later).toHaveBeenCalledWith({ klass: 'credential', label: 'k', surface: 'toString' });
    });

    it('shares one registry across installed copies of core, keyed on Symbol.for', () => {
      const key = Symbol.for('@platform-sec/sensitive-string-core/redaction-observers');
      const shared = (globalThis as Record<symbol, unknown>)[key];

      expect(shared).toBe(redactionObservers);

      const before = redactionObservers.observers.length;
      const stop = observeRedactions(() => undefined);

      expect(redactionObservers.observers).toHaveLength(before + 1);
      stop();
      expect(redactionObservers.observers).toHaveLength(before);
    });
  });
});
