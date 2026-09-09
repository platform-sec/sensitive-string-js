import { Readable } from 'node:stream';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, expect, it } from 'vitest';
import { resolveScrubPolicy } from './policy.js';
import { scrubPayload } from './walk.js';
import type { ScrubPolicy } from './types.js';

const CANARY = 'LEAKED_SECRET_walk_7b2e';

const scrub = (payload: unknown, policy: ScrubPolicy = {}) =>
  scrubPayload(payload, resolveScrubPolicy(policy), 'event');

/** Stands in for an ORM entity: a class instance a serializer downstream still checks. */
class UserEntity {
  constructor(
    readonly id: string,
    readonly apiKey: SensitiveString<'credential'>
  ) {}
}

describe('stage 1: structural redaction', () => {
  it('replaces a SensitiveString with its marker', () => {
    const { payload } = scrub({ extra: { s: new SensitiveString(CANARY, 'credential') } });

    expect(payload).toEqual({ extra: { s: '[REDACTED:credential]' } });
  });

  // TEST-SCRUB-WALK-SERIALIZED
  it('replaces a serialize() result, which is the one shape toJSON cannot save', () => {
    const wire = new SensitiveString(CANARY, 'credential', 'tok').serialize();
    const { payload } = scrub({ request: { data: { token: wire } } });

    expect(JSON.stringify(payload)).not.toContain(CANARY);
    expect(payload).toEqual({ request: { data: { token: '[REDACTED:credential]' } } });
  });

  it('replaces a serialize() result naming an unregistered class', () => {
    const { payload } = scrub({ x: { __sensitive: true, klass: 'nope', value: CANARY } });

    expect(JSON.stringify(payload)).not.toContain(CANARY);
  });

  // TEST-SCRUB-WALK-SHARED
  it('keeps an object referenced twice as one shared reference', () => {
    // This is the reason stage 1 is redactCopy and not redactInStructure. A
    // vendor event legitimately holds the same object at two paths, and
    // redactInStructure replaces the second visit with '[Circular]'.
    const shared = { requestId: 'abc' };
    const { payload } = scrub({ a: shared, b: shared });

    const result = payload as { a: object; b: object };

    expect(result.a).toBe(result.b);
    expect(result.a).not.toBe(shared);
    expect(result.a).toEqual({ requestId: 'abc' });
  });

  it('keeps prototypes, so a downstream serializer still sees the class', () => {
    const entity = new UserEntity('u1', new SensitiveString(CANARY, 'credential'));
    const { payload } = scrub({ contexts: { user: entity } });

    const copied = (payload as { contexts: { user: UserEntity } }).contexts.user;

    expect(copied).toBeInstanceOf(UserEntity);
    expect(copied.apiKey).toBe('[REDACTED:credential]');
  });

  it('does not modify the payload it was given', () => {
    const secret = new SensitiveString(CANARY, 'credential');
    const original = { extra: { s: secret, authorization: `Bearer ${CANARY}` } };

    scrub(original);

    expect(original.extra.s).toBe(secret);
    expect(original.extra.authorization).toBe(`Bearer ${CANARY}`);
  });

  it('survives a cycle', () => {
    const node: Record<string, unknown> = { name: 'root', token: CANARY };
    node['self'] = node;

    const { payload } = scrub(node);
    const result = payload as Record<string, unknown>;

    expect(result['self']).toBe(result);
    expect(result['token']).toBe('[SCRUBBED]');
  });

  it('passes a stream through rather than copying its internals', () => {
    const stream = Readable.from(['x']);
    const { payload } = scrub({ body: stream });

    expect((payload as { body: unknown }).body).toBe(stream);
  });
});

describe('stage 2: the denylist', () => {
  it('censors a denied key at any depth', () => {
    const { payload } = scrub({
      request: { headers: { authorization: `Bearer ${CANARY}`, 'x-trace': 'ok' } },
    });

    expect(payload).toEqual({
      request: { headers: { authorization: '[SCRUBBED]', 'x-trace': 'ok' } },
    });
  });

  // TEST-SCRUB-WALK-NONSTRING
  it('censors a denied key regardless of the value type', () => {
    const { payload } = scrub({
      token: { nested: 'object' },
      password: 42,
      secret: ['a', 'b'],
      api_key: null,
    });

    expect(payload).toEqual({
      token: '[SCRUBBED]',
      password: '[SCRUBBED]',
      secret: '[SCRUBBED]',
      api_key: '[SCRUBBED]',
    });
  });

  it('replaces rather than deletes', () => {
    // An absent key and a censored key mean different things to somebody
    // debugging why a header was not sent at all.
    const { payload } = scrub({ headers: { cookie: CANARY } });

    expect('cookie' in (payload as { headers: object }).headers).toBe(true);
  });

  it('censors inside an array element', () => {
    const { payload } = scrub({ breadcrumbs: [{ data: { token: CANARY } }] });

    expect(JSON.stringify(payload)).not.toContain(CANARY);
  });

  it('honours a caller censor string', () => {
    const { payload } = scrub({ token: CANARY }, { censor: '***' });

    expect(payload).toEqual({ token: '***' });
  });

  it('scrubs query parameters at a configured URL position and keeps the route', () => {
    const { payload } = scrub(
      { request: { url: `https://api.test/pay/42?token=${CANARY}&page=2` } },
      { urlKeys: ['request.url'] }
    );

    const url = (payload as { request: { url: string } }).request.url;

    expect(url).not.toContain(CANARY);
    expect(url).toContain('/pay/42');
    expect(url).toContain('page=2');
  });

  it('leaves a URL position alone when the string parses as neither shape', () => {
    const { payload } = scrub({ request: { url: 'about:blank' } }, { urlKeys: ['request.url'] });

    expect((payload as { request: { url: string } }).request.url).toBe('about:blank');
  });

  it('reaches a stack frame vars object by key name, at any depth', () => {
    // Sentry's includeLocalVariables puts locals under
    // exception.values[].stacktrace.frames[].vars. No special code path: the
    // matcher is depth-independent, and 3.4's `opts.rawToken` case is a
    // nested object like any other.
    const { payload } = scrub({
      exception: {
        values: [{ stacktrace: { frames: [{ vars: { opts: { password: CANARY } } }] } }],
      },
    });

    expect(JSON.stringify(payload)).not.toContain(CANARY);
  });
});

describe('the report', () => {
  it('counts instances and collects their classes', () => {
    const { report } = scrub({
      a: new SensitiveString(CANARY, 'credential'),
      b: new SensitiveString(CANARY, 'sensitive'),
    });

    expect(report.instances).toBe(2);
    expect([...report.classes].sort()).toEqual(['credential', 'sensitive']);
    expect(report.kind).toBe('event');
    expect(report.failed).toBe(false);
  });

  it('counts a serialize() result as an instance and names its class', () => {
    const { report } = scrub({ t: new SensitiveString(CANARY, 'credential', 'tok').serialize() });

    expect(report.instances).toBe(1);
    expect([...report.classes]).toEqual(['credential']);
  });

  it('counts a value shared at two paths once', () => {
    const secret = new SensitiveString(CANARY, 'credential');
    const { report } = scrub({ a: secret, b: secret });

    expect(report.instances).toBe(1);
  });

  // TEST-SCRUB-WALK-NOVALUES
  it('carries no value, masked or otherwise', () => {
    const { report } = scrub(
      { authorization: `Bearer ${CANARY}`, s: new SensitiveString(CANARY, 'credential', 'tok') },
      { reportLabels: true }
    );

    const everything = [
      ...report.classes,
      ...(report.labels ?? []),
      ...report.deniedKeys,
      String(report.instances),
      String(report.markersSeen),
    ];

    expect(JSON.stringify(everything)).not.toContain(CANARY);
    expect(report.deniedKeys).toEqual(['authorization']);
  });

  it('omits labels unless asked, and includes them when asked', () => {
    const payload = { s: new SensitiveString(CANARY, 'credential', 'stripe_key') };

    expect(scrub(payload).report.labels).toBeUndefined();
    expect(scrub(payload, { reportLabels: true }).report.labels).toEqual(['stripe_key']);
  });

  it('reports the label of a serialize() result when asked', () => {
    const wire = new SensitiveString(CANARY, 'credential', 'wire_label').serialize();

    expect(scrub({ t: wire }, { reportLabels: true }).report.labels).toEqual(['wire_label']);
  });

  it('deduplicates denied key names in encounter order', () => {
    const { report } = scrub({
      headers: { authorization: 'a', cookie: 'b' },
      other: { authorization: 'c' },
    });

    expect(report.deniedKeys).toEqual(['authorization', 'cookie']);
  });

  it('reports the class of a wrapped value sitting under a denied key', () => {
    // An operator wants to know a credential was in scope whether or not a
    // key name is what caught it. Stage 1 already replaced this one, so the
    // denylist has nothing left to do and does not claim the key.
    const { payload, report } = scrub({ token: new SensitiveString(CANARY, 'credential') });

    expect(payload).toEqual({ token: '[REDACTED:credential]' });
    expect(report.instances).toBe(1);
    expect([...report.classes]).toEqual(['credential']);
    expect(report.deniedKeys).toEqual([]);
  });

  it('reports the class of a raw value the denylist caught', () => {
    const { report } = scrub({ token: CANARY });

    expect(report.instances).toBe(0);
    expect(report.deniedKeys).toEqual(['token']);
  });
});

describe('the marker rule', () => {
  // TEST-SCRUB-WALK-MARKER
  it('counts a marker that arrived in captured data, not the ones stage 1 wrote', () => {
    const { report } = scrub({
      captured: { responseBody: 'auth failed for [REDACTED:credential]' },
      wrapped: new SensitiveString(CANARY, 'credential'),
    });

    expect(report.markersSeen).toBe(1);
    expect([...report.markerClasses]).toEqual(['credential']);
    expect(report.instances).toBe(1);
  });

  it('counts every sighting in one string', () => {
    const { report } = scrub({ body: '[REDACTED:credential] and [REDACTED]' });

    expect(report.markersSeen).toBe(2);
    expect([...report.markerClasses]).toEqual(['credential']);
  });

  it('does not throw on a sighting', () => {
    // 3.7 says an integration that transmits throws on a marker. An error
    // tracker is a sink, and throwing would suppress the report of the very
    // incident the marker is evidence of.
    expect(() => scrub({ body: '[REDACTED:credential]' })).not.toThrow();
  });

  it('reports nothing when onMarker is ignore', () => {
    const { report } = scrub({ body: '[REDACTED:credential]' }, { onMarker: 'ignore' });

    expect(report.markersSeen).toBe(0);
    expect(report.markerClasses.size).toBe(0);
  });

  it('leaves the marker in place, since it is the desired output', () => {
    const { payload } = scrub({ body: 'saw [REDACTED:credential] here' });

    expect(payload).toEqual({ body: 'saw [REDACTED:credential] here' });
  });
});

describe('objects that refuse a property read', () => {
  // envalid's cleanEnv() result is the case this was found on: a Proxy that
  // throws for any name that was not declared.
  const hostile = new Proxy(
    { declared: 'ok' },
    {
      get(target, name) {
        if (name in target) {
          return (target as Record<string | symbol, unknown>)[name];
        }
        throw new ReferenceError(`${String(name)} was not declared`);
      },
    }
  );

  it('walks the object rather than failing the scrub', () => {
    const { payload } = scrub({ env: hostile });

    expect(payload).toEqual({ env: { declared: 'ok' } });
  });

  it('still censors a denied key on it', () => {
    const guarded = new Proxy(
      { token: CANARY },
      {
        get(target, name) {
          if (name in target) {
            return (target as Record<string | symbol, unknown>)[name];
          }
          throw new ReferenceError('nope');
        },
      }
    );

    expect(JSON.stringify(scrub({ env: guarded }).payload)).not.toContain(CANARY);
  });
});

describe('onMatch: observe', () => {
  const observe = (payload: unknown, policy: ScrubPolicy = {}) =>
    scrub(payload, { ...policy, onMatch: 'observe' });

  it('leaves a denied key in place and still reports it', () => {
    const { payload, report } = observe({
      request: { headers: { authorization: `Bearer ${CANARY}` } },
    });

    expect(payload).toEqual({ request: { headers: { authorization: `Bearer ${CANARY}` } } });
    expect(report.deniedKeys).toEqual(['authorization']);
  });

  it('leaves a denied path in place and still reports it', () => {
    const { payload, report } = observe({ request: { cookies: { session: CANARY } } });

    expect(payload).toEqual({ request: { cookies: { session: CANARY } } });
    expect(report.deniedKeys).toEqual(['cookies']);
  });

  it("leaves a URL's denied parameters in place and still reports their names", () => {
    const url = `http://127.0.0.1/pay?token=${CANARY}&page=2`;
    const { payload, report } = observe({ request: { url } }, { urlKeys: ['request.url'] });

    expect(payload).toEqual({ request: { url } });
    expect(report.deniedKeys).toEqual(['token']);
  });

  it('leaves a value-shape match in place and still reports the shape', () => {
    const { payload, report } = observe(
      { extra: { note: CANARY } },
      { denyValues: [/^LEAKED_SECRET_\w+$/] }
    );

    expect(payload).toEqual({ extra: { note: CANARY } });
    expect(report.deniedValues).toHaveLength(1);
  });

  it('still replaces a SensitiveString and a serialize() result, which stage 2 does not govern', () => {
    const wire = new SensitiveString(CANARY, 'credential', 'tok').serialize();
    const { payload, report } = observe({
      extra: { s: new SensitiveString(CANARY, 'credential'), wire },
    });

    expect(JSON.stringify(payload)).not.toContain(CANARY);
    expect(payload).toEqual({
      extra: { s: '[REDACTED:credential]', wire: '[REDACTED:credential]' },
    });
    expect(report.instances).toBe(2);
  });

  it('produces the same report censor mode does for the same payload', () => {
    const build = () => ({
      request: {
        headers: { authorization: `Bearer ${CANARY}`, cookie: `s=${CANARY}` },
        url: `http://127.0.0.1/p?token=${CANARY}`,
        data: { s: new SensitiveString(CANARY, 'credential', 'k'), note: '[REDACTED:credential]' },
      },
    });
    const policy: ScrubPolicy = { urlKeys: ['request.url'], reportLabels: true };

    const censored = scrub(build(), policy).report;
    const observed = scrub(build(), { ...policy, onMatch: 'observe' }).report;

    expect(observed).toEqual(censored);
    expect(censored.deniedKeys).toEqual(['authorization', 'cookie', 'token']);
  });

  it('still hands back a copy rather than the payload it was given', () => {
    const input = { request: { headers: { authorization: CANARY } } };
    const { payload } = observe(input);

    expect(payload).not.toBe(input);
    expect(payload).toEqual(input);
  });

  it('fails closed on a misspelt mode', () => {
    const { payload } = scrub(
      { headers: { authorization: CANARY } },
      { onMatch: 'observ' as 'observe' }
    );

    expect(JSON.stringify(payload)).not.toContain(CANARY);
  });
});
