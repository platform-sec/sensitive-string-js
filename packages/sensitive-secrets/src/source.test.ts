import { describe, it, expect, vi } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

import { SecretNotFoundError, SecretPayloadError } from './errors.js';
import { normalizeRef } from './source.js';
import type { SecretLoadEvent } from './types.js';
import { FakeSecretSource } from './__tests__/fake-source.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function jsonSecret(value: Record<string, unknown>) {
  return { payload: { kind: 'string' as const, value: JSON.stringify(value) } };
}

describe('normalizeRef', () => {
  it('treats a bare string as a path with no version', () => {
    expect(normalizeRef('prod/db')).toEqual({ path: 'prod/db' });
  });

  it('passes a ref through', () => {
    expect(normalizeRef({ path: 'prod/db', version: '7' })).toEqual({
      path: 'prod/db',
      version: '7',
    });
  });

  it('rejects an empty path', () => {
    expect(() => normalizeRef('')).toThrow(/non-empty path/);
  });
});

describe('get', () => {
  it('wraps the value as a credential by default', async () => {
    const source = FakeSecretSource.of({
      'prod/token': { payload: { kind: 'string', value: CANARY } },
    });

    const record = await source.get('prod/token');

    expect(record.value).toBeInstanceOf(SensitiveString);
    expect(record.value.klass).toBe('credential');
    expect(record.value.label).toBe('prod/token');
    expect(String(record.value)).not.toContain(CANARY);
    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('takes an explicit class at the call site', async () => {
    const source = FakeSecretSource.of({
      'prod/email': { payload: { kind: 'string', value: 'a@b.test' } },
    });

    const record = await source.get('prod/email', { klass: 'sensitive' });

    expect(record.value.klass).toBe('sensitive');
  });

  it('takes a label override', async () => {
    const source = FakeSecretSource.of({ a: { payload: { kind: 'string', value: 'v' } } });

    const record = await source.get('a', { label: 'custom' });

    expect(record.value.label).toBe('custom');
  });

  it('reports the version the provider served, not the alias requested', async () => {
    const source = FakeSecretSource.of({
      'prod/db': { payload: { kind: 'string', value: 'v' }, version: '7' },
    });

    const record = await source.get({ path: 'prod/db', version: 'latest' });

    expect(record.ref.version).toBe('7');
  });

  it('carries provider metadata that never reaches the label', async () => {
    const source = FakeSecretSource.of({
      'prod/db': {
        payload: { kind: 'string', value: 'v' },
        metadata: { arn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf' },
      },
    });

    const record = await source.get('prod/db');

    expect(record.ref.metadata['arn']).toContain('123456789012');
    expect(record.value.label).toBe('prod/db');
  });

  it('throws for an absent secret', async () => {
    const source = FakeSecretSource.of({});

    await expect(source.get('nope')).rejects.toBeInstanceOf(SecretNotFoundError);
  });

  it('refuses a map payload and names the surface that reads one', async () => {
    const source = FakeSecretSource.of({
      'kv/db': { payload: { kind: 'map', value: { password: 'p' } } },
    });

    await expect(source.get('kv/db')).rejects.toThrow(/Use getJson\(\) or getAll\(\)/);
  });

  it('binds a provider deadline to the instance', async () => {
    const source = FakeSecretSource.of({
      lease: { payload: { kind: 'string', value: 'v' }, lifetime: { ttl: 30_000 } },
    });

    const record = await source.get('lease');

    expect(record.value.ttlRemaining()).toBeGreaterThan(0);
    expect(record.value.ttlRemaining()).toBeLessThanOrEqual(30_000);
  });

  it('uses the caller ttl only where the provider supplied none', async () => {
    const source = FakeSecretSource.of({
      none: { payload: { kind: 'string', value: 'v' } },
      lease: { payload: { kind: 'string', value: 'v' }, lifetime: { ttl: 30_000 } },
    });

    const fallback = await source.get('none', { ttl: 1_000 });
    const provider = await source.get('lease', { ttl: 999_000 });

    expect(fallback.value.ttlRemaining()).toBeLessThanOrEqual(1_000);
    expect(provider.value.ttlRemaining()).toBeLessThanOrEqual(30_000);
  });
});

describe('getOptional', () => {
  it('returns null for an absent secret', async () => {
    const source = FakeSecretSource.of({});

    await expect(source.getOptional('nope')).resolves.toBeNull();
  });

  it('returns null for an absent version', async () => {
    const source = FakeSecretSource.of({});

    await expect(source.getOptional({ path: 'nope', version: '3' })).resolves.toBeNull();
  });

  it('throws for an authorization failure rather than reporting absence', async () => {
    const denied = new Error('permission denied');
    const source = FakeSecretSource.of({ 'prod/db': denied });

    await expect(source.getOptional('prod/db')).rejects.toBe(denied);
  });

  it('throws for a decode failure rather than reporting absence', async () => {
    const source = FakeSecretSource.of({ 'prod/db': { payload: { kind: 'string', value: 'v' } } });

    await expect(
      source.getOptional({ path: 'prod/db' }).then(() => source.getJson('prod/db', { fields: {} }))
    ).rejects.toBeInstanceOf(SecretPayloadError);
  });
});

describe('getJson', () => {
  const payload = {
    username: 'app',
    password: CANARY,
    host: 'db.internal',
    port: 5432,
  };

  it('wraps declared fields by their declared class', async () => {
    const source = FakeSecretSource.of({ 'prod/db': jsonSecret(payload) });

    const record = await source.getJson('prod/db', {
      fields: { username: 'sensitive', password: 'credential', host: 'plain', port: 'plain' },
    });

    expect(record.fields.username.klass).toBe('sensitive');
    expect(record.fields.password.klass).toBe('credential');
    expect(record.fields.host).toBe('db.internal');
    expect(record.fields.port).toBe(5432);
  });

  it('labels a field with the path and the field name', async () => {
    const source = FakeSecretSource.of({ 'prod/db': jsonSecret(payload) });

    const record = await source.getJson('prod/db', { fields: { password: 'credential' } });

    expect(record.fields.password.label).toBe('prod/db#password');
  });

  it('wraps an undeclared field under the default fallback', async () => {
    const source = FakeSecretSource.of({ 'prod/db': jsonSecret(payload) });

    const record = await source.getJson('prod/db', { fields: { username: 'sensitive' } });

    expect(record.extra.fields.get('password')?.klass).toBe('credential');
    expect(record.extra.fields.get('host')?.klass).toBe('credential');
  });

  it('takes rules for undeclared keys', async () => {
    const source = FakeSecretSource.of({ 'prod/db': jsonSecret(payload) });

    const record = await source.getJson('prod/db', {
      fields: { password: 'credential' },
      rules: [{ pattern: /^host$/, klass: 'plain' }],
      fallback: 'sensitive',
    });

    expect(record.extra.plain.get('host')).toBe('db.internal');
    expect(record.extra.fields.get('username')?.klass).toBe('sensitive');
  });

  it('lists every key the payload carried', async () => {
    const source = FakeSecretSource.of({ 'prod/db': jsonSecret(payload) });

    const record = await source.getJson('prod/db', { fields: { password: 'credential' } });

    expect([...record.keys].sort()).toEqual(['host', 'password', 'port', 'username']);
  });

  it('wraps a nested field by dot path', async () => {
    const source = FakeSecretSource.of({
      'prod/db': jsonSecret({ db: { password: CANARY, host: 'h' } }),
    });

    const record = await source.getJson('prod/db', {
      fields: { 'db.password': 'credential', 'db.host': 'plain' },
    });

    expect(record.fields['db.password'].klass).toBe('credential');
    expect(record.fields['db.password'].label).toBe('prod/db#db.password');
  });

  it('throws when a declared field is missing from the payload', async () => {
    const source = FakeSecretSource.of({ 'prod/db': jsonSecret({ username: 'app' }) });

    await expect(
      source.getJson('prod/db', { fields: { username: 'sensitive', password: 'credential' } })
    ).rejects.toThrow(/has no field 'password'/);
  });

  it('throws when a declared credential field is not a string', async () => {
    const source = FakeSecretSource.of({ 'prod/db': jsonSecret({ password: 12345 }) });

    await expect(source.getJson('prod/db', { fields: { password: 'credential' } })).rejects.toThrow(
      /is not a string, so it cannot be wrapped/
    );
  });

  it('allows a declared plain field to hold a number', async () => {
    const source = FakeSecretSource.of({ 'prod/db': jsonSecret({ port: 5432 }) });

    const record = await source.getJson('prod/db', { fields: { port: 'plain' } });

    expect(record.fields.port).toBe(5432);
  });

  it('throws when a declared plain field holds a container', async () => {
    const source = FakeSecretSource.of({ 'prod/db': jsonSecret({ tags: { a: 'b' } }) });

    await expect(source.getJson('prod/db', { fields: { tags: 'plain' } })).rejects.toThrow(
      /holds an object or an array/
    );
  });

  it('reads a map payload without going through JSON.parse', async () => {
    const source = FakeSecretSource.of({
      'kv/db': { payload: { kind: 'map', value: { password: CANARY } } },
    });

    const record = await source.getJson('kv/db', { fields: { password: 'credential' } });

    expect(record.fields.password.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('throws rather than coercing a payload that is not a JSON object', async () => {
    const source = FakeSecretSource.of({
      list: { payload: { kind: 'string', value: '["a","b"]' } },
    });

    await expect(source.getJson('list', { fields: {} })).rejects.toThrow(/is not a JSON object/);
  });
});

describe('getAll', () => {
  it('separates wrapped fields from plain ones', async () => {
    const source = FakeSecretSource.of({
      config: jsonSecret({ API_KEY: CANARY, LOG_LEVEL: 'debug', PORT: 8080 }),
    });

    const record = await source.getAll('config', {
      rules: [{ pattern: /KEY|TOKEN|SECRET/, klass: 'credential' }],
      fallback: 'plain',
    });

    expect(record.fields.get('API_KEY')?.klass).toBe('credential');
    expect(record.plain.get('LOG_LEVEL')).toBe('debug');
    expect(record.fields.has('LOG_LEVEL')).toBe(false);
  });

  it('wraps everything where the store is secret by construction', async () => {
    const source = FakeSecretSource.of({ 'kv/prod/db': jsonSecret({ a: '1', b: '2' }) });

    const record = await source.getAll('kv/prod/db', { fallback: 'credential' });

    expect([...record.fields.keys()].sort()).toEqual(['a', 'b']);
    expect(record.plain.size).toBe(0);
  });

  it('requires an explicit fallback', async () => {
    const source = FakeSecretSource.of({ a: jsonSecret({ b: 'c' }) });

    await expect(source.getAll('a', {} as unknown as { fallback: 'plain' })).rejects.toThrow(
      /getAll requires an explicit fallback/
    );
  });

  it('never puts a raw string in the fields map', async () => {
    const source = FakeSecretSource.of({ config: jsonSecret({ A: 'a', B: 'b' }) });

    const record = await source.getAll('config', { fallback: 'credential' });

    for (const value of record.fields.values()) {
      expect(value).toBeInstanceOf(SensitiveString);
    }
  });
});

describe('onLoad', () => {
  it('emits a single event carrying no secret material', async () => {
    const events: SecretLoadEvent[] = [];
    const source = FakeSecretSource.of(
      { 'prod/token': { payload: { kind: 'string', value: CANARY }, version: '7' } },
      { onLoad: (event) => events.push(event) }
    );

    await source.get('prod/token');

    expect(events).toHaveLength(1);
    const [event] = events;
    expect(event?.kind).toBe('single');
    expect(event?.source).toBe('fake');
    expect(event?.cached).toBe(false);
    expect(event?.ref.version).toBe('7');
    expect(JSON.stringify(event)).not.toContain(CANARY);
  });

  it('emits a bulk event with the key names and the counts', async () => {
    const events: SecretLoadEvent[] = [];
    const source = FakeSecretSource.of(
      { config: jsonSecret({ API_KEY: CANARY, LOG_LEVEL: 'debug' }) },
      { onLoad: (event) => events.push(event) }
    );

    await source.getAll('config', {
      rules: [{ pattern: /KEY/, klass: 'credential' }],
      fallback: 'plain',
    });

    const [event] = events;
    expect(event?.kind).toBe('bulk');

    if (event?.kind !== 'bulk') {
      throw new Error('expected a bulk event');
    }

    expect([...event.keys].sort()).toEqual(['API_KEY', 'LOG_LEVEL']);
    expect(event.counts).toEqual({ credential: 1, sensitive: 0, plain: 1 });
    expect(JSON.stringify(event)).not.toContain(CANARY);
  });

  it('reports a cache hit as cached', async () => {
    const events: SecretLoadEvent[] = [];
    const source = FakeSecretSource.of(
      { a: { payload: { kind: 'string', value: 'v' } } },
      { onLoad: (event) => events.push(event) }
    );

    await source.get('a');
    await source.get('a');

    expect(events.map((event) => event.cached)).toEqual([false, true]);
    expect(source.calls).toHaveLength(1);
  });

  it('carries the deadline where one was bound', async () => {
    const events: SecretLoadEvent[] = [];
    const source = FakeSecretSource.of(
      { a: { payload: { kind: 'string', value: 'v' }, lifetime: { ttl: 5_000 } } },
      { onLoad: (event) => events.push(event) }
    );

    await source.get('a');

    expect(events[0]?.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('propagates an error thrown by the hook rather than swallowing it', async () => {
    const source = FakeSecretSource.of(
      { a: { payload: { kind: 'string', value: 'v' } } },
      {
        onLoad: () => {
          throw new Error('audit sink is down');
        },
      }
    );

    await expect(source.get('a')).rejects.toThrow('audit sink is down');
  });
});

describe('refresh', () => {
  it('drops every shape of entry for a ref', async () => {
    const source = FakeSecretSource.of({ 'prod/db': jsonSecret({ password: 'p' }) });

    await source.get({ path: 'prod/db' }).catch(() => undefined);
    await source.getJson('prod/db', { fields: { password: 'credential' } });
    source.refresh('prod/db');
    await source.getJson('prod/db', { fields: { password: 'credential' } });

    expect(source.calls.filter((call) => call.path === 'prod/db').length).toBeGreaterThan(1);
  });

  it('leaves instances handed out before it working', async () => {
    const source = FakeSecretSource.of({ a: { payload: { kind: 'string', value: CANARY } } });

    const before = await source.get('a');
    source.refresh('a');

    expect(before.value.reveal({ name: 'test' })).toBe(CANARY);
  });
});

describe('audit', () => {
  it('does not fire auditReveal on a load, because wrapping is not revealing', async () => {
    const auditReveal = vi.fn();
    const source = FakeSecretSource.of({ a: { payload: { kind: 'string', value: 'v' } } });

    const record = await source.get('a');

    expect(auditReveal).not.toHaveBeenCalled();

    record.value.reveal({ name: 'use', auditReveal });

    expect(auditReveal).toHaveBeenCalledTimes(1);
  });
});

describe('keys that contain a dot', () => {
  // Kubernetes Secret keys are routinely `tls.key`, `ca.crt` and
  // `.dockerconfigjson`, so this is the common shape rather than an edge case.
  // An earlier version wrapped by dot path through core's `wrapSensitiveByPath`,
  // which reads `tls.key` as a path into a nested object, matched nothing, and
  // put the secret in the plain map as an ordinary string with no error.
  const tls = {
    'tls.key': CANARY,
    'tls.crt': 'public certificate',
    '.dockerconfigjson': '{"auths":{}}',
  };

  it('wraps a flat key containing a dot', async () => {
    const source = FakeSecretSource.of({
      'payments/tls': { payload: { kind: 'map', value: tls } },
    });

    const record = await source.getAll('payments/tls', { fallback: 'credential' });

    expect(record.fields.get('tls.key')).toBeInstanceOf(SensitiveString);
    expect(record.plain.get('tls.key')).toBeUndefined();
    expect(record.fields.get('tls.key')?.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('wraps a leading-dot key', async () => {
    const source = FakeSecretSource.of({
      'payments/tls': { payload: { kind: 'map', value: tls } },
    });

    const record = await source.getAll('payments/tls', { fallback: 'credential' });

    expect(record.fields.get('.dockerconfigjson')).toBeInstanceOf(SensitiveString);
  });

  it('classifies such a key by an exact field match', async () => {
    const source = FakeSecretSource.of({
      'payments/tls': { payload: { kind: 'map', value: tls } },
    });

    const record = await source.getAll('payments/tls', {
      fields: { 'tls.crt': 'plain' },
      fallback: 'credential',
    });

    expect(record.plain.get('tls.crt')).toBe('public certificate');
    expect(record.fields.get('tls.key')).toBeInstanceOf(SensitiveString);
  });

  it('declares such a key in getJson', async () => {
    const source = FakeSecretSource.of({
      'payments/tls': { payload: { kind: 'map', value: tls } },
    });

    const record = await source.getJson('payments/tls', {
      fields: { 'tls.key': 'credential', 'tls.crt': 'plain' },
    });

    expect(record.fields['tls.key'].reveal({ name: 'test' })).toBe(CANARY);
    expect(record.fields['tls.crt']).toBe('public certificate');
  });

  it('refuses a payload where a dotted key and a nested one collide', async () => {
    const source = FakeSecretSource.of({
      ambiguous: { payload: { kind: 'map', value: { 'a.b': CANARY, a: { b: 'other' } } } },
    });

    await expect(source.getAll('ambiguous', { fallback: 'credential' })).rejects.toThrow(
      /both address 'a\.b'/
    );
  });
});

describe('a value the provider already wrapped', () => {
  it('is kept rather than re-wrapped, so its deadline survives', async () => {
    const existing = new SensitiveString(CANARY, 'credential', 'provider-label', { ttl: 30_000 });
    const source = FakeSecretSource.of({
      pre: { payload: { kind: 'map', value: { token: existing } } },
    });

    const record = await source.getAll('pre', { fallback: 'credential' });

    expect(record.fields.get('token')).toBe(existing);
    expect(record.fields.get('token')?.label).toBe('provider-label');
  });
});
