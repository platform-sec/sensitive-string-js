import { describe, it, expect, vi } from 'vitest';
import { SensitiveString, withRevealContext } from '@platform-sec/sensitive-string-core';
import {
  SecretNotFoundError,
  describeLabelDisclosure,
} from '@platform-sec/sensitive-string-secrets';
import { putJson } from '@platform-sec/sensitive-string-secrets/write';

import { VaultRequestError } from './transport.js';
import type { SecretLoadEvent } from '@platform-sec/sensitive-string-secrets';
import {
  FakeTransport,
  TEST_TOKEN,
  dynamicBody,
  kvV1Body,
  kvV2Body,
  source,
  vaultToken,
} from './__tests__/fake-transport.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CONTEXT = { name: 'rotate-db-credential', reason: 'scheduled rotation' };

describe('reads', () => {
  it('reads a KV v2 path through the data segment', async () => {
    const transport = FakeTransport.of({
      'kv/data/prod/db': { body: kvV2Body({ username: 'app', password: CANARY }) },
    });

    const record = await source(transport).getJson('kv/prod/db', {
      fields: { username: 'sensitive', password: 'credential' },
    });

    expect(transport.requests[0]?.path).toBe('kv/data/prod/db');
    expect(record.fields.password.reveal({ name: 'test' })).toBe(CANARY);
    expect(record.fields.username.klass).toBe('sensitive');
  });

  it('reads a KV v1 path directly', async () => {
    const transport = FakeTransport.of({
      'secret/prod/db': { body: kvV1Body({ password: CANARY }) },
    });

    const record = await source(transport, { mounts: [{ path: 'secret', kv: 1 }] }).getJson(
      'secret/prod/db',
      { fields: { password: 'credential' } }
    );

    expect(transport.requests[0]?.path).toBe('secret/prod/db');
    expect(record.fields.password.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('binds no deadline from a KV v1 lease_duration, which is not an expiry', async () => {
    // Measured on Vault 1.21.4 and OpenBao 2.6.2: a KV v1 read reports the
    // mount's default TTL of 2764800 seconds with an empty lease id. Binding
    // it would expire a valid credential after 32 days, and nothing would have
    // revoked it.
    const transport = FakeTransport.of({
      'secret/prod/db': { body: kvV1Body({ password: CANARY }) },
    });

    const record = await source(transport, { mounts: [{ path: 'secret', kv: 1 }] }).getAll(
      'secret/prod/db',
      { fallback: 'credential' }
    );

    for (const value of record.fields.values()) {
      expect(value.expiresAt).toBeUndefined();
    }

    // Kept where an audit trail can have it, with nothing enforcing it.
    expect(record.ref.metadata['lease_duration']).toBe(2_764_800);
  });

  it('binds no deadline from a KV v2 read either', async () => {
    const transport = FakeTransport.of({
      'kv/data/prod/db': { body: kvV2Body({ password: CANARY }) },
    });

    const record = await source(transport).getAll('kv/prod/db', { fallback: 'credential' });

    for (const value of record.fields.values()) {
      expect(value.expiresAt).toBeUndefined();
    }
  });

  it('reports a KV v1 read as unversioned rather than echoing an alias', async () => {
    const transport = FakeTransport.of({
      'secret/prod/db': { body: kvV1Body({ password: CANARY }) },
    });

    const record = await source(transport, { mounts: [{ path: 'secret', kv: 1 }] }).getAll(
      'secret/prod/db',
      { fallback: 'credential' }
    );

    expect(record.ref.version).toBe('unversioned');
  });

  it('refuses a pinned version against a KV v1 mount', async () => {
    // KV v1 overwrites in place, so the version query is ignored and the read
    // would silently return the current value under the caller's belief that
    // they pinned one.
    const transport = FakeTransport.of({
      'secret/prod/db': { body: kvV1Body({ password: CANARY }) },
    });

    await expect(
      source(transport, { mounts: [{ path: 'secret', kv: 1 }] }).getAll(
        { path: 'secret/prod/db', version: '3' },
        { fallback: 'credential' }
      )
    ).rejects.toThrow(/has no versions/);
  });

  it('defaults an unlisted mount to KV v2', async () => {
    const transport = FakeTransport.of({ 'other/data/a': { body: kvV2Body({ a: 'b' }) } });
    const vault = source(transport);

    expect(vault.kvVersion('other/a')).toBe(2);
    await vault.getAll('other/a', { fallback: 'credential' });

    expect(transport.requests[0]?.path).toBe('other/data/a');
  });

  it('passes a pinned version as a query parameter', async () => {
    const transport = FakeTransport.of({ 'kv/data/prod/db': { body: kvV2Body({ a: 'b' }) } });

    await source(transport).getAll(
      { path: 'kv/prod/db', version: '3' },
      { fallback: 'credential' }
    );

    expect(transport.requests[0]?.query).toEqual({ version: '3' });
  });

  it('reports the version Vault served, not the alias asked for', async () => {
    const transport = FakeTransport.of({ 'kv/data/prod/db': { body: kvV2Body({ a: 'b' }) } });

    const record = await source(transport).getAll('kv/prod/db', { fallback: 'credential' });

    expect(record.ref.version).toBe('7');
  });

  it('refuses a single-value read of a path that holds named fields', async () => {
    const transport = FakeTransport.of({ 'kv/data/prod/db': { body: kvV2Body({ a: 'b' }) } });

    await expect(source(transport).get('kv/prod/db')).rejects.toThrow(
      /Use getJson\(\) or getAll\(\)/
    );
  });

  describe('absence', () => {
    it('reports a 404 as absence through getOptional', async () => {
      const transport = FakeTransport.of({});

      await expect(source(transport).getOptional('kv/prod/missing')).resolves.toBeNull();
    });

    it('throws for a 404 through get', async () => {
      const transport = FakeTransport.of({});

      await expect(source(transport).get('kv/prod/missing')).rejects.toBeInstanceOf(
        SecretNotFoundError
      );
    });

    it('keeps throwing for a 403, since a denial is not an absence', async () => {
      const transport = FakeTransport.of({
        'kv/data/prod/db': { status: 403, errors: ['permission denied'] },
      });

      await expect(source(transport).getOptional('kv/prod/db')).rejects.toBeInstanceOf(
        VaultRequestError
      );
    });

    it('keeps throwing for a 500', async () => {
      const transport = FakeTransport.of({ 'kv/data/prod/db': { status: 500 } });

      await expect(source(transport).getOptional('kv/prod/db')).rejects.toBeInstanceOf(
        VaultRequestError
      );
    });
  });
});

describe('labels', () => {
  it('is the logical path within the store', async () => {
    const transport = FakeTransport.of({
      'kv/data/prod/db': { body: kvV2Body({ password: CANARY }) },
    });

    const record = await source(transport).getJson('kv/prod/db', {
      fields: { password: 'credential' },
    });

    expect(record.fields.password.label).toBe('kv/prod/db#password');
  });

  it('refuses an endpoint pasted into the path rather than half-normalizing it', async () => {
    // The label rule is about what reaches a log line, and an endpoint carries
    // an internal hostname and port. Silently stripping it would also leave a
    // request path that does not exist, so the boundary refuses instead.
    const transport = FakeTransport.of({
      'kv/data/prod/db': { body: kvV2Body({ password: CANARY }) },
    });

    await expect(
      source(transport).getJson('https://vault.internal:8200/v1/kv/data/prod/db', {
        fields: { password: 'credential' },
      })
    ).rejects.toThrow(/logical path within the store/);
  });

  it('matches the path the caller asked for, rather than rewriting it', async () => {
    // A caller who writes the `data/` segment themselves gets a request to
    // `kv/data/data/prod/db`, which does not exist. Rewriting the label to
    // `kv/prod/db` would make it disagree with what was actually requested and
    // turn a loud not-found into a confusing one.
    const transport = FakeTransport.of({
      'kv/data/data/prod/db': { body: kvV2Body({ password: CANARY }) },
    });

    const record = await source(transport).getJson('kv/data/prod/db', {
      fields: { password: 'credential' },
    });

    expect(record.fields.password.label).toBe('kv/data/prod/db#password');
    expect(describeLabelDisclosure(record.fields.password.label ?? '')).toEqual([]);
  });

  it('drops a leading slash, which is harmless input rather than a mistake', async () => {
    const transport = FakeTransport.of({
      'kv/data/prod/db': { body: kvV2Body({ password: CANARY }) },
    });

    const record = await source(transport).getJson('/kv/prod/db', {
      fields: { password: 'credential' },
    });

    expect(record.fields.password.label).toBe('kv/prod/db#password');
  });

  it('discloses nothing under the rule for an ordinary path', async () => {
    const transport = FakeTransport.of({
      'kv/data/prod/db': { body: kvV2Body({ password: CANARY }) },
    });

    const record = await source(transport).getAll('kv/prod/db', { fallback: 'credential' });

    for (const value of record.fields.values()) {
      expect(describeLabelDisclosure(value.label ?? '')).toEqual([]);
    }
  });
});

describe('the client token', () => {
  it('is revealed per request and sent as the auth header', async () => {
    const token = new SensitiveString(TEST_TOKEN, 'credential', 'vault-token');
    const transport = FakeTransport.of({ 'kv/data/prod/db': { body: kvV2Body({ a: 'b' }) } });

    await source(transport, { token }).getAll('kv/prod/db', { fallback: 'credential' });

    expect(transport.requests[0]?.headers['X-Vault-Token']).toBe(TEST_TOKEN);
  });

  it('reaches an ambient audit sink, under this package name', async () => {
    const seen: { label: string; context: string }[] = [];
    const transport = FakeTransport.of({ 'kv/data/prod/db': { body: kvV2Body({ a: 'b' }) } });
    const vault = source(transport, { token: vaultToken() });

    await withRevealContext(
      {
        name: 'boot',
        auditReveal: (value) => seen.push({ label: value.label ?? '', context: 'boot' }),
      },
      async () => {
        await vault.getAll('kv/prod/db', { fallback: 'credential' });
      }
    );

    // The token reveal is the most security-relevant one in the process. An
    // explicit context object would name it correctly and make it the one
    // reveal nobody's sink sees.
    expect(seen.map((entry) => entry.label)).toContain('vault-token');
  });

  it('never puts the token into a load event', async () => {
    const events: SecretLoadEvent[] = [];
    const transport = FakeTransport.of({ 'kv/data/prod/db': { body: kvV2Body({ a: 'b' }) } });

    await source(transport, { onLoad: (event) => events.push(event) }).getAll('kv/prod/db', {
      fallback: 'credential',
    });

    expect(JSON.stringify(events)).not.toContain(TEST_TOKEN);
  });
});

describe('load events', () => {
  it('reports the resolved version and no secret material', async () => {
    const events: SecretLoadEvent[] = [];
    const transport = FakeTransport.of({
      'kv/data/prod/db': {
        body: kvV2Body({ password: CANARY }, { custom_metadata: { owner: 'payments' } }),
      },
    });

    await source(transport, { onLoad: (event) => events.push(event) }).getAll('kv/prod/db', {
      fallback: 'credential',
    });

    const [event] = events;

    expect(event?.ref.version).toBe('7');
    expect(event?.ref.metadata['owner']).toBe('payments');
    expect(JSON.stringify(event)).not.toContain(CANARY);
  });
});

describe('response wrapping', () => {
  it('sends the wrap TTL header and wraps the token as a credential', async () => {
    const transport = FakeTransport.of({
      'kv/data/prod/db': {
        body: {
          wrap_info: {
            token: 'hvs.WRAPPED_abc',
            ttl: 60,
            wrapped_accessor: 'acc-1',
            creation_time: '2026-09-01T00:00:00Z',
          },
        },
      },
    });

    const wrapped = await source(transport).getWrapped('kv/prod/db', 60);

    expect(transport.requests[0]?.headers['X-Vault-Wrap-TTL']).toBe('60');
    expect(wrapped.token.klass).toBe('credential');
    expect(wrapped.token.label).toBe('kv/prod/db#wrapping-token');
    expect(wrapped.token.ttlRemaining()).toBeLessThanOrEqual(60_000);
    expect(wrapped.accessor).toBe('acc-1');
  });

  it('pins the same version a plain read would', async () => {
    const transport = FakeTransport.of({
      'kv/data/prod/db': { body: { wrap_info: { token: 'hvs.WRAPPED_abc', ttl: 60 } } },
    });

    await source(transport).getWrapped({ path: 'kv/prod/db', version: '3' }, 60);

    expect(transport.requests[0]?.query).toEqual({ version: '3' });
  });

  it('throws where the response came back unwrapped', async () => {
    const transport = FakeTransport.of({ 'kv/data/prod/db': { body: kvV2Body({ a: 'b' }) } });

    await expect(source(transport).getWrapped('kv/prod/db', 60)).rejects.toThrow(
      /did not come back wrapped/
    );
  });

  it('exchanges a wrapping token for the value it wraps', async () => {
    const transport = FakeTransport.of({
      'sys/wrapping/unwrap': { body: { data: { password: CANARY } } },
    });

    const record = await source(transport).unwrap(
      new SensitiveString('hvs.WRAPPED_abc', 'credential'),
      { fallback: 'credential' },
      'kv/prod/db'
    );

    expect(transport.requests[0]?.headers['X-Vault-Token']).toBe('hvs.WRAPPED_abc');
    expect(record.fields.get('password')?.reveal({ name: 'test' })).toBe(CANARY);
    expect(record.fields.get('password')?.label).toBe('kv/prod/db#password');
  });
});

describe('writes', () => {
  it('writes a KV v2 payload nested under data and reads it back', async () => {
    const stored: Record<string, unknown> = { password: 'old' };
    const transport = FakeTransport.of({
      'POST kv/data/prod/db': { body: { data: { version: 8 } } },
      'GET kv/data/prod/db': { body: kvV2Body(stored, { version: 8 }) },
    });

    // The read-back reads whatever the fake stored, so the write has to land
    // there for the comparison to pass.
    const vault = source(transport);
    const original = transport.request.bind(transport);
    vi.spyOn(transport, 'request').mockImplementation(async (request) => {
      if (request.method === 'POST') {
        const body = request.body as { data: Record<string, unknown> };
        Object.assign(stored, body.data);
        transport.set('GET kv/data/prod/db', { body: kvV2Body(stored, { version: 8 }) });
      }

      return original(request);
    });

    const written = await putJson(
      vault,
      'kv/prod/db',
      { password: new SensitiveString(CANARY, 'credential') },
      { context: CONTEXT }
    );

    expect(written.version).toBe('8');
  });

  it('refuses a single-value write, since a KV path holds named fields', async () => {
    const transport = FakeTransport.of({});

    await expect(
      source(transport).writeSecret({ path: 'kv/prod/db' }, { kind: 'string', value: CANARY })
    ).rejects.toThrow(/Use putJson\(\)/);
  });
});

describe('token renewal', () => {
  it('renews once and reports the granted lifetime', async () => {
    const transport = FakeTransport.of({
      'auth/token/renew-self': { body: { auth: { lease_duration: 3_600 } } },
    });

    const granted = await source(transport).renewToken();

    expect(granted).toBe(3_600_000);
  });

  it('sends an increment in seconds', async () => {
    const transport = FakeTransport.of({
      'auth/token/renew-self': { body: { auth: { lease_duration: 3_600 } } },
    });

    await source(transport).renewToken(1_800_000);

    expect(transport.requests[0]?.body).toEqual({ increment: 1_800 });
  });

  it('surfaces a renewal failure rather than retrying it silently', async () => {
    const errors: unknown[] = [];
    const transport = FakeTransport.of({
      'auth/token/renew-self': { status: 403, errors: ['permission denied'] },
    });
    const vault = source(transport, {
      onAuthError: (error) => errors.push(error),
      tokenRenewal: { intervalMs: 5 },
    });

    try {
      await new Promise((resolve) => setTimeout(resolve, 30));

      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toBeInstanceOf(VaultRequestError);
    } finally {
      vault.close();
    }
  });

  it('stops on close', async () => {
    const transport = FakeTransport.of({
      'auth/token/renew-self': { body: { auth: { lease_duration: 3_600 } } },
    });
    const vault = source(transport, { tokenRenewal: { intervalMs: 5 } });

    await new Promise((resolve) => setTimeout(resolve, 20));
    vault.close();
    const after = transport.requests.length;
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(transport.requests).toHaveLength(after);
  });
});

describe('dynamic secrets alongside KV', () => {
  it('binds a real lease where KV binds nothing', async () => {
    const transport = FakeTransport.of({
      'kv/data/prod/db': { body: kvV2Body({ password: CANARY }) },
      'database/creds/app': { body: dynamicBody({ password: CANARY }) },
    });
    const vault = source(transport);

    const kv = await vault.getAll('kv/prod/db', { fallback: 'credential' });
    const lease = await vault.dynamic('database/creds/app');

    expect(kv.fields.get('password')?.expiresAt).toBeUndefined();
    expect(lease.fields.get('password')?.expiresAt).toBeInstanceOf(Date);
  });
});
