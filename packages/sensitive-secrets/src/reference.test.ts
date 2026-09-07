import { describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  containsSensitive,
  getCurrentRevealContext,
  isSensitiveValueReference,
  redactInStructure,
  safeStringify,
  withAuditedReveals,
} from '@platform-sec/sensitive-string-core';
import type {
  RevealContext,
  SensitiveValueReference,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

import { ReferenceRefusedError } from './errors.js';
import { createReferenceResolver, fieldReference, toReference } from './reference.js';
import type { Referenceable, ReferenceAllowEntry, ReferenceResolver } from './reference.js';
import { assertNoCanary, errorText } from './testing.js';
import type { ProviderResult, SecretLoadEvent, SecretRef, SecretSource } from './types.js';
import { FakeSecretSource } from './__tests__/fake-source.js';

const CANARY = 'LEAKED_SECRET_ref_7d41';

const context = { name: 'charge-worker', reason: 'resolving a job reference' } as const;

/** A record shaped like the ones the three reads return, without any of them running. */
function record(path: string, version = '7') {
  return { ref: { path, version, metadata: {} } };
}

/**
 * A source that fails the test if it is reached.
 *
 * Every refusal in this file is supposed to happen before the store is touched,
 * and the only way to keep that true across a later refactor is to make the
 * fetch itself an assertion failure rather than something the test would still
 * pass without.
 */
function untouchedSource(): SecretSource {
  const reached = (): never => {
    throw new Error('the source was reached, and the refusal was supposed to precede it');
  };

  return {
    get: reached,
    getOptional: reached,
    getJson: reached,
    getAll: reached,
    refresh: reached,
  };
}

function paymentsSource(events: SecretLoadEvent[] = []): FakeSecretSource {
  return FakeSecretSource.of(
    {
      'kv/payments/stripe': { payload: { kind: 'string', value: CANARY }, version: '7' },
      'kv/analytics/db': {
        payload: {
          kind: 'string',
          value: JSON.stringify({ username: 'reporting', password: CANARY, port: 5432 }),
        },
        version: '3',
      },
    },
    { onLoad: (event) => events.push(event) }
  );
}

const PAYMENTS_ALLOW: readonly ReferenceAllowEntry[] = [
  { path: 'kv/payments/*', klass: 'credential' },
  { path: 'kv/analytics/db', fields: { password: 'credential', username: 'sensitive' } },
];

function resolver(
  source: SecretSource,
  allow: readonly ReferenceAllowEntry[] = PAYMENTS_ALLOW,
  store = 'vault-prod'
): ReferenceResolver {
  return createReferenceResolver({ store, source, allow });
}

/**
 * A reference as a sender would put it on a queue.
 *
 * The overrides are loosely typed on purpose: half of these tests send a member
 * the format does not allow, which is the whole point of them, and a signature
 * that refused those would only move the casts to every call site.
 */
function reference(overrides: Record<string, unknown> = {}): SensitiveValueReference {
  return {
    __sensitiveRef: true,
    v: 1,
    store: 'vault-prod',
    path: 'kv/payments/stripe',
    version: '7',
    ...overrides,
  } as unknown as SensitiveValueReference;
}

async function refusal(promise: Promise<unknown>): Promise<ReferenceRefusedError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ReferenceRefusedError) {
      return error;
    }

    throw error;
  }

  throw new Error('expected the reference to be refused');
}

describe('toReference', () => {
  it('mints a pointer from the record a read returned', () => {
    expect(toReference(record('kv/payments/stripe'), { store: 'vault-prod' })).toEqual({
      __sensitiveRef: true,
      v: 1,
      store: 'vault-prod',
      path: 'kv/payments/stripe',
      version: '7',
    });
  });

  it('is recognized by core as the wire shape it is', () => {
    expect(isSensitiveValueReference(toReference(record('a/b'), { store: 's' }))).toBe(true);
  });

  it('carries no secret material, and no value is reachable from it', async () => {
    const source = paymentsSource();
    const loaded = await source.get('kv/payments/stripe');
    const ref = toReference(loaded, { store: 'vault-prod' });

    assertNoCanary(CANARY, ref, 'a minted reference');
    expect(containsSensitive(ref)).toBe(false);
    expect(safeStringify(ref)).toContain('kv/payments/stripe');
  });

  it('performs no I/O and reveals nothing', async () => {
    const source = paymentsSource();
    const loaded = await source.get('kv/payments/stripe');
    const before = source.calls.length;
    const audit = vi.fn();

    withAuditedReveals('mint', audit, () => toReference(loaded, { store: 'vault-prod' }));

    expect(source.calls.length).toBe(before);
    expect(audit).not.toHaveBeenCalled();
  });

  it('pins the version the sender read, by default', () => {
    expect(toReference(record('a/b', '12'), { store: 's' }).version).toBe('12');
  });

  it('leaves the version out when the sender asked for current', () => {
    expect(toReference(record('a/b'), { store: 's', pinVersion: false }).version).toBeUndefined();
  });

  it("never pins the 'unknown' sentinel, which is not a version", () => {
    expect(toReference(record('a/b', 'unknown'), { store: 's' }).version).toBeUndefined();
  });

  it('carries an advisory class when the sender passes one', () => {
    expect(toReference(record('a/b'), { store: 's', klass: 'credential' }).klass).toBe(
      'credential'
    );
  });

  it('refuses an advisory class with no registered policy', () => {
    expect(() =>
      toReference(record('a/b'), { store: 's', klass: 'nonsense' as SensitivityClass })
    ).toThrow(TypeError);
  });

  it('requires a store, because a path alone does not identify a secret', () => {
    expect(() => toReference(record('a/b'), { store: '' })).toThrow(/store identity/);
  });

  it('refuses anything that is not a record', () => {
    const value = new SensitiveString(CANARY, 'credential', 'kv/payments/stripe');

    // A value, a derived value, a bare ref and a bare path are all things a
    // caller reaches for, and none of them is the record the read returned.
    for (const candidate of [
      value,
      value.substring(0, 4),
      { path: 'kv/payments/stripe' },
      'kv/payments/stripe',
      null,
      undefined,
    ]) {
      expect(() =>
        toReference(candidate as unknown as Referenceable, { store: 'vault-prod' })
      ).toThrow(TypeError);
    }
  });
});

describe('fieldReference', () => {
  it('names one field of a multi-value secret', () => {
    expect(
      fieldReference(record('kv/analytics/db', '3'), 'password', { store: 'vault-prod' })
    ).toEqual({
      __sensitiveRef: true,
      v: 1,
      store: 'vault-prod',
      path: 'kv/analytics/db',
      version: '3',
      field: 'password',
    });
  });

  it('needs a field name', () => {
    expect(() => fieldReference(record('a/b'), '', { store: 's' })).toThrow(TypeError);
  });
});

describe('createReferenceResolver, construction', () => {
  it('needs an allowlist, and the empty one is legal', () => {
    expect(() => resolver(untouchedSource(), [])).not.toThrow();
    expect(() =>
      createReferenceResolver({
        store: 'vault-prod',
        source: untouchedSource(),
        allow: undefined as unknown as ReferenceAllowEntry[],
      })
    ).toThrow(/allowlist/);
  });

  it('needs exactly one of klass and fields on an entry', () => {
    expect(() => resolver(untouchedSource(), [{ path: 'a/b' }])).toThrow(/exactly one/);
    expect(() =>
      resolver(untouchedSource(), [
        { path: 'a/b', klass: 'credential', fields: { p: 'credential' } },
      ])
    ).toThrow(/exactly one/);
  });

  it('refuses an entry whose fields map is empty, which would resolve nothing', () => {
    expect(() => resolver(untouchedSource(), [{ path: 'a/b', fields: {} }])).toThrow(/no fields/);
  });

  it('refuses a class with no registered policy, on either half', () => {
    expect(() =>
      resolver(untouchedSource(), [{ path: 'a/b', klass: 'nonsense' as SensitivityClass }])
    ).toThrow(/no registered policy/);
    expect(() =>
      resolver(untouchedSource(), [{ path: 'a/b', fields: { p: 'nonsense' as SensitivityClass } }])
    ).toThrow(/no registered policy/);
  });

  it('accepts a trailing wildcard on a segment boundary and refuses one anywhere else', () => {
    expect(() =>
      resolver(untouchedSource(), [{ path: 'kv/payments/*', klass: 'credential' }])
    ).not.toThrow();
    expect(() => resolver(untouchedSource(), [{ path: '*', klass: 'credential' }])).not.toThrow();

    for (const pattern of ['kv/pay*', 'kv/*/stripe', 'kv/*/*', '*/stripe']) {
      expect(() => resolver(untouchedSource(), [{ path: pattern, klass: 'credential' }])).toThrow(
        /supported pattern/
      );
    }
  });

  it('refuses an entry whose own path is malformed', () => {
    for (const pattern of ['/kv/payments', 'kv//payments', 'kv/../payments']) {
      expect(() => resolver(untouchedSource(), [{ path: pattern, klass: 'credential' }])).toThrow(
        TypeError
      );
    }
  });

  it('copies the allowlist, so a later mutation cannot widen a live resolver', async () => {
    const allow: ReferenceAllowEntry[] = [];
    const instance = createReferenceResolver({
      store: 'vault-prod',
      source: untouchedSource(),
      allow,
    });

    allow.push({ path: '*', klass: 'credential' });

    expect((await refusal(instance.resolve(reference(), { context }))).reason).toBe('path');
  });

  it('copies each entry too, so editing one cannot widen a live resolver', async () => {
    const allow: ReferenceAllowEntry[] = [{ path: 'kv/analytics/db', klass: 'credential' }];
    const instance = createReferenceResolver({
      store: 'vault-prod',
      source: untouchedSource(),
      allow,
    });

    // Copying the array alone would leave the caller holding the entries, and
    // an allowlist a caller can still edit is not one the resolver owns.
    const entry = allow[0];

    if (entry !== undefined) {
      (entry as { path: string }).path = '*';
    }

    expect((await refusal(instance.resolve(reference(), { context }))).reason).toBe('path');
  });

  it('refuses a fields allowlist against a source that has no getJson', () => {
    const withoutGetJson: Record<string, unknown> = { ...untouchedSource() };
    delete withoutGetJson['getJson'];

    // A field entry resolves through getJson, so the fault is configuration and
    // belongs at construction rather than at the first field reference.
    expect(() =>
      createReferenceResolver({
        store: 'vault-prod',
        source: withoutGetJson as unknown as SecretSource,
        allow: [{ path: 'kv/analytics/db', fields: { password: 'credential' } }],
      })
    ).toThrow(/getJson/);
  });

  it('names an empty field name as what it is', () => {
    expect(() =>
      resolver(untouchedSource(), [{ path: 'a/b', fields: { '': 'credential' } }])
    ).toThrow(/empty name/);
  });

  it("refuses '/*', which would be an entry that can never match", () => {
    expect(() => resolver(untouchedSource(), [{ path: '/*', klass: 'credential' }])).toThrow(
      /starts with a slash/
    );
  });
});

describe('resolve, the refusals that precede the store', () => {
  it('refuses something that is not a reference', async () => {
    const instance = resolver(untouchedSource());

    for (const candidate of [
      null,
      undefined,
      'kv/payments/stripe',
      7,
      { path: 'kv/payments/stripe' },
    ]) {
      expect((await refusal(instance.resolve(candidate, { context }))).reason).toBe('shape');
    }
  });

  it('separates a version it cannot read from a payload that is not a reference', async () => {
    const instance = resolver(untouchedSource());
    const error = await refusal(instance.resolve(reference({ v: 2 }), { context }));

    expect(error.reason).toBe('format');
    expect(error.message).toContain('2');
  });

  it('refuses a reference missing a member the format requires', async () => {
    const instance = resolver(untouchedSource());
    const withoutStore: Record<string, unknown> = { ...reference() };
    delete withoutStore['store'];

    expect((await refusal(instance.resolve(withoutStore, { context }))).reason).toBe('shape');
  });

  it('refuses a reference minted for another store', async () => {
    const instance = resolver(untouchedSource());
    const error = await refusal(
      instance.resolve(reference({ store: 'vault-staging' }), { context })
    );

    expect(error.reason).toBe('store');
    expect(error.message).toContain('vault-prod');
    expect(error.message).not.toContain('vault-staging');
  });

  it('refuses a path shape rather than normalizing it', async () => {
    const instance = resolver(untouchedSource(), [{ path: '*', klass: 'credential' }]);

    const paths = [
      'kv/payments/../../root/master-key',
      'kv/./payments/stripe',
      'kv//payments/stripe',
      '/kv/payments/stripe',
      // Built rather than typed: a newline in a path is what turns one refused
      // line in a log into two, one of which reads as a record the receiver
      // wrote, and a source file that holds the byte itself is worse than the
      // test it enables.
      `kv/payments/strip${String.fromCharCode(10)}e`,
      `kv/payments/${String.fromCharCode(0)}stripe`,
    ];

    for (const path of paths) {
      const error = await refusal(instance.resolve(reference({ path }), { context }));

      expect(error.reason).toBe('path');
      expect(error.path).toBe(path);
    }
  });

  /**
   * The escape a segment check does not catch on its own.
   *
   * Splitting on `/` and refusing a `..` segment is the obvious rule and it is
   * not enough, because the parser downstream sees a different set of segments
   * than this library does. The pin below measures that rather than asserting
   * it, and the refusals underneath are what keeps such a path from ever
   * reaching a provider.
   */
  it('pins the URL parsing this rule exists for', () => {
    const parse = (path: string) => new URL(`https://vault.internal:8200/v1/${path}`).pathname;

    expect(parse('kv/payments/%2e%2e/%2e%2e/auth/token/lookup-self')).toBe(
      '/v1/auth/token/lookup-self'
    );
    expect(parse('kv/payments/%2E%2E/%2E%2E/auth/token/lookup-self')).toBe(
      '/v1/auth/token/lookup-self'
    );
    expect(parse(String.raw`kv/payments/..\..\auth/token/lookup-self`)).toBe(
      '/v1/auth/token/lookup-self'
    );
    expect(new URL('https://h/v1/kv/payments/stripe?list=true').search).toBe('?list=true');
  });

  it('refuses a path carrying a character a URL parser reads as structure', async () => {
    const instance = resolver(untouchedSource(), [{ path: 'kv/payments/*', klass: 'credential' }]);

    const paths = [
      // A percent-encoded traversal: no `..` segment for the split to find,
      // and an arbitrary read once the provider builds a URL from it.
      'kv/payments/%2e%2e/%2e%2e/auth/token/lookup-self',
      'kv/payments/%2E%2E/%2E%2E/auth/token/lookup-self',
      // The same escape with no percent sign in it at all.
      String.raw`kv/payments/..\..\auth/token/lookup-self`,
      // A permitted read turned into a different request against the store.
      'kv/payments/stripe?list=true',
      'kv/payments/stripe#/../../auth',
    ];

    for (const path of paths) {
      const error = await refusal(instance.resolve(reference({ path }), { context }));

      expect(error.reason).toBe('path');
      expect(error.path).toBe(path);
      expect(error.message).not.toContain('auth');
    }
  });

  it('refuses an allowlist pattern carrying one, so the rule cannot be opted out of', () => {
    expect(() =>
      resolver(untouchedSource(), [{ path: 'kv/payments/%2e%2e/*', klass: 'credential' }])
    ).toThrow(/URL parser/);
  });

  it('refuses a version outside the charset, which is where an injection would go', async () => {
    const instance = resolver(untouchedSource());

    const versions = ['7/../8', 'v1?raw=true', 'v1#frag', 'v 1', 'a'.repeat(129), '7&x=1'];

    for (const version of versions) {
      const error = await refusal(instance.resolve(reference({ version }), { context }));

      expect(error.reason).toBe('version');
      expect(error.version).toBe(version);
    }
  });

  it('refuses a resolve with no context of its own', async () => {
    const instance = resolver(untouchedSource());
    const error = await refusal(
      instance.resolve(reference(), {} as unknown as { context: { name: string } })
    );

    expect(error.reason).toBe('no-context');
    // Nothing from the reference, because nothing from it was read.
    expect(error.path).toBe('');
  });

  it('reports the missing context before anything about the reference', async () => {
    const instance = resolver(untouchedSource());

    // The receiver's own mistake outranks the sender's, so a caller who forgot
    // the context is told that once rather than after fixing the payload too.
    const error = await refusal(
      instance.resolve({ nonsense: true }, {} as unknown as { context: { name: string } })
    );

    expect(error.reason).toBe('no-context');
  });

  it('keeps an attacker-chosen path and version out of every message', async () => {
    const instance = resolver(untouchedSource(), [{ path: 'kv/payments/*', klass: 'credential' }]);
    const probe = `kv/payments/${CANARY}`;

    const errors = [
      await refusal(instance.resolve(reference({ path: `${probe}/../..` }), { context })),
      await refusal(instance.resolve(reference({ path: 'kv/other/thing' }), { context })),
      await refusal(instance.resolve(reference({ version: `${CANARY}?x` }), { context })),
      await refusal(instance.resolve(reference({ store: CANARY }), { context })),
    ];

    for (const error of errors) {
      expect(error.message).not.toContain(CANARY);
      expect(error.stack ?? '').not.toContain(CANARY);
      expect((error as { cause?: unknown }).cause).toBeUndefined();
    }
  });
});

describe('resolve, the allowlist', () => {
  it('resolves nothing with an empty allowlist', async () => {
    const instance = resolver(untouchedSource(), []);

    expect((await refusal(instance.resolve(reference(), { context }))).reason).toBe('path');
  });

  it('refuses a path no entry covers', async () => {
    const instance = resolver(untouchedSource());
    const error = await refusal(
      instance.resolve(reference({ path: 'kv/root/master-key' }), { context })
    );

    expect(error.reason).toBe('path');
    expect(error.path).toBe('kv/root/master-key');
    expect(error.message).not.toContain('kv/root');
  });

  it('matches a trailing wildcard only at the segment boundary', async () => {
    const instance = resolver(paymentsSource(), [{ path: 'kv/payments/*', klass: 'credential' }]);

    await expect(instance.resolve(reference(), { context })).resolves.toBeInstanceOf(
      SensitiveString
    );

    const error = await refusal(
      instance.resolve(reference({ path: 'kv/paymentsx/stripe' }), { context })
    );

    expect(error.reason).toBe('path');
  });

  it('covers the subtree below a wildcard, and not the prefix itself', async () => {
    const source = FakeSecretSource.of({
      'kv/payments/eu/stripe': { payload: { kind: 'string', value: CANARY } },
    });
    const instance = resolver(source, [{ path: 'kv/payments/*', klass: 'credential' }]);

    await expect(
      instance.resolve(reference({ path: 'kv/payments/eu/stripe' }), { context })
    ).resolves.toBeInstanceOf(SensitiveString);

    expect(
      (await refusal(instance.resolve(reference({ path: 'kv/payments' }), { context }))).reason
    ).toBe('path');
  });

  it('refuses a whole-secret reference against an entry that resolves fields', async () => {
    const instance = resolver(untouchedSource());
    const error = await refusal(
      instance.resolve(reference({ path: 'kv/analytics/db', version: '3' }), { context })
    );

    expect(error.reason).toBe('field');
  });

  it('refuses a field reference against an entry that resolves whole secrets', async () => {
    const instance = resolver(untouchedSource());
    const error = await refusal(instance.resolve(reference({ field: 'password' }), { context }));

    expect(error.reason).toBe('field');
  });

  it('refuses a field the matching entry does not declare', async () => {
    const instance = resolver(untouchedSource());
    const error = await refusal(
      instance.resolve(reference({ path: 'kv/analytics/db', version: '3', field: 'port' }), {
        context,
      })
    );

    expect(error.reason).toBe('field');
    expect(error.message).not.toContain('port');
  });

  it('picks the entry whose kind matches, when both cover the path', async () => {
    const source = paymentsSource();
    const instance = resolver(source, [
      { path: 'kv/analytics/*', klass: 'credential' },
      { path: 'kv/analytics/db', fields: { username: 'sensitive' } },
    ]);

    const whole = await instance.resolve(reference({ path: 'kv/analytics/db', version: '3' }), {
      context,
    });
    const field = await instance.resolve(
      reference({ path: 'kv/analytics/db', version: '3', field: 'username' }),
      { context }
    );

    expect(whole.klass).toBe('credential');
    expect(field.klass).toBe('sensitive');
  });

  it('takes the strictest class among the entries covering a path, in either order', async () => {
    const broad: ReferenceAllowEntry = { path: 'kv/*', klass: 'sensitive' };
    const specific: ReferenceAllowEntry = { path: 'kv/payments/stripe', klass: 'credential' };

    // A subtree rule and a rule for one path under it are how an operator
    // writes this, and taking the first would make the class a function of the
    // order the two lines were written in.
    for (const allow of [
      [broad, specific],
      [specific, broad],
    ]) {
      const value = await resolver(paymentsSource(), allow).resolve(reference(), { context });

      expect(value.klass).toBe('credential');
    }
  });

  it('takes the strictest class among the entries declaring a field, in either order', async () => {
    const broad: ReferenceAllowEntry = {
      path: 'kv/analytics/*',
      fields: { password: 'sensitive' },
    };
    const specific: ReferenceAllowEntry = {
      path: 'kv/analytics/db',
      fields: { password: 'credential' },
    };

    for (const allow of [
      [broad, specific],
      [specific, broad],
    ]) {
      const value = await resolver(paymentsSource(), allow).resolve(
        reference({ path: 'kv/analytics/db', version: '3', field: 'password' }),
        { context }
      );

      expect(value.klass).toBe('credential');
    }
  });
});

describe('resolve, what the receiver gets', () => {
  it('fetches with the receiver credentials and wraps under the receiver rule', async () => {
    const source = paymentsSource();
    const value = await resolver(source).resolve(reference(), { context });

    expect(value).toBeInstanceOf(SensitiveString);
    expect(value.klass).toBe('credential');
    expect(value.label).toBe('kv/payments/stripe');
    expect(value.reveal({ name: 'test' })).toBe(CANARY);
    expect(String(value)).not.toContain(CANARY);
  });

  it('resolves one field, labelled as one', async () => {
    const source = paymentsSource();
    const value = await resolver(source).resolve(
      reference({ path: 'kv/analytics/db', version: '3', field: 'password' }),
      { context }
    );

    expect(value.klass).toBe('credential');
    expect(value.label).toBe('kv/analytics/db#password');
    expect(value.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('takes the class from the allowlist and not from the wire', async () => {
    const source = paymentsSource();
    const value = await resolver(source).resolve(reference({ klass: 'sensitive' }), { context });

    expect(value.klass).toBe('credential');
  });

  it('lets the wire tighten the class, which is the one direction it may move', async () => {
    const source = paymentsSource();
    const instance = resolver(source, [{ path: 'kv/payments/*', klass: 'sensitive' }]);

    expect((await instance.resolve(reference(), { context })).klass).toBe('sensitive');
    expect((await instance.resolve(reference({ klass: 'credential' }), { context })).klass).toBe(
      'credential'
    );
  });

  it('derives its own label and ignores the one on the wire', async () => {
    const source = paymentsSource();
    const value = await resolver(source).resolve(
      reference({ label: 'https://vault.internal:8200/kv/payments/stripe' }),
      { context }
    );

    expect(value.label).toBe('kv/payments/stripe');
  });

  it('sends the pinned version to the store, and fails rather than falling back', async () => {
    const source = paymentsSource();

    await resolver(source).resolve(reference({ version: '7' }), { context });

    expect(source.calls.at(-1)).toEqual({ path: 'kv/payments/stripe', version: '7' });

    const missing = FakeSecretSource.of({ 'kv/payments/stripe': null });

    await expect(
      resolver(missing).resolve(reference({ version: '7' }), { context })
    ).rejects.toThrow(/not found/);
  });

  it('asks for current when the sender pinned nothing', async () => {
    const source = paymentsSource();

    await resolver(source).resolve(reference({ version: undefined }), { context });

    expect(source.calls.at(-1)).toEqual({ path: 'kv/payments/stripe' });
  });

  it('emits the load event a direct get for the same ref would emit', async () => {
    const direct: SecretLoadEvent[] = [];
    const viaReference: SecretLoadEvent[] = [];

    await paymentsSource(direct).get(
      { path: 'kv/payments/stripe', version: '7' },
      { klass: 'credential' }
    );
    await resolver(paymentsSource(viaReference)).resolve(reference(), { context });

    const shape = (event: SecretLoadEvent | undefined) => ({ ...event, durationMs: 0 });

    expect(shape(viaReference[0])).toEqual(shape(direct[0]));
  });

  it('does not fire the reveal hook, because a load is not a reveal', async () => {
    const source = paymentsSource();
    const audit = vi.fn();

    await withAuditedReveals('receiver', audit, async () =>
      resolver(source).resolve(reference(), { context })
    );

    expect(audit).not.toHaveBeenCalled();
  });

  it('runs the fetch under a child of the ambient context, so an audit hook survives', async () => {
    const duringFetch: (RevealContext | null)[] = [];

    class ContextReadingSource extends FakeSecretSource {
      protected override async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
        // Where a provider reveals its own token to authenticate the request,
        // under a child of whatever context is ambient.
        duringFetch.push(getCurrentRevealContext());

        return await super.fetchSecret(ref);
      }
    }

    const source = ContextReadingSource.of({
      'kv/payments/stripe': { payload: { kind: 'string', value: CANARY } },
    });

    await withAuditedReveals('receiver', vi.fn(), async () =>
      resolver(source).resolve(reference({ version: undefined }), { context })
    );

    // The caller's own name, so the provider's token reveal is recorded under
    // the operation that caused it, and the application's hook, which a bare
    // context would have dropped on the floor.
    expect(duringFetch).toHaveLength(1);
    expect(duringFetch[0]?.name).toBe('charge-worker');
    expect(duringFetch[0]?.reason).toBe('resolving a job reference');
    expect(typeof duringFetch[0]?.auditReveal).toBe('function');
  });
});

describe('a reference on the receiving side', () => {
  it('survives a redaction walk with its path intact, so a job stays debuggable', () => {
    const job = { job: 'charge', key: reference() };

    expect(redactInStructure(job)).toEqual(job);
    expect(containsSensitive(job)).toBe(false);
  });

  it('keeps the canary out of every failure a resolve can produce', async () => {
    const instance = resolver(untouchedSource());
    const failures: unknown[] = [];

    for (const candidate of [
      reference({ path: `kv/payments/${CANARY}/../..` }),
      reference({ store: CANARY }),
      reference({ version: `${CANARY}?x` }),
      reference({ path: `kv/root/${CANARY}` }),
      reference({ field: CANARY }),
    ]) {
      failures.push(await refusal(instance.resolve(candidate, { context })));
    }

    // The store being unreachable is the one failure that is not a refusal, and
    // it goes through a permitted reference so the fetch is actually attempted.
    const unreachable = FakeSecretSource.of({
      'kv/payments/stripe': new Error('the provider is unreachable'),
    });

    await expect(resolver(unreachable).resolve(reference(), { context })).rejects.toThrow(
      /unreachable/
    );

    for (const failure of failures) {
      assertNoCanary(CANARY, failure, 'a refusal');
      expect(errorText(failure)).not.toContain(CANARY);
    }
  });
});
