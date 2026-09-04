import { describe, it, expect } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

import { SecretWriteRefusedError } from './errors.js';
import { isWritable, put, putJson } from './write.js';
import type { WritableSecretSource } from './write.js';
import { CorruptingSecretSource, FakeSecretSource } from './__tests__/fake-source.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CONTEXT = { name: 'rotate-db-credential', reason: 'scheduled rotation' };

function writable(): FakeSecretSource {
  return FakeSecretSource.of({ 'prod/db': { payload: { kind: 'string', value: 'old' } } });
}

describe('isWritable', () => {
  it('recognises a source with a write half', () => {
    expect(isWritable(writable())).toBe(true);
  });
});

describe('put', () => {
  it('reveals an instance under the caller context and stores the raw value', async () => {
    const source = writable();
    const revealed: string[] = [];
    const value = new SensitiveString(CANARY, 'credential', 'db#password');

    await put(source, 'prod/db', value, {
      context: {
        ...CONTEXT,
        auditReveal: (read) => revealed.push(read.label ?? ''),
      },
    });

    expect(source.writes).toHaveLength(1);
    expect(source.writes[0]?.payload).toEqual({ kind: 'string', value: CANARY });
    expect(revealed).toEqual(['db#password']);
  });

  it('accepts a plain string', async () => {
    const source = writable();

    await put(source, 'prod/db', CANARY, { context: CONTEXT });

    expect(source.writes[0]?.payload).toEqual({ kind: 'string', value: CANARY });
  });

  describe('the marker refusal', () => {
    it('refuses a value that was stringified by template interpolation', async () => {
      const source = writable();
      const value = new SensitiveString(CANARY, 'credential');
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the implicit coercion is the subject of this test
      const interpolated = `${value}`;

      await expect(
        put(source, 'prod/db', interpolated, { context: CONTEXT })
      ).rejects.toBeInstanceOf(SecretWriteRefusedError);
      expect(source.writes).toHaveLength(0);
    });

    it('refuses a JSON body built from a mix of wrapped and raw values', async () => {
      const source = writable();
      const body = JSON.stringify({
        username: 'app',
        password: new SensitiveString(CANARY, 'credential'),
      });

      await expect(put(source, 'prod/db', body, { context: CONTEXT })).rejects.toThrow(
        /redaction marker/
      );
      expect(source.writes).toHaveLength(0);
    });

    it('names the fix', async () => {
      const source = writable();

      await expect(
        put(source, 'prod/db', '[REDACTED:credential]', { context: CONTEXT })
      ).rejects.toThrow(/Call reveal\(\) with a context/);
    });

    it('reports the refusal reason', async () => {
      const source = writable();

      try {
        await put(source, 'prod/db', '[REDACTED:credential]', { context: CONTEXT });
        expect.unreachable('put should have thrown');
      } catch (error) {
        expect((error as SecretWriteRefusedError).reason).toBe('marker');
      }
    });
  });

  describe('the context requirement', () => {
    it('refuses a write with no context', async () => {
      const source = writable();

      await expect(
        put(source, 'prod/db', CANARY, {} as unknown as { context: typeof CONTEXT })
      ).rejects.toThrow(/no reveal context/);
      expect(source.writes).toHaveLength(0);
    });

    it('refuses a context with no name', async () => {
      const source = writable();

      await expect(put(source, 'prod/db', CANARY, { context: { name: '' } })).rejects.toThrow(
        /no reveal context/
      );
    });
  });

  describe('read-back verification', () => {
    it('is on by default and reads the new version back', async () => {
      const source = writable();

      const written = await put(source, 'prod/db', CANARY, { context: CONTEXT });

      expect(written.version).toBe('v2');
      expect(source.calls.some((call) => call.version === 'v2')).toBe(true);
    });

    it('throws when the stored value is not what was sent', async () => {
      const source = CorruptingSecretSource.of({
        'prod/db': { payload: { kind: 'string', value: 'old' } },
      });

      try {
        await put(source, 'prod/db', CANARY, { context: CONTEXT });
        expect.unreachable('put should have thrown');
      } catch (error) {
        expect((error as SecretWriteRefusedError).reason).toBe('read-back');
        expect((error as Error).message).not.toContain(CANARY);
      }
    });

    it('can be turned off, and then makes no second call', async () => {
      const source = writable();

      await put(source, 'prod/db', CANARY, { context: CONTEXT, verifyReadBack: false });

      expect(source.calls).toHaveLength(0);
    });
  });
});

describe('putJson', () => {
  function mapSource(): FakeSecretSource {
    return FakeSecretSource.of({
      'kv/prod/db': { payload: { kind: 'map', value: { password: 'old' } } },
    });
  }

  it('writes a field map and reads it back', async () => {
    const source = mapSource();

    const written = await putJson(
      source,
      'kv/prod/db',
      { username: 'app', password: new SensitiveString(CANARY, 'credential') },
      { context: CONTEXT }
    );

    expect(source.writes[0]?.payload).toEqual({
      kind: 'map',
      value: { username: 'app', password: CANARY },
    });
    expect(written.version).toBe('v2');
  });

  it('refuses when any field holds a marker', async () => {
    const source = mapSource();
    const value = new SensitiveString(CANARY, 'credential');

    await expect(
      putJson(
        source,
        'kv/prod/db',
        // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the implicit coercion is the subject of this test
        { username: 'app', password: `${value}` },
        { context: CONTEXT }
      )
    ).rejects.toThrow(/field 'password'/);
    expect(source.writes).toHaveLength(0);
  });

  it('throws when a field does not read back as written', async () => {
    const source = CorruptingSecretSource.of({
      'kv/prod/db': { payload: { kind: 'map', value: { password: 'old' } } },
    });

    await expect(
      putJson(source, 'kv/prod/db', { password: CANARY }, { context: CONTEXT })
    ).rejects.toThrow(/did not read back as written/);
  });
});

describe('the write entry point', () => {
  it('takes any writable source rather than a provider-specific one', () => {
    const source: WritableSecretSource = writable();

    expect(typeof source.writeSecret).toBe('function');
    expect(typeof source.get).toBe('function');
  });
});
