import { describe, it, expect } from 'vitest';
import { SecretPayloadError } from '@platform-sec/sensitive-string-secrets';

import {
  kvMetadataPath,
  kvReadPath,
  kvWriteBody,
  kvWritePath,
  kvWrittenVersion,
  parseKvResponse,
  splitMount,
} from './kv.js';
import { kvV1Body, kvV2Body } from './__tests__/fake-transport.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const REF = { path: 'kv/prod/db' };

describe('splitMount', () => {
  it('splits a mount from the path below it', () => {
    expect(splitMount('kv/prod/db')).toEqual({ mount: 'kv', rest: 'prod/db' });
  });

  it('handles a bare mount', () => {
    expect(splitMount('kv')).toEqual({ mount: 'kv', rest: '' });
  });

  it('ignores a leading slash', () => {
    expect(splitMount('/kv/prod/db')).toEqual({ mount: 'kv', rest: 'prod/db' });
  });
});

describe('kvReadPath', () => {
  it('inserts the data segment for KV v2', () => {
    expect(kvReadPath('kv/prod/db', 2)).toBe('kv/data/prod/db');
  });

  it('leaves a KV v1 path alone', () => {
    expect(kvReadPath('secret/prod/db', 1)).toBe('secret/prod/db');
  });

  it('is the same path a write uses', () => {
    expect(kvWritePath('kv/prod/db', 2)).toBe(kvReadPath('kv/prod/db', 2));
  });
});

describe('kvMetadataPath', () => {
  it('addresses the KV v2 metadata endpoint', () => {
    expect(kvMetadataPath('kv/prod/db')).toBe('kv/metadata/prod/db');
  });
});

describe('parseKvResponse', () => {
  describe('KV v2', () => {
    it('reads the payload from data.data', () => {
      const read = parseKvResponse(kvV2Body({ password: CANARY }), 2, REF);

      expect(read.data).toEqual({ password: CANARY });
    });

    it('takes the concrete version from data.metadata.version', () => {
      const read = parseKvResponse(kvV2Body({ a: 'b' }), 2, {
        path: 'kv/prod/db',
        version: 'latest',
      });

      expect(read.version).toBe('7');
    });

    it('puts custom_metadata on the ref metadata, since it is not secret', () => {
      const read = parseKvResponse(
        kvV2Body({ a: 'b' }, { custom_metadata: { owner: 'payments', tier: 'prod' } }),
        2,
        REF
      );

      expect(read.metadata['owner']).toBe('payments');
      expect(read.metadata['tier']).toBe('prod');
    });

    it('keeps the non-secret version metadata', () => {
      const read = parseKvResponse(kvV2Body({ a: 'b' }), 2, REF);

      expect(read.metadata['created_time']).toBe('2026-09-01T00:00:00Z');
      expect(read.metadata['destroyed']).toBe(false);
    });

    it('reports no lease, since a KV read has none', () => {
      const read = parseKvResponse(kvV2Body({ a: 'b' }), 2, REF);

      expect(read.leaseDurationSeconds).toBe(0);
      expect(read.renewable).toBe(false);
    });

    it('names the likely cause when a KV v1 response arrives', () => {
      expect(() => parseKvResponse(kvV1Body({ password: CANARY }), 2, REF)).toThrow(
        /if it is really KV v1/
      );
    });

    it('does not put the payload into that diagnostic', () => {
      try {
        parseKvResponse(kvV1Body({ password: CANARY }), 2, REF);
        expect.unreachable('parseKvResponse should have thrown');
      } catch (error) {
        expect((error as Error).message).not.toContain(CANARY);
      }
    });
  });

  describe('KV v1', () => {
    it('reads the payload from data', () => {
      const read = parseKvResponse(kvV1Body({ password: CANARY }), 1, REF);

      expect(read.data).toEqual({ password: CANARY });
    });

    it('names the likely cause when a KV v2 response arrives', () => {
      // Getting this wrong yields a payload whose fields are `data` and
      // `metadata` rather than the ones the caller named, which would wrap two
      // containers and find none of the declared fields.
      expect(() => parseKvResponse(kvV2Body({ password: CANARY }), 1, REF)).toThrow(
        /configure it as KV v2/
      );
    });

    it('does not mistake a real payload with those two keys for a v2 response', () => {
      const read = parseKvResponse(kvV1Body({ data: 'a', metadata: 'b', extra: 'c' }), 1, REF);

      expect(read.data).toEqual({ data: 'a', metadata: 'b', extra: 'c' });
    });
  });

  describe('malformed responses', () => {
    it('rejects a body that is not an object', () => {
      expect(() => parseKvResponse('nope', 2, REF)).toThrow(SecretPayloadError);
    });

    it('rejects a body with no data', () => {
      expect(() => parseKvResponse({ request_id: 'a' }, 2, REF)).toThrow(/returned no data/);
    });
  });
});

describe('kvWriteBody', () => {
  it('nests under data for KV v2', () => {
    expect(kvWriteBody({ password: CANARY }, 2)).toEqual({ data: { password: CANARY } });
  });

  it('sends the fields directly for KV v1', () => {
    expect(kvWriteBody({ password: CANARY }, 1)).toEqual({ password: CANARY });
  });
});

describe('kvWrittenVersion', () => {
  it('reads the new version off a KV v2 write response', () => {
    expect(kvWrittenVersion({ data: { version: 8 } }, 2)).toBe('8');
  });

  it('reports KV v1 as unversioned rather than inventing a number', () => {
    expect(kvWrittenVersion(undefined, 1)).toBe('unversioned');
  });

  it('reports unknown where KV v2 gave no version', () => {
    expect(kvWrittenVersion({}, 2)).toBe('unknown');
  });
});
