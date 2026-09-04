import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve, sep } from 'node:path';

import got14 from 'got14';
import { bearer } from '@platform-sec/sensitive-string-http';
import { findMarker, startRecordingServer } from '@platform-sec/sensitive-string-http/testing';
import type { RecordingServer } from '@platform-sec/sensitive-string-http/testing';
import { findRawValue } from '@platform-sec/sensitive-string-testing';

import { createSensitiveGot } from '../client.js';
import { CANARY, token } from './fixtures.js';

/**
 * A compatibility test rather than a second copy of the suite, matching how
 * `sensitive-express` covers Express 4.
 *
 * The peer range claims got 14. What actually differs between the majors, for
 * this package: got 16 is ESM-only and dropped the named `got` export that 14
 * provided alongside the default, so the package imports the default; and got
 * 16 requires Node 22. The option names, the hooks and the settled-object
 * shapes this wrapper reaches for are the same, and that is what is asserted
 * here.
 */

let server: RecordingServer;

beforeEach(async () => {
  server = await startRecordingServer();
});

afterEach(async () => {
  await server.close();
});

describe('got 14', () => {
  it('resolves the alias to got 14', () => {
    // got's `exports` map has no `./package.json` entry, so neither an import
    // nor `require` reaches the manifest the way the Express 4 alias test does.
    // The entry point resolves, so the manifest is read from beside it.
    //
    // `createRequire` is anchored on the working directory rather than on
    // `import.meta.url`, because the repository program type-checks these files
    // against a `NodeNext`/CommonJS-capable target where `import.meta` is not
    // available. Vitest runs from the repository root.
    const from = createRequire(resolve(process.cwd(), 'packages/sensitive-got/src/x.js'));
    const entry = from.resolve('got14');
    const root = entry.slice(0, entry.lastIndexOf(`${sep}dist${sep}`));
    const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
      version: string;
    };

    expect(manifest.version.startsWith('14.')).toBe(true);
  });

  it('reveals at the wire and leaves no marker', async () => {
    const api = createSensitiveGot(
      got14.extend({ prefixUrl: server.origin, retry: { limit: 0 } }),
      {
        allowInsecureTransport: true,
      }
    );

    await api.post(
      '/charges',
      { card: { number: token() } },
      {
        headers: { authorization: bearer(token()) },
      }
    );

    expect(server.requests[0]?.headers['authorization']).toBe(`Bearer ${CANARY}`);
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('scrubs both settlement paths the same way', async () => {
    const api = createSensitiveGot(
      got14.extend({ prefixUrl: server.origin, retry: { limit: 0 } }),
      {
        allowInsecureTransport: true,
      }
    );

    const response = await api.get('/x', { headers: { authorization: bearer(token()) } });

    expect(findRawValue(response, CANARY)).toBeUndefined();

    server.reply({ status: 401, body: '{"e":1}' });

    const error = await api
      .get('/x', { headers: { authorization: bearer(token()) }, searchParams: { t: token() } })
      .catch((caught: unknown) => caught);

    expect(findRawValue(error, CANARY)).toBeUndefined();
  });
});
