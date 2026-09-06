/**
 * The per-client stripping table, checked against the clients themselves.
 *
 * `isStrippedAcrossOrigins` decides whether a request carrying a credential
 * may keep following redirects, and it answers from a table of what each
 * client was measured to drop. A table like that is worth exactly as much as
 * its last measurement, so this re-runs the measurement: two loopback servers
 * on different ports, which is a different origin under the scheme/host/port
 * rule, a 302 from the first to the second, and the second recording what
 * arrived.
 *
 * A client that changes its behaviour in a future release fails here rather
 * than quietly widening what the table promises.
 *
 * The clients are peer dependencies of the wrapper packages rather than of
 * this one, so each is imported dynamically and its case skips where it cannot
 * be resolved.
 */

import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { isStrippedAcrossOrigins, measuredClients } from '../auth.js';

const PROBES: Readonly<Record<string, string>> = {
  authorization: 'Bearer CANARY_AUTH',
  cookie: 'session=CANARY_COOKIE',
  'proxy-authorization': 'Basic CANARY_PROXY',
  'x-api-key': 'CANARY_APIKEY',
};

const PROBE_NAMES = Object.keys(PROBES);

let landing: http.Server;
let redirector: http.Server;
let start = '';
let received: http.IncomingHttpHeaders | null = null;

function port(server: http.Server): number {
  return (server.address() as AddressInfo).port;
}

beforeAll(async () => {
  landing = http.createServer((req, res) => {
    received = { ...req.headers };
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
  });

  redirector = http.createServer((_req, res) => {
    res.writeHead(302, { location: `http://127.0.0.1:${port(landing)}/landed` });
    res.end();
  });

  const listen = (s: http.Server): Promise<void> =>
    new Promise((resolve) => s.listen(0, '127.0.0.1', () => resolve()));

  await listen(landing);
  await listen(redirector);
  start = `http://127.0.0.1:${port(redirector)}/start`;
});

afterAll(() => {
  landing.close();
  redirector.close();
});

/** Header names that reached the second origin. */
function forwarded(): string[] {
  if (received === null) {
    throw new Error('no request reached the second origin');
  }

  const seen = received;

  return PROBE_NAMES.filter((name) => seen[name] !== undefined);
}

async function resolves(specifier: string): Promise<boolean> {
  try {
    await import(specifier);

    return true;
  } catch {
    return false;
  }
}

const CASES: ReadonlyArray<{ client: string; specifier: string; send: () => Promise<void> }> = [
  {
    client: 'fetch',
    specifier: 'node:http',
    send: async () => {
      await fetch(start, { headers: { ...PROBES }, redirect: 'follow' });
    },
  },
  {
    client: 'axios',
    specifier: 'axios',
    send: async () => {
      const { default: axios } = await import('axios');
      await axios.get(start, { headers: { ...PROBES }, maxRedirects: 5 });
    },
  },
  {
    client: 'got',
    specifier: 'got',
    send: async () => {
      const { default: got } = await import('got');
      await got(start, { headers: { ...PROBES }, followRedirect: true, retry: { limit: 0 } });
    },
  },
  {
    client: 'ky',
    specifier: 'ky',
    send: async () => {
      const { default: ky } = await import('ky');
      await ky.get(start, { headers: { ...PROBES }, retry: 0 });
    },
  },
  {
    client: 'undici',
    specifier: 'undici',
    send: async () => {
      const undici = await import('undici');
      const dispatcher = new undici.Agent().compose(
        undici.interceptors.redirect({ maxRedirections: 5 })
      );
      const res = await undici.request(start, { headers: { ...PROBES }, dispatcher });
      await res.body.dump();
      await dispatcher.close();
    },
  },
];

describe('cross-origin redirect stripping, measured', () => {
  it('has a case for every client in the table', () => {
    // A client added to the table without a case here would be exempt on an
    // unverified claim, which is the failure this file exists to prevent.
    expect(CASES.map((c) => c.client).sort()).toEqual([...measuredClients()].sort());
  });

  for (const { client, specifier, send } of CASES) {
    it(`${client} strips exactly what the table says it strips`, async () => {
      if (!(await resolves(specifier))) {
        return;
      }

      received = null;
      await send();

      const survived = forwarded();
      const claimedStripped = PROBE_NAMES.filter((name) => isStrippedAcrossOrigins(name, client));
      const claimedForwarded = PROBE_NAMES.filter((name) => !isStrippedAcrossOrigins(name, client));

      // Both directions. A header the table calls stripped must not arrive, and
      // a header the table does not exempt must actually be at risk: if a
      // client quietly started stripping `x-api-key`, the default would be
      // stricter than it needs to be and the table should say so.
      expect(survived.sort()).toEqual(claimedForwarded.sort());
      for (const name of claimedStripped) {
        expect(survived).not.toContain(name);
      }
    });
  }

  it('forwards a custom auth header, which is the reason this package exists', async () => {
    received = null;
    await fetch(start, { headers: { ...PROBES }, redirect: 'follow' });

    expect(forwarded()).toContain('x-api-key');
  });
});
