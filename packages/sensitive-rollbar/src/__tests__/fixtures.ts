import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import Rollbar from 'rollbar';

import type { RollbarConfig } from '../install.js';

/**
 * A local endpoint standing in for the Rollbar API, which is how every
 * measurement in this suite is taken.
 *
 * No test contacts Rollbar and none mocks it. The real SDK is installed as a
 * dev dependency and driven end to end with `endpoint` pointed at a server on
 * loopback, so the suite exercises the vendor's own transform pipeline, its
 * scrub pass, its truncation and its encoder, and it asserts on the bytes that
 * would have gone over the wire.
 *
 * That last part matters for this vendor in particular. Rollbar's own scrub
 * runs *before* the seam this package composes, so an assertion taken inside
 * the transform sees only half of what protects a payload. Only the body does.
 * This is the transport-level assertion the design's Q2 leaves as a test-only
 * measure.
 */
export interface Capture {
  /** Every request body received, in arrival order, as sent. */
  readonly bodies: string[];
  /** The `data` object of the last occurrence delivered. */
  last(): Record<string, unknown>;
  /** The raw bytes of every delivery, joined, for a canary sweep. */
  raw(): string;
}

export interface Endpoint {
  readonly capture: Capture;
  readonly url: string;
  close(): Promise<void>;
}

/** Start a capturing endpoint on loopback. */
export async function startEndpoint(): Promise<Endpoint> {
  const bodies: string[] = [];

  const server: Server = createServer((request, response) => {
    let body = '';

    request.setEncoding('utf8');
    request.on('data', (chunk: string) => {
      body += chunk;
    });
    request.on('end', () => {
      bodies.push(body);
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end('{"err":0,"result":{"id":1,"uuid":"u"}}');
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const { port } = server.address() as AddressInfo;

  const capture: Capture = {
    bodies,
    last() {
      const body = bodies[bodies.length - 1];

      if (body === undefined) {
        throw new Error('no occurrence was delivered');
      }

      const parsed = JSON.parse(body) as { data?: Record<string, unknown> };

      if (parsed.data === undefined) {
        throw new Error('delivered body carried no data');
      }

      return parsed.data;
    },
    raw() {
      return bodies.join('\n');
    },
  };

  return {
    capture,
    url: `http://127.0.0.1:${String(port)}/api/1/item/`,
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** A client wired to a capturing endpoint. */
export function createClient(endpoint: Endpoint, config: RollbarConfig = {}): Rollbar {
  return new Rollbar({
    accessToken: '0'.repeat(32),
    endpoint: endpoint.url,
    captureUncaught: false,
    captureUnhandledRejections: false,
    ...config,
  });
}

/**
 * Report an error and wait for the delivery to finish, so a case never races
 * the socket.
 *
 * The arguments are passed positionally and only when present. Rollbar decides
 * what each one is from its shape, and an empty object handed over as the
 * request is claimed as the custom data instead, which silently moves every
 * field a case was asserting on.
 */
export async function report(
  client: Rollbar,
  error: Error,
  request?: Record<string, unknown>,
  custom?: Record<string, unknown>
): Promise<void> {
  const args: unknown[] = [error];

  if (request !== undefined) {
    args.push(request);
  }

  if (custom !== undefined) {
    args.push(custom);
  }

  await new Promise<void>((resolve) => {
    client.error(...(args as Parameters<Rollbar['error']>), () => resolve());
  });
}

/**
 * A request as an express middleware would hand one over.
 *
 * Rollbar assembles `data.request` from this itself, at transform position 6,
 * before its own scrub and long before this package's seam.
 */
export function requestWith(canary: string): Record<string, unknown> {
  return {
    url: `/pay/42?token=${canary}&page=2`,
    method: 'POST',
    headers: {
      host: '127.0.0.1:8080',
      authorization: `Bearer ${canary}`,
      cookie: `session=${canary}`,
      'x-api-key': canary,
      'x-trace': 'keep-me',
    },
    body: { client_secret: canary, amount: 10 },
    socket: { remoteAddress: '1.2.3.4' },
  };
}
