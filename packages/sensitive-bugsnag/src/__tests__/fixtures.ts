import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';

import Bugsnag from '@bugsnag/js';
import type { Client, Event } from '@bugsnag/js';

import type { BugsnagConfig } from '../install.js';

/**
 * A local endpoint standing in for Bugsnag, which is how every measurement in
 * this suite is taken.
 *
 * No test contacts Bugsnag and none mocks it. The real SDK is installed as a
 * dev dependency and driven end to end with the notify endpoint pointed at a
 * server on loopback, so the suite exercises the SDK's own callback ordering,
 * its `redactedKeys` pass and its `safe-json-stringify` encoder, and it asserts
 * on the bytes that would have gone over the wire.
 *
 * That last part is the whole reason for a socket rather than a swapped
 * delivery object. `redactedKeys` runs inside the encoder, and an assertion on
 * the event object never sees it; only the serialized body does. This is the
 * transport-level assertion the design's Q2 leaves as a test-only measure, and
 * for this vendor it is the only place the two scrubbing stages are visible
 * together.
 */
export interface Capture {
  /** Every request body received, in arrival order, as sent. */
  readonly bodies: { url: string; body: string }[];
  /** The bodies delivered to the notify endpoint. */
  events(): unknown[];
  /** The last event payload, which is what a single-notify case wants. */
  lastEvent(): Record<string, unknown>;
  /** The raw bytes of every delivery, joined, for a canary sweep. */
  raw(): string;
}

export interface Endpoint {
  readonly capture: Capture;
  readonly endpoints: { notify: string; sessions: string };
  close(): Promise<void>;
}

/** Start a capturing endpoint on loopback. */
export async function startEndpoint(): Promise<Endpoint> {
  const bodies: { url: string; body: string }[] = [];

  const server: Server = createServer((request, response) => {
    let body = '';

    request.setEncoding('utf8');
    request.on('data', (chunk: string) => {
      body += chunk;
    });
    request.on('end', () => {
      bodies.push({ url: request.url ?? '', body });
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end('{}');
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const { port } = server.address() as AddressInfo;

  const capture: Capture = {
    bodies,
    events() {
      return bodies
        .filter((entry) => entry.url.includes('notify'))
        .map((entry) => JSON.parse(entry.body) as unknown);
    },
    lastEvent() {
      const all = capture.events();
      const last = all[all.length - 1] as { events?: unknown[] } | undefined;
      const event = last?.events?.[0];

      if (event === undefined || event === null || typeof event !== 'object') {
        throw new Error('no event was delivered');
      }

      return event as Record<string, unknown>;
    },
    raw() {
      return bodies.map((entry) => entry.body).join('\n');
    },
  };

  return {
    capture,
    endpoints: {
      notify: `http://127.0.0.1:${String(port)}/notify`,
      sessions: `http://127.0.0.1:${String(port)}/sessions`,
    },
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/**
 * A client wired to a capturing endpoint.
 *
 * `createClient` rather than `start`, so cases do not share the module-level
 * singleton and a second `start` in one process is not warned about and
 * ignored.
 */
export function createClient(endpoint: Endpoint, config: Partial<BugsnagConfig> = {}): Client {
  // Each client installs an `uncaughtException` and an `unhandledRejection`
  // listener, and a suite creates one per case. The warning is a property of
  // driving the real SDK repeatedly in one process, not of anything this
  // package does.
  process.setMaxListeners(0);

  return Bugsnag.createClient({
    apiKey: '0'.repeat(32),
    endpoints: endpoint.endpoints,
    autoTrackSessions: false,
    // The SDK logs a warning per delivery failure and per config fallback, and
    // a suite that drives it a hundred times is otherwise unreadable.
    logger: null,
    ...config,
  });
}

/** Notify and wait for the delivery to finish, so a case never races the socket. */
export async function notify(
  client: Client,
  error: Error,
  onError?: (event: Event) => boolean
): Promise<void> {
  await new Promise<void>((resolve) => {
    if (onError === undefined) {
      client.notify(error, undefined, () => resolve());

      return;
    }

    client.notify(error, onError, () => resolve());
  });
}
