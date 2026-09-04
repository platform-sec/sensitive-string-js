import * as Sentry from '@sentry/node';
import type { NodeOptions } from '@sentry/node';

/**
 * The envelope shape, read off the transport option the SDK takes.
 *
 * `@sentry/node` re-exports its event types but not `Envelope`, which lives in
 * `@sentry/core`. Deriving it from `transport` keeps `@sentry/core` out of
 * this package and ties the type to the callback that has to accept it.
 */
type Envelope = Parameters<ReturnType<NonNullable<NodeOptions['transport']>>['send']>[0];

/**
 * A capturing transport, which is how every measurement in this suite is
 * taken.
 *
 * No test here contacts Sentry. The real SDK is installed as a dev dependency
 * and driven end to end with the network replaced, so the suite exercises the
 * SDK's own normalizer, hook ordering, and envelope encoding rather than a
 * mock of them. A mock of the SDK would agree with whatever this package
 * believed when it was written, which is the one thing worth testing.
 */
export interface Capture {
  readonly envelopes: Envelope[];
  /** Every event item across every envelope, in order. */
  events(): Record<string, unknown>[];
  /** The last event item, which is the one a single-capture test wants. */
  lastEvent(): Record<string, unknown>;
}

export function createCapture(): {
  capture: Capture;
  transport: NonNullable<NodeOptions['transport']>;
} {
  const envelopes: Envelope[] = [];

  const capture: Capture = {
    envelopes,
    events() {
      const found: Record<string, unknown>[] = [];

      for (const envelope of envelopes) {
        for (const item of envelope[1]) {
          const [header, payload] = item as [{ type?: string }, unknown];

          if (header.type === 'event' && payload !== null && typeof payload === 'object') {
            found.push(payload as Record<string, unknown>);
          }
        }
      }

      return found;
    },
    lastEvent() {
      const all = capture.events();
      const last = all[all.length - 1];

      if (last === undefined) {
        throw new Error('no event was captured');
      }

      return last;
    },
  };

  return {
    capture,
    transport: () => ({
      send: (envelope: Envelope) => {
        envelopes.push(envelope);

        return Promise.resolve({});
      },
      flush: () => Promise.resolve(true),
    }),
  };
}

/**
 * Install the SDK's async context strategy before any case runs.
 *
 * `Sentry.init` installs it, and until it is installed `withIsolationScope`
 * forks under a different implementation than the one `Sentry.addEventProcessor`
 * resolves through afterwards. Measured: without this, the first `init` inside
 * a `withIsolationScope` registers its event processor on the *root* isolation
 * scope rather than on the fork, so that one scrubber survives every later
 * case. The symptom is a second scrubber running first and normalizing every
 * wrapped value, which shows up as an event carrying `sensitive.classes` and a
 * marker sighting but no labels.
 *
 * A bare `init` with no integrations installs the strategy and leaves nothing
 * behind.
 */
let strategyInstalled = false;

function installAsyncContextStrategy(): void {
  if (strategyInstalled) {
    return;
  }

  // Each `init` adds a `beforeExit` listener, and a suite calls it once per
  // case. The warning is a property of driving the real SDK repeatedly in one
  // process, not of anything this package does.
  process.setMaxListeners(0);

  Sentry.init({ dsn: 'https://abc@o0.ingest.sentry.io/0', defaultIntegrations: false });
  strategyInstalled = true;
}

/**
 * Run one case against a real client, isolated from every other case.
 *
 * The integration registers its scope event processor through
 * `Sentry.addEventProcessor`, which targets the isolation scope. Without a
 * fresh isolation scope per case the processors accumulate, one per `init`,
 * and every event is scrubbed and reported as many times as there have been
 * cases. Isolating the scope is what keeps a report meaning one payload.
 */
export async function runIsolated(
  options: NodeOptions,
  body: () => void | Promise<void>
): Promise<void> {
  installAsyncContextStrategy();

  await Sentry.withIsolationScope(async () => {
    await Sentry.withScope(async () => {
      Sentry.init({
        dsn: 'https://abc@o0.ingest.sentry.io/0',
        defaultIntegrations: false,
        ...options,
      });

      await body();
      await Sentry.flush(2000);
    });
  });
}

/**
 * A request as the SDK's own request data assembly produces it.
 *
 * Measured on `@sentry/node` 10.73.0 at stock `dataCollection`, with no
 * `sendDefaultPii`: every one of these fields reaches the outgoing event
 * verbatim when nothing is scrubbing.
 */
export function normalizedRequest(canary: string): Record<string, unknown> {
  return {
    url: `http://127.0.0.1:8080/pay/42?token=${canary}&page=2`,
    method: 'POST',
    headers: {
      authorization: `Bearer ${canary}`,
      cookie: `session=${canary}`,
      'x-api-key': canary,
      'x-trace': 'keep-me',
    },
    query_string: `token=${canary}&page=2`,
    data: { client_secret: canary, refresh_token: canary, amount: 10 },
    cookies: { session: canary },
  };
}

/** Attach a request to the active scope the way the SDK's own integrations do. */
export function attachRequest(canary: string): void {
  Sentry.getCurrentScope().setSDKProcessingMetadata({
    normalizedRequest: normalizedRequest(canary),
  });
}
