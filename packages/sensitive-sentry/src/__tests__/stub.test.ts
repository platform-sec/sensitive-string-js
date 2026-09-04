import * as Sentry from '@sentry/node';
import { describe, expect, it, vi } from 'vitest';

import { TIGHTENED_CATEGORIES, recommendedDataCollection } from '../collection.js';
import { withSensitiveScrubbing } from '../install.js';
import { CLASSES_TAG, SCRUB_FAILED_TAG, buildBreadcrumbStub, buildEventStub } from '../stub.js';
import { createCapture, runIsolated } from './fixtures.js';

const CANARY = 'LEAKED_SECRET_stub_5c8b';

/** A value the walk cannot finish: enumerating it throws. */
function unwalkable(): Record<string, unknown> {
  const hostile: Record<string, unknown> = {};

  Object.defineProperty(hostile, 'boom', {
    enumerable: true,
    get() {
      throw new Error('property read exploded');
    },
  });

  return hostile;
}

describe('the stub, through the real SDK', () => {
  // TEST-SENTRY-STUB
  it('keeps the error and drops the payload when scrubbing throws', async () => {
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport }), () => {
      Sentry.getCurrentScope().setExtra('hostile', unwalkable());
      Sentry.getCurrentScope().setExtra('access_token', CANARY);
      Sentry.captureException(new TypeError('payment failed'));
    });

    const event = capture.lastEvent();
    const exception = event['exception'] as { values: { type: string; value: string }[] };

    // The signal that an error of this shape happened survives.
    expect(exception.values[0]?.type).toBe('TypeError');
    // Its payload does not, and neither does the canary beside it.
    expect(event['extra']).toBeUndefined();
    expect(JSON.stringify(event)).not.toContain(CANARY);
    expect((event['tags'] as Record<string, string>)[SCRUB_FAILED_TAG]).toBe('true');
  });

  it('is a real event rather than a client-side drop', async () => {
    // Returning null would tell Sentry the event was deliberately discarded.
    // Losing the error entirely is the outcome the stub exists to avoid.
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport }), () => {
      Sentry.getCurrentScope().setExtra('hostile', unwalkable());
      Sentry.captureException(new Error('boom'));
    });

    expect(capture.events()).toHaveLength(1);
  });

  it('reports failed: true so a scrubber broken on one shape is visible', async () => {
    const { transport } = createCapture();
    const onScrub = vi.fn();

    await runIsolated(withSensitiveScrubbing({ transport }, { onScrub }), () => {
      Sentry.getCurrentScope().setExtra('hostile', unwalkable());
      Sentry.captureException(new Error('boom'));
    });

    const reports = onScrub.mock.calls.map((call) => call[0] as { failed: boolean; kind: string });

    expect(reports.some((report) => report.failed && report.kind === 'event')).toBe(true);
  });

  it('does not throw to the caller of captureException', async () => {
    const { transport } = createCapture();
    let threw = false;

    await runIsolated(withSensitiveScrubbing({ transport }), () => {
      try {
        Sentry.getCurrentScope().setExtra('hostile', unwalkable());
        Sentry.captureException(new Error('boom'));
      } catch {
        threw = true;
      }
    });

    expect(threw).toBe(false);
  });

  it('replaces a breadcrumb it could not walk, keeping its category', async () => {
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport }), () => {
      Sentry.addBreadcrumb({ category: 'fetch', data: unwalkable() });
      Sentry.captureException(new Error('boom'));
    });

    const crumbs = capture.lastEvent()['breadcrumbs'] as { category: string; data: unknown }[];

    expect(crumbs[0]?.category).toBe('fetch');
    expect(crumbs[0]?.data).toEqual({ [SCRUB_FAILED_TAG]: true });
  });
});

describe('stub construction', () => {
  it('carries the grouping data and nothing that was in the payload', () => {
    const stub = buildEventStub({
      event_id: 'abc',
      timestamp: 1,
      platform: 'node',
      level: 'error',
      fingerprint: ['charge'],
      message: `failed for ${CANARY}`,
      extra: { token: CANARY },
      request: { headers: { authorization: CANARY } },
      exception: { values: [{ type: 'RangeError', value: `bad ${CANARY}` }] },
    });

    expect(stub.event_id).toBe('abc');
    expect(stub.fingerprint).toEqual(['charge']);
    expect(stub.level).toBe('error');
    expect(stub.exception?.values?.[0]?.type).toBe('RangeError');
    expect(stub.tags?.[SCRUB_FAILED_TAG]).toBe('true');
    expect(JSON.stringify(stub)).not.toContain(CANARY);
    expect(stub.message).toBeUndefined();
    expect(stub.extra).toBeUndefined();
    expect(stub.request).toBeUndefined();
  });

  it('omits absent fields rather than setting them undefined', () => {
    // `exactOptionalPropertyTypes` is on, and a key present with an undefined
    // value serializes differently from an absent one.
    const stub = buildEventStub({});

    expect('event_id' in stub).toBe(false);
    expect('exception' in stub).toBe(false);
  });

  it('does not carry a breadcrumb message or data through', () => {
    const stub = buildBreadcrumbStub({
      category: 'http',
      level: 'warning',
      timestamp: 5,
      message: `GET ${CANARY}`,
      data: { url: CANARY },
    });

    expect(stub.category).toBe('http');
    expect(stub.level).toBe('warning');
    expect(stub.timestamp).toBe(5);
    expect(JSON.stringify(stub)).not.toContain(CANARY);
  });
});

describe('recommendedDataCollection', () => {
  it('turns off exactly the categories it documents', () => {
    expect(recommendedDataCollection.cookies).toBe(false);
    expect(recommendedDataCollection.httpBodies).toEqual([]);
    expect(recommendedDataCollection.databaseQueryData).toBe(false);
    expect(recommendedDataCollection.genAI).toEqual({ inputs: false, outputs: false });
  });

  it('keeps the categories a scrubbed report still needs', () => {
    // Headers and query parameters are scrubbed by name and are most of what
    // makes an error report actionable.
    expect(recommendedDataCollection.httpHeaders).toEqual({ request: true, response: true });
    expect(recommendedDataCollection.urlQueryParams).toBe(true);
  });

  it('lists every category it tightens, so the README cannot drift', () => {
    expect([...TIGHTENED_CATEGORIES].sort()).toEqual(
      ['cookies', 'databaseQueryData', 'genAI', 'httpBodies'].sort()
    );
  });

  it('is inert until a caller spreads it', async () => {
    // The package does not change what Sentry collects on anyone's behalf.
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport }), () => {
      Sentry.captureException(new Error('boom'));
    });

    expect(capture.lastEvent()['tags']).toBeUndefined();
    expect(CLASSES_TAG).toBe('sensitive.classes');
  });
});
