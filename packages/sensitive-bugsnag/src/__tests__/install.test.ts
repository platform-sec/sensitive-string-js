import type { Client } from '@bugsnag/js';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { DEFAULT_DENY_KEYS, type ScrubReport } from '@platform-sec/sensitive-string-scrub';
import { createCanary } from '@platform-sec/sensitive-string-scrub/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { REPORT_SECTION } from '../event.js';
import { BugsnagScrubbingError, isApplied, withSensitiveScrubbing } from '../install.js';
import { BUGSNAG_BODY_PATHS } from '../paths.js';
import { createClient, notify, startEndpoint, type Endpoint } from './fixtures.js';

let endpoint: Endpoint;

beforeEach(async () => {
  endpoint = await startEndpoint();
});

afterEach(async () => {
  await endpoint.close();
});

const API_KEY = '0'.repeat(32);

describe('redactedKeys', () => {
  it('unions the resolved denylist into the caller list', () => {
    const config = withSensitiveScrubbing({
      apiKey: API_KEY,
      redactedKeys: ['x-internal-signature', /^internal_/],
    });

    const keys = config.redactedKeys ?? [];

    expect(keys).toContain('x-internal-signature');
    expect(keys.some((entry) => entry instanceof RegExp)).toBe(true);

    for (const key of DEFAULT_DENY_KEYS) {
      expect(keys).toContain(key.toLowerCase());
    }
  });

  it('is a superset of the vendor own default', () => {
    // Bugsnag ships exactly one key. Invariant 15 is that the resolved list
    // never loses what the vendor already had.
    const keys = withSensitiveScrubbing({ apiKey: API_KEY }).redactedKeys ?? [];

    expect(keys).toContain('password');
  });

  it('drops a key the caller took back with allowKeys', () => {
    // Feeding the resolved list rather than the raw defaults is what makes
    // `allowKeys` reach the vendor's own encoder as well as the walk. Without
    // it the walk would keep the value and the encoder would redact it anyway.
    const keys =
      withSensitiveScrubbing(
        { apiKey: API_KEY },
        { allowKeys: [{ key: 'token', reason: 'opaque request id, not a credential' }] }
      ).redactedKeys ?? [];

    expect(keys).not.toContain('token');
    expect(keys).toContain('access_token');
  });

  it('refuses a list the SDK would silently replace with its default', () => {
    // An invalid `redactedKeys` makes the SDK warn and fall back to
    // `['password']`, which would undo the whole union without failing
    // anything. Better to say so at start.
    expect(() =>
      withSensitiveScrubbing({ apiKey: API_KEY, redactedKeys: [42 as unknown as string] })
    ).toThrow(BugsnagScrubbingError);
  });
});

describe('composition', () => {
  it('composes a caller callback rather than replacing it, and runs after it', async () => {
    const seen: string[] = [];
    const client = createClient(
      endpoint,
      withSensitiveScrubbing({
        apiKey: API_KEY,
        onError: (event) => {
          seen.push('caller');
          event.addMetadata('creds', { access_token: 'raw' });

          return true;
        },
      })
    );

    await notify(client, new Error('boom'));

    const event = endpoint.capture.lastEvent();
    const metadata = event['metaData'] as { creds: { access_token: string } };

    expect(seen).toEqual(['caller']);
    // Censored, and by the walk rather than only by the encoder, which is what
    // "runs after" buys: a caller callback cannot add raw data behind it.
    //
    // The delivered string is Bugsnag's `[REDACTED]` rather than this library's
    // `[SCRUBBED]`, because `access_token` is in the `redactedKeys` union too
    // and the encoder runs last, over a value the walk had already replaced.
    // Both censors are equally safe and the vendor's wins by position. See
    // `app metadata` below for a region the encoder does not reach, where this
    // package's own censor is what arrives.
    expect(metadata.creds.access_token).toBe('[REDACTED]');
  });

  it('is the only thing scrubbing a region the vendor encoder does not reach', async () => {
    // `redactedKeys` applies under `metaData`, breadcrumb metadata, `request`
    // and `response`, and nowhere else. `app` is where this package's own
    // censor is visible unmixed with the vendor's.
    const client = createClient(
      endpoint,
      withSensitiveScrubbing({
        apiKey: API_KEY,
        onError: (event) => {
          event.app = { ...event.app, api_key: 'raw', version: '1.2.3' };

          return true;
        },
      })
    );

    await notify(client, new Error('boom'));

    const app = endpoint.capture.lastEvent()['app'] as { api_key: string; version: string };

    expect(app.api_key).toBe('[SCRUBBED]');
    expect(app.version).toBe('1.2.3');
  });

  it('keeps a caller array of callbacks in order', async () => {
    const seen: string[] = [];
    const client = createClient(
      endpoint,
      withSensitiveScrubbing({
        apiKey: API_KEY,
        onError: [
          () => {
            seen.push('a');

            return true;
          },
          () => {
            seen.push('b');

            return true;
          },
        ],
      })
    );

    await notify(client, new Error('boom'));

    expect(seen).toEqual(['a', 'b']);
  });

  it('lets a caller callback returning false still drop the event', async () => {
    const client = createClient(
      endpoint,
      withSensitiveScrubbing({ apiKey: API_KEY, onError: () => false })
    );

    await notify(client, new Error('boom'));

    expect(endpoint.capture.bodies).toEqual([]);
  });

  it('does not modify the config object it was given', () => {
    const original = { apiKey: API_KEY, redactedKeys: ['mine'] };
    const wrapped = withSensitiveScrubbing(original);

    expect(original.redactedKeys).toEqual(['mine']);
    expect(original).not.toHaveProperty('onError');
    expect(wrapped).not.toBe(original);
  });

  it('is idempotent', () => {
    const once = withSensitiveScrubbing({ apiKey: API_KEY });
    const twice = withSensitiveScrubbing(once);

    expect(isApplied(once)).toBe(true);
    expect(twice).toBe(once);
    expect(Array.isArray(twice.onError) ? twice.onError.length : 0).toBe(1);
  });
});

describe('reporting', () => {
  it('reports once per payload and names classes without values', async () => {
    const canary = createCanary('report');
    const reports: ScrubReport[] = [];
    const client = createClient(
      endpoint,
      withSensitiveScrubbing(
        { apiKey: API_KEY },
        {
          reportLabels: true,
          onScrub: (report) => {
            reports.push(report);
          },
        }
      )
    );

    client.addMetadata('creds', {
      wrapped: new SensitiveString(canary, 'credential', 'stripe-key'),
      access_token: canary,
    });

    await notify(client, new Error('boom'));

    const events = reports.filter((report) => report.kind === 'event');

    expect(events).toHaveLength(1);
    expect([...(events[0]?.classes ?? [])]).toEqual(['credential']);
    expect(events[0]?.deniedKeys).toContain('access_token');
    expect(events[0]?.labels).toEqual(['stripe-key']);
    expect(JSON.stringify(reports)).not.toContain(canary);
  });

  it('writes the classes onto the event and holds the labels back', async () => {
    const client = createClient(endpoint, withSensitiveScrubbing({ apiKey: API_KEY }));

    client.addMetadata('creds', {
      wrapped: new SensitiveString('x', 'credential', 'stripe-key'),
    });

    await notify(client, new Error('boom'));

    const metadata = endpoint.capture.lastEvent()['metaData'] as Record<
      string,
      Record<string, unknown>
    >;

    expect(metadata[REPORT_SECTION]?.['classes']).toBe('credential');
    // Q7: a label is user-supplied, high cardinality, and this package is not
    // going to be the thing that sends one to a third party by default.
    expect(metadata[REPORT_SECTION]?.['labels']).toBeUndefined();
  });

  it('records a marker that arrived in captured data', async () => {
    // The marker rule, inverted: a `[REDACTED:` in captured data is evidence
    // that some other integration sent a placeholder where a value belonged.
    // Recorded, never thrown on.
    const client = createClient(endpoint, withSensitiveScrubbing({ apiKey: API_KEY }));

    client.addMetadata('http', { responseBody: '{"error":"[REDACTED:credential] rejected"}' });
    await notify(client, new Error('boom'));

    const metadata = endpoint.capture.lastEvent()['metaData'] as Record<
      string,
      Record<string, unknown>
    >;

    expect(metadata[REPORT_SECTION]?.['marker_seen']).toBe(1);
    expect(metadata[REPORT_SECTION]?.['marker_classes']).toBe('credential');
  });

  it('does not count its own breadcrumb markers as sightings', async () => {
    // The event pass walks breadcrumbs that this package's own `onBreadcrumb`
    // already scrubbed, and stage 1 wrote a marker into each one. Counting
    // those here would have this package manufacturing evidence about itself.
    const client = createClient(endpoint, withSensitiveScrubbing({ apiKey: API_KEY }));

    client.leaveBreadcrumb('auth', { a: new SensitiveString('x', 'credential') });
    client.leaveBreadcrumb('auth', { b: new SensitiveString('y', 'sensitive') });
    client.addMetadata('creds', { direct: new SensitiveString('z', 'credential') });
    await notify(client, new Error('boom'));

    const metadata = endpoint.capture.lastEvent()['metaData'] as Record<
      string,
      Record<string, unknown>
    >;

    // Two markers sit in the delivered breadcrumbs and neither is counted.
    expect(metadata[REPORT_SECTION]?.['marker_seen']).toBeUndefined();

    // The event still reports what its own regions held, so the assertion above
    // is not passing because nothing was reported at all. The `sensitive` class
    // from the second breadcrumb is absent for the same reason the markers are:
    // by the event pass those instances are already strings, and the breadcrumb
    // seam reported them under its own `kind` when they were created.
    expect(metadata[REPORT_SECTION]?.['classes']).toBe('credential');
  });
});

describe('never throwing', () => {
  it('sends a stripped event when scrubbing throws, rather than dropping it', async () => {
    // A getter that throws on every read is the smallest way to break the walk
    // from inside the payload. The signal that an error of this shape happened
    // has to survive; the payload does not.
    const reports: ScrubReport[] = [];

    // A caller's own value pattern that throws is the smallest way to break the
    // walk from inside, and it breaks nothing else: a getter that throws would
    // also take out Bugsnag's encoder, which replaces the whole event with
    // "[Throws: ...]" and would be testing the SDK rather than this package.
    const exploding = /never-matches/;

    Object.defineProperty(exploding, 'test', {
      value: () => {
        throw new Error('pattern exploded');
      },
    });

    const client = createClient(
      endpoint,
      withSensitiveScrubbing(
        { apiKey: API_KEY },
        {
          denyValues: [exploding],
          onScrub: (report) => {
            reports.push(report);
          },
        }
      )
    );

    client.addMetadata('creds', { access_token: 'raw' });
    await notify(client, new Error('boom'));

    // Nothing dropped: the error still arrived.
    expect(endpoint.capture.bodies.length).toBe(1);

    const event = endpoint.capture.lastEvent();
    const metadata = event['metaData'] as Record<string, Record<string, unknown>>;
    const exceptions = event['exceptions'] as { errorClass: string; errorMessage: string }[];

    expect(metadata[REPORT_SECTION]?.['scrub_failed']).toBe(true);
    expect(metadata['creds']).toBeUndefined();
    expect(exceptions[0]?.errorClass).toBe('Error');
    expect(exceptions[0]?.errorMessage).toBe('[SCRUBBED]');
    expect(reports.some((report) => report.failed && report.kind === 'event')).toBe(true);
  });

  it('swallows what onScrub throws', async () => {
    // The one failure with nowhere to go: reporting that the reporter threw
    // would call the reporter.
    const client = createClient(
      endpoint,
      withSensitiveScrubbing(
        { apiKey: API_KEY },
        {
          onScrub: () => {
            throw new Error('reporter exploded');
          },
        }
      )
    );

    await notify(client, new Error('boom'));

    expect(endpoint.capture.bodies.length).toBe(1);
  });
});

describe('the caller own state', () => {
  it('does not mutate anything reachable from the thrown error', async () => {
    // Invariant 9. Bugsnag's contract requires mutating the event it hands
    // over, and `event.originalError` is the caller's own object.
    const detail = { access_token: 'raw-value', nested: { api_key: 'also-raw' } };
    const error = Object.assign(new Error('boom'), { detail });
    const client = createClient(
      endpoint,
      withSensitiveScrubbing({
        apiKey: API_KEY,
        onError: (event) => {
          event.addMetadata('creds', detail);

          return true;
        },
      })
    );

    await notify(client, error);

    expect(detail.access_token).toBe('raw-value');
    expect(detail.nested.api_key).toBe('also-raw');

    // And the copy that was sent is censored, so the two really are different
    // objects rather than the assertion above passing by accident.
    const metadata = endpoint.capture.lastEvent()['metaData'] as {
      creds: { access_token: string; nested: { api_key: string } };
    };

    expect(metadata.creds.access_token).toBe('[REDACTED]');
    expect(metadata.creds.nested.api_key).toBe('[REDACTED]');
  });

  it('does not mutate a breadcrumb metadata object the caller still holds', async () => {
    const metadata = { refresh_token: 'raw-value' };
    const client = createClient(endpoint, withSensitiveScrubbing({ apiKey: API_KEY }));

    client.leaveBreadcrumb('auth', metadata);
    await notify(client, new Error('boom'));

    expect(metadata.refresh_token).toBe('raw-value');

    const crumbs = endpoint.capture.lastEvent()['breadcrumbs'] as {
      metaData: { refresh_token: string };
    }[];

    expect(crumbs[0]?.metaData.refresh_token).toBe('[REDACTED]');
  });

  it('leaves a client breadcrumb buffer usable by the next event', async () => {
    // `event.breadcrumbs` is a shallow slice of the client's buffer, so the
    // event pass clones rather than mutates. If it mutated, the second event
    // would carry a breadcrumb scrubbed twice, which is harmless, and one whose
    // metadata object the client shares, which is not.
    const client = createClient(endpoint, withSensitiveScrubbing({ apiKey: API_KEY }));

    client.leaveBreadcrumb('auth', { refresh_token: 'raw-value', note: 'keep' });
    await notify(client, new Error('one'));
    await notify(client, new Error('two'));

    const events = endpoint.capture.events() as { events: Record<string, unknown>[] }[];
    const second = events[1]?.events[0]?.['breadcrumbs'] as {
      metaData: { refresh_token: string; note: string };
    }[];

    expect(second[0]?.metaData.refresh_token).toBe('[REDACTED]');
    expect(second[0]?.metaData.note).toBe('keep');
  });
});

describe('opt-in policy pieces', () => {
  it('censors bodies when the caller asks for the body paths, and not before', async () => {
    const attach = (event: { request?: Record<string, unknown> }) => {
      event.request = { url: 'http://127.0.0.1/pay', body: { anything: 'at all' } };

      return true;
    };

    const bare = createClient(
      endpoint,
      withSensitiveScrubbing({ apiKey: API_KEY, onError: attach })
    );

    await notify(bare, new Error('boom'));

    // Not on by default. A body is arbitrary application shape, and emptying one
    // from inside a scrubbing package would remove most of what makes a 400
    // report actionable.
    expect((endpoint.capture.lastEvent()['request'] as { body: unknown }).body).toEqual({
      anything: 'at all',
    });

    const strict = createClient(
      endpoint,
      withSensitiveScrubbing(
        { apiKey: API_KEY, onError: attach },
        { denyPaths: [...BUGSNAG_BODY_PATHS] }
      )
    );

    await notify(strict, new Error('boom'));

    const request = endpoint.capture.lastEvent()['request'] as { body: unknown; url: string };

    expect(request.body).toBe('[SCRUBBED]');
    // Replaced, never deleted, and the rest of the request survives.
    expect(request.url).toBe('http://127.0.0.1/pay');
  });

  it('censors a value shape when the caller opts into one', async () => {
    // Q3: off by default, on by name. A bearer token forwarded into a field
    // nobody named `authorization` is invisible to a key list.
    const client: Client = createClient(
      endpoint,
      withSensitiveScrubbing({ apiKey: API_KEY }, { denyValues: ['jwt'] })
    );

    client.addMetadata('claims', {
      forwarded: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLWhlcmU',
      note: 'keep-me',
    });

    await notify(client, new Error('boom'));

    const metadata = endpoint.capture.lastEvent()['metaData'] as {
      claims: { forwarded: string; note: string };
      sensitive: Record<string, unknown>;
    };

    expect(metadata.claims.forwarded).toBe('[SCRUBBED]');
    expect(metadata.claims.note).toBe('keep-me');
    expect(metadata.sensitive['value_shapes']).toBe('jwt');
  });
});
