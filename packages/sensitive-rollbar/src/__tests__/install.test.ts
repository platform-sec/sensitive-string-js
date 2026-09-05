import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { DEFAULT_DENY_KEYS, type ScrubReport } from '@platform-sec/sensitive-string-scrub';
import { createCanary } from '@platform-sec/sensitive-string-scrub/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  REPORT_KEY,
  RollbarScrubbingError,
  isApplied,
  withSensitiveScrubbing,
} from '../install.js';
import { ROLLBAR_DENY_PATHS } from '../paths.js';
import { createClient, report, startEndpoint, type Endpoint } from './fixtures.js';

let endpoint: Endpoint;

beforeEach(async () => {
  endpoint = await startEndpoint();
});

afterEach(async () => {
  await endpoint.close();
});

/** The `custom` section of the last delivered occurrence. */
function lastCustom(): Record<string, unknown> {
  return endpoint.capture.last()['custom'] as Record<string, unknown>;
}

describe('the scrub lists', () => {
  it('adds the resolved denylist to what the caller supplied', () => {
    const config = withSensitiveScrubbing({ scrubFields: ['my_custom_field'] });

    expect(config.scrubFields).toContain('my_custom_field');

    for (const key of DEFAULT_DENY_KEYS) {
      expect(config.scrubFields).toContain(key.toLowerCase());
    }
  });

  it('leaves the vendor list authoritative by default', () => {
    // Rollbar concatenates a supplied `scrubFields` onto its own 25, so the
    // default path adds to the vendor's list rather than replacing it. Nothing
    // this package gets wrong about the vendor's defaults can subtract from
    // them here.
    const config = withSensitiveScrubbing({});

    expect(config.overwriteScrubFields).toBeUndefined();
  });

  it('resolves to a superset of the vendor own lists', () => {
    const client = createClient(endpoint, withSensitiveScrubbing({}));
    const bare = createClient(endpoint);

    for (const field of bare.options.scrubFields ?? []) {
      expect(client.options.scrubFields).toContain(field);
    }

    for (const header of bare.options.scrubHeaders ?? []) {
      expect(client.options.scrubHeaders).toContain(header);
    }
  });

  it('passes the paths Rollbar ships but does not apply', () => {
    // `requestScrubFields` is documentation on a stock client: `scrubPaths`
    // resolves to undefined. This is one of the few places this package
    // tightens the vendor rather than adding beside it.
    const client = createClient(endpoint, withSensitiveScrubbing({}));

    for (const path of ROLLBAR_DENY_PATHS) {
      expect(client.options.scrubPaths).toContain(path);
    }
  });

  it('takes ownership of the list only when allowKeys asks for a key back', () => {
    const config = withSensitiveScrubbing(
      {},
      { allowKeys: [{ key: 'token', reason: 'opaque request id, not a credential' }] }
    );

    expect(config.overwriteScrubFields).toBe(true);
    expect(config.scrubFields).not.toContain('token');
    expect(config.scrubFields).toContain('access_token');
  });

  it('refuses allowKeys alongside an explicit overwriteScrubFields: false', () => {
    // The two answers to "who owns the scrub list" cannot both be honoured:
    // Rollbar would concatenate its own defaults back on, and the allowed key
    // would still be censored.
    expect(() =>
      withSensitiveScrubbing(
        { overwriteScrubFields: false },
        { allowKeys: [{ key: 'token', reason: 'opaque request id' }] }
      )
    ).toThrow(RollbarScrubbingError);
  });

  it('really does send a key the caller took back', async () => {
    const allowed = createCanary('allowed');
    const client = createClient(
      endpoint,
      withSensitiveScrubbing(
        {},
        { allowKeys: [{ key: 'token', reason: 'opaque request id, not a credential' }] }
      )
    );

    await report(client, new Error('boom'), undefined, { token: allowed, access_token: 'gone' });

    expect(lastCustom()['token']).toBe(allowed);
    expect(lastCustom()['access_token']).not.toBe('gone');
  });
});

describe('composition', () => {
  it('composes a caller transform rather than replacing it, and runs after it', async () => {
    const seen: string[] = [];
    const client = createClient(
      endpoint,
      withSensitiveScrubbing({
        transform(data: Record<string, unknown>) {
          seen.push('caller');
          (data['custom'] as Record<string, unknown>)['x-api-key'] = 'added-raw';
        },
      })
    );

    await report(client, new Error('boom'), undefined, { note: 'keep-me' });

    expect(seen).toEqual(['caller']);
    // Added by the caller's transform and censored anyway, which is what
    // running last buys on a vendor with one seam.
    expect(lastCustom()['x-api-key']).toBe('[SCRUBBED]');
    expect(lastCustom()['note']).toBe('keep-me');
  });

  it('does not let a caller transform that throws disable the scrubbing', async () => {
    // The measurement this matters most for: Rollbar's response to a throwing
    // transform is to remove the option for the life of the process and send
    // the original item. A caller's own bug must not be able to do that.
    const canary = createCanary('throwing');
    const client = createClient(
      endpoint,
      withSensitiveScrubbing({
        transform() {
          throw new Error('caller transform exploded');
        },
      })
    );

    await report(client, new Error('one'), undefined, { 'x-api-key': canary });
    await report(client, new Error('two'), undefined, { 'x-api-key': canary });

    expect(endpoint.capture.bodies.length).toBe(2);
    expect(endpoint.capture.raw()).not.toContain(canary);
  });

  it('does not let a caller transform that rejects disable the scrubbing', async () => {
    const canary = createCanary('rejecting');
    const client = createClient(
      endpoint,
      withSensitiveScrubbing({
        transform() {
          return Promise.reject(new Error('caller transform rejected'));
        },
      })
    );

    await report(client, new Error('boom'), undefined, { 'x-api-key': canary });

    expect(endpoint.capture.bodies.length).toBe(1);
    expect(endpoint.capture.raw()).not.toContain(canary);
  });

  it('awaits an async caller transform before scrubbing', async () => {
    const canary = createCanary('async');
    const client = createClient(
      endpoint,
      withSensitiveScrubbing({
        async transform(data: Record<string, unknown>) {
          await Promise.resolve();
          (data['custom'] as Record<string, unknown>)['api_key'] = canary;
        },
      })
    );

    await report(client, new Error('boom'), undefined, { note: 'keep-me' });

    expect(lastCustom()['api_key']).not.toBe(canary);
    expect(endpoint.capture.raw()).not.toContain(canary);
  });

  it('does not modify the config object it was given', () => {
    const original = { accessToken: 'token', scrubFields: ['mine'] };
    const wrapped = withSensitiveScrubbing(original);

    expect(original.scrubFields).toEqual(['mine']);
    expect(original).not.toHaveProperty('transform');
    expect(wrapped).not.toBe(original);
  });

  it('is idempotent', () => {
    const once = withSensitiveScrubbing({});
    const twice = withSensitiveScrubbing(once);

    expect(isApplied(once)).toBe(true);
    expect(twice).toBe(once);
  });
});

describe('the flattened wrapped value', () => {
  it('puts the marker back and holds the label', async () => {
    const label = createCanary('label');
    const client = createClient(endpoint, withSensitiveScrubbing({}));

    await report(client, new Error('boom'), undefined, {
      wrapped: new SensitiveString('SECRET', 'credential', label),
    });

    expect(lastCustom()['wrapped']).toBe('[REDACTED:credential]');
    expect(endpoint.capture.raw()).not.toContain(label);
  });

  it('reports the class it recovered', async () => {
    const client = createClient(endpoint, withSensitiveScrubbing({}));

    await report(client, new Error('boom'), undefined, {
      wrapped: new SensitiveString('SECRET', 'credential'),
    });

    const section = lastCustom()[REPORT_KEY] as Record<string, unknown>;

    expect(section['classes']).toBe('credential');
  });

  it('sends the label when the caller opts in', async () => {
    const client = createClient(endpoint, withSensitiveScrubbing({}, { reportLabels: true }));

    await report(client, new Error('boom'), undefined, {
      wrapped: new SensitiveString('SECRET', 'credential', 'stripe-key'),
    });

    const section = lastCustom()[REPORT_KEY] as Record<string, unknown>;

    expect(section['labels']).toBe('stripe-key');
  });

  it('leaves an application object that merely looks similar alone', async () => {
    // The recognizer matches on structure and the structure is narrow, but the
    // cost of a false positive is a value an engineer needed. These are the
    // near misses.
    const client = createClient(endpoint, withSensitiveScrubbing({}));

    await report(client, new Error('boom'), undefined, {
      threeKeys: { klass: 'credential', label: 'x', extra: 1 },
      wrongType: { klass: 42 },
      wrongPartner: { klass: 'credential', name: 'x' },
      empty: {},
    });

    const custom = lastCustom();

    expect(custom['threeKeys']).toEqual({ klass: 'credential', label: 'x', extra: 1 });
    expect(custom['wrongType']).toEqual({ klass: 42 });
    expect(custom['wrongPartner']).toEqual({ klass: 'credential', name: 'x' });
    expect(custom['empty']).toEqual({});
  });
});

describe('reporting', () => {
  it('reports once per payload and names classes without values', async () => {
    const canary = createCanary('report');
    const reports: ScrubReport[] = [];
    const client = createClient(
      endpoint,
      withSensitiveScrubbing(
        {},
        {
          onScrub: (scrubbed) => {
            reports.push(scrubbed);
          },
        }
      )
    );

    await report(client, new Error('boom'), undefined, {
      'x-api-key': canary,
      wire: new SensitiveString(canary, 'credential').serialize(),
    });

    expect(reports).toHaveLength(1);
    expect(reports[0]?.kind).toBe('event');
    expect([...(reports[0]?.classes ?? [])]).toEqual(['credential']);
    expect(reports[0]?.deniedKeys).toContain('x-api-key');
    expect(JSON.stringify(reports)).not.toContain(canary);
  });

  it('records a marker that arrived in captured data', async () => {
    // The marker rule, inverted: a `[REDACTED:` in captured data is evidence
    // that some other integration sent a placeholder where a value belonged.
    // Recorded, never thrown on.
    const client = createClient(endpoint, withSensitiveScrubbing({}));

    await report(client, new Error('boom'), undefined, {
      responseBody: '{"error":"[REDACTED:credential] rejected"}',
    });

    const section = lastCustom()[REPORT_KEY] as Record<string, unknown>;
    const delivered = endpoint.capture.raw().split('[REDACTED:credential]').length - 1;

    // Counted once per position rather than once per distinct string, and
    // Rollbar copies custom data to more than one position in the payload. The
    // count is asserted against the delivered copies rather than against a
    // literal, so a change in that duplication reads as what it is.
    expect(delivered).toBeGreaterThan(1);
    expect(section['marker_seen']).toBe(delivered);
    expect(section['marker_classes']).toBe('credential');
  });

  it('censors a value shape when the caller opts into one', async () => {
    const client = createClient(endpoint, withSensitiveScrubbing({}, { denyValues: ['jwt'] }));

    await report(client, new Error('boom'), undefined, {
      forwarded: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLWhlcmU',
      note: 'keep-me',
    });

    const section = lastCustom()[REPORT_KEY] as Record<string, unknown>;

    expect(lastCustom()['forwarded']).toBe('[SCRUBBED]');
    expect(lastCustom()['note']).toBe('keep-me');
    expect(section['value_shapes']).toBe('jwt');
  });
});

describe('never throwing', () => {
  it('sends a stripped occurrence when scrubbing throws, rather than losing it', async () => {
    const reports: ScrubReport[] = [];

    // A caller's own value pattern that throws is the smallest way to break the
    // walk from inside without breaking the vendor's own pipeline too.
    const exploding = /never-matches/;

    Object.defineProperty(exploding, 'test', {
      value: () => {
        throw new Error('pattern exploded');
      },
    });

    const client = createClient(
      endpoint,
      withSensitiveScrubbing(
        {},
        {
          denyValues: [exploding],
          onScrub: (scrubbed) => {
            reports.push(scrubbed);
          },
        }
      )
    );

    await report(client, new Error('boom'), undefined, { 'x-api-key': 'raw-value' });

    expect(endpoint.capture.bodies.length).toBe(1);

    const data = endpoint.capture.last();
    const section = lastCustom()[REPORT_KEY] as Record<string, unknown>;

    expect(section['scrub_failed']).toBe(true);
    expect(data['level']).toBe('error');
    expect(endpoint.capture.raw()).not.toContain('raw-value');
    expect(reports.some((scrubbed) => scrubbed.failed)).toBe(true);
  });

  it('swallows what onScrub throws', async () => {
    const client = createClient(
      endpoint,
      withSensitiveScrubbing(
        {},
        {
          onScrub: () => {
            throw new Error('reporter exploded');
          },
        }
      )
    );

    await report(client, new Error('boom'), undefined, { note: 'keep' });

    expect(endpoint.capture.bodies.length).toBe(1);
    expect(lastCustom()['note']).toBe('keep');
  });
});
