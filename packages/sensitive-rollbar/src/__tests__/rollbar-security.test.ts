import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  createCanary,
  expectCanaryPresent,
  expectNoCanary,
} from '@platform-sec/sensitive-string-scrub/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { withSensitiveScrubbing } from '../install.js';
import { createClient, report, requestWith, startEndpoint, type Endpoint } from './fixtures.js';

/**
 * The canary sweep, and the pinning tests under it.
 *
 * Every measurement here was taken on Node 22.15.0 against `rollbar` 3.1.0,
 * driving the real SDK to an HTTP server on loopback. Nothing contacts Rollbar
 * and nothing mocks it: the point is to exercise the vendor's own transform
 * pipeline and scrub pass, because a mock would agree with whatever this
 * package believed when it was written.
 */

let endpoint: Endpoint;

beforeEach(async () => {
  endpoint = await startEndpoint();
});

afterEach(async () => {
  await endpoint.close();
});

/** One capturable position, and how to put a canary in it. */
interface Position {
  readonly name: string;
  readonly request?: (canary: string) => Record<string, unknown>;
  readonly custom?: (canary: string) => Record<string, unknown>;
  /**
   * A wrapped canary is unreachable by any structural search even before
   * scrubbing, because the value lives in an ES2022 private field. Those
   * positions prove themselves by the marker the payload carries in their
   * place, which for this vendor is a marker this package puts back.
   */
  readonly wrapped?: true;
}

const POSITIONS: readonly Position[] = [
  {
    name: 'request headers, url and body',
    request: (canary) => requestWith(canary),
  },
  {
    name: 'a custom field under a denied key',
    custom: (canary) => ({ access_token: canary, note: 'keep-me' }),
  },
  {
    name: 'a custom field nested three deep under a denied key',
    custom: (canary) => ({ outer: { inner: { private_key: canary } } }),
  },
  {
    name: 'a key Rollbar own list does not carry',
    custom: (canary) => ({ 'x-amz-security-token': canary, refresh_token: canary }),
  },
  {
    name: 'a url in a custom field',
    custom: (canary) => ({ url: `https://api.test/v1/pay?token=${canary}` }),
  },
  {
    name: 'a serialize() result',
    custom: (canary) => ({
      wire: new SensitiveString(canary, 'credential', 'tok').serialize(),
    }),
  },
  {
    name: 'a serialize() result in a request body',
    request: (canary) => ({
      url: '/pay',
      method: 'POST',
      headers: {},
      body: { payload: new SensitiveString(canary, 'credential').serialize() },
    }),
  },
  {
    name: 'a wrapped value in a custom field',
    wrapped: true,
    custom: (canary) => ({ anything: new SensitiveString(canary, 'credential') }),
  },
  {
    name: 'a wrapped value nested in a custom field',
    wrapped: true,
    custom: (canary) => ({ deep: { inner: new SensitiveString(canary, 'credential') } }),
  },
];

describe('canary sweep', () => {
  for (const position of POSITIONS) {
    // TEST-ROLLBAR-CANARY
    it(`does not send the canary from ${position.name}`, async () => {
      const canary = createCanary('rollbar');
      const client = createClient(endpoint, withSensitiveScrubbing({}));

      await report(
        client,
        new Error('boom'),
        position.request?.(canary),
        position.custom?.(canary)
      );

      expect(endpoint.capture.bodies.length).toBeGreaterThan(0);
      expectNoCanary(endpoint.capture.raw(), canary, `${position.name} delivery`);
    });
  }

  // TEST-ROLLBAR-CANARY-LEAKS
  it('proves each position exists by leaking without the scrubbing', async () => {
    // A sweep that only asserts absence keeps passing when the fixture stops
    // exercising anything. This runs the same positions with no scrubbing
    // installed and lists which ones arrive.
    const leaked: string[] = [];

    for (const position of POSITIONS) {
      const bare = await startEndpoint();

      try {
        const canary = createCanary('bare');
        const client = createClient(bare);

        await report(
          client,
          new Error('boom'),
          position.request?.(canary),
          position.custom?.(canary)
        );

        if (bare.capture.raw().includes(canary)) {
          leaked.push(position.name);
        }
      } finally {
        await bare.close();
      }
    }

    // Shorter than the other vendors', and deliberately so: this is the list of
    // positions Rollbar's own defaults do *not* close, which is what the README
    // means when it says this package is thin.
    //
    // Two of them are worth naming. The request position leaks because
    // `x-api-key` is not one of the ten names in `commonScrubHeaders`, though
    // the `authorization` header, the `cookie` header, the `token` query
    // parameter and the `client_secret` body field beside it are all closed by
    // the vendor. The nested position leaks because `private_key` is not one of
    // the twenty-five in `scrubFields`, at any depth.
    //
    // The wrapped positions are absent because the private field is unreachable
    // either way, and `access_token` is absent because the vendor already
    // carries that name.
    expect(leaked.sort()).toEqual(
      [
        'a custom field nested three deep under a denied key',
        'a key Rollbar own list does not carry',
        'a serialize() result',
        'a serialize() result in a request body',
        'request headers, url and body',
      ].sort()
    );
  });
});

describe('pinning: what this package depends on', () => {
  // TEST-ROLLBAR-PIN-CONCAT
  it('concatenates a supplied scrubFields onto its own 25 defaults', () => {
    // The basis for not passing `overwriteScrubFields` unless a caller took a
    // key back. If Rollbar ever substitutes instead of concatenating, the
    // default path would silently drop the vendor's own list.
    const client = createClient(endpoint, { scrubFields: ['my_custom_field'] });
    const fields = client.options.scrubFields ?? [];

    expect(fields).toHaveLength(26);
    expect(fields).toContain('my_custom_field');
    expect(fields).toContain('access_token');
  });

  // TEST-ROLLBAR-PIN-DEFAULTS
  it('ships the lists section 5 of the design claims', () => {
    const client = createClient(endpoint);

    expect(client.options.scrubFields).toHaveLength(25);
    expect(client.options.scrubHeaders).toEqual([
      'authorization',
      'www-authorization',
      'http_authorization',
      'omniauth.auth',
      'cookie',
      'oauth-access-token',
      'x-access-token',
      'x_csrf_token',
      'http_x_csrf_token',
      'x-csrf-token',
    ]);
    // `requestScrubFields` is documentation rather than a default: the option
    // that would apply it is unset on a stock client, which is why this package
    // passes the paths itself.
    expect(client.options.scrubPaths).toBeUndefined();
  });

  // TEST-ROLLBAR-PIN-SCRUB-FIRST
  it('runs its own scrub before the transform seam', async () => {
    // Answers one of the design's open measurements. Because the vendor scrubs
    // first, this package's seam sees a payload whose known keys are already
    // censored, and everything it adds is what the vendor's list does not name.
    let seen: unknown;
    const client = createClient(endpoint, {
      transform(data: Record<string, unknown>) {
        seen = (data['custom'] as Record<string, unknown> | undefined)?.['password'];
      },
    });

    await report(client, new Error('boom'), undefined, { password: 'raw-value' });

    expect(seen).toBe('********');
  });

  // TEST-ROLLBAR-PIN-FLATTEN
  it('flattens a wrapped value to its own enumerable properties, toJSON ignored', async () => {
    // The measurement `flattened.ts` exists for, and the one place in this
    // repository where a vendor's serialization does not honour `toJSON()`. The
    // key set asserted here is what the recognizer matches on, so a change to
    // the class fails this rather than silently narrowing the recognizer.
    const wrapped = new SensitiveString('SECRET', 'credential', 'stripe-key');

    expect(Object.keys(wrapped)).toEqual(['klass', 'label']);
    expect(JSON.stringify(wrapped)).toBe('"[REDACTED:credential]"');

    let seen: unknown;
    const client = createClient(endpoint, {
      transform(data: Record<string, unknown>) {
        seen = (data['custom'] as Record<string, unknown> | undefined)?.['wrapped'];
      },
    });

    await report(client, new Error('boom'), undefined, { wrapped });

    // Not the marker, and not the instance: a plain object of its own
    // enumerable properties, carrying the label.
    expect(seen).toEqual({ klass: 'credential', label: 'stripe-key' });
    expect(seen).not.toBeInstanceOf(SensitiveString);
  });

  // TEST-ROLLBAR-PIN-LABEL-LEAK
  it('would send the label of a wrapped value without this package', async () => {
    // The finding `flattened.ts` closes. Q7 keeps labels off by default because
    // a label is user-supplied and high cardinality; on this vendor one reaches
    // the wire by accident unless something stops it.
    const label = createCanary('label');
    const client = createClient(endpoint);

    await report(client, new Error('boom'), undefined, {
      wrapped: new SensitiveString('SECRET', 'credential', label),
    });

    expectCanaryPresent(endpoint.capture.raw(), label, 'the unscrubbed label');
  });

  // TEST-ROLLBAR-PIN-TRANSFORM-THROW
  it('disables the transform for the process when it throws, and sends the raw item', async () => {
    // The measurement the never-throw contract matters most for. One exception
    // out of the composed transform would turn scrubbing off for every payload
    // after it, silently, with a log line as the only evidence.
    const canary = createCanary('disabled');
    let calls = 0;
    const client = createClient(endpoint, {
      transform() {
        calls += 1;

        throw new Error('transform exploded');
      },
    });

    await report(client, new Error('one'), undefined, { 'x-amz-security-token': canary });
    await report(client, new Error('two'), undefined, { 'x-amz-security-token': canary });

    // Called once. The second occurrence never reached it, because the first
    // throw removed the option from the notifier's own copy of the config.
    expect(calls).toBe(1);

    // Both occurrences were sent, and both carry the value the transform would
    // have removed. That is what a fail-open looks like on this vendor, and it
    // is the whole reason the composed transform catches everything.
    expect(endpoint.capture.bodies.length).toBe(2);
    expectCanaryPresent(
      endpoint.capture.raw(),
      canary,
      'a payload sent with the transform disabled'
    );
  });
});

describe('the regions this package cannot reach', () => {
  // TEST-ROLLBAR-GAP
  it('does not scrub what Rollbar adds after the transform seam', async () => {
    // `addConfiguredOptions` and `addDiagnosticKeys` run at transform positions
    // 12 and 13, after the seam. The diagnostic block carries the original
    // error's own message. Documented by executing it, so the README sentence
    // and the behaviour cannot drift apart.
    const canary = createCanary('diagnostic');
    const client = createClient(endpoint, withSensitiveScrubbing({}));

    await report(client, new Error(`boom ${canary}`));

    const data = endpoint.capture.last();
    const notifier = data['notifier'] as {
      diagnostic: { raw_error: { message: string } };
    };

    expect(notifier.diagnostic.raw_error.message).toContain(canary);
  });
});
