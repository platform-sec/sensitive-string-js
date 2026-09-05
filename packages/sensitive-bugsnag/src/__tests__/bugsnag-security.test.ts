import type { Client, Event } from '@bugsnag/js';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  createCanary,
  expectCanaryPresent,
  expectNoCanary,
} from '@platform-sec/sensitive-string-scrub/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { withSensitiveScrubbing } from '../install.js';
import { createClient, notify, startEndpoint, type Endpoint } from './fixtures.js';

/**
 * The canary sweep, and the pinning tests under it.
 *
 * Every measurement here was taken on Node 22.15.0 against `@bugsnag/js`
 * 8.10.0, driving the real SDK to an HTTP server on loopback. Nothing contacts
 * Bugsnag and nothing mocks it: the point is to exercise the SDK's own callback
 * ordering, its `redactedKeys` pass and its encoder, because a mock would agree
 * with whatever this package believed when it was written.
 *
 * The assertion is on the delivered bytes rather than on the event object, and
 * it has to be. `redactedKeys` runs inside the encoder, so half of what this
 * package configures is invisible until the body exists.
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
  /** Client-level state, set before the error is reported. */
  readonly setup?: (client: Client, canary: string) => void;
  /**
   * An `onError` composed into the config, which is where a framework plugin
   * attaches request data. It runs before this package's scrubber, measured, so
   * a position placed here is one the package actually covers.
   */
  readonly attach?: (event: Event, canary: string) => void;
  /**
   * A wrapped canary is unreachable by any structural search even before
   * scrubbing, because the value lives in an ES2022 private field. Those
   * positions prove themselves by the marker the SDK emits in their place.
   */
  readonly wrapped?: true;
}

const POSITIONS: readonly Position[] = [
  {
    name: 'request headers',
    attach: (event, canary) => {
      event.request = {
        headers: {
          authorization: `Bearer ${canary}`,
          cookie: `session=${canary}`,
          'x-api-key': canary,
          'x-trace': 'keep-me',
        },
      };
    },
  },
  {
    name: 'a request url query parameter',
    attach: (event, canary) => {
      event.request = { url: `http://127.0.0.1:8080/pay/42?token=${canary}&page=2` };
    },
  },
  {
    name: 'a request body',
    attach: (event, canary) => {
      event.request = { body: { client_secret: canary, refresh_token: canary, amount: 10 } };
    },
  },
  {
    name: 'response headers',
    attach: (event, canary) => {
      event.response = { statusCode: 401, headers: { 'set-cookie': `s=${canary}` } };
    },
  },
  {
    name: 'the context, which a route middleware sets from the url',
    setup: (client, canary) => {
      client.setContext(`/pay?token=${canary}`);
    },
  },
  {
    name: 'metadata under a denied key',
    setup: (client, canary) => {
      client.addMetadata('creds', { access_token: canary, note: 'keep-me' });
    },
  },
  {
    name: 'metadata nested three deep under a denied key',
    setup: (client, canary) => {
      client.addMetadata('creds', { outer: { inner: { private_key: canary } } });
    },
  },
  {
    name: 'a serialize() result in metadata',
    setup: (client, canary) => {
      client.addMetadata('wire', {
        payload: new SensitiveString(canary, 'credential', 'tok').serialize(),
      });
    },
  },
  {
    name: 'a serialize() result in a request body',
    attach: (event, canary) => {
      event.request = { body: { payload: new SensitiveString(canary, 'credential').serialize() } };
    },
  },
  {
    name: 'a wrapped value in metadata',
    wrapped: true,
    setup: (client, canary) => {
      client.addMetadata('creds', { anything: new SensitiveString(canary, 'credential') });
    },
  },
  {
    name: 'a wrapped value as a feature flag variant',
    wrapped: true,
    setup: (client, canary) => {
      client.addFeatureFlag('rollout', String(new SensitiveString(canary, 'credential')));
    },
  },
  {
    name: 'breadcrumb metadata under a denied key',
    setup: (client, canary) => {
      client.leaveBreadcrumb('auth', { refresh_token: canary, note: 'keep-me' });
    },
  },
  {
    name: 'a url in breadcrumb metadata',
    setup: (client, canary) => {
      client.leaveBreadcrumb('fetch', { url: `https://api.test/v1/pay?token=${canary}` });
    },
  },
  {
    name: 'a wrapped value in breadcrumb metadata',
    wrapped: true,
    setup: (client, canary) => {
      client.leaveBreadcrumb('auth', {
        arguments: ['user', new SensitiveString(canary, 'credential')],
      });
    },
  },
  {
    name: 'a breadcrumb pushed straight onto the event by an earlier callback',
    attach: (event, canary) => {
      event.breadcrumbs = [
        ...event.breadcrumbs,
        {
          type: 'manual',
          message: 'late',
          metadata: { oauth_token: canary },
          timestamp: new Date(),
          toJSON() {
            return { type: 'manual', name: 'late', metaData: { oauth_token: canary } };
          },
        } as unknown as (typeof event.breadcrumbs)[number],
      ];
    },
  },
  {
    name: 'app metadata, which the SDK own redaction does not reach',
    attach: (event, canary) => {
      event.app = { ...event.app, api_key: canary };
    },
  },
];

describe('canary sweep', () => {
  for (const position of POSITIONS) {
    // TEST-BUGSNAG-CANARY
    it(`does not send the canary from ${position.name}`, async () => {
      const canary = createCanary('bugsnag');
      const client = createClient(
        endpoint,
        withSensitiveScrubbing({
          apiKey: '0'.repeat(32),
          onError: (event) => {
            position.attach?.(event, canary);

            return true;
          },
        })
      );

      position.setup?.(client, canary);
      await notify(client, new Error('boom'));

      expect(endpoint.capture.bodies.length).toBeGreaterThan(0);
      expectNoCanary(endpoint.capture.raw(), canary, `${position.name} delivery`);
    });
  }

  // TEST-BUGSNAG-CANARY-LEAKS
  it('proves each position exists by leaking without the scrubbing', async () => {
    // A sweep that only asserts absence keeps passing when the fixture stops
    // exercising anything. This runs the same positions with no scrubbing and
    // requires the canary to arrive, so every case above is testing something.
    const leaked: string[] = [];

    for (const position of POSITIONS) {
      const bare = await startEndpoint();

      try {
        const canary = createCanary('bare');
        const client = createClient(bare, {
          apiKey: '0'.repeat(32),
          onError: (event: Event) => {
            position.attach?.(event, canary);

            return true;
          },
        });

        position.setup?.(client, canary);
        await notify(client, new Error('boom'));

        if (bare.capture.raw().includes(canary)) {
          leaked.push(position.name);
        }
      } finally {
        await bare.close();
      }
    }

    // Every position except the wrapped ones, which the library already covers
    // through `toJSON()` and which are here to prove that stays true.
    const expected = POSITIONS.filter((p) => p.wrapped !== true).map((p) => p.name);

    expect(leaked.sort()).toEqual(expected.sort());
  });
});

describe('pinning: what this package depends on', () => {
  // TEST-BUGSNAG-PIN-REDACTED-DEFAULT
  it('ships one redacted key, and applies it in four regions only', async () => {
    // The basis for the union in `unionRedactedKeys`, and the reason the
    // callbacks are load bearing rather than a convenience on top of the
    // vendor's own list. Both halves will change, and this is what notices.
    const canary = createCanary('regions');
    const client = createClient(endpoint, {
      apiKey: '0'.repeat(32),
      onError: (event) => {
        event.request = { headers: { password: canary } };
        event.app = { ...event.app, password: canary };

        return true;
      },
    });

    client.addMetadata('m', { password: canary });
    await notify(client, new Error('boom'));

    const event = endpoint.capture.lastEvent();
    const metadata = event['metaData'] as { m: { password: string } };
    const request = event['request'] as { headers: { password: string } };
    const app = event['app'] as { password: string };

    expect(client).toBeDefined();
    expect(metadata.m.password).toBe('[REDACTED]');
    expect(request.headers.password).toBe('[REDACTED]');
    // Not one of `events.[].metaData`, `events.[].breadcrumbs.[].metaData`,
    // `events.[].request` or `events.[].response`, so the vendor's own pass
    // never looks at it.
    expect(app.password).toBe(canary);
  });

  // TEST-BUGSNAG-PIN-ORDER
  it('runs config callbacks in order, then addOnError, then the per-notify one', async () => {
    // This is why the scrubber is appended to the config array rather than
    // prepended: the last position it can reach is the end of that array. The
    // per-notify callback is the gap, and the gap test below executes it.
    const order: string[] = [];
    const client = createClient(endpoint, {
      apiKey: '0'.repeat(32),
      onError: [
        () => {
          order.push('config-a');

          return true;
        },
        () => {
          order.push('config-b');

          return true;
        },
      ],
    });

    client.addOnError(() => {
      order.push('addOnError');

      return true;
    });

    await notify(client, new Error('boom'), () => {
      order.push('per-notify');

      return true;
    });

    expect(order).toEqual(['config-a', 'config-b', 'addOnError', 'per-notify']);
  });

  // TEST-BUGSNAG-PIN-LIVE
  it('hands onError live instances and onBreadcrumb the caller own metadata object', async () => {
    // Two facts the scrubber is built on. Live instances are what gives stage 1
    // and the class list anything to work with. The breadcrumb metadata being
    // the caller's own object is why the breadcrumb seam assigns a copy instead
    // of writing through it: mutating in place would rewrite application state.
    const metadata = { wrapped: new SensitiveString('x', 'credential') };
    let liveInError = false;
    let crumbIsCallerObject = false;

    const client = createClient(endpoint, {
      apiKey: '0'.repeat(32),
      onBreadcrumb: (crumb) => {
        // Only the breadcrumb this case leaves. `_notify` leaves one of its own
        // for the error after every callback has run, and it would otherwise
        // overwrite the observation with its own generated metadata.
        if (crumb.message === 'auth') {
          crumbIsCallerObject = crumb.metadata === metadata;
        }

        return true;
      },
      onError: (event) => {
        liveInError = (event.getMetadata('creds', 'wrapped') as unknown) instanceof SensitiveString;

        return true;
      },
    });

    client.addMetadata('creds', { wrapped: new SensitiveString('x', 'credential') });
    client.leaveBreadcrumb('auth', metadata);
    await notify(client, new Error('boom'));

    expect(liveInError).toBe(true);
    expect(crumbIsCallerObject).toBe(true);
  });

  // TEST-BUGSNAG-PIN-TOJSON
  it('honours toJSON in its encoder, so a wrapped value is already the marker', () => {
    // The reason stage 1 is defence in depth for this vendor rather than the
    // thing that makes a wrapped value safe. Rollbar does not do this, which is
    // why the two packages are not interchangeable.
    expect(JSON.stringify({ s: new SensitiveString('x', 'credential') })).toBe(
      '{"s":"[REDACTED:credential]"}'
    );
  });

  // TEST-BUGSNAG-PIN-ORIGINAL
  it('keeps the caller own error reachable from the event', async () => {
    // Invariant 9's hazard, stated as a measurement. Anything this package
    // wrote through `originalError` would be rewriting application state.
    const error = Object.assign(new Error('boom'), { detail: { api_key: 'x' } });
    let sameError = false;

    const client = createClient(
      endpoint,
      withSensitiveScrubbing({
        apiKey: '0'.repeat(32),
        onError: (event) => {
          sameError = event.originalError === error;

          return true;
        },
      })
    );

    await notify(client, error);

    expect(sameError).toBe(true);
    expect(error.detail.api_key).toBe('x');
  });

  // TEST-BUGSNAG-PIN-SESSION
  it('sends no application data in a Node session payload', async () => {
    // Why the session seam is composed for coverage rather than for a leak. If
    // a future notifier starts putting the user in the payload, this fails and
    // the seam is already there.
    const canary = createCanary('session');
    const client = createClient(endpoint, { apiKey: '0'.repeat(32) });

    client.setUser('u1', `${canary}@x.test`, canary);
    client.startSession();

    await new Promise((resolve) => setTimeout(resolve, 400));

    const sessions = endpoint.capture.bodies.filter((entry) => entry.url.includes('session'));

    for (const session of sessions) {
      expectNoCanary(session.body, canary, 'session payload');
    }
  });

  // TEST-BUGSNAG-PIN-THROW
  it('logs a throwing callback and keeps going', async () => {
    // The behaviour the never-throw contract exists not to depend on. A hook
    // that throws here does not lose the event today; the guard is what makes
    // that true regardless of what the SDK does with it tomorrow.
    const reached: string[] = [];
    const client = createClient(endpoint, {
      apiKey: '0'.repeat(32),
      onError: [
        () => {
          throw new Error('callback exploded');
        },
        () => {
          reached.push('after');

          return true;
        },
      ],
    });

    await notify(client, new Error('boom'));

    expect(reached).toEqual(['after']);
    expect(endpoint.capture.bodies.length).toBe(1);
  });
});

describe('the gap this package cannot close', () => {
  // TEST-BUGSNAG-GAP
  it('does not scrub what a per-notify onError adds', async () => {
    // Documented by executing it, so the README sentence and the behaviour
    // cannot drift apart. `notify(err, onError)` runs its callback after every
    // config callback, measured, and there is no public seam after that one.
    const canary = createCanary('gap');
    const client = createClient(endpoint, withSensitiveScrubbing({ apiKey: '0'.repeat(32) }));

    await notify(client, new Error('boom'), (event) => {
      event.addMetadata('late', { oauth_token: canary });

      return true;
    });

    const event = endpoint.capture.lastEvent();
    const metadata = event['metaData'] as { late: { oauth_token: string } };

    // Bugsnag's own `redactedKeys` still fires, because it runs in the encoder
    // after every callback. That is the whole of what covers this position, and
    // it is why the union with `redactedKeys` is not optional.
    expect(metadata.late.oauth_token).toBe('[REDACTED]');

    // A key outside the denylist added that late is genuinely not covered.
    await notify(client, new Error('boom'), (event) => {
      event.addMetadata('late', { house_key: canary });

      return true;
    });

    expectCanaryPresent(endpoint.capture.raw(), canary, 'the documented gap');
  });
});
