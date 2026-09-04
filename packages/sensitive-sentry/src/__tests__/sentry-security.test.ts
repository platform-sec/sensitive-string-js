import * as Sentry from '@sentry/node';
import {
  SensitiveString,
  redactCopy,
  redactInStructure,
} from '@platform-sec/sensitive-string-core';
import { createCanary, expectNoCanary } from '@platform-sec/sensitive-string-scrub/testing';
import { describe, expect, it } from 'vitest';

import { withSensitiveScrubbing } from '../install.js';
import { attachRequest, createCapture, runIsolated } from './fixtures.js';

/**
 * The canary sweep, and the pinning tests under it.
 *
 * Every measurement here was taken on Node 22.15.0 against `@sentry/node`
 * 10.73.0, driving the real SDK to a capturing transport. Nothing contacts
 * Sentry and nothing mocks it: the point is to exercise the SDK's own
 * normalizer, hook ordering and envelope encoding, because a mock would agree
 * with whatever this package believed when it was written.
 */

/** One capturable position, and how to put a canary in it. */
interface Position {
  readonly name: string;
  readonly place: (canary: string) => void;
  /** Extra integrations the position needs to exist at all. */
  readonly integrations?: () => unknown[];
  /**
   * A wrapped canary is unreachable by any structural search even before
   * scrubbing, because the value lives in an ES2022 private field. Those
   * positions prove themselves by the marker the SDK emits in their place.
   */
  readonly wrapped?: true;
}

const POSITIONS: readonly Position[] = [
  {
    name: 'request headers, cookies, url, query string and body',
    integrations: () => [Sentry.requestDataIntegration()],
    place: (canary) => {
      attachRequest(canary);
      Sentry.captureException(new Error('boom'));
    },
  },
  {
    name: 'extra',
    place: (canary) => {
      Sentry.getCurrentScope().setExtra('access_token', canary);
      Sentry.captureException(new Error('boom'));
    },
  },
  {
    name: 'contexts',
    place: (canary) => {
      Sentry.getCurrentScope().setContext('creds', { api_key: canary, note: 'keep' });
      Sentry.captureException(new Error('boom'));
    },
  },
  {
    name: 'tags',
    place: (canary) => {
      Sentry.getCurrentScope().setTag('session_id', canary);
      Sentry.captureException(new Error('boom'));
    },
  },
  {
    name: 'user',
    place: (canary) => {
      Sentry.getCurrentScope().setUser({ id: 'u1', password: canary });
      Sentry.captureException(new Error('boom'));
    },
  },
  {
    name: 'breadcrumb data',
    place: (canary) => {
      Sentry.addBreadcrumb({ message: 'auth', data: { refresh_token: canary } });
      Sentry.captureException(new Error('boom'));
    },
  },
  {
    name: 'breadcrumb url',
    place: (canary) => {
      Sentry.addBreadcrumb({
        category: 'fetch',
        data: { url: `https://api.test/v1/pay?token=${canary}` },
      });
      Sentry.captureException(new Error('boom'));
    },
  },
  {
    name: 'a custom property on the thrown error, with extraErrorData enabled',
    integrations: () => [Sentry.extraErrorDataIntegration()],
    place: (canary) => {
      Sentry.captureException(Object.assign(new Error('boom'), { client_secret: canary }));
    },
  },
  {
    name: 'an error.cause chain',
    integrations: () => [Sentry.linkedErrorsIntegration(), Sentry.extraErrorDataIntegration()],
    place: (canary) => {
      const cause = Object.assign(new Error('inner'), { oauth_token: canary });

      Sentry.captureException(new Error('outer', { cause }));
    },
  },
  {
    name: 'a stack frame variable, as includeLocalVariables would capture it',
    place: (canary) => {
      Sentry.captureEvent({
        exception: {
          values: [
            {
              type: 'Error',
              value: 'boom',
              stacktrace: {
                frames: [{ function: 'charge', vars: { opts: { private_key: canary } } }],
              },
            },
          ],
        },
      });
    },
  },
  {
    name: 'a wrapped value in extra',
    wrapped: true,
    place: (canary) => {
      Sentry.getCurrentScope().setExtra('secret', new SensitiveString(canary, 'credential'));
      Sentry.captureException(new Error('boom'));
    },
  },
  {
    name: 'a wrapped value in a context',
    wrapped: true,
    place: (canary) => {
      Sentry.getCurrentScope().setContext('creds', {
        token: new SensitiveString(canary, 'credential'),
      });
      Sentry.captureException(new Error('boom'));
    },
  },
  {
    name: 'a wrapped value in breadcrumb data',
    wrapped: true,
    place: (canary) => {
      Sentry.addBreadcrumb({
        message: 'auth',
        data: { arguments: ['user', new SensitiveString(canary, 'credential')] },
      });
      Sentry.captureException(new Error('boom'));
    },
  },
  {
    name: 'a serialize() result in extra',
    place: (canary) => {
      Sentry.getCurrentScope().setExtra(
        'wire',
        new SensitiveString(canary, 'credential', 'tok').serialize()
      );
      Sentry.captureException(new Error('boom'));
    },
  },
  {
    name: 'a serialize() result in a request body',
    integrations: () => [Sentry.requestDataIntegration()],
    place: (canary) => {
      Sentry.getCurrentScope().setSDKProcessingMetadata({
        normalizedRequest: {
          url: 'http://127.0.0.1:8080/pay',
          method: 'POST',
          data: { payload: new SensitiveString(canary, 'credential').serialize() },
        },
      });
      Sentry.captureException(new Error('boom'));
    },
  },
];

describe('canary sweep', () => {
  for (const position of POSITIONS) {
    // TEST-SENTRY-CANARY
    it(`does not send the canary from ${position.name}`, async () => {
      const canary = createCanary('sentry');
      const { capture, transport } = createCapture();
      const integrations = position.integrations?.() ?? [];

      await runIsolated(
        withSensitiveScrubbing({ transport, integrations: integrations as never }),
        () => {
          position.place(canary);
        }
      );

      expect(capture.envelopes.length).toBeGreaterThan(0);

      // The whole envelope, not just the event: the transport is the last
      // thing before the network.
      expectNoCanary(capture.envelopes, canary, `${position.name} envelope`);
      expectNoCanary(JSON.stringify(capture.envelopes), canary, `${position.name} serialized`);
    });
  }

  it('proves each position exists by leaking without the scrubbing', async () => {
    // A sweep that only asserts absence keeps passing when the fixture is
    // wrong. This runs the same positions with no scrubbing and requires the
    // canary to arrive, so every case above is testing something.
    const leaked: string[] = [];

    for (const position of POSITIONS) {
      const canary = createCanary('bare');
      const { capture, transport } = createCapture();

      await runIsolated(
        { transport, integrations: (position.integrations?.() ?? []) as never },
        () => {
          position.place(canary);
        }
      );

      if (JSON.stringify(capture.envelopes).includes(canary)) {
        leaked.push(position.name);
      }
    }

    // Every position except the wrapped ones, which the library already covers
    // through `toJSON()` and which are here to prove that stays true.
    const expected = POSITIONS.filter((p) => p.wrapped !== true).map((p) => p.name);

    expect(leaked.sort()).toEqual(expected.sort());
  });
});

describe('pinning: what this package depends on', () => {
  // TEST-SENTRY-PIN-NORMALIZE
  it('hands an event processor live instances and beforeSend normalized ones', async () => {
    // This is why the hook map is what it is. If Sentry moves normalization,
    // the map is wrong and stage 1 has to move with it.
    const seen: Record<string, boolean> = {};
    const { transport } = createCapture();

    await runIsolated(
      {
        transport,
        beforeSend(event) {
          seen['beforeSend'] = event.extra?.['s'] instanceof SensitiveString;
          return event;
        },
      },
      () => {
        Sentry.addEventProcessor((event) => {
          seen['processor'] = event.extra?.['s'] instanceof SensitiveString;
          return event;
        });
        Sentry.getCurrentScope().setExtra('s', new SensitiveString('x', 'credential'));
        Sentry.captureException(new Error('boom'));
      }
    );

    expect(seen['processor']).toBe(true);
    expect(seen['beforeSend']).toBe(false);
  });

  // TEST-SENTRY-PIN-ORDER
  it('runs a setup-registered scope processor after every integration', async () => {
    // An integration listed first does not see contexts.Error in its own
    // processEvent; a scope processor it registers from setup() does.
    const order: string[] = [];
    const { transport } = createCapture();

    const probe = {
      name: 'Probe',
      setup() {
        Sentry.addEventProcessor((event) => {
          order.push(`scope:${event.contexts?.['Error'] !== undefined}`);
          return event;
        });
      },
      processEvent(event: Sentry.Event) {
        order.push(`processEvent:${event.contexts?.['Error'] !== undefined}`);
        return event;
      },
    };

    await runIsolated(
      { transport, integrations: [probe, Sentry.extraErrorDataIntegration()] as never },
      () => {
        Sentry.captureException(Object.assign(new Error('boom'), { detail: 'x' }));
      }
    );

    expect(order).toEqual(['processEvent:false', 'scope:true']);
  });

  // TEST-SENTRY-PIN-COPY
  it('keeps a shared reference that redactInStructure would corrupt', () => {
    // Pins the reason stage 1 uses redactCopy. Against this repository rather
    // than the vendor, because it is this repository's helper that differs.
    const shared = { requestId: 'abc' };
    const event = { extra: { a: shared, b: shared } };

    const flattened = redactInStructure(event) as { extra: { b: unknown } };
    const copied = redactCopy(event) as { extra: { a: object; b: object } };

    expect(flattened.extra.b).toBe('[Circular]');
    expect(copied.extra.a).toBe(copied.extra.b);
  });

  // TEST-SENTRY-PIN-THROW
  it('drops the original event and sends a replacement when a hook throws', async () => {
    // The behaviour the never-throw wrapper exists to avoid depending on. If
    // this ever changes, the stub path is still correct and this test is what
    // says the dependency never became accidental.
    const { capture, transport } = createCapture();
    let threwToCaller = false;

    await runIsolated(
      {
        transport,
        beforeSend() {
          throw new Error('scrubber exploded');
        },
      },
      () => {
        try {
          Sentry.captureException(new Error('original boom'));
        } catch {
          threwToCaller = true;
        }
      }
    );

    const values = capture.lastEvent()['exception'] as { values: { value: string }[] };

    expect(threwToCaller).toBe(false);
    expect(values.values[0]?.value).toBe('scrubber exploded');
  });

  // TEST-SENTRY-PIN-EXTRAERROR
  it('normalizes error properties before any event processor sees them', async () => {
    // The one measured source of a false marker sighting: a wrapped value on a
    // thrown error arrives at the scope processor already rendered as its
    // marker, indistinguishable from a marker that arrived in captured data.
    // extraErrorData is not a default integration, which is what keeps this
    // narrow, and the README says so.
    const seen: Record<string, unknown> = {};
    const { transport } = createCapture();

    await runIsolated(
      { transport, integrations: [Sentry.extraErrorDataIntegration()] as never },
      () => {
        Sentry.addEventProcessor((event) => {
          seen['contextsError'] = (event.contexts?.['Error'] as Record<string, unknown>)?.[
            'wrapped'
          ];
          seen['extra'] = event.extra?.['direct'] instanceof SensitiveString;
          return event;
        });

        Sentry.captureException(
          Object.assign(new Error('boom'), { wrapped: new SensitiveString('x', 'credential') }),
          { extra: { direct: new SensitiveString('x', 'credential') } }
        );
      }
    );

    expect(seen['contextsError']).toBe('[REDACTED:credential]');
    expect(seen['extra']).toBe(true);
  });
});
