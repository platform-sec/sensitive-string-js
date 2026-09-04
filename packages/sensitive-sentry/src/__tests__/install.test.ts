import * as Sentry from '@sentry/node';
import type { Event, NodeOptions } from '@sentry/node';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { ScrubReport } from '@platform-sec/sensitive-string-scrub';
import { describe, expect, it, vi } from 'vitest';

import {
  COVERED_HOOKS,
  SentryScrubbingError,
  isApplied,
  withSensitiveScrubbing,
} from '../install.js';
import { INTEGRATION_NAME } from '../integration.js';
import { CLASSES_TAG, MARKER_TAG, SCRUB_FAILED_TAG } from '../stub.js';
import { attachRequest, createCapture, runIsolated } from './fixtures.js';

const CANARY = 'LEAKED_SECRET_install_3a7f';

describe('hook composition', () => {
  // TEST-SENTRY-COMPOSE
  it('wraps every before* hook the SDK declares', () => {
    const wrapped = withSensitiveScrubbing({});

    for (const name of COVERED_HOOKS) {
      expect(typeof wrapped[name], `${name} was not composed`).toBe('function');
    }
  });

  it('composes a caller hook rather than replacing it', async () => {
    const { capture, transport } = createCapture();
    const calls: string[] = [];

    await runIsolated(
      withSensitiveScrubbing({
        transport,
        beforeSend(event) {
          calls.push('user');
          return { ...event, tags: { ...event.tags, userHookRan: 'yes' } };
        },
      }),
      () => {
        Sentry.captureException(new Error('boom'));
      }
    );

    expect(calls).toEqual(['user']);
    expect((capture.lastEvent()['tags'] as Record<string, string>)['userHookRan']).toBe('yes');
  });

  // TEST-SENTRY-ORDER
  it('runs the caller hook after the scrubber, on the already-scrubbed payload', async () => {
    const { transport } = createCapture();
    const seen: unknown[] = [];

    await runIsolated(
      withSensitiveScrubbing({
        transport,
        integrations: [Sentry.requestDataIntegration()],
        beforeSend(event) {
          seen.push((event.request as { headers: Record<string, string> } | undefined)?.headers);
          return event;
        },
      }),
      () => {
        attachRequest(CANARY);
        Sentry.captureException(new Error('boom'));
      }
    );

    expect((seen[0] as Record<string, string>)['authorization']).toBe('[SCRUBBED]');
  });

  it('lets a caller hook returning null still drop the payload', async () => {
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport, beforeSend: () => null }), () => {
      Sentry.captureException(new Error('boom'));
    });

    expect(capture.events()).toHaveLength(0);
  });

  it('sends the scrubbed payload when a caller hook throws', async () => {
    const { capture, transport } = createCapture();

    await runIsolated(
      withSensitiveScrubbing({
        transport,
        integrations: [Sentry.requestDataIntegration()],
        beforeSend() {
          throw new Error('user hook exploded');
        },
      }),
      () => {
        attachRequest(CANARY);
        Sentry.captureException(new Error('original boom'));
      }
    );

    // Measured on @sentry/node 10.73.0: a throwing beforeSend drops the
    // original event and sends one describing the scrubber instead. Catching
    // the caller's hook is what keeps the real error.
    const event = capture.lastEvent();
    const exception = event['exception'] as { values: { value: string }[] };

    expect(exception.values[0]?.value).toBe('original boom');
    expect(JSON.stringify(event)).not.toContain(CANARY);
  });

  it('composes beforeBreadcrumb, which no integration can reach', async () => {
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport }), () => {
      Sentry.addBreadcrumb({ message: 'auth', data: { access_token: CANARY, ok: 'keep' } });
      Sentry.captureException(new Error('boom'));
    });

    const crumbs = capture.lastEvent()['breadcrumbs'] as { data: Record<string, string> }[];

    expect(crumbs[0]?.data['access_token']).toBe('[SCRUBBED]');
    expect(crumbs[0]?.data['ok']).toBe('keep');
  });
});

describe('the integration', () => {
  it('is appended to an array of integrations', () => {
    const wrapped = withSensitiveScrubbing({ integrations: [Sentry.dedupeIntegration()] });
    const integrations = wrapped.integrations as { name: string }[];

    expect(integrations.map((i) => i.name)).toContain(INTEGRATION_NAME);
    expect(integrations).toHaveLength(2);
  });

  it('preserves the function form, so a caller filtering the defaults still filters', () => {
    const wrapped = withSensitiveScrubbing({
      integrations: (defaults) => defaults.filter((i) => i.name !== 'Dedupe'),
    });

    const build = wrapped.integrations as (d: { name: string }[]) => { name: string }[];
    const result = build([{ name: 'Dedupe' }, { name: 'Http' }] as never);

    expect(result.map((i) => i.name)).toEqual(['Http', INTEGRATION_NAME]);
  });

  // TEST-SENTRY-ORDER-SETUP
  it('scrubs contexts written by an integration listed after it', async () => {
    // The measurement this package's shape turns on. An integration's
    // processEvent runs in registration order, so a scrubber written that way
    // and listed first would never see contexts.<ErrorName>. A scope event
    // processor registered from setup() runs after every integration.
    const { capture, transport } = createCapture();

    await runIsolated(
      withSensitiveScrubbing({
        transport,
        integrations: [Sentry.extraErrorDataIntegration()],
      }),
      () => {
        const error = Object.assign(new Error('boom'), { access_token: CANARY, keep: 'yes' });
        Sentry.captureException(error);
      }
    );

    const contexts = capture.lastEvent()['contexts'] as Record<string, Record<string, unknown>>;

    expect(contexts['Error']?.['access_token']).toBe('[SCRUBBED]');
    expect(contexts['Error']?.['keep']).toBe('yes');
  });
});

describe('idempotence', () => {
  // TEST-SENTRY-IDEMPOTENT
  it('returns the same object when applied twice', () => {
    const once = withSensitiveScrubbing({ dsn: 'x' });

    expect(withSensitiveScrubbing(once)).toBe(once);
  });

  it('marks what it produced', () => {
    expect(isApplied({})).toBe(false);
    expect(isApplied(withSensitiveScrubbing({}))).toBe(true);
  });

  it('does not append the integration twice', () => {
    const once = withSensitiveScrubbing({});
    const twice = withSensitiveScrubbing(once);
    const integrations = twice.integrations as { name: string }[];

    expect(integrations.filter((i) => i.name === INTEGRATION_NAME)).toHaveLength(1);
  });

  it('reports each payload once', async () => {
    // An event passes the scope event processor and then beforeSend. Only the
    // first reports, so a report still means one payload.
    const { transport } = createCapture();
    const reports: ScrubReport[] = [];

    await runIsolated(
      withSensitiveScrubbing(
        { transport, integrations: [Sentry.requestDataIntegration()] },
        { onScrub: (report) => reports.push(report) }
      ),
      () => {
        attachRequest(CANARY);
        Sentry.captureException(new Error('boom'));
      }
    );

    expect(reports.filter((report) => report.kind === 'event')).toHaveLength(1);
  });

  it('does not modify the options object it was given', () => {
    const original: NodeOptions = { dsn: 'x' };

    withSensitiveScrubbing(original);

    expect(original).toEqual({ dsn: 'x' });
    expect(original.beforeSend).toBeUndefined();
  });
});

describe('sendDefaultPii', () => {
  // TEST-SENTRY-PII
  it('is refused rather than scrubbed harder', () => {
    expect(() => withSensitiveScrubbing({ sendDefaultPii: true })).toThrow(SentryScrubbingError);
  });

  it('names dataCollection in the refusal', () => {
    expect(() => withSensitiveScrubbing({ sendDefaultPii: true })).toThrow(/dataCollection/);
  });

  it('allows it explicitly off, and allows it unset', () => {
    expect(() => withSensitiveScrubbing({ sendDefaultPii: false })).not.toThrow();
    expect(() => withSensitiveScrubbing({})).not.toThrow();
  });
});

describe('tags', () => {
  it('names the classes that were in scope, without a value', async () => {
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport }), () => {
      Sentry.getCurrentScope().setExtra('s', new SensitiveString(CANARY, 'credential', 'stripe'));
      Sentry.captureException(new Error('boom'));
    });

    const tags = capture.lastEvent()['tags'] as Record<string, string>;

    expect(tags[CLASSES_TAG]).toBe('credential');
    expect(JSON.stringify(tags)).not.toContain('stripe');
    expect(JSON.stringify(tags)).not.toContain(CANARY);
  });

  it('adds labels only when the caller opts in', async () => {
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport }, { reportLabels: true }), () => {
      Sentry.getCurrentScope().setExtra('s', new SensitiveString(CANARY, 'credential', 'stripe'));
      Sentry.captureException(new Error('boom'));
    });

    expect((capture.lastEvent()['tags'] as Record<string, string>)['sensitive.labels']).toBe(
      'stripe'
    );
  });

  // TEST-SENTRY-MARKER
  it('tags a marker found in captured data instead of throwing', async () => {
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport }), () => {
      Sentry.getCurrentScope().setExtra('responseBody', 'auth failed for [REDACTED:credential]');
      Sentry.captureException(new Error('boom'));
    });

    const event = capture.lastEvent();

    expect((event['tags'] as Record<string, string>)[MARKER_TAG]).toBe('1');
    // The marker is the desired output, so it stays where it was found.
    expect((event['extra'] as Record<string, string>)['responseBody']).toContain('[REDACTED:');
  });

  it('is silent when nothing was found', async () => {
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport }), () => {
      Sentry.captureException(new Error('boom'));
    });

    const tags = (capture.lastEvent()['tags'] ?? {}) as Record<string, string>;

    expect(tags[CLASSES_TAG]).toBeUndefined();
    expect(tags[MARKER_TAG]).toBeUndefined();
    expect(tags[SCRUB_FAILED_TAG]).toBeUndefined();
  });
});

describe('onScrub', () => {
  it('receives counts and key names, never a value', async () => {
    const { transport } = createCapture();
    const onScrub = vi.fn();

    await runIsolated(
      withSensitiveScrubbing(
        { transport, integrations: [Sentry.requestDataIntegration()] },
        { onScrub }
      ),
      () => {
        attachRequest(CANARY);
        Sentry.captureException(new Error('boom'));
      }
    );

    const report = onScrub.mock.calls
      .map((call) => call[0] as ScrubReport)
      .find((r) => r.kind === 'event');

    expect(report?.deniedKeys).toContain('authorization');
    expect(JSON.stringify(onScrub.mock.calls)).not.toContain(CANARY);
  });

  it('does not take the hook down when it throws', async () => {
    const { capture, transport } = createCapture();

    await runIsolated(
      withSensitiveScrubbing(
        { transport, integrations: [Sentry.requestDataIntegration()] },
        {
          onScrub: () => {
            throw new Error('metrics backend down');
          },
        }
      ),
      () => {
        attachRequest(CANARY);
        Sentry.captureException(new Error('boom'));
      }
    );

    expect(capture.events()).toHaveLength(1);
    expect(JSON.stringify(capture.lastEvent())).not.toContain(CANARY);
  });
});

describe('the documented gap', () => {
  // TEST-SENTRY-GAP
  it('does not scrub what a processor registered after init adds', async () => {
    // Scope event processors run in registration order, so one the
    // application registers after withSensitiveScrubbing runs after ours.
    // This asserts the limitation by executing it, so the README sentence and
    // the behaviour cannot drift apart. beforeSend is the backstop that keeps
    // this from being a total gap: it catches a denied key name, and this test
    // uses a key outside the denylist to show the part that is genuinely open.
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport }), () => {
      Sentry.addEventProcessor((event: Event) => ({
        ...event,
        extra: { ...event.extra, lateAddition: CANARY },
      }));

      Sentry.captureException(new Error('boom'));
    });

    expect((capture.lastEvent()['extra'] as Record<string, string>)['lateAddition']).toBe(CANARY);
  });

  it('still catches a denied key name added by a late processor, at beforeSend', async () => {
    const { capture, transport } = createCapture();

    await runIsolated(withSensitiveScrubbing({ transport }), () => {
      Sentry.addEventProcessor((event: Event) => ({
        ...event,
        extra: { ...event.extra, access_token: CANARY },
      }));

      Sentry.captureException(new Error('boom'));
    });

    expect((capture.lastEvent()['extra'] as Record<string, string>)['access_token']).toBe(
      '[SCRUBBED]'
    );
  });
});
