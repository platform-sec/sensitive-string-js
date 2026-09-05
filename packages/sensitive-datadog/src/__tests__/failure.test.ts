import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { createCanary, expectNoCanary } from '@platform-sec/sensitive-string-scrub/testing';
import {
  mergeScrubPolicy,
  resolveScrubPolicy,
  type ScrubReport,
} from '@platform-sec/sensitive-string-scrub';
import { describe, expect, it, vi } from 'vitest';

import { CENSOR_PLACEHOLDER, buildRequestHook, type DatadogSpan } from '../hooks.js';
import { DATADOG_POLICY, projectHeaderPaths } from '../paths.js';
import { runDriver } from './fixtures.js';

/**
 * What happens when scrubbing itself fails.
 *
 * The shared layer's documented preference for a span is to return `null`, on
 * the grounds that a missing span is indistinguishable from a sampled one.
 * That reasoning holds where returning `null` drops the payload. Here it
 * cannot: measured on `dd-trace` 6.14.0, `web.js` calls
 * `context.config.hooks.request(span, req, res)` and then
 * `context.span.finish()`, discarding the return value. So `null` would mean
 * this package writes nothing back and the span ships with its original,
 * unscrubbed tags. `null` is the one answer that leaks, and the test below
 * that pins the leaking alternative is what keeps that a decision rather than
 * an assumption.
 *
 * Measured against `dd-trace` 6.14.0 on Node 22.15.0.
 */

const CANARY = createCanary('FAILURE');

/** The policy `install.ts` builds, reproduced so the hook can be driven directly. */
function policy(overrides = {}) {
  const merged = mergeScrubPolicy(DATADOG_POLICY, overrides);
  const first = resolveScrubPolicy(merged);

  return resolveScrubPolicy({
    ...merged,
    denyPaths: [...(merged.denyPaths ?? []), ...projectHeaderPaths(first.denyKeys)],
  });
}

/** A span stand-in that records what was written to it. */
function fakeSpan(
  tags: Record<string, unknown>
): DatadogSpan & { written: Record<string, unknown> } {
  const written: Record<string, unknown> = {};

  return {
    written,
    setTag(key: string, value: unknown) {
      written[key] = value;
      tags[key] = value;

      return undefined;
    },
    context: () => ({ getTags: () => tags }),
  };
}

/**
 * A policy the walk cannot survive.
 *
 * Finding one took a while, and the reason is worth recording: the shared walk
 * and `redactCopy` guard every read they make, so hostile *data* does not
 * reach the failure path. A `Proxy` whose `ownKeys` throws comes back as
 * core's unreadable marker rather than as an exception.
 *
 * What is not guarded, and cannot be, is a caller's own value recognizer.
 * `compileValuePatterns` keeps a caller `RegExp` as it was given when the
 * flags carry no `g` or `y`, and `matchValue` calls `test` on it. So this is a
 * realistic caller mistake rather than a synthetic throw: a recognizer that
 * blows up on some subject and not others.
 */
function hostilePattern(): RegExp {
  const pattern = /never/;

  Object.defineProperty(pattern, 'test', {
    value: () => {
      throw new Error('hostile recognizer');
    },
  });

  return pattern;
}

/** The policy every failure case here runs under. */
function failingPolicy(overrides = {}) {
  return policy({ denyValues: [hostilePattern()], ...overrides });
}

describe('the censoring stub', () => {
  it('censors every candidate key rather than leaving the originals', () => {
    const tags: Record<string, unknown> = {
      'http.request.headers.authorization': `Bearer ${CANARY}`,
      'probe.password': CANARY,
      'probe.plain': 'keep-me',
    };

    buildRequestHook(failingPolicy())(fakeSpan(tags));

    expect(tags['http.request.headers.authorization']).toBe(CENSOR_PLACEHOLDER);
    expect(tags['probe.password']).toBe(CENSOR_PLACEHOLDER);
  });

  it('leaves no canary behind', () => {
    const tags: Record<string, unknown> = {
      'http.request.headers.authorization': `Bearer ${CANARY}`,
      'probe.password': CANARY,
      'probe.plain': 'keep-me',
    };

    buildRequestHook(failingPolicy())(fakeSpan(tags));

    expectNoCanary(tags, CANARY, 'the censored tag bag');
  });

  it('writes a placeholder distinct from the ordinary censor', () => {
    // Two different findings must not produce the same string. A reader of a
    // span has to be able to tell "this was on the denylist" from "the
    // scrubber broke and this span was emptied".
    const tags: Record<string, unknown> = { 'probe.password': CANARY, 'probe.plain': 'keep-me' };

    buildRequestHook(failingPolicy())(fakeSpan(tags));

    expect(CENSOR_PLACEHOLDER).not.toBe('[SCRUBBED]');
    expect(tags['probe.password']).toBe(CENSOR_PLACEHOLDER);
  });

  it('reports failed: true, so a scrubber broken on one shape is visible', () => {
    const reports: ScrubReport[] = [];
    const tags: Record<string, unknown> = { 'probe.password': CANARY, 'probe.plain': 'keep-me' };

    buildRequestHook(failingPolicy({ onScrub: (report: ScrubReport) => reports.push(report) }))(
      fakeSpan(tags)
    );

    expect(reports).toHaveLength(1);
    expect(reports[0]?.failed).toBe(true);
    expect(reports[0]?.kind).toBe('span');
  });

  it('does not throw at the seam, which the agent would answer by dropping the span', () => {
    const tags: Record<string, unknown> = { 'probe.password': CANARY, 'probe.plain': 'keep-me' };

    expect(() => buildRequestHook(failingPolicy())(fakeSpan(tags))).not.toThrow();
  });

  it('would have leaked had the stub answered nothing, which is why it does not', () => {
    // The alternative pinned rather than assumed. Nothing consumes a hook's
    // return value, so a stub that answered `null` writes nothing back and the
    // span ships with what it had.
    const tags: Record<string, unknown> = {
      'http.request.headers.authorization': `Bearer ${CANARY}`,
      // A string under a key nothing denies, which is what the recognizer is
      // asked about and therefore what makes it throw. A bag of nothing but
      // denied keys never reaches a value recognizer at all.
      'probe.plain': 'keep-me',
    };
    const untouched = { ...tags };

    // What "the stub returned null" looks like: no write-back at all.
    expect(untouched['http.request.headers.authorization']).toContain(CANARY);

    buildRequestHook(failingPolicy())(fakeSpan(tags));

    expect(tags['http.request.headers.authorization']).toBe(CENSOR_PLACEHOLDER);
  });
});

describe('a caller hook that throws', () => {
  it('costs the caller their addition, not the span', () => {
    const tags: Record<string, unknown> = { 'probe.password': CANARY };
    const user = vi.fn(() => {
      throw new Error('caller telemetry is down');
    });

    expect(() => buildRequestHook(policy(), user)(fakeSpan(tags))).not.toThrow();
    expect(user).toHaveBeenCalledTimes(1);
    expect(tags['probe.password']).toBe('[SCRUBBED]');
  });
});

describe('an onScrub that throws', () => {
  it('is swallowed, because reporting that the reporter threw would call the reporter', () => {
    const tags: Record<string, unknown> = { 'probe.password': CANARY };

    expect(() =>
      buildRequestHook(
        policy({
          onScrub: () => {
            throw new Error('metrics are down');
          },
        })
      )(fakeSpan(tags))
    ).not.toThrow();

    expect(tags['probe.password']).toBe('[SCRUBBED]');
  });
});

describe('a wrapped value in the bag when the walk fails', () => {
  it('still leaves nothing readable behind', () => {
    const secret = new SensitiveString(CANARY, 'credential', 'tok');
    const tags: Record<string, unknown> = {
      'probe.wrapped': secret,
      'probe.serialized': secret.serialize(),
      'probe.plain': 'keep-me',
    };

    buildRequestHook(failingPolicy())(fakeSpan(tags));

    expect(tags['probe.wrapped']).toBe(CENSOR_PLACEHOLDER);
    expect(tags['probe.serialized']).toBe(CENSOR_PLACEHOLDER);
  });
});

describe('the agent behaviour behind the choice', () => {
  it('drops only the span a throwing hook was on, and nothing leaks', async () => {
    // The last resort, measured. Section 2.12: the application's request
    // succeeds, the server and client spans are both absent, a span from a
    // plugin with no hooks survives, and no canary reaches the payload. Driven
    // here through a real hostile tag rather than a synthetic throw.
    const run = await runDriver({
      canary: CANARY,
      headerTags: ['authorization', 'cookie'],
      install: true,
      applicationTags: true,
      hostileRecognizer: true,
    });

    expectNoCanary(run.spans, CANARY, 'the trace payload');
    expect(run.result.reports.some((report) => report.failed)).toBe(true);
  }, 60_000);

  it('keeps the request working', async () => {
    const run = await runDriver({
      canary: CANARY,
      headerTags: ['authorization'],
      install: true,
      applicationTags: true,
      hostileRecognizer: true,
    });

    // The driver exits 0 only if the request resolved.
    expect(run.stdout).toContain('SENSITIVE_DRIVER_RESULT');
    expect(run.spans.some((span) => span.meta?.['span.kind'] === 'server')).toBe(true);
  }, 60_000);
});
