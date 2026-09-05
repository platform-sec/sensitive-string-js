import {
  createCanary,
  expectCanaryPresent,
  expectNoCanary,
} from '@platform-sec/sensitive-string-scrub/testing';
import { beforeAll, describe, expect, it } from 'vitest';

import { REQUEST_HEADER_PREFIX, RESPONSE_HEADER_PREFIX } from '../paths.js';
import {
  clientSpan,
  ensureBuilt,
  headerTags,
  runDriver,
  serverSpan,
  type DriverRun,
} from './fixtures.js';

/**
 * The hooks, against the real agent and the real msgpack.
 *
 * Every case is one process posting to a stand-in trace agent this file owns,
 * and every assertion is against the decoded `PUT /v0.4/traces` body. The
 * scrubbed arm and the unscrubbed companion are the same process spec with
 * `install` flipped, so a case that stops exercising anything fails the
 * companion rather than passing quietly.
 *
 * Measured against `dd-trace` 6.14.0 on Node 22.15.0.
 */

const CANARY = createCanary('HOOKS');
const CAPTURED = ['authorization', 'cookie', 'x-api-key', 'x-trace'];

let bare: DriverRun;
let scrubbed: DriverRun;

beforeAll(async () => {
  ensureBuilt();

  bare = await runDriver({ canary: CANARY, headerTags: CAPTURED });
  scrubbed = await runDriver({ canary: CANARY, headerTags: CAPTURED, install: true });
}, 180_000);

describe('the leak this row exists for', () => {
  it('reaches the server span with nothing installed', () => {
    expect(headerTags(serverSpan(bare.spans))).toMatchObject({
      [`${REQUEST_HEADER_PREFIX}authorization`]: `Bearer ${CANARY}`,
      [`${REQUEST_HEADER_PREFIX}cookie`]: `session=${CANARY}`,
      [`${REQUEST_HEADER_PREFIX}x-api-key`]: CANARY,
    });
  });

  it('reaches the client span too, which is the half a user does not expect', () => {
    expect(headerTags(clientSpan(bare.spans))).toMatchObject({
      [`${REQUEST_HEADER_PREFIX}authorization`]: `Bearer ${CANARY}`,
    });
  });

  it('reaches the response header direction as well', () => {
    expect(headerTags(serverSpan(bare.spans))[`${RESPONSE_HEADER_PREFIX}x-api-key`]).toBe(CANARY);
  });

  it('leaks, so every absence asserted below means something', () => {
    expectCanaryPresent(bare.spans, CANARY, 'the unscrubbed trace payload');
  });
});

describe('with scrubbing installed', () => {
  it('censors the credential headers on the server span', () => {
    const tags = headerTags(serverSpan(scrubbed.spans));

    expect(tags[`${REQUEST_HEADER_PREFIX}authorization`]).toBe('[SCRUBBED]');
    expect(tags[`${REQUEST_HEADER_PREFIX}cookie`]).toBe('[SCRUBBED]');
    expect(tags[`${REQUEST_HEADER_PREFIX}x-api-key`]).toBe('[SCRUBBED]');
  });

  it('censors them on the client span', () => {
    const tags = headerTags(clientSpan(scrubbed.spans));

    expect(tags[`${REQUEST_HEADER_PREFIX}authorization`]).toBe('[SCRUBBED]');
    expect(tags[`${REQUEST_HEADER_PREFIX}cookie`]).toBe('[SCRUBBED]');
  });

  it('censors the response header direction', () => {
    expect(headerTags(serverSpan(scrubbed.spans))[`${RESPONSE_HEADER_PREFIX}x-api-key`]).toBe(
      '[SCRUBBED]'
    );
  });

  it('keeps the header the operator turned capture on for', () => {
    expect(headerTags(serverSpan(scrubbed.spans))[`${REQUEST_HEADER_PREFIX}x-trace`]).toBe(
      'keep-me'
    );
  });

  it('keeps the route and the method, so the span is still worth having', () => {
    expect(serverSpan(scrubbed.spans).meta?.['http.url']).toContain('/pay');
    expect(serverSpan(scrubbed.spans).meta?.['http.method']).toBe('POST');
  });

  it('leaks no canary anywhere in the payload', () => {
    expectNoCanary(scrubbed.spans, CANARY, 'the trace payload');
  });
});

describe('policy handling', () => {
  it('takes a caller denylist entry', async () => {
    const run = await runDriver({
      canary: CANARY,
      headerTags: CAPTURED,
      install: true,
      installOptions: { denyKeys: ['x-trace'] },
    });

    expect(headerTags(serverSpan(run.spans))[`${REQUEST_HEADER_PREFIX}x-trace`]).toBe('[SCRUBBED]');
  }, 60_000);

  it('honours allowKeys, with the reason recorded', async () => {
    const run = await runDriver({
      canary: CANARY,
      headerTags: CAPTURED,
      install: true,
      installOptions: {
        allowKeys: [{ key: 'x-api-key', reason: 'opaque tenant id here, not a secret' }],
      },
    });

    expect(headerTags(serverSpan(run.spans))[`${REQUEST_HEADER_PREFIX}x-api-key`]).toBe(CANARY);
  }, 60_000);

  it('captures a header the caller named even when it is denied', async () => {
    // The tag exists and its presence stays diagnostic; the value does not.
    const run = await runDriver({
      canary: CANARY,
      install: true,
      installOptions: { captureHeaders: ['authorization'] },
    });

    expect(headerTags(serverSpan(run.spans))[`${REQUEST_HEADER_PREFIX}authorization`]).toBe(
      '[SCRUBBED]'
    );
  }, 60_000);
});

describe('reporting', () => {
  it('reports per scrubbed span, with names and no values', () => {
    expect(scrubbed.result.reports.length).toBeGreaterThan(0);

    const spanReports = scrubbed.result.reports.filter((report) => report.kind === 'span');

    expect(spanReports.length).toBe(scrubbed.result.reports.length);
    expect(spanReports.some((report) => report.deniedKeys.length > 0)).toBe(true);
    expect(JSON.stringify(scrubbed.result.reports)).not.toContain(CANARY);
  });

  it('reports no failure on the ordinary path', () => {
    expect(scrubbed.result.reports.every((report) => !report.failed)).toBe(true);
  });

  it('finds tag enumeration available on this dd-trace', () => {
    expect(scrubbed.result.degraded).toEqual([]);
    expect(scrubbed.result.notes['installation']).toMatchObject({ enumeratesTags: true });
  });
});
