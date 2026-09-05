import { join } from 'node:path';
import {
  createCanary,
  expectCanaryPresent,
  expectNoCanary,
  findCoreImports,
} from '@platform-sec/sensitive-string-scrub/testing';
import { beforeAll, describe, expect, it } from 'vitest';

import { REQUEST_HEADER_PREFIX, RESPONSE_HEADER_PREFIX } from '../paths.js';
import {
  clientSpan,
  ensureBuilt,
  headerTags,
  packageRoot,
  runDriver,
  serverSpan,
  type DriverRun,
  type EncodedSpan,
} from './fixtures.js';

/**
 * The sweep, and the companion that keeps it honest.
 *
 * Every position runs twice: once with scrubbing installed and once without,
 * and the unscrubbed run is required to leak. A sweep that only asserts
 * absence keeps passing when a fixture stops exercising anything, which is
 * what the error tracking design's success criteria should have asked for and
 * did not.
 *
 * Measured against `dd-trace` 6.14.0 on Node 22.15.0.
 */

const CANARY = createCanary('SWEEP');
const CAPTURED = ['authorization', 'cookie', 'x-api-key', 'x-trace'];

/** Every position this package can reach, in one process. */
const SWEEP = {
  canary: CANARY,
  headerTags: CAPTURED,
  applicationTags: true,
} as const;

let bare: DriverRun;
let scrubbed: DriverRun;

beforeAll(async () => {
  ensureBuilt();

  bare = await runDriver(SWEEP);
  scrubbed = await runDriver({ ...SWEEP, install: true });
}, 180_000);

describe('the whole sweep', () => {
  it('leaks in every position with nothing installed', () => {
    expectCanaryPresent(bare.spans, CANARY, 'the unscrubbed trace payload');
  });

  it('leaks nothing with scrubbing installed', () => {
    expectNoCanary(scrubbed.spans, CANARY, 'the trace payload');
  });

  it('produced the spans it claims to have swept', () => {
    // Section count is a property of the fixture rather than of the package,
    // and it decides whether the absence above proves anything.
    const names = new Set(scrubbed.spans.map((span) => span.name));

    expect(names.has('probe.tags')).toBe(true);
    expect(scrubbed.spans.some((span) => span.meta?.['span.kind'] === 'server')).toBe(true);
    expect(
      scrubbed.spans.some(
        (span) => span.meta?.['span.kind'] === 'client' && span.meta?.['http.method'] !== undefined
      )
    ).toBe(true);
  });
});

describe('each position, scrubbed and bare', () => {
  const positions: [string, (run: DriverRun) => unknown][] = [
    [
      'an inbound request header on the server span',
      (run) => headerTags(serverSpan(run.spans))[`${REQUEST_HEADER_PREFIX}authorization`],
    ],
    [
      'an outbound request header on the client span',
      (run) => headerTags(clientSpan(run.spans))[`${REQUEST_HEADER_PREFIX}cookie`],
    ],
    [
      'a response header',
      (run) => headerTags(serverSpan(run.spans))[`${RESPONSE_HEADER_PREFIX}x-api-key`],
    ],
    ['a query parameter in http.url', (run) => serverSpan(run.spans).meta?.['http.url']],
    ['an application-set string tag', (run) => probeMeta(run)['probe.password']],
    ['an application-set URL tag', (run) => probeMeta(run)['probe.url']],
    [
      'an application-set wrapped tag',
      (run) => probeMeta(run)['probe.wrapped'] ?? probeMeta(run)['probe.wrapped.klass'],
    ],
    [
      'an application-set serialize() result',
      (run) => probeMeta(run)['probe.serialized'] ?? probeMeta(run)['probe.serialized.value'],
    ],
  ];

  it.each(positions)('%s is clean once scrubbed', (_name, read) => {
    expectNoCanary(read(scrubbed), CANARY, 'the position');
  });

  /**
   * Two positions cannot be asked to leak, for opposite reasons.
   *
   * The wrapped tag is safe with nothing installed because `dd-trace` flattens
   * it into a class tag rather than writing the value; its own case is below.
   * `http.url` is safe because the agent's own query obfuscator covers
   * `token=` by default, which is section 2.1's measurement and the reason
   * this package composes with that pattern rather than replacing it. The
   * parameter the default does *not* cover has its own case below.
   */
  const CANNOT_LEAK = ['wrapped', 'http.url'];

  it.each(positions.filter(([name]) => !CANNOT_LEAK.some((skip) => name.includes(skip))))(
    '%s carries the canary when nothing is installed',
    (_name, read) => {
      expectCanaryPresent(read(bare), CANARY, 'the unscrubbed position');
    }
  );

  it("the agent's own obfuscator already covers ?token=, which is why it is composed with", () => {
    const url = serverSpan(bare.spans).meta?.['http.url'] ?? '';

    expect(url).toContain('<redacted>');
    expect(url).not.toContain(`token=${CANARY}`);
  });

  it('leaks a query parameter the agent default does not cover, until this package composes', () => {
    // `cookie` is on the shared denylist and is not in `dd-trace`'s default
    // pattern, so it is the parameter that proves the composition does
    // something.
    const bareUrl = serverSpan(bare.spans).meta?.['http.url'] ?? '';

    expect(bareUrl).toContain(`cookie=${CANARY}`);

    const scrubbedUrl = serverSpan(scrubbed.spans).meta?.['http.url'] ?? '';

    expect(scrubbedUrl).not.toContain(CANARY);
    expect(scrubbedUrl).toContain('page=2');
  });

  it('the wrapped tag leaks the label rather than the value, with nothing installed', () => {
    // The other half of section 2.3, and the reason `reportLabels` being off
    // has to mean something here: the label is transmitted with no option
    // involved.
    expect(probeMeta(bare)['probe.wrapped.label']).toBe('tok');
    expect(probeMeta(scrubbed)['probe.wrapped.label']).toBeUndefined();
  });
});

describe('a framework-served request', () => {
  /**
   * The correction the design did not have.
   *
   * `web.js`'s `setFramework` calls `web.setConfig(req, config)` and replaces
   * the request's whole plugin config with the framework plugin's, hooks and
   * header list included. So an express-served request runs the **express**
   * plugin's hook, and covering `http` alone leaves `express.request` carrying
   * the raw header. Measured, with a hook on `http` only:
   *
   * ```
   * express.request  http.request.headers.authorization  "Bearer LEAKED_..."
   * http.request     http.request.headers.authorization  "[SCRUBBED]"
   * ```
   */
  let framework: { bare: DriverRun; scrubbed: DriverRun };

  beforeAll(async () => {
    framework = {
      bare: await runDriver({ canary: CANARY, headerTags: CAPTURED, framework: 'express' }),
      scrubbed: await runDriver({
        canary: CANARY,
        headerTags: CAPTURED,
        framework: 'express',
        install: true,
      }),
    };
  }, 120_000);

  it('produces an express.request span rather than a web.request one', () => {
    expect(framework.bare.spans.some((span) => span.name === 'express.request')).toBe(true);
  });

  it('leaks the credential headers with nothing installed', () => {
    expectCanaryPresent(framework.bare.spans, CANARY, 'the unscrubbed express payload');
  });

  it('censors them on the express span', () => {
    const span = framework.scrubbed.spans.find((entry) => entry.name === 'express.request');

    expect(span, 'no express.request span was produced').toBeDefined();
    expect(headerTags(span as EncodedSpan)[`${REQUEST_HEADER_PREFIX}authorization`]).toBe(
      '[SCRUBBED]'
    );
  });

  it('leaks nothing anywhere in the express payload', () => {
    expectNoCanary(framework.scrubbed.spans, CANARY, 'the express trace payload');
  });
});

describe('invariant 8: this package does not reveal', () => {
  it('imports only the core names a scrubbing package is allowed', () => {
    const allowed = new Set([
      'redactCopy',
      'containsSensitive',
      'sensitiveClassesIn',
      'SensitiveString',
      'SensitivityClass',
    ]);

    const disallowed = findCoreImports(join(packageRoot(), 'src')).filter(
      (entry) => !allowed.has(entry.name)
    );

    expect(disallowed).toEqual([]);
  });
});

/** The `probe.tags` span's meta, which is where the application-set positions live. */
function probeMeta(run: DriverRun): Record<string, string> {
  const span = run.spans.find((entry) => entry.name === 'probe.tags');

  if (span === undefined) {
    throw new Error(`no probe.tags span among ${run.spans.map((entry) => entry.name).join(', ')}`);
  }

  return span.meta ?? {};
}
