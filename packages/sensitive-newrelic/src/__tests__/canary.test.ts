import { join } from 'node:path';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  createCanary,
  expectCanaryPresent,
  expectNoCanary,
  findCoreImports,
} from '@platform-sec/sensitive-string-scrub/testing';
import { describe, expect, it } from 'vitest';

import { sensitiveAttributes } from '../attributes.js';
import { sensitiveAgentConfig } from '../config.js';
import { attributeNames, packageRoot, runServerless, type InvocationSpec } from './fixtures.js';

/**
 * The sweep, and the companion that keeps it honest.
 *
 * Every case runs twice: once with the generated configuration and once
 * without. The unscrubbed run is required to leak. A sweep that only asserts
 * absence keeps passing when a fixture stops exercising anything, which is the
 * failure the error tracking design's success criteria should have asked for
 * and did not.
 *
 * The agent is real and runs in its own process per case, in serverless mode,
 * and the payload is the gzipped one it would have posted to the collector.
 * Nothing here contacts New Relic.
 *
 * Measured against `newrelic` 14.3.10 on Node 22.15.0.
 */

const SCRUBBED = sensitiveAgentConfig();

/** The same invocation with and without the generated exclusions. */
function bothWays(spec: InvocationSpec): {
  scrubbed: ReturnType<typeof runServerless>;
  bare: ReturnType<typeof runServerless>;
} {
  return {
    scrubbed: runServerless(SCRUBBED, spec),
    bare: runServerless({}, spec),
  };
}

describe('inbound request headers under allow_all_headers', () => {
  const canary = createCanary('HEADERS');
  const { scrubbed, bare } = bothWays({ canary });

  it('leaks without the generated configuration', () => {
    expectCanaryPresent(bare, canary, 'the unscrubbed payload');
  });

  it('carries the credential headers when nothing is excluding them', () => {
    expect(attributeNames(bare)).toContain('request.headers.authorization');
    expect(attributeNames(bare)).toContain('request.headers.cookie');
    // The renamed one. An exclusion spelled `x-api-key` would not have caught
    // it, which is the whole reason `names.ts` exists.
    expect(attributeNames(bare)).toContain('request.headers.xApiKey');
  });

  it('drops all three with the generated configuration', () => {
    expect(attributeNames(scrubbed)).not.toContain('request.headers.authorization');
    expect(attributeNames(scrubbed)).not.toContain('request.headers.cookie');
    expect(attributeNames(scrubbed)).not.toContain('request.headers.xApiKey');
  });

  it('keeps the headers an operator turned capture on for', () => {
    expect(attributeNames(scrubbed)).toContain('request.headers.userAgent');
    expect(attributeNames(scrubbed)).toContain('request.headers.host');
  });

  it('keeps the route, which is what the transaction is about', () => {
    expect(attributeNames(scrubbed)).toContain('request.uri');
  });
});

describe('custom attributes whose names are denied', () => {
  const canary = createCanary('CUSTOM');
  const { scrubbed, bare } = bothWays({ canary, deniedAttributes: true });

  it('leaks without the generated configuration', () => {
    expectCanaryPresent(bare, canary, 'the unscrubbed payload');
  });

  it('drops password, token and api_key with it', () => {
    const names = attributeNames(scrubbed);

    expect(names).not.toContain('password');
    expect(names).not.toContain('token');
    expect(names).not.toContain('api_key');
  });

  it('keeps an attribute nothing denied', () => {
    expect(attributeNames(scrubbed)).toContain('tenant');
  });
});

describe("noticeError's second argument", () => {
  const canary = createCanary('NOTICED');
  const { scrubbed, bare } = bothWays({ canary, errorAttributes: true });

  it('leaks without the generated configuration', () => {
    expectCanaryPresent(bare, canary, 'the unscrubbed payload');
  });

  it('is filtered by the same rules', () => {
    expect(attributeNames(scrubbed)).not.toContain('password');
  });
});

describe('custom span attributes', () => {
  const canary = createCanary('SPAN');
  const { scrubbed, bare } = bothWays({
    canary,
    spanAttributes: { password: 'placeholder', tenant: 'acme' },
  });

  it('carries the span attribute when nothing excludes it', () => {
    expect(attributeNames(bare)).toContain('password');
    expectCanaryPresent(bare, canary, 'the unscrubbed payload');
  });

  it('drops the denied one and keeps the other', () => {
    expect(attributeNames(scrubbed)).not.toContain('password');
    expect(attributeNames(scrubbed)).toContain('tenant');
  });
});

describe('a wrapped value the application did not coerce', () => {
  const canary = createCanary('WRAPPED');
  const payload = runServerless(SCRUBBED, {
    canary,
    wrappedAttribute: true,
    serializedAttribute: true,
  });

  it('is dropped by the agent, silently', () => {
    // Measured, and the reason `sensitiveAttributes` exists: the attribute
    // does not arrive at all rather than arriving as its marker.
    expect(attributeNames(payload)).not.toContain('wrapped');
    expect(attributeNames(payload)).not.toContain('serialized');
  });

  it('takes the serialize() result with it, so nothing leaks either way', () => {
    expectNoCanary(payload, canary, 'the payload');
  });
});

describe('a wrapped value the application coerced', () => {
  const canary = createCanary('COERCED');
  const secret = new SensitiveString(canary, 'credential', 'tok');
  const coerced = sensitiveAttributes({
    wrapped: secret,
    serialized: secret.serialize(),
    password: canary,
    tenant: 'acme',
  });
  const payload = runServerless(SCRUBBED, { canary, coerced });

  it('arrives as the marker rather than as nothing', () => {
    const names = attributeNames(payload);

    expect(names).toContain('wrapped');
    expect(names).toContain('serialized');
  });

  it('carries the class and not the value', () => {
    expectNoCanary(payload, canary, 'the payload');
    expect(JSON.stringify(payload)).toContain('[REDACTED:credential]');
  });

  it('is still filtered by the agent for a denied name', () => {
    expect(attributeNames(payload)).not.toContain('password');
  });

  it('does not transmit the label', () => {
    expect(JSON.stringify(payload)).not.toContain('tok"');
  });
});

describe('the whole sweep', () => {
  const canary = createCanary('SWEEP');

  /**
   * Every position this package can reach, in one invocation.
   *
   * The positions it cannot reach are deliberately absent, and the README
   * lists each: log forwarding, the browser agent, SQL captured under
   * `record_sql`, metric and transaction names.
   */
  const spec: InvocationSpec = {
    canary,
    deniedAttributes: true,
    errorAttributes: true,
    spanAttributes: { password: 'placeholder' },
  };

  it('leaks in every one of those positions with no configuration', () => {
    expectCanaryPresent(runServerless({}, spec), canary, 'the unscrubbed payload');
  });

  it('leaks nothing with the generated configuration', () => {
    expectNoCanary(runServerless(SCRUBBED, spec), canary, 'the payload');
  });

  it('swept all five payload sections rather than four', () => {
    // Section count is a property of the fixture, not of the package, and it
    // is the one that decides whether the sweep above proves anything about
    // span attributes. Without an `account_id` the agent turns distributed
    // tracing back off in serverless mode and emits no `span_event_data` at
    // all, and every span assertion here would pass vacuously.
    expect(Object.keys(runServerless(SCRUBBED, spec).data).sort()).toEqual([
      'analytic_event_data',
      'error_data',
      'error_event_data',
      'metric_data',
      'span_event_data',
    ]);
  });
});

describe('invariant 8: this package does not reveal', () => {
  it('imports only the core names a scrubbing package is allowed', () => {
    const src = join(packageRoot(), 'src');
    const allowed = new Set([
      'redactCopy',
      'containsSensitive',
      'sensitiveClassesIn',
      'SensitiveString',
      'SensitivityClass',
    ]);

    const disallowed = findCoreImports(src).filter((entry) => !allowed.has(entry.name));

    expect(disallowed).toEqual([]);
  });
});
