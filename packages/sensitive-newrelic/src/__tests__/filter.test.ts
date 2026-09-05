import { describe, expect, it } from 'vitest';

import { sensitiveAgentConfig } from '../config.js';
import { AGENT_VERSION, agentRequire } from './fixtures.js';

/**
 * The rule engine, driven directly.
 *
 * This is the finding that shapes the whole package, and it is not visible
 * from New Relic's documentation. Rules are prefix matches with a trailing `*`
 * and nothing else, and `_doTest` resolves include against exclude by **match
 * strength**, where an exact match scores `Infinity` and a wildcard scores its
 * matched length. So a wildcard exclusion is a default that any more specific
 * include lifts, and an exact global exclusion is a floor that nothing in the
 * configuration surface can.
 *
 * `config.test.ts` asserts the generator emits exact rules. This file is why
 * that matters, measured through the agent's own `AttributeFilter` rather than
 * asserted from the documentation.
 *
 * Measured against `newrelic` 14.3.10 on Node 22.15.0.
 */

const require_ = agentRequire();

interface AttributeFilterModule {
  new (config: unknown): { filterAll: (destinations: number, key: string) => number };
  DESTINATIONS: Record<string, number>;
}

const AttributeFilter = require_(
  'newrelic/lib/config/attribute-filter.js'
) as AttributeFilterModule;

const Config = require_('newrelic/lib/config/index.js') as {
  initialize: (options: Record<string, unknown>) => unknown;
};

const { DESTINATIONS } = AttributeFilter;

/** The six destinations an attribute can reach, by name. */
const DESTINATION_NAMES = [
  'TRANS_EVENT',
  'TRANS_TRACE',
  'ERROR_EVENT',
  'BROWSER_EVENT',
  'SPAN_EVENT',
  'TRANS_SEGMENT',
] as const;

const ALL_DESTINATIONS = DESTINATION_NAMES.reduce(
  (mask, name) => mask | (DESTINATIONS[name] ?? 0),
  0
);

/** Which destinations one attribute name survives to, under one configuration. */
function destinations(config: Record<string, unknown>, key: string): string[] {
  const resolved = Config.initialize({
    app_name: ['probe'],
    license_key: 'x'.repeat(40),
    agent_enabled: false,
    logging: { enabled: false },
    ...config,
  });

  const mask = new AttributeFilter(resolved).filterAll(ALL_DESTINATIONS, key);

  return DESTINATION_NAMES.filter((name) => {
    const bit = DESTINATIONS[name] ?? 0;

    return bit !== 0 && (mask & bit) === bit;
  });
}

const AUTHORIZATION = 'request.headers.authorization';

describe(`the destination matrix, newrelic ${AGENT_VERSION}`, () => {
  it('sends an attribute to five destinations at defaults', () => {
    // Five rather than six: browser monitoring attributes are off by default,
    // so BROWSER_EVENT never appears in any row below.
    expect(destinations({}, AUTHORIZATION)).toEqual([
      'TRANS_EVENT',
      'TRANS_TRACE',
      'ERROR_EVENT',
      'SPAN_EVENT',
      'TRANS_SEGMENT',
    ]);
  });

  it('drops it under a wildcard exclusion', () => {
    expect(destinations({ attributes: { exclude: ['request.headers.*'] } }, AUTHORIZATION)).toEqual(
      []
    );
  });

  it('restores it when a more specific include is added: a wildcard is not a floor', () => {
    expect(
      destinations(
        { attributes: { exclude: ['request.headers.*'], include: [AUTHORIZATION] } },
        AUTHORIZATION
      )
    ).toHaveLength(5);
  });

  it('restores it when a longer wildcard include beats a shorter wildcard exclude', () => {
    expect(
      destinations(
        { attributes: { exclude: ['request.*'], include: ['request.headers.*'] } },
        AUTHORIZATION
      )
    ).toHaveLength(5);
  });

  it('restores it on exactly one destination when the include is scoped there', () => {
    expect(
      destinations(
        {
          attributes: { exclude: ['request.headers.*'] },
          error_collector: { attributes: { include: [AUTHORIZATION] } },
        },
        AUTHORIZATION
      )
    ).toEqual(['ERROR_EVENT']);
  });

  it('keeps it dropped under an exact exclusion, whatever the include says', () => {
    // The row the whole package rests on. `_doTest` returns false on
    // `globalExclude === EXACT_MATCH` before it evaluates any include at all.
    expect(
      destinations(
        {
          attributes: { exclude: [AUTHORIZATION] },
          error_collector: { attributes: { include: [AUTHORIZATION] } },
        },
        AUTHORIZATION
      )
    ).toEqual([]);
  });

  it('keeps it dropped under an exact exclusion and a global include', () => {
    expect(
      destinations(
        { attributes: { exclude: [AUTHORIZATION], include: [AUTHORIZATION] } },
        AUTHORIZATION
      )
    ).toEqual([]);
  });

  it('drops everything when attributes are off wholesale', () => {
    expect(destinations({ attributes: { enabled: false } }, AUTHORIZATION)).toEqual([]);
  });

  it('leaves a neighbouring attribute alone', () => {
    expect(
      destinations({ attributes: { exclude: ['request.headers.*'] } }, 'request.uri')
    ).toHaveLength(5);
  });
});

describe('the generated configuration through the real filter', () => {
  const generated = sensitiveAgentConfig().attributes;

  it.each([
    ['request.headers.authorization', 'an inbound credential header'],
    ['request.headers.cookie', 'an inbound cookie'],
    ['request.headers.xApiKey', 'a renamed inbound header'],
    ['response.headers.setCookie', 'a response header'],
    ['request.parameters.token', 'a parsed query parameter'],
    ['password', 'a custom attribute'],
  ])('drops %s (%s) from every destination', (key) => {
    expect(destinations({ attributes: { exclude: [...generated.exclude] } }, key)).toEqual([]);
  });

  it('cannot be reopened by a later include, global or per destination', () => {
    const reopened = {
      attributes: { exclude: [...generated.exclude], include: ['request.headers.authorization'] },
      error_collector: { attributes: { include: ['request.headers.authorization'] } },
      span_events: { attributes: { include: ['request.headers.authorization'] } },
    };

    expect(destinations(reopened, 'request.headers.authorization')).toEqual([]);
  });

  it('the opt-in wildcard, on its own, is reopened: the README says so and this pins it', () => {
    expect(
      destinations(
        {
          attributes: {
            exclude: ['request.headers.*'],
            include: ['request.headers.authorization'],
          },
        },
        'request.headers.authorization'
      )
    ).toHaveLength(5);
  });

  it('leaves an attribute nothing denied alone', () => {
    expect(
      destinations({ attributes: { exclude: [...generated.exclude] } }, 'request.uri')
    ).toHaveLength(5);
  });

  it('leaves a header the operator wanted alone', () => {
    expect(
      destinations({ attributes: { exclude: [...generated.exclude] } }, 'request.headers.userAgent')
    ).toHaveLength(5);
  });
});

describe('casing, which the agent rules are sensitive to', () => {
  const generated = sensitiveAgentConfig().attributes;

  /**
   * The ten shipped defaults that are written in camelCase.
   *
   * `_importRules` compiles the rules into a `RegExp` with no `i` flag, and
   * `resolveScrubPolicy` lowercases the denylist, so generating from the
   * resolved set alone excluded `accesstoken` and transmitted `accessToken`.
   * Each of these is in the shared denylist in this casing precisely because
   * that is how it appears in a JavaScript payload, so losing them is losing
   * the names most likely to be there.
   */
  it.each([
    'accessToken',
    'refreshToken',
    'sessionId',
    'clientSecret',
    'privateKey',
    'confirmPassword',
    'passwordConfirmation',
    'secretKey',
    'secretToken',
    'idToken',
  ])('excludes %s, not only its lowercased form', (key) => {
    expect(destinations({ attributes: { exclude: [...generated.exclude] } }, key)).toEqual([]);
  });

  it.each(['accesstoken', 'sessionid', 'privatekey'])('still excludes %s', (key) => {
    expect(destinations({ attributes: { exclude: [...generated.exclude] } }, key)).toEqual([]);
  });

  it('excludes a caller key in the casing they wrote it', () => {
    const withCaller = sensitiveAgentConfig({ denyKeys: ['xInternalSignature'] }).attributes;

    expect(
      destinations({ attributes: { exclude: [...withCaller.exclude] } }, 'xInternalSignature')
    ).toEqual([]);
  });

  it('drops every casing of a key the caller took back', () => {
    const allowed = sensitiveAgentConfig({
      allowKeys: [{ key: 'accessToken', reason: 'opaque handle on this service, not a bearer' }],
    }).attributes;

    expect(allowed.exclude).not.toContain('accessToken');
    expect(allowed.exclude).not.toContain('accesstoken');
  });
});
