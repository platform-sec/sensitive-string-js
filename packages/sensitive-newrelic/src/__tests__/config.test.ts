import { DEFAULT_DENY_KEYS, ScrubPolicyError } from '@platform-sec/sensitive-string-scrub';
import { describe, expect, it, vi } from 'vitest';

import { sensitiveAgentConfig } from '../config.js';
import { REQUEST_HEADER_PREFIX } from '../names.js';

/**
 * The generator, asserted with no agent running.
 *
 * `sensitiveAgentConfig` is pure, which is the only reason a configuration
 * generator is testable at all. `filter.test.ts` and `canary.test.ts` take the
 * output of this file and put it through the real agent; this file is about
 * what it generates and why.
 */

describe('sensitiveAgentConfig', () => {
  it('excludes every default denied key in the agent vocabulary', () => {
    const { attributes } = sensitiveAgentConfig();

    expect(attributes.exclude).toContain('request.headers.authorization');
    expect(attributes.exclude).toContain('request.headers.cookie');
    expect(attributes.exclude).toContain('response.headers.setCookie');
  });

  it('translates a hyphenated header into the spelling the agent writes', () => {
    const { attributes } = sensitiveAgentConfig();

    // The whole reason this package exists. Measured on `newrelic` 14.3.10, an
    // exclusion spelled `request.headers.x-api-key` is silently ignored and
    // one spelled `request.headers.xApiKey` is honoured.
    expect(attributes.exclude).toContain('request.headers.xApiKey');
  });

  it('keeps the raw spelling alongside the translated one', () => {
    const { attributes } = sensitiveAgentConfig();

    expect(attributes.exclude).toContain('request.headers.x-api-key');
  });

  it('covers the bare key, for a custom or top-level attribute', () => {
    const { attributes } = sensitiveAgentConfig();

    expect(attributes.exclude).toContain('password');
    expect(attributes.exclude).toContain('token');
  });

  it('covers the parsed query parameter position', () => {
    const { attributes } = sensitiveAgentConfig();

    expect(attributes.exclude).toContain('request.parameters.token');
  });

  it('adds a caller key in every position a default key gets', () => {
    const { attributes } = sensitiveAgentConfig({ denyKeys: ['x-internal-signature'] });

    expect(attributes.exclude).toContain('request.headers.xInternalSignature');
    expect(attributes.exclude).toContain('response.headers.xInternalSignature');
    expect(attributes.exclude).toContain('request.parameters.x-internal-signature');
    expect(attributes.exclude).toContain('x-internal-signature');
  });

  it('drops a key the caller took back, in every position', () => {
    const { attributes } = sensitiveAgentConfig({
      allowKeys: [{ key: 'token', reason: 'opaque correlation id on this service' }],
    });

    expect(attributes.exclude).not.toContain('token');
    expect(attributes.exclude).not.toContain('request.parameters.token');
    expect(attributes.exclude).not.toContain('request.headers.token');
  });

  it('refuses an allowKeys entry with no reason', () => {
    expect(() => sensitiveAgentConfig({ allowKeys: [{ key: 'token', reason: '  ' }] })).toThrow(
      ScrubPolicyError
    );
  });

  it('refuses a key named in both lists', () => {
    expect(() =>
      sensitiveAgentConfig({
        denyKeys: ['x-thing'],
        allowKeys: [{ key: 'x-thing', reason: 'safe' }],
      })
    ).toThrow(ScrubPolicyError);
  });
});

describe('exact rules, not wildcards', () => {
  it('emits no wildcard by default', () => {
    const { attributes } = sensitiveAgentConfig();

    expect(attributes.exclude.filter((entry) => entry.includes('*'))).toEqual([]);
  });

  it('emits the one wildcard only when asked', () => {
    const { attributes } = sensitiveAgentConfig({ excludeAllRequestHeaders: true });

    expect(attributes.exclude).toContain(`${REQUEST_HEADER_PREFIX}*`);
  });

  it('keeps the exact rules when the wildcard is on', () => {
    // The wildcard is a default and the exact rules are a floor, so the
    // wildcard is additive rather than a replacement. A configuration with
    // only the wildcard is reopened by one later `include` line.
    const { attributes } = sensitiveAgentConfig({ excludeAllRequestHeaders: true });

    expect(attributes.exclude).toContain('request.headers.authorization');
  });
});

describe('merging', () => {
  const existing = {
    app_name: ['payments'],
    attributes: {
      enabled: true,
      include: ['request.headers.xRequestId'],
      exclude: ['request.parameters.ssn'],
    },
  };

  it('is a superset of both inputs', () => {
    const { attributes } = sensitiveAgentConfig({}, existing);
    const generated = sensitiveAgentConfig().attributes.exclude;

    for (const entry of existing.attributes.exclude) {
      expect(attributes.exclude).toContain(entry);
    }

    for (const entry of generated) {
      expect(attributes.exclude).toContain(entry);
    }
  });

  it("carries forward the caller's other attribute fields", () => {
    const { attributes } = sensitiveAgentConfig({}, existing);

    expect(attributes.enabled).toBe(true);
    expect(attributes.include).toEqual(['request.headers.xRequestId']);
  });

  it('does not modify the caller configuration', () => {
    const before = JSON.stringify(existing);

    sensitiveAgentConfig({ denyKeys: ['x-thing'] }, existing);

    expect(JSON.stringify(existing)).toBe(before);
  });

  it('deduplicates an entry the caller already had', () => {
    const { attributes } = sensitiveAgentConfig(
      {},
      { attributes: { exclude: ['request.headers.authorization'] } }
    );
    const hits = attributes.exclude.filter((entry) => entry === 'request.headers.authorization');

    expect(hits).toHaveLength(1);
  });

  it('generates the same list with no existing configuration at all', () => {
    expect(sensitiveAgentConfig({}, {}).attributes.exclude).toEqual(
      sensitiveAgentConfig().attributes.exclude
    );
  });
});

describe('purity and reporting', () => {
  it('is pure, so two calls agree', () => {
    expect(sensitiveAgentConfig({ denyKeys: ['a'] })).toEqual(
      sensitiveAgentConfig({ denyKeys: ['a'] })
    );
  });

  it('orders by denied key, so a configuration diff is reviewable', () => {
    // The bare-key entries are one per spelling of each denied key and carry no
    // prefix, so their order is the order the generator walked the denylist in.
    // Sorted means adding one key moves one line rather than reshuffling the
    // file. Sorted by codepoint, so `X-Rollbar-Access-Token` precedes
    // `aaa-first`, which is what makes this an assertion about stability rather
    // than about the alphabet.
    const { attributes } = sensitiveAgentConfig({ denyKeys: ['aaa-first', 'zzz-last'] });
    const bare = attributes.exclude.filter((entry) => !entry.includes('.') && !entry.includes('*'));

    expect(bare).toEqual([...bare].sort());
    expect(bare).toContain('aaa-first');
    expect(bare.at(-1)).toBe('zzz-last');
  });

  it('reports once per call, with names and counts and no value', () => {
    const onScrub = vi.fn();

    sensitiveAgentConfig({ denyKeys: ['x-internal-signature'], onScrub });

    expect(onScrub).toHaveBeenCalledTimes(1);

    const report = onScrub.mock.calls[0]?.[0] as {
      kind: string;
      deniedKeys: readonly string[];
      failed: boolean;
    };

    expect(report.kind).toBe('transaction');
    expect(report.failed).toBe(false);
    expect(report.deniedKeys).toContain('x-internal-signature');

    // The canonical key set, not the rule spellings. A key that produced two
    // rules because the agent's matching is case-sensitive is one denied key.
    expect(report.deniedKeys.length).toBe(DEFAULT_DENY_KEYS.length + 1 - duplicates());
    expect(report.deniedKeys).toEqual([...report.deniedKeys].map((key) => key.toLowerCase()));
  });

  it('survives an onScrub that throws, because this runs at startup', () => {
    expect(() =>
      sensitiveAgentConfig({
        onScrub: () => {
          throw new Error('metrics are down');
        },
      })
    ).not.toThrow();
  });
});

/** `DEFAULT_DENY_KEYS` carries names that differ only in case, which resolve to one. */
function duplicates(): number {
  const lowered = new Set(DEFAULT_DENY_KEYS.map((key) => key.toLowerCase()));

  return DEFAULT_DENY_KEYS.length - lowered.size;
}
