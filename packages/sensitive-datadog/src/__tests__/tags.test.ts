import {
  createCanary,
  expectCanaryPresent,
  expectNoCanary,
} from '@platform-sec/sensitive-string-scrub/testing';
import { beforeAll, describe, expect, it } from 'vitest';

import { ensureBuilt, runDriver, type DriverRun, type EncodedSpan } from './fixtures.js';

/**
 * Application-set span tags, which is where the second leak lives.
 *
 * Nothing on this path calls `toJSON()`. Measured on `dd-trace` 6.14.0,
 * `addMixedTag` flattens an object one level with `Object.entries` and
 * recurses once with `nested` set, which suppresses any further recursion. For
 * a `SensitiveString` that finds the two own enumerable properties:
 *
 * ```
 * probe.klass  "credential"
 * probe.label  "tok"
 * ```
 *
 * The value does not leak, which is the good half. Two things follow that are
 * not. The marker never appears, so the marker convention the rest of this
 * library depends on does not hold here. And the label is transmitted, with no
 * option involved and nothing in the library's control, which is the first
 * place the secrets-manager rule against a label carrying an account or tenant
 * identifier stops being hygiene.
 *
 * For a `serialize()` result the same one level of flattening is exactly
 * enough to reach the raw value:
 *
 * ```
 * probe.klass       "credential"
 * probe.value       "LEAKED_SECRET_abc123xyz"
 * probe.label       "tok"
 * probe.__sensitive 1                          (in metrics, boolean coerced)
 * ```
 *
 * This is the strongest case in the whole row for the structural walk. At an
 * error tracker it is defence in depth over a `toJSON()` that already works.
 * Here it is the only defence, and what it prevents is a full-value leak of a
 * credential onto a span tag.
 *
 * Measured against `dd-trace` 6.14.0 on Node 22.15.0.
 */

const CANARY = createCanary('TAGS');

let bare: DriverRun;
let scrubbed: DriverRun;

beforeAll(async () => {
  ensureBuilt();

  bare = await runDriver({ canary: CANARY, applicationTags: true, request: false });
  scrubbed = await runDriver({
    canary: CANARY,
    applicationTags: true,
    request: false,
    install: true,
  });
}, 180_000);

function probeSpan(run: DriverRun): EncodedSpan {
  const found = run.spans.find((span) => span.name === 'probe.tags');

  if (found === undefined) {
    throw new Error(`no probe.tags span among ${run.spans.map((span) => span.name).join(', ')}`);
  }

  return found;
}

describe('with nothing installed', () => {
  it('flattens a wrapped value into a class tag and a label tag', () => {
    const meta = probeSpan(bare).meta ?? {};

    expect(meta['probe.wrapped.klass']).toBe('credential');
    expect(meta['probe.wrapped.label']).toBe('tok');
  });

  it('writes only the class for a value with no label', () => {
    const meta = probeSpan(bare).meta ?? {};

    expect(meta['probe.unlabelled.klass']).toBe('credential');
    expect(meta['probe.unlabelled.label']).toBeUndefined();
  });

  it('writes the raw value of a serialize() result, which is the leak', () => {
    expect((probeSpan(bare).meta ?? {})['probe.serialized.value']).toBe(CANARY);
  });

  it('writes a denied application tag verbatim', () => {
    expect((probeSpan(bare).meta ?? {})['probe.password']).toBe(CANARY);
  });

  it('writes a URL tag with its query intact', () => {
    expect((probeSpan(bare).meta ?? {})['probe.url']).toContain(CANARY);
  });

  it('leaks, so every absence asserted below means something', () => {
    expectCanaryPresent(bare.spans, CANARY, 'the unscrubbed trace payload');
  });

  it('never reaches a wrapped tag through toJSON, and never through String either', () => {
    // The marker convention does not hold on this path: an unscrubbed wrapped
    // value arrives as a class tag rather than as `[REDACTED:credential]`.
    // An error message is the exception, and it is a string before the agent
    // ever sees it.
    const meta = probeSpan(bare).meta ?? {};

    expect(meta['probe.wrapped']).toBeUndefined();
    expect(meta['error.message']).toBe('failed for [REDACTED:credential]');
  });
});

describe('with scrubbing installed', () => {
  it('replaces a wrapped value with its marker', () => {
    expect((probeSpan(scrubbed).meta ?? {})['probe.wrapped']).toBe('[REDACTED:credential]');
  });

  it('stops the class and label tags from being written at all', () => {
    const meta = probeSpan(scrubbed).meta ?? {};

    expect(meta['probe.wrapped.klass']).toBeUndefined();
    expect(meta['probe.wrapped.label']).toBeUndefined();
  });

  it('does not transmit the label, which reportLabels being off is supposed to mean', () => {
    const meta = probeSpan(scrubbed).meta ?? {};

    expect(Object.entries(meta).filter(([, value]) => value === 'tok')).toEqual([]);
    expect(Object.keys(meta).filter((key) => key.endsWith('.label'))).toEqual([]);
  });

  it('replaces a serialize() result with the marker of the class it names', () => {
    const meta = probeSpan(scrubbed).meta ?? {};

    expect(meta['probe.serialized']).toBe('[REDACTED:credential]');
    expect(meta['probe.serialized.value']).toBeUndefined();
  });

  it('censors a denied application tag', () => {
    expect((probeSpan(scrubbed).meta ?? {})['probe.password']).toBe('[SCRUBBED]');
  });

  it('rewrites a URL tag and keeps the route', () => {
    const url = (probeSpan(scrubbed).meta ?? {})['probe.url'] ?? '';

    expect(url).toContain('/v1/pay');
    expect(url).toContain('page=2');
    expect(url).not.toContain(CANARY);
  });

  it('keeps a tag nothing denied', () => {
    expect((probeSpan(scrubbed).meta ?? {})['probe.plain']).toBe('keep-me');
  });

  it('keeps an error message, which was already a string and already safe', () => {
    expect((probeSpan(scrubbed).meta ?? {})['error.message']).toBe(
      'failed for [REDACTED:credential]'
    );
  });

  it('leaks no canary anywhere in the payload', () => {
    expectNoCanary(scrubbed.spans, CANARY, 'the trace payload');
  });

  it('reports the class that was in scope, and no value', () => {
    const found = scrubbed.result.reports.filter((report) => report.instances > 0);

    expect(found.length).toBeGreaterThan(0);
    expect(found[0]?.classes).toContain('credential');
    expect(JSON.stringify(scrubbed.result.reports)).not.toContain(CANARY);
  });

  it('reports no labels unless the caller asks', () => {
    expect(scrubbed.result.reports.every((report) => report.labels === undefined)).toBe(true);
  });
});

describe('the shapes the agent drops on its own', () => {
  it('writes nothing for a nested object, scrubbed or not', () => {
    // `addMixedTag`'s one level of recursion is exhausted by the first key, so
    // `probe.nested.token.klass` never exists. Worth pinning: it is the reason
    // the walk is not the only thing standing between a wrapped value and the
    // payload for *this* shape, and a future agent that recursed further would
    // change that silently.
    const bareMeta = probeSpan(bare).meta ?? {};

    expect(Object.keys(bareMeta).filter((key) => key.startsWith('probe.nested.token'))).toEqual([]);
  });

  it('keeps the scrubbed nested object out of the payload too', () => {
    expectNoCanary(probeSpan(scrubbed), CANARY, 'the probe span');
  });
});
