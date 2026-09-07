import { afterEach, describe, expect, it } from 'vitest';
import { deterministicRedaction } from './deterministic.js';
import {
  MARKER_PREFIX,
  containsRedactionMarker,
  redactionMatchers,
  resetRedactionMarkerCache,
} from './redaction-marker.js';
import { getPolicy, registerPolicy, resetPolicies } from './policy.js';
import { SensitiveString } from './sensitive-string.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

afterEach(() => {
  resetPolicies();
  resetRedactionMarkerCache();
});

describe('containsRedactionMarker', () => {
  it('finds what a default policy actually renders', () => {
    const secret = new SensitiveString(CANARY, 'credential');

    expect(containsRedactionMarker(String(secret))).toBe(true);
    expect(containsRedactionMarker(JSON.stringify({ token: secret }))).toBe(true);
  });

  it('finds a marker embedded in a longer string', () => {
    const secret = new SensitiveString(CANARY, 'sensitive');

    // Interpolation, which is how a marker usually reaches a column.
    expect(containsRedactionMarker(`Bearer ${String(secret)}`)).toBe(true);
  });

  it('passes an ordinary value through', () => {
    expect(containsRedactionMarker(CANARY)).toBe(false);
    expect(containsRedactionMarker('')).toBe(false);
    expect(containsRedactionMarker('a perfectly normal sentence')).toBe(false);
  });

  it('recognizes a class this process never registered', () => {
    // A column written by an older release, or by a service that registered a
    // class this one does not have. The per-class detectors this replaced
    // enumerated the registry and so answered false here, which is the
    // direction that hands a corrupt column back as if it were a value.
    expect(containsRedactionMarker('[REDACTED:pci-pan]')).toBe(true);
  });
});

describe('a custom policy', () => {
  it('is recognized when its redaction is constant', () => {
    registerPolicy(
      { ...getPolicy('sensitive'), name: 'sensitive', redact: () => '***' },
      { overwrite: true }
    );

    expect(containsRedactionMarker('***')).toBe(true);
    expect(containsRedactionMarker(`note: *** was here`)).toBe(true);
  });

  it('is recognized through markerPattern when its redaction varies', () => {
    // The gap that motivated moving this into core. A deterministic redaction
    // renders a different string per value, so no probe can derive a needle for
    // it; core already provided `markerPattern` for exactly this, and the two
    // detectors written for a database ignored the field.
    registerPolicy(
      deterministicRedaction('sensitive', {
        key: Buffer.alloc(32, 7),
        scope: 'test-correlation',
        prefix: 'corr',
      }),
      { overwrite: true }
    );

    const rendered = String(new SensitiveString(CANARY, 'sensitive'));

    expect(rendered).not.toContain(MARKER_PREFIX);
    expect(rendered).not.toContain(CANARY);
    expect(containsRedactionMarker(rendered)).toBe(true);
  });

  it('does not contribute a needle when its redaction varies and it declares nothing', () => {
    registerPolicy(
      {
        ...getPolicy('sensitive'),
        name: 'sensitive',
        redact: (value: string) => `len:${String(value.length)}`,
      },
      { overwrite: true }
    );

    // Nothing constant to look for, so this reports what it can rather than
    // deriving a needle from one probe that would fire on unrelated strings.
    expect(containsRedactionMarker('len:23')).toBe(false);
    expect(redactionMatchers()).not.toContain('len:29');
  });

  it('does not break the scan when its redaction throws', () => {
    registerPolicy(
      {
        ...getPolicy('sensitive'),
        name: 'sensitive',
        redact: () => {
          throw new Error('no');
        },
      },
      { overwrite: true, skipRedactValidation: true }
    );

    expect(() => containsRedactionMarker('[REDACTED:credential]')).not.toThrow();
    expect(containsRedactionMarker('[REDACTED:credential]')).toBe(true);
  });
});

describe('the memo', () => {
  it('picks up a policy replaced under a name that already existed', () => {
    // The case a memo keyed on the set of class names cannot see, and the
    // reason `policyRegistryVersion` exists. Both detectors this replaced were
    // keyed on the names and so kept answering from the previous policy.
    expect(containsRedactionMarker('###')).toBe(false);

    registerPolicy(
      { ...getPolicy('sensitive'), name: 'sensitive', redact: () => '###' },
      { overwrite: true }
    );

    expect(containsRedactionMarker('###')).toBe(true);
  });

  it('picks up a newly registered class', () => {
    registerPolicy({ ...getPolicy('sensitive'), name: 'phi', redact: () => '<<phi>>' });

    expect(containsRedactionMarker('<<phi>>')).toBe(true);
  });

  it('drops a marker that resetPolicies took away', () => {
    registerPolicy(
      { ...getPolicy('sensitive'), name: 'sensitive', redact: () => '###' },
      { overwrite: true }
    );
    expect(containsRedactionMarker('###')).toBe(true);

    resetPolicies();

    expect(containsRedactionMarker('###')).toBe(false);
    expect(containsRedactionMarker('[REDACTED:sensitive]')).toBe(true);
  });

  it('returns the same array while the registry is unchanged', () => {
    expect(redactionMatchers()).toBe(redactionMatchers());
  });
});

describe('a global markerPattern', () => {
  it('answers the same way twice', () => {
    // `markerPattern` is documented as not carrying `g`, but it arrives from an
    // application. `test()` on a global pattern advances `lastIndex`, so the
    // second scan of the same string would start mid-string and miss.
    registerPolicy(
      {
        ...getPolicy('sensitive'),
        name: 'sensitive',
        redact: (value: string) => `tag-${String(value.length)}`,
        markerPattern: /tag-\d+/g,
      },
      { overwrite: true }
    );

    expect(containsRedactionMarker('tag-42')).toBe(true);
    expect(containsRedactionMarker('tag-42')).toBe(true);
  });
});

describe('the canary sweep', () => {
  it('never echoes the value it was asked about', () => {
    const secret = new SensitiveString(CANARY, 'credential');
    containsRedactionMarker(String(secret));

    for (const matcher of redactionMatchers()) {
      expect(String(matcher)).not.toContain(CANARY);
    }
  });
});
