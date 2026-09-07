import { registerPolicy, resetPolicies } from '@platform-sec/sensitive-string-core';
import { afterEach, describe, expect, it } from 'vitest';
import { containsRedactionMarker, redactionMarkers, resetMarkerCache } from './marker.js';

describe('redactionMarkers', () => {
  afterEach(() => {
    resetPolicies();
    resetMarkerCache();
  });

  it('covers the default shape for every registered class', () => {
    const markers = redactionMarkers();
    expect(markers.has('[REDACTED:sensitive]')).toBe(true);
    expect(markers.has('[REDACTED:credential]')).toBe(true);
  });

  it('derives a custom policy marker rather than assuming the default shape', () => {
    // registerPolicy accepts a redact of the caller's own, and a package that
    // only knew the default would miss exactly the deployment that customised
    // it.
    registerPolicy(
      {
        name: 'sensitive',
        redact: () => '<<hidden>>',
        requireConstantTimeEquals: false,
        allowPartialQueries: true,
        allowMask: true,
      },
      { overwrite: true }
    );
    resetMarkerCache();
    expect(redactionMarkers().has('<<hidden>>')).toBe(true);
  });

  it('keeps the default shape as well, for rows written before the policy changed', () => {
    registerPolicy(
      {
        name: 'sensitive',
        redact: () => '<<hidden>>',
        requireConstantTimeEquals: false,
        allowPartialQueries: true,
        allowMask: true,
      },
      { overwrite: true }
    );
    resetMarkerCache();
    expect(redactionMarkers().has('[REDACTED:sensitive]')).toBe(true);
  });

  it('ignores a redaction that varies with the value', () => {
    // A partial mask is not a marker: there is nothing fixed to search a column
    // for, and adding one probe's output would make the check wrong in both
    // directions at once.
    registerPolicy(
      {
        name: 'sensitive',
        redact: (value: string) => `${value.slice(0, 2)}***`,
        requireConstantTimeEquals: false,
        allowPartialQueries: true,
        allowMask: true,
      },
      { overwrite: true }
    );
    resetMarkerCache();
    const markers = [...redactionMarkers()];
    expect(markers.every((m) => !m.endsWith('***'))).toBe(true);
  });

  it('survives a policy whose redaction throws on the probe it is asked with', () => {
    // Core validates a redact function at registration, with its own canaries,
    // so one that throws unconditionally cannot be registered at all. One that
    // throws for some inputs can, and the probes here are inputs core never
    // tried.
    registerPolicy(
      {
        name: 'sensitive',
        redact: (value: string) => {
          if (value.startsWith('aaaa')) throw new Error('nope');
          return '[hidden]';
        },
        requireConstantTimeEquals: false,
        allowPartialQueries: true,
        allowMask: true,
      },
      { overwrite: true }
    );
    resetMarkerCache();
    expect(() => redactionMarkers()).not.toThrow();
    expect(redactionMarkers().has('[REDACTED:sensitive]')).toBe(true);
  });

  it('memoizes until the set of registered classes changes', () => {
    const first = redactionMarkers();
    expect(redactionMarkers()).toBe(first);
  });
});

describe('containsRedactionMarker', () => {
  it('matches a bare marker and one embedded in a longer string', () => {
    // Concatenation and interpolation are how a marker reaches a column as
    // often as a bare assignment is, and that column is corrupt either way.
    expect(containsRedactionMarker('[REDACTED:sensitive]')).toBe(true);
    expect(containsRedactionMarker('Bearer [REDACTED:credential]')).toBe(true);
  });

  it('leaves an ordinary value alone', () => {
    expect(containsRedactionMarker('a@example.com')).toBe(false);
    expect(containsRedactionMarker('')).toBe(false);
    expect(containsRedactionMarker('REDACTED')).toBe(false);
  });
});
