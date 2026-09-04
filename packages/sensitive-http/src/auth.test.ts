import { describe, expect, it } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

import {
  apiKey,
  basic,
  bearer,
  isAuthHeader,
  isStrippedAcrossOrigins,
  renderAuthHeader,
} from './auth.js';
import { MarkerLeakError } from './errors.js';
import { PlanBuilder } from './scrub.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const ctx = { name: 'test' };

function render(header: ReturnType<typeof bearer>, name = 'authorization') {
  const builder = new PlanBuilder();
  const value = renderAuthHeader(header, name, ctx, builder.section('header'));

  return { value, plan: builder.build() };
}

describe('auth helpers', () => {
  it('builds a Bearer header and records the reveal against the header name', () => {
    const { value, plan } = render(bearer(new SensitiveString(CANARY, 'credential')));

    expect(value).toBe(`Bearer ${CANARY}`);
    expect(plan.headers).toEqual(['authorization']);
    expect(plan.entries[0]?.marker).toBe('[REDACTED:credential]');
  });

  it('base64-encodes Basic auth from components it guarded as plain text', () => {
    const { value } = render(basic('svc', new SensitiveString(CANARY, 'credential')));

    expect(value).toBe(`Basic ${Buffer.from(`svc:${CANARY}`).toString('base64')}`);
  });

  it('refuses a Basic username the caller built by interpolating an instance', () => {
    // Interpolating an instance is the footgun under test: exactly what a
    // caller does by accident, and exactly what the guard has to catch.
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    const interpolated = `${new SensitiveString(CANARY, 'sensitive')}`;

    expect(() => render(basic(interpolated, new SensitiveString(CANARY, 'credential')))).toThrow(
      MarkerLeakError
    );
  });

  it('renders an apiKey as the bare value, since the name comes from the key', () => {
    const { value } = render(apiKey(new SensitiveString(CANARY, 'credential')), 'x-api-key');

    expect(value).toBe(CANARY);
  });

  it('recognizes its own descriptors and nothing else', () => {
    expect(isAuthHeader(bearer(new SensitiveString(CANARY, 'credential')))).toBe(true);
    expect(isAuthHeader({ scheme: 'bearer', parts: [] })).toBe(false);
    expect(isAuthHeader('Bearer x')).toBe(false);
    expect(isAuthHeader(null)).toBe(false);
  });

  it('knows which header names the platform strips across origins', () => {
    expect(isStrippedAcrossOrigins('Authorization')).toBe(true);
    expect(isStrippedAcrossOrigins('cookie')).toBe(true);
    expect(isStrippedAcrossOrigins('Proxy-Authorization')).toBe(true);
    expect(isStrippedAcrossOrigins('x-api-key')).toBe(false);
    expect(isStrippedAcrossOrigins('PRIVATE-TOKEN')).toBe(false);
  });

  it('leaves no descriptor path that produces a raw value without a reveal', () => {
    const header = bearer(new SensitiveString(CANARY, 'credential'));

    expect(JSON.stringify(header.parts)).not.toContain(CANARY);
    expect(String(header.parts[0])).toBe('[REDACTED:credential]');
  });
});
