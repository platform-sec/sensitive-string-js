import { describe, it, expect } from 'vitest';
import { SecretPayloadError } from '@platform-sec/sensitive-string-secrets';
import type { ResolvedSecretRef } from '@platform-sec/sensitive-string-secrets';

import { jwtExpiry } from './token.js';
import { jwt } from './__tests__/fake-api.js';

const REF: ResolvedSecretRef = { path: 'payments/sa-token', version: '1', metadata: {} };
const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('jwtExpiry', () => {
  it('reads exp and converts it from seconds', () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;

    expect(jwtExpiry(jwt({ exp, sub: 'system:serviceaccount:payments:api' }), REF)).toEqual(
      new Date(exp * 1000)
    );
  });

  it('reports a token with no exp as having no deadline', () => {
    // A legacy service account token does not expire. Binding a deadline to it
    // would expire a token that never expires.
    expect(jwtExpiry(jwt({ sub: 'system:serviceaccount:payments:api' }), REF)).toBeUndefined();
  });

  it('reads only exp, so the claims that name the pod stay where they are', () => {
    const exp = Math.floor(Date.now() / 1000) + 60;
    const result = jwtExpiry(
      jwt({
        exp,
        'kubernetes.io': { namespace: 'payments', pod: { name: 'api-7d9', uid: 'abc' } },
      }),
      REF
    );

    expect(result).toEqual(new Date(exp * 1000));
  });

  it('refuses a token field that is not a JWT, and quotes none of it', () => {
    try {
      jwtExpiry(CANARY, REF);
      expect.unreachable('the value should have been refused');
    } catch (error) {
      expect(error).toBeInstanceOf(SecretPayloadError);
      expect((error as Error).message).not.toContain(CANARY);
      expect((error as Error).message).toContain('not a JWT');
    }
  });

  it('routes a malformed payload through the shared guard rather than a SyntaxError', () => {
    const broken = `${Buffer.from('{}').toString('base64url')}.${Buffer.from(CANARY).toString('base64url')}.sig`;

    try {
      jwtExpiry(broken, REF);
      expect.unreachable('the token should have been refused');
    } catch (error) {
      expect(error).toBeInstanceOf(SecretPayloadError);
      expect((error as Error).message).not.toContain(CANARY);
      expect((error as { cause?: unknown }).cause).toBeUndefined();
    }
  });

  it('ignores an exp that is not a number', () => {
    expect(jwtExpiry(jwt({ exp: 'soon' }), REF)).toBeUndefined();
  });
});

describe('whitespace around a token', () => {
  it('is trimmed, so a token written from a file still parses', () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;

    expect(jwtExpiry(`${jwt({ exp })}\n`, REF)).toEqual(new Date(exp * 1000));
  });
});
