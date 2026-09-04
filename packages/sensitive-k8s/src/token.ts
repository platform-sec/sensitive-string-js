/**
 * Bound service account tokens, and the one claim worth reading.
 *
 * A projected service account token has an `expirationSeconds` and is refreshed
 * in place by the kubelet. The token is a JWT, its `exp` claim is a real
 * deadline, and binding it turns "this token stopped working" into an error
 * that names the token rather than a 401 from whatever it was presented to.
 *
 * Three constraints, all of them load-bearing:
 *
 * - The decode happens before wrapping, so it is not a reveal.
 * - Only `exp` is read. The rest of the claim set is discarded rather than put
 *   on `metadata`, because a service account JWT's claims name the namespace,
 *   the pod, and the service account UID, and `metadata` reaches the audit sink.
 * - The payload goes through the shared JSON guard. A malformed token is
 *   otherwise a `SyntaxError` holding a slice of the token, which is the leak
 *   this whole layer exists to prevent, arriving through a different door.
 *
 * Signature verification is not performed and is not this package's job. The
 * token came from the kubelet through a trusted mount, and verifying it would
 * need the cluster's public keys and would be implementing token validation,
 * which is a different concern in a different row.
 */

import { SecretPayloadError, parsePayload } from '@platform-sec/sensitive-string-secrets';
import type { ResolvedSecretRef } from '@platform-sec/sensitive-string-secrets';

/** base64url, which a JWT uses and which `Buffer` decodes only after a swap. */
function fromBase64Url(segment: string): string {
  return Buffer.from(segment.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

/**
 * The `exp` claim, as a `Date`.
 *
 * Returns undefined for a token that has no `exp`, which is what a legacy
 * non-expiring service account token looks like. That is an absence of a
 * deadline rather than an error: binding one would expire a token that never
 * expires.
 *
 * @throws SecretPayloadError when the value is not a JWT at all, which is worth
 *   being loud about: a field named `token` that is not a token means the
 *   Secret is not the shape the caller thinks it is.
 */
export function jwtExpiry(token: string, ref: ResolvedSecretRef): Date | undefined {
  const segments = token.split('.');

  if (segments.length !== 3) {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}' has a 'token' field that is not a JWT, ` +
        `so its expiry cannot be read. Turn off readTokenExpiry for this secret.`,
      ref.path,
      ref.version
    );
  }

  let decoded: string;

  try {
    decoded = fromBase64Url(segments[1] ?? '');
  } catch {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}' has a 'token' field whose payload is ` +
        `not base64url.`,
      ref.path,
      ref.version
    );
  }

  // Through the shared guard, so a malformed payload produces an error naming
  // the secret rather than a SyntaxError quoting part of the token.
  const claims = parsePayload(decoded, ref);
  const exp = claims['exp'];

  if (typeof exp !== 'number' || !Number.isFinite(exp)) {
    return undefined;
  }

  return new Date(exp * 1_000);
}
