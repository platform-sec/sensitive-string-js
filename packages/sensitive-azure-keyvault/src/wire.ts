/**
 * The Key Vault wire shape, and the one place this library is stricter than the
 * provider it wraps.
 *
 * `properties.expiresOn` is the cleanest deadline mapping of the eight sources
 * in this row: an operator set a date, the date means the secret stops being
 * valid, and core has exactly that concept. Every other provider needed an
 * argument about which of its date fields is a deadline and which is a
 * schedule. This one needed an argument about whether to enforce it.
 */

import { SecretError, logicalLabel } from '@platform-sec/sensitive-string-secrets';
import type {
  ResolvedSecretRef,
  SecretLifetime,
  SecretMetadata,
} from '@platform-sec/sensitive-string-secrets';
import type { KeyVaultSecret, SecretProperties } from '@azure/keyvault-secrets';

/**
 * A secret whose `notBefore` has not arrived.
 *
 * Core has no not-yet-valid state. The options were to throw, to report the
 * secret as absent, or to hand back a value that is not supposed to work yet,
 * and the last two both turn a deployment ordering mistake into something that
 * fails later and somewhere else. Adding a real not-yet-valid state to core is
 * a larger change and is not something to smuggle in through a provider.
 */
export class SecretNotYetValidError extends SecretError {
  override readonly name = 'SecretNotYetValidError';

  constructor(
    message: string,
    path: string,
    version: string,
    /** The `notBefore` the vault reported. A date, not secret material. */
    readonly notBefore: Date
  ) {
    super(message, path, version);
  }
}

/**
 * The metadata a Key Vault response carries, minus the secret.
 *
 * `vaultUrl` names the tenant, so it belongs here and not in a label. So does
 * `id`, which is the vault URL with the name and version appended.
 *
 * `contentType` is surfaced and never acted on. `application/json` on it is the
 * convention that says `getJson` is the right read, and switching behaviour on
 * it would mean a caller's code changes meaning because somebody edited a field
 * in the portal. Section 8.2 of the design makes the same call for Kubernetes
 * Secret types, for the same reason.
 */
export function azureMetadata(properties: SecretProperties): SecretMetadata {
  return {
    vaultUrl: properties.vaultUrl,
    ...(properties.id === undefined ? {} : { id: properties.id }),
    ...(properties.contentType === undefined ? {} : { contentType: properties.contentType }),
    ...(properties.enabled === undefined ? {} : { enabled: properties.enabled }),
    ...(properties.managed === undefined ? {} : { managed: properties.managed }),
    ...(properties.createdOn === undefined
      ? {}
      : { createdAt: properties.createdOn.toISOString() }),
    ...(properties.updatedOn === undefined
      ? {}
      : { updatedAt: properties.updatedOn.toISOString() }),
    ...(properties.expiresOn === undefined
      ? {}
      : { expiresAt: properties.expiresOn.toISOString() }),
    ...(properties.notBefore === undefined
      ? {}
      : { notBefore: properties.notBefore.toISOString() }),
    ...(properties.recoveryLevel === undefined ? {} : { recoveryLevel: properties.recoveryLevel }),
    ...tagMetadata(properties.tags),
  };
}

/**
 * Tags, flattened under a prefix.
 *
 * Tags are operator-chosen strings and reach the load hook. They are not
 * secrets and are not treated as such, which is worth stating because a tag
 * named `password` would be surfaced exactly as written: it is metadata the
 * operator put on the resource, not part of the secret's value.
 */
function tagMetadata(tags: Readonly<Record<string, string>> | undefined): SecretMetadata {
  if (tags === undefined) {
    return {};
  }

  return Object.fromEntries(Object.entries(tags).map(([key, value]) => [`tag.${key}`, value]));
}

/**
 * The deadline, if this deployment wants it enforced.
 *
 * With `honorExpiresOn` on, a secret whose `expiresOn` has passed is wrapped
 * with a deadline already behind it: it constructs and refuses to reveal. That
 * is the intended behaviour and it is the reason the option exists. Whether Key
 * Vault itself refuses to serve such a secret is in the README's table; the
 * mapping holds either way, and where the service does not enforce the date, an
 * operator who set one still meant it.
 */
export function azureLifetime(
  properties: SecretProperties,
  honorExpiresOn: boolean
): SecretLifetime | undefined {
  if (!honorExpiresOn || properties.expiresOn === undefined) {
    return undefined;
  }

  return { expiresAt: properties.expiresOn };
}

/** Refuse a secret that is not valid yet. */
export function assertActive(
  properties: SecretProperties,
  ref: ResolvedSecretRef,
  now: Date
): void {
  const notBefore = properties.notBefore;

  if (notBefore !== undefined && notBefore.getTime() > now.getTime()) {
    throw new SecretNotYetValidError(
      `Secret '${ref.path}' version '${ref.version}' is not valid before ` +
        `${notBefore.toISOString()}. A future-dated secret in production is a deployment ` +
        `ordering mistake rather than a value to hand out.`,
      ref.path,
      ref.version,
      notBefore
    );
  }
}

/**
 * The name and version a secret identifier carries.
 *
 * A caller may pass `https://<vault>.vault.azure.net/secrets/<name>/<version>`,
 * which is what the portal and the ARM template both show. Two things have to
 * come off it: the vault URL names the tenant and must not become a label, and
 * the trailing version has to be honoured rather than dropped. Dropping it
 * would silently serve the current version to a caller who pinned one, which is
 * the failure mode worth ruling out by construction.
 */
export function parseSecretIdentifier(identifier: string): {
  readonly name: string;
  readonly version: string | undefined;
} {
  const path = logicalLabel(identifier);
  const segments = path.split('/').filter((segment) => segment !== '');
  const at = segments.indexOf('secrets');

  if (at === -1) {
    return { name: path, version: undefined };
  }

  return { name: segments[at + 1] ?? path, version: segments[at + 2] };
}

/**
 * The resolved ref.
 *
 * `properties.version` is the concrete version. A `getSecret` with no version
 * asks for the current one and the response says which it was, which is the
 * whole point of the rule: two reads a second apart can legitimately differ.
 */
export function azureResolvedRef(secret: KeyVaultSecret): ResolvedSecretRef {
  return {
    path: secret.name,
    version: secret.properties.version ?? 'current',
    metadata: azureMetadata(secret.properties),
  };
}
