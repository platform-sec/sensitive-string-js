/**
 * The OCI wire shape, and the two clients that make this the easiest package in
 * the row to point at the wrong API.
 *
 * `oci-vault`'s `VaultsClient` manages secrets, their metadata, and their
 * versions, and does not return secret contents. `oci-secrets`'
 * `SecretsClient.getSecretBundle` is the read path. This package is named for
 * the product and depends on the data plane; the name mismatch is confusing
 * enough that the README says so too.
 */

import { SecretPayloadError, decodeBase64 } from '@platform-sec/sensitive-string-secrets';
import type {
  ResolvedSecretRef,
  SecretLifetime,
  SecretMetadata,
} from '@platform-sec/sensitive-string-secrets';
import type { models } from 'oci-secrets';

export type SecretBundle = models.SecretBundle;

/** The stages that occupy the `version` slot alongside a numeric version. */
export const STAGES = ['CURRENT', 'PENDING', 'LATEST', 'PREVIOUS', 'DEPRECATED'] as const;

export type Stage = (typeof STAGES)[number];

export function isStage(value: string): value is Stage {
  return (STAGES as readonly string[]).includes(value.toUpperCase());
}

/** An OCID, which encodes the realm, the region and the tenancy. */
const OCID = /^ocid\d*\.[a-z]/i;

export function isOcid(value: string): boolean {
  return OCID.test(value);
}

/**
 * Which request field a `version` belongs in.
 *
 * OCI splits what this library holds in one slot across three: a numeric
 * `versionNumber`, a `secretVersionName`, and a `stage`. A version that is all
 * digits is a number, one of the five known stages is a stage, and anything
 * else is a version name. Misrouting produces a 404, which arrives as an
 * absence rather than as a different secret.
 */
export function versionFields(version: string | undefined): {
  versionNumber?: number;
  secretVersionName?: string;
  stage?: string;
} {
  if (version === undefined) {
    return {};
  }

  if (/^\d+$/.test(version)) {
    return { versionNumber: Number(version) };
  }

  if (isStage(version)) {
    return { stage: version.toUpperCase() };
  }

  return { secretVersionName: version };
}

/**
 * The payload, decoded once the content type is what it claims to be.
 *
 * `secretBundleContent` is a discriminated union on `contentType` with one
 * member, `BASE64`. Handling the one that exists and refusing anything else is
 * the point: a new content type decoded as base64 would produce silent garbage
 * that travels downstream as a credential and fails as an authentication error
 * somewhere else.
 *
 * The decode goes through the shared base64 guard rather than
 * `Buffer.from(value, 'base64')`, which skips characters outside the alphabet
 * instead of failing. That leniency is how a damaged bundle becomes
 * plausible-looking garbage with no diagnostic pointing back here.
 *
 * Decoding produces two copies of the secret, the base64 string on the response
 * and the decoded string, and neither can be cleared on demand. That is in the
 * README under what this does not protect.
 */
export function ociPayload(bundle: SecretBundle, ref: ResolvedSecretRef): string {
  const content = bundle.secretBundleContent;

  if (content === undefined) {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}' carried no bundle content.`,
      ref.path,
      ref.version
    );
  }

  if (content.contentType !== 'BASE64') {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}' arrived with content type ` +
        `'${content.contentType}', which this package does not decode. Decoding an ` +
        `unrecognized type as base64 would produce garbage that looks like a secret.`,
      ref.path,
      ref.version
    );
  }

  if (typeof content.content !== 'string') {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}' arrived with a BASE64 bundle carrying ` +
        `no content.`,
      ref.path,
      ref.version
    );
  }

  return decodeBase64(content.content, ref);
}

/**
 * The lifetime, and the date that looks like one and is not.
 *
 * `timeOfExpiry` is the secret version's own expiry and maps to `expiresAt`.
 * `timeOfDeletion` is the scheduled deletion of the secret resource: a secret
 * pending deletion still works until it is deleted, so binding it would expire
 * a live credential early, which is the same call this row makes for a rotation
 * schedule.
 */
export function ociLifetime(bundle: SecretBundle): SecretLifetime | undefined {
  return bundle.timeOfExpiry === undefined ? undefined : { expiresAt: bundle.timeOfExpiry };
}

/**
 * The resolved ref.
 *
 * `versionNumber` is the concrete version, which is what makes `stage: LATEST`
 * usable in an audit trail. The secret OCID encodes the tenancy, the region and
 * the realm, so it goes on `metadata` and never into `path` or a label.
 */
export function ociResolvedRef(bundle: SecretBundle, label: string): ResolvedSecretRef {
  const metadata: SecretMetadata = {
    secretId: bundle.secretId,
    ...(bundle.versionName === undefined ? {} : { versionName: bundle.versionName }),
    ...(bundle.timeCreated === undefined ? {} : { createdAt: bundle.timeCreated.toISOString() }),
    ...(bundle.timeOfExpiry === undefined ? {} : { expiresAt: bundle.timeOfExpiry.toISOString() }),
    ...(bundle.timeOfDeletion === undefined
      ? {}
      : { deletionAt: bundle.timeOfDeletion.toISOString() }),
    ...(bundle.stages === undefined ? {} : { stages: bundle.stages.join(',') }),
  };

  return {
    path: label,
    version: String(bundle.versionNumber),
    metadata,
  };
}
