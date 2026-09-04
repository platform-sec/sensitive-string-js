/**
 * The Secret Manager wire shape.
 *
 * Two things about it shape this package. The payload is bytes rather than a
 * string, which means a decode and a copy this package cannot clear. And a
 * version alias is resolved server-side, which is why the response's own `name`
 * rather than the request's is what a resolved ref reports.
 */

import { SecretPayloadError } from '@platform-sec/sensitive-string-secrets';
import type {
  ResolvedSecretRef,
  SecretLifetime,
  SecretMetadata,
  SecretRef,
} from '@platform-sec/sensitive-string-secrets';
import type { protos } from '@google-cloud/secret-manager';

import { crc32c, toChecksum } from './crc32c.js';

export type AccessResponse = protos.google.cloud.secretmanager.v1.IAccessSecretVersionResponse;
export type Secret = protos.google.cloud.secretmanager.v1.ISecret;
export type Timestamp = protos.google.protobuf.ITimestamp;

/** `projects/<project>/secrets/<id>/versions/<version>`. */
const RESOURCE = /^projects\/([^/]+)\/secrets\/([^/]+)(?:\/versions\/([^/]+))?$/;

export interface ParsedResource {
  readonly project: string;
  readonly secret: string;
  readonly version: string | undefined;
}

export function parseResource(name: string): ParsedResource | undefined {
  const match = RESOURCE.exec(name);

  if (match === null) {
    return undefined;
  }

  const [, project = '', secret = '', version] = match;

  return { project, secret, version };
}

/**
 * The label: the secret's short name.
 *
 * A fully qualified resource name is `projects/<number>/secrets/<id>/...`, and
 * the project number identifies the organization's billing account as
 * effectively as the AWS account id does. It goes on `metadata`.
 */
export function gcpLabel(path: string): string {
  return parseResource(path)?.secret ?? path;
}

/**
 * The resource name to request.
 *
 * A caller may pass a short name plus a configured project, or a fully
 * qualified name. `latest` is the API's own alias and is what an unversioned
 * read means.
 */
export function resourceName(ref: SecretRef, project: string | undefined): string {
  const parsed = parseResource(ref.path);

  if (parsed !== undefined) {
    // A version on the path and a version on the ref both being present is a
    // caller contradicting themselves. The explicit one wins, because it is the
    // one they wrote at the call site rather than in configuration.
    const version = ref.version ?? parsed.version ?? 'latest';

    return `projects/${parsed.project}/secrets/${parsed.secret}/versions/${version}`;
  }

  if (project === undefined || project === '') {
    throw new TypeError(
      `GcpSecretSource needs a project to resolve the short name '${ref.path}'. Pass ` +
        `{ project } to the constructor, or use a fully qualified ` +
        `'projects/<project>/secrets/<name>' path.`
    );
  }

  return `projects/${project}/secrets/${ref.path}/versions/${ref.version ?? 'latest'}`;
}

/**
 * The payload bytes, verified.
 *
 * The check runs before anything is wrapped. A mismatch names the secret and
 * the version and never the content, which is the same rule every decoder in
 * this row follows: a decoder that fails on content puts content in its error.
 *
 * `requireChecksum` decides what an absent `dataCrc32c` means. It defaults to
 * off because whether the API supplies one on every path is not something this
 * package has measured, and failing a load over a field that may legitimately
 * be absent would be the wrong way to find out. A deployment that has checked
 * its own paths can turn it on and get an unconditional guarantee.
 */
export function verifiedPayload(
  payload: protos.google.cloud.secretmanager.v1.ISecretPayload,
  ref: ResolvedSecretRef,
  requireChecksum: boolean
): string {
  const data = payload.data;

  if (data === null || data === undefined) {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}' carried no payload data.`,
      ref.path,
      ref.version
    );
  }

  const bytes =
    typeof data === 'string'
      ? Buffer.from(data, 'base64')
      : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  const expected = toChecksum(payload.dataCrc32c);

  if (expected === undefined) {
    if (requireChecksum) {
      throw new SecretPayloadError(
        `Secret '${ref.path}' version '${ref.version}' arrived without a usable dataCrc32c ` +
          `and this source requires one.`,
        ref.path,
        ref.version
      );
    }
  } else if (crc32c(bytes) !== expected) {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}' failed its CRC32C check. The bytes ` +
        `Secret Manager sent are not the bytes that arrived.`,
      ref.path,
      ref.version
    );
  }

  return bytes.toString('utf8');
}

/** A protobuf timestamp, which arrives with its seconds as an int64. */
export function timestampToDate(timestamp: Timestamp | null | undefined): Date | undefined {
  if (timestamp === null || timestamp === undefined) {
    return undefined;
  }

  const seconds = Number(timestamp.seconds ?? 0);
  const nanos = Number(timestamp.nanos ?? 0);

  if (!Number.isFinite(seconds) || !Number.isFinite(nanos)) {
    return undefined;
  }

  const date = new Date(seconds * 1_000 + Math.floor(nanos / 1_000_000));

  return Number.isNaN(date.getTime()) ? undefined : date;
}

/**
 * The resolved ref.
 *
 * `version` comes from the response's `name`, never from the request. This is
 * the provider where that rule earns itself: two reads of `latest` a second
 * apart can legitimately return different versions, and an audit trail
 * recording `latest` for both cannot tell them apart.
 */
export function gcpResolvedRef(response: AccessResponse, ref: SecretRef): ResolvedSecretRef {
  const name = response.name ?? undefined;
  const parsed = name === undefined ? undefined : parseResource(name);

  return {
    path: parsed?.secret ?? gcpLabel(ref.path),
    version: parsed?.version ?? 'unknown',
    metadata: {
      ...(name === undefined ? {} : { resourceName: name }),
      ...(parsed === undefined ? {} : { project: parsed.project }),
    },
  };
}

/**
 * The lifetime, and the field that looks like one and is not.
 *
 * `expireTime` on the secret resource is a real deletion time: the secret is
 * gone after it, so a value derived from it stops working. It maps to
 * `expiresAt`.
 *
 * The `rotation` block does not. It schedules a Pub/Sub notification and
 * neither creates a version nor invalidates the current one, so a deadline
 * derived from it would expire a credential that is still correct. It is
 * recorded and never bound.
 */
export function gcpSecretMetadata(secret: Secret): {
  readonly lifetime: SecretLifetime | undefined;
  readonly metadata: SecretMetadata;
} {
  const expiresAt = timestampToDate(secret.expireTime);
  const nextRotation = timestampToDate(secret.rotation?.nextRotationTime);

  return {
    lifetime: expiresAt === undefined ? undefined : { expiresAt },
    metadata: {
      ...(expiresAt === undefined ? {} : { expiresAt: expiresAt.toISOString() }),
      ...(nextRotation === undefined ? {} : { nextRotationAt: nextRotation.toISOString() }),
      ...(secret.etag === undefined || secret.etag === null ? {} : { etag: secret.etag }),
      ...(secret.createTime === undefined
        ? {}
        : { createdAt: timestampToDate(secret.createTime)?.toISOString() }),
    },
  };
}
