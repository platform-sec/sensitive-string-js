/**
 * The AWS wire shape, and the two things it gets wrong for this library.
 *
 * `GetSecretValueCommandOutput` carries the secret in one of two fields, and
 * every other field on it names the account. Both are handled here rather than
 * in the source, so the response object is destructured in one place and
 * nothing downstream ever holds it.
 */

import { SecretPayloadError, logicalLabel } from '@platform-sec/sensitive-string-secrets';
import type {
  ProviderPayload,
  ResolvedSecretRef,
  SecretMetadata,
  SecretRef,
} from '@platform-sec/sensitive-string-secrets';
import type {
  DescribeSecretCommandOutput,
  GetSecretValueCommandOutput,
} from '@aws-sdk/client-secrets-manager';

/**
 * A secret ARN.
 *
 * `arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf`. The
 * account id sits in the fifth field, which is why an ARN cannot be a label.
 */
const SECRET_ARN = /^arn:([^:]*):secretsmanager:([^:]*):([^:]*):secret:(.*)$/;

export interface ParsedArn {
  readonly partition: string;
  readonly region: string;
  readonly account: string;
  /** Everything after `secret:`, including AWS's six-character suffix. */
  readonly name: string;
}

export function parseArn(value: string): ParsedArn | undefined {
  const match = SECRET_ARN.exec(value);

  if (match === null) {
    return undefined;
  }

  const [, partition = '', region = '', account = '', name = ''] = match;

  return { partition, region, account, name };
}

/**
 * The label for a ref, before the response is seen.
 *
 * `SecretId` accepts a name or an ARN, and the ARN carries the account id into
 * every log line the value ever appears in. This reduces it to the name.
 *
 * AWS's six random characters are kept rather than stripped. Stripping them
 * looks tidier and is a guess: a partial ARN has no suffix, and a secret
 * genuinely named `prod/config-backup` would lose its last word to a rule that
 * cannot tell one case from the other. The suffix discloses nothing, so the
 * deterministic answer is the right one. Pass the name rather than the ARN and
 * the question does not arise.
 */
export function awsLabel(secretId: string): string {
  return parseArn(secretId)?.name ?? logicalLabel(secretId);
}

/**
 * A version id, as distinct from a staging label.
 *
 * `GetSecretValue` takes `VersionId` or `VersionStage` and this library has one
 * `version` slot, so something has to decide which field a string goes in. AWS
 * generates a version id as a UUID and staging labels are words: `AWSCURRENT`,
 * `AWSPENDING`, `AWSPREVIOUS`, or a name an operator chose.
 *
 * Guessing is acceptable here only because the failure direction is safe. A
 * staging label misrouted to `VersionId` produces `ResourceNotFoundException`,
 * which arrives as an absence rather than as a different secret. `versionIs`
 * overrides it for a deployment that named a stage like a UUID.
 */
const VERSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type VersionSlot = 'auto' | 'stage' | 'id';

export function versionField(
  version: string,
  slot: VersionSlot
): { VersionId: string } | { VersionStage: string } {
  const asId = slot === 'id' || (slot === 'auto' && VERSION_ID.test(version));

  return asId ? { VersionId: version } : { VersionStage: version };
}

/** How `SecretBinary` is turned into a string. */
export type BinaryEncoding = 'utf8' | 'base64';

/**
 * The payload, from whichever of the two fields carried it.
 *
 * Exactly one of them is present on a real response. Neither being present is
 * not a shape this can coerce, so it fails rather than handing back an empty
 * string that would travel downstream as a credential.
 *
 * Decoding `SecretBinary` produces a second copy of the secret that this
 * package cannot clear, which is in the README under what it does not protect.
 */
export function awsPayload(
  response: Pick<GetSecretValueCommandOutput, 'SecretString' | 'SecretBinary'>,
  ref: ResolvedSecretRef,
  encoding: BinaryEncoding
): ProviderPayload {
  if (typeof response.SecretString === 'string') {
    return { kind: 'string', value: response.SecretString };
  }

  if (response.SecretBinary !== undefined) {
    return {
      kind: 'string',
      value: Buffer.from(
        response.SecretBinary.buffer,
        response.SecretBinary.byteOffset,
        response.SecretBinary.byteLength
      ).toString(encoding),
    };
  }

  throw new SecretPayloadError(
    `Secret '${ref.path}' version '${ref.version}' carried neither SecretString nor ` +
      `SecretBinary. A secret version always holds one of them, so this is a response ` +
      `shape this package does not recognize.`,
    ref.path,
    ref.version
  );
}

/**
 * The resolved ref.
 *
 * `path` is the secret's name rather than what the caller passed, so an ARN in
 * the request does not become an account id in an error message. The ARN itself
 * is not discarded: it goes on `metadata`, which reaches the load hook and never
 * reaches redacted output.
 *
 * `version` is `VersionId`, which is the point of the rule that a resolved ref
 * carries a concrete version. During a rotation both `AWSCURRENT` and
 * `AWSPENDING` are valid, so an audit trail recording the stage cannot say
 * which value a process actually got.
 */
export function awsResolvedRef(
  response: GetSecretValueCommandOutput,
  ref: SecretRef,
  extra: SecretMetadata = {}
): ResolvedSecretRef {
  const arn = response.ARN;
  const parsed = arn === undefined ? undefined : parseArn(arn);
  const metadata: Record<string, string | number | boolean | undefined> = {
    ...extra,
    ...(arn === undefined ? {} : { arn }),
    ...(parsed === undefined ? {} : { region: parsed.region, account: parsed.account }),
    ...(response.CreatedDate === undefined
      ? {}
      : { createdAt: response.CreatedDate.toISOString() }),
    ...(response.VersionStages === undefined
      ? {}
      : { versionStages: response.VersionStages.join(',') }),
  };

  return {
    path: response.Name ?? awsLabel(ref.path),
    version: response.VersionId ?? 'unknown',
    metadata,
  };
}

/**
 * Rotation metadata, which is metadata and never a deadline.
 *
 * `NextRotationDate` is the most tempting field in this API and binding it
 * would be wrong: the current version of a rotated secret keeps working after
 * its next rotation date, usually until the rotation actually succeeds and
 * often well past that. A value derived from it would throw while still being
 * the live credential.
 */
export function rotationMetadata(described: DescribeSecretCommandOutput): SecretMetadata {
  return {
    rotationEnabled: described.RotationEnabled ?? false,
    ...(described.NextRotationDate === undefined
      ? {}
      : { nextRotationAt: described.NextRotationDate.toISOString() }),
    ...(described.LastRotatedDate === undefined
      ? {}
      : { lastRotatedAt: described.LastRotatedDate.toISOString() }),
    ...(described.RotationRules?.AutomaticallyAfterDays === undefined
      ? {}
      : { rotationAfterDays: described.RotationRules.AutomaticallyAfterDays }),
    ...(described.RotationRules?.ScheduleExpression === undefined
      ? {}
      : { rotationSchedule: described.RotationRules.ScheduleExpression }),
  };
}
