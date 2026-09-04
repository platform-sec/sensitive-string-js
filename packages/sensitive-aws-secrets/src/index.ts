/**
 * @platform-sec/sensitive-string-aws-secrets
 *
 * AWS Secrets Manager as a `SecretSource`, so a secret arrives wrapped rather
 * than as a plain string on a response object.
 *
 * ```ts
 * const res = await client.send(new GetSecretValueCommand({ SecretId: 'prod/db' }));
 * const { password } = JSON.parse(res.SecretString!);
 * ```
 *
 * Three things have gone wrong there and none of them throws. `res` holds the
 * raw secret and is an ordinary object, so it reaches an error tracker if the
 * next line fails while it is in scope. `password` is a plain string with no
 * class, no label and no audit trail. And if the secret turns out to hold a
 * bare API key rather than JSON, the `SyntaxError` carries up to twenty
 * characters of it into the report.
 *
 * @example
 * ```ts
 * import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
 * import { AwsSecretSource } from '@platform-sec/sensitive-string-aws-secrets';
 *
 * const aws = new AwsSecretSource({ client: new SecretsManagerClient({ region: 'us-east-1' }) });
 *
 * const db = await aws.getJson('prod/db', {
 *   fields: { username: 'sensitive', password: 'credential', host: 'plain', port: 'plain' },
 * });
 *
 * db.fields.password; // SensitiveString<credential:prod/db#password>
 * db.ref.version;     // the VersionId, never 'AWSCURRENT'
 * ```
 *
 * @packageDocumentation
 */

export { AwsSecretSource } from './source.js';
export type { AwsSecretsClient, AwsSecretSourceOptions } from './source.js';

export {
  awsLabel,
  awsPayload,
  awsResolvedRef,
  parseArn,
  rotationMetadata,
  versionField,
} from './wire.js';
export type { BinaryEncoding, ParsedArn, VersionSlot } from './wire.js';
