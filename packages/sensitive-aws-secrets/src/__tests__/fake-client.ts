import { DescribeSecretCommand, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import type {
  DescribeSecretCommandOutput,
  GetSecretValueCommandOutput,
} from '@aws-sdk/client-secrets-manager';

import { AwsSecretSource } from '../source.js';
import type { AwsSecretsClient, AwsSecretSourceOptions } from '../source.js';

/**
 * A client driven by recorded response objects.
 *
 * The fixtures are typed as the SDK's own output types, so a field this package
 * reads has to exist on the real response and a field AWS renamed fails the
 * build rather than the runtime. That is what a fixture can do about the rule
 * this row learned the hard way: a fixture written from a design document tests
 * the document. The types are the provider's, and the measured behaviours are
 * in the README's table.
 *
 * Nothing here calls AWS. `src/__tests__/live.test.ts` is the second tier and
 * skips itself unless an endpoint is configured.
 */

export const ACCOUNT = '123456789012';

export function arnFor(name: string, suffix = 'AbCdEf'): string {
  return `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:${name}-${suffix}`;
}

/** An error shaped like the SDK's, which is matched by name and not by class. */
export function awsError(name: string, message = 'the request failed'): Error {
  const error = new Error(message);
  error.name = name;

  return error;
}

export interface Recorded {
  readonly get?: GetSecretValueCommandOutput | Error;
  readonly describe?: DescribeSecretCommandOutput | Error;
}

export class FakeSecretsManager implements AwsSecretsClient {
  readonly commands: { readonly kind: string; readonly input: unknown }[] = [];

  constructor(private readonly routes: Map<string, Recorded>) {}

  static of(routes: Readonly<Record<string, Recorded>>): FakeSecretsManager {
    return new FakeSecretsManager(new Map(Object.entries(routes)));
  }

  send(command: GetSecretValueCommand): Promise<GetSecretValueCommandOutput>;
  send(command: DescribeSecretCommand): Promise<DescribeSecretCommandOutput>;
  send(
    command: GetSecretValueCommand | DescribeSecretCommand
  ): Promise<GetSecretValueCommandOutput | DescribeSecretCommandOutput> {
    const kind = command instanceof GetSecretValueCommand ? 'get' : 'describe';
    const input = command.input as { SecretId?: string };
    this.commands.push({ kind, input });

    const recorded = this.routes.get(input.SecretId ?? '');
    const reply = kind === 'get' ? recorded?.get : recorded?.describe;

    if (reply === undefined) {
      return Promise.reject(awsError('ResourceNotFoundException', 'Secrets Manager cannot find'));
    }

    if (reply instanceof Error) {
      return Promise.reject(reply);
    }

    return Promise.resolve(reply);
  }
}

/** A `GetSecretValue` response, in the shape the SDK types describe. */
export function getResponse(
  name: string,
  fields: Partial<GetSecretValueCommandOutput> = {}
): GetSecretValueCommandOutput {
  return {
    $metadata: { httpStatusCode: 200, requestId: 'a1b2' },
    ARN: arnFor(name),
    Name: name,
    VersionId: 'b9b1f2c4-4a2f-4a6b-9a1d-0f6a3c2b7e11',
    VersionStages: ['AWSCURRENT'],
    CreatedDate: new Date('2026-09-01T00:00:00Z'),
    ...fields,
  };
}

export function describeResponse(
  name: string,
  fields: Partial<DescribeSecretCommandOutput> = {}
): DescribeSecretCommandOutput {
  return {
    $metadata: { httpStatusCode: 200 },
    ARN: arnFor(name),
    Name: name,
    RotationEnabled: true,
    RotationRules: { AutomaticallyAfterDays: 30 },
    NextRotationDate: new Date('2026-10-01T00:00:00Z'),
    LastRotatedDate: new Date('2026-09-01T00:00:00Z'),
    ...fields,
  };
}

export function source(
  client: AwsSecretsClient,
  options: Partial<AwsSecretSourceOptions> = {}
): AwsSecretSource {
  return new AwsSecretSource({ client, cache: { ttl: 0 }, ...options });
}
