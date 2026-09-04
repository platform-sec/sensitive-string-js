import { SensitiveString } from '@platform-sec/sensitive-string-core';

import { InfisicalRequestError } from '../transport.js';
import type { InfisicalRequest, InfisicalResponse, InfisicalTransport } from '../transport.js';
import { InfisicalSecretSource } from '../source.js';
import type { InfisicalSecretSourceOptions } from '../source.js';

/**
 * A transport driven by recorded response bodies.
 *
 * Nothing here calls Infisical. The `secrets` array shape is what the raw read
 * returns; every value in these fixtures is a string, which is what the API
 * sends, so nothing here invents a number a real server did not.
 */

export interface Recorded {
  readonly status?: number;
  readonly body?: unknown;
  readonly messages?: readonly string[];
}

export const TEST_TOKEN = 'st.abc.TESTTOKEN_abc123';
export const PROJECT_ID = 'a1b2c3d4e5f6';

export function infisicalToken(): SensitiveString<'credential'> {
  return new SensitiveString(TEST_TOKEN, 'credential', 'infisical-token');
}

/** An entry of the `secrets` array, in the fields the API returns. */
export function entry(secretKey: string, secretValue: string): Record<string, unknown> {
  return {
    id: `id-${secretKey}`,
    workspace: PROJECT_ID,
    environment: 'prod',
    version: 1,
    type: 'shared',
    secretKey,
    secretValue,
    secretComment: '',
  };
}

export function secretsBody(...entries: Record<string, unknown>[]): unknown {
  return { secrets: entries, imports: [] };
}

export class FakeTransport implements InfisicalTransport {
  readonly requests: InfisicalRequest[] = [];

  constructor(private readonly routes: Map<string, Recorded>) {}

  static of(routes: Readonly<Record<string, Recorded>>): FakeTransport {
    return new FakeTransport(new Map(Object.entries(routes)));
  }

  request(request: InfisicalRequest): Promise<InfisicalResponse> {
    this.requests.push(request);

    const key = `${request.query['environment'] ?? ''}${request.query['secretPath'] ?? ''}`;
    const recorded = this.routes.get(key);

    if (recorded === undefined) {
      return Promise.reject(
        new InfisicalRequestError(404, request.path, ['Folder with path not found'])
      );
    }

    const status = recorded.status ?? 200;

    if (status >= 400) {
      return Promise.reject(
        new InfisicalRequestError(status, request.path, recorded.messages ?? [])
      );
    }

    return Promise.resolve({ status, body: recorded.body });
  }
}

export function source(
  transport: InfisicalTransport,
  options: Partial<InfisicalSecretSourceOptions> = {}
): InfisicalSecretSource {
  return new InfisicalSecretSource({
    transport,
    token: infisicalToken(),
    projectId: PROJECT_ID,
    environment: 'prod',
    cache: { ttl: 0 },
    ...options,
  });
}
