import { SensitiveString } from '@platform-sec/sensitive-string-core';

import { DopplerRequestError } from '../transport.js';
import type { DopplerRequest, DopplerResponse, DopplerTransport } from '../transport.js';
import { DopplerSecretSource } from '../source.js';
import type { DopplerSecretSourceOptions } from '../source.js';

/**
 * A transport driven by recorded response bodies.
 *
 * Nothing here calls Doppler. The rule this row works to is that every number
 * in a fixture is one a real server sent, and these fixtures carry no numbers:
 * the download endpoint returns a flat map of strings and no version, which is
 * why the resolved ref reports `'unknown'` rather than inventing one.
 */

export interface Recorded {
  readonly status?: number;
  readonly body?: unknown;
  readonly messages?: readonly string[];
}

export const TEST_TOKEN = 'dp.st.prod.TESTTOKEN_abc123';

export function dopplerToken(): SensitiveString<'credential'> {
  return new SensitiveString(TEST_TOKEN, 'credential', 'doppler-token');
}

export class FakeTransport implements DopplerTransport {
  readonly requests: DopplerRequest[] = [];

  constructor(private readonly routes: Map<string, Recorded>) {}

  static of(routes: Readonly<Record<string, Recorded>>): FakeTransport {
    return new FakeTransport(new Map(Object.entries(routes)));
  }

  request(request: DopplerRequest): Promise<DopplerResponse> {
    this.requests.push(request);

    const key = [request.query['project'], request.query['config']]
      .filter((part) => part !== undefined)
      .join('/');
    const recorded = this.routes.get(key);

    if (recorded === undefined) {
      return Promise.reject(
        new DopplerRequestError(404, request.path, ['Could not find requested config'])
      );
    }

    const status = recorded.status ?? 200;

    if (status >= 400) {
      return Promise.reject(new DopplerRequestError(status, request.path, recorded.messages ?? []));
    }

    return Promise.resolve({ status, body: recorded.body });
  }
}

export function source(
  transport: DopplerTransport,
  options: Partial<DopplerSecretSourceOptions> = {}
): DopplerSecretSource {
  return new DopplerSecretSource({
    transport,
    token: dopplerToken(),
    project: 'payments',
    cache: { ttl: 0 },
    ...options,
  });
}
