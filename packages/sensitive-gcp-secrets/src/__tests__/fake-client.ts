import { GcpSecretSource } from '../source.js';
import type { GcpSecretsClient, GcpSecretSourceOptions } from '../source.js';
import { crc32c } from '../crc32c.js';
import type { AccessResponse, Secret } from '../wire.js';

/**
 * A client driven by recorded responses.
 *
 * The fixtures are typed as the SDK's generated proto interfaces, so a field
 * this package reads has to exist on the real message. Nothing here calls GCP.
 */

export const PROJECT = '123456789012';

/** A gax error, which is matched by its numeric gRPC status. */
export function gaxError(code: number, message = 'the request failed'): Error {
  return Object.assign(new Error(message), { code });
}

export interface Fixture {
  readonly value?: string;
  /** Overrides the computed checksum, for the corruption cases. */
  readonly crc?: unknown;
  readonly omitCrc?: boolean;
  readonly version?: string;
  readonly error?: Error;
  readonly secret?: Secret | Error;
}

export class FakeSecretManager implements GcpSecretsClient {
  readonly requests: string[] = [];

  constructor(private readonly routes: Map<string, Fixture>) {}

  static of(routes: Readonly<Record<string, Fixture>>): FakeSecretManager {
    return new FakeSecretManager(new Map(Object.entries(routes)));
  }

  accessSecretVersion(request: {
    name: string;
  }): Promise<readonly [AccessResponse, ...(readonly unknown[])]> {
    this.requests.push(request.name);

    const fixture = this.#lookup(request.name);

    if (fixture === undefined) {
      return Promise.reject(gaxError(5, 'Secret Version [x] not found'));
    }

    if (fixture.error !== undefined) {
      return Promise.reject(fixture.error);
    }

    return Promise.resolve([accessResponse(request.name, fixture)]);
  }

  getSecret(request: { name: string }): Promise<readonly [Secret, ...(readonly unknown[])]> {
    this.requests.push(request.name);

    const fixture = this.#lookup(`${request.name}/versions/latest`);
    const secret = fixture?.secret;

    if (secret === undefined) {
      return Promise.reject(gaxError(5, 'Secret [x] not found'));
    }

    if (secret instanceof Error) {
      return Promise.reject(secret);
    }

    return Promise.resolve([secret]);
  }

  #lookup(name: string): Fixture | undefined {
    return this.routes.get(name);
  }
}

/** An `AccessSecretVersionResponse`, with the checksum the API would compute. */
export function accessResponse(requested: string, fixture: Fixture): AccessResponse {
  const bytes = Buffer.from(fixture.value ?? '', 'utf8');
  const resolved = requested.replace(/\/versions\/[^/]+$/, `/versions/${fixture.version ?? '7'}`);

  return {
    name: resolved,
    payload: {
      data: bytes,
      ...(fixture.omitCrc === true
        ? {}
        : { dataCrc32c: fixture.crc === undefined ? crc32c(bytes) : (fixture.crc as number) }),
    },
  };
}

export function source(
  client: GcpSecretsClient,
  options: Partial<GcpSecretSourceOptions> = {}
): GcpSecretSource {
  return new GcpSecretSource({ client, project: PROJECT, cache: { ttl: 0 }, ...options });
}

export function secretResource(name: string, fields: Partial<Secret> = {}): Secret {
  return {
    name: `projects/${PROJECT}/secrets/${name}`,
    etag: '"abc"',
    createTime: { seconds: 1_756_684_800, nanos: 0 },
    ...fields,
  };
}
