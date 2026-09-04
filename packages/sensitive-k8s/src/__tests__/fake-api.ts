import type { V1Secret } from '@kubernetes/client-node';

import { K8sSecretSource } from '../source.js';
import type { K8sCoreApi, K8sSecretSourceOptions } from '../source.js';

/**
 * An API client driven by recorded `V1Secret` objects.
 *
 * The fixtures are typed as the client's own model class, so a field this
 * package reads has to exist on the real object. Nothing here calls a cluster;
 * `src/__tests__/live.test.ts` is the second tier and skips itself unless a
 * kubeconfig is configured.
 */

export const NAMESPACE = 'payments';

/** An `ApiException`-shaped failure. Matched structurally, so this is enough. */
export function k8sError(code: number, message = 'the request failed'): Error {
  return Object.assign(new Error(message), { code, name: 'ApiException' });
}

export function b64(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64');
}

export interface Fixture {
  readonly data?: Readonly<Record<string, string>>;
  /** Written through without encoding, for the cases where it is not base64. */
  readonly rawData?: Readonly<Record<string, string>>;
  readonly type?: string;
  readonly annotations?: Readonly<Record<string, string>>;
  readonly stringData?: Readonly<Record<string, string>>;
  readonly resourceVersion?: string;
  readonly error?: Error;
}

export function v1Secret(name: string, fixture: Fixture): V1Secret {
  return {
    apiVersion: 'v1',
    kind: 'Secret',
    type: fixture.type ?? 'Opaque',
    metadata: {
      name,
      namespace: NAMESPACE,
      uid: 'b1f2c4d5-4a2f-4a6b-9a1d-0f6a3c2b7e11',
      resourceVersion: fixture.resourceVersion ?? '184213',
      creationTimestamp: new Date('2026-09-01T00:00:00Z'),
      ...(fixture.annotations === undefined ? {} : { annotations: { ...fixture.annotations } }),
    },
    ...(fixture.stringData === undefined ? {} : { stringData: { ...fixture.stringData } }),
    ...(fixture.data === undefined && fixture.rawData === undefined
      ? {}
      : {
          data: {
            ...Object.fromEntries(
              Object.entries(fixture.data ?? {}).map(([key, value]) => [key, b64(value)])
            ),
            ...fixture.rawData,
          },
        }),
  };
}

export class FakeCoreApi implements K8sCoreApi {
  readonly requests: { name: string; namespace: string }[] = [];

  constructor(private readonly routes: Map<string, Fixture>) {}

  static of(routes: Readonly<Record<string, Fixture>>): FakeCoreApi {
    return new FakeCoreApi(new Map(Object.entries(routes)));
  }

  readNamespacedSecret(request: { name: string; namespace: string }): Promise<V1Secret> {
    this.requests.push({ ...request });

    const fixture =
      this.routes.get(`${request.namespace}/${request.name}`) ?? this.routes.get(request.name);

    if (fixture === undefined) {
      return Promise.reject(k8sError(404, 'secrets "x" not found'));
    }

    if (fixture.error !== undefined) {
      return Promise.reject(fixture.error);
    }

    return Promise.resolve(v1Secret(request.name, fixture));
  }
}

/**
 * A source over the fake API.
 *
 * The options type spells out `| undefined` per key rather than using
 * `Partial`, because `exactOptionalPropertyTypes` makes those different types:
 * a test that wants "no namespace configured" has to be able to pass
 * `{ namespace: undefined }`, and `Partial` refuses it.
 */
export function source(
  api: K8sCoreApi,
  options: Partial<K8sSecretSourceOptions> = {}
): K8sSecretSource {
  return new K8sSecretSource({ api, namespace: NAMESPACE, cache: { ttl: 0 }, ...options });
}

/** A JWT with the given `exp`, signature not included because nothing verifies it. */
export function jwt(claims: Readonly<Record<string, unknown>>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

  return `${encode({ alg: 'RS256', kid: 'abc' })}.${encode(claims)}.c2lnbmF0dXJl`;
}
