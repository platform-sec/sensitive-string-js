/**
 * @platform-sec/sensitive-string-k8s
 *
 * Kubernetes Secrets as a `SecretSource`.
 *
 * A Kubernetes Secret is a flat map of keys to base64 values, so it is a
 * `getAll` source, and it is the one in this row where the built-in
 * classification specs do most of the work. `tls.crt` is why they exist: a
 * certificate is published to every client that opens a connection, so wrapping
 * it as a credential protects nothing and breaks the code that parses it.
 *
 * @example
 * ```ts
 * import { CoreV1Api, KubeConfig } from '@kubernetes/client-node';
 * import { K8sSecretSource, k8sSecretTypeSpec } from '@platform-sec/sensitive-string-k8s';
 *
 * const kc = new KubeConfig();
 * kc.loadFromDefault();
 *
 * const k8s = new K8sSecretSource({ api: kc.makeApiClient(CoreV1Api), namespace: 'payments' });
 *
 * const creds = await k8s.getAll('db-creds', { fallback: 'credential' });
 * creds.fields.get('password');
 *
 * const tls = await k8s.getAll('ingress-tls', k8sSecretTypeSpec('kubernetes.io/tls'));
 * tls.plain.get('tls.crt');    // a certificate is public
 * tls.fields.get('tls.key');
 * ```
 *
 * @packageDocumentation
 */

export { K8sSecretSource, expandDockerConfig } from './source.js';
export type { K8sCoreApi, K8sSecretSourceOptions } from './source.js';

export { K8sMountedSource, SERVICE_ACCOUNT_PATH } from './mounted.js';
export type { K8sMountedSourceOptions } from './mounted.js';

export { K8S_SECRET_TYPES, isKnownSecretType, k8sSecretTypeSpec } from './types.js';
export type { K8sSecretType } from './types.js';

export { LAST_APPLIED, hasDataBearingAnnotation, k8sMetadata } from './metadata.js';

export { jwtExpiry } from './token.js';
