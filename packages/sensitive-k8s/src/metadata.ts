/**
 * The metadata strip, and the annotation that holds a second copy of the
 * Secret.
 *
 * A Secret created with `kubectl apply` carries
 * `metadata.annotations['kubectl.kubernetes.io/last-applied-configuration']`,
 * whose value is the JSON the user applied, `data` included. Annotations are
 * not treated as secret by most tooling: they are printed by `kubectl
 * describe`, collected by inventory and policy agents, and copied into audit
 * records.
 *
 * So this strips `metadata.annotations` entirely rather than removing one known
 * key. The mechanism that put a copy of the Secret in an annotation is a
 * convention, other tools follow similar ones, and an allowlist survives
 * conventions this package has not heard of.
 *
 * That is the response-object invariant arriving in an unusual shape. The
 * response holds a second copy of the secret in a field nobody thinks of as
 * secret, and the fix is the same one: the provider response does not leave the
 * provider package.
 */

import type { SecretMetadata } from '@platform-sec/sensitive-string-secrets';
import type { V1Secret } from '@kubernetes/client-node';

/** The annotation `kubectl apply` writes, named here so the README can point at it. */
export const LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration';

/**
 * The fields a `V1Secret` contributes to `ResolvedSecretRef.metadata`.
 *
 * An allowlist. `annotations`, `labels` and `managedFields` are all absent:
 * annotations for the reason above, labels because they are operator-chosen and
 * a copy of a Secret has been found in one, and `managedFields` because it is a
 * per-field apply history that says nothing an audit record wants.
 */
export function k8sMetadata(secret: V1Secret): SecretMetadata {
  const meta = secret.metadata;

  return {
    ...(meta?.name === undefined ? {} : { name: meta.name }),
    ...(meta?.namespace === undefined ? {} : { namespace: meta.namespace }),
    ...(meta?.resourceVersion === undefined ? {} : { resourceVersion: meta.resourceVersion }),
    ...(meta?.uid === undefined ? {} : { uid: meta.uid }),
    ...(secret.type === undefined ? {} : { type: secret.type }),
    ...(secret.immutable === undefined ? {} : { immutable: secret.immutable }),
    ...(meta?.creationTimestamp === undefined
      ? {}
      : { createdAt: new Date(meta.creationTimestamp).toISOString() }),
  };
}

/**
 * Whether a Secret carries an annotation holding a second copy of its data.
 *
 * A test helper rather than a runtime guard: the strip above is unconditional,
 * so nothing needs to ask at run time. It exists so a suite can assert that a
 * fixture which does carry one still produces metadata that does not.
 */
export function hasDataBearingAnnotation(secret: V1Secret): boolean {
  const annotations = secret.metadata?.annotations;

  if (annotations === undefined) {
    return false;
  }

  // Both spellings. Measured on Kubernetes v1.34.1, `kubectl apply` of a
  // manifest written with `stringData` puts the secret into the annotation
  // **unencoded**: the annotation holds the plaintext where the Secret's own
  // `data` holds base64. Checking only for `"data"` would miss the worse of
  // the two cases.
  return Object.values(annotations).some(
    (value) => value.includes('"data"') || value.includes('"stringData"')
  );
}
