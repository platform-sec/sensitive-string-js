/**
 * The built-in classification specs, one per well-known Secret type.
 *
 * A Kubernetes Secret is a flat map of keys to base64 values, so it is a
 * `getAll` source, and `fallback: 'credential'` is the right default for most
 * of them. It is wrong for exactly the keys that matter most, which is what
 * makes these specs worth shipping.
 *
 * `tls.crt` is the case that carries the argument. A certificate is published
 * to every client that opens a connection, so wrapping it as a credential
 * protects nothing and breaks the code that parses it, compares its
 * fingerprint, or hands it to a TLS context expecting a string.
 *
 * The specs are exported and are **not** applied automatically from the
 * Secret's `type` field. Behaviour that changes because a server-side field
 * changed is behaviour that breaks a caller when somebody edits a resource, and
 * the caller who writes `k8sSecretTypeSpec('kubernetes.io/tls')` can see in
 * their own code what it does.
 */

import type { GetAllOptions } from '@platform-sec/sensitive-string-secrets';

/** The Secret types that have a correct classification a blanket fallback misses. */
export const K8S_SECRET_TYPES = [
  'kubernetes.io/tls',
  'kubernetes.io/basic-auth',
  'kubernetes.io/ssh-auth',
  'kubernetes.io/service-account-token',
  'kubernetes.io/dockerconfigjson',
  'kubernetes.io/dockercfg',
  'Opaque',
] as const;

export type K8sSecretType = (typeof K8S_SECRET_TYPES)[number];

/** A spec without the parts `getAll` takes from the call site. */
type Spec = Omit<GetAllOptions, 'label' | 'ttl'>;

const SPECS: Readonly<Record<K8sSecretType, Spec>> = {
  'kubernetes.io/tls': {
    fields: {
      // The private key, and the two public documents that are routinely
      // wrapped by mistake. A certificate is not a secret.
      'tls.key': 'credential',
      'tls.crt': 'plain',
      'ca.crt': 'plain',
    },
    fallback: 'credential',
  },
  'kubernetes.io/basic-auth': {
    // A username is not a credential and is not public either: it identifies a
    // principal, which is what `sensitive` is for.
    fields: { password: 'credential', username: 'sensitive' },
    fallback: 'credential',
  },
  'kubernetes.io/ssh-auth': {
    fields: { 'ssh-privatekey': 'credential', 'ssh-publickey': 'plain' },
    fallback: 'credential',
  },
  'kubernetes.io/service-account-token': {
    fields: {
      token: 'credential',
      'ca.crt': 'plain',
      'service-ca.crt': 'plain',
      namespace: 'plain',
    },
    fallback: 'credential',
  },
  'kubernetes.io/dockerconfigjson': dockerSpec('.dockerconfigjson'),
  'kubernetes.io/dockercfg': dockerSpec('.dockercfg'),
  // No spec. An Opaque Secret's keys mean whatever the operator decided, and
  // guessing at them is how `tls.crt` gets wrapped.
  Opaque: { fallback: 'credential' },
};

/**
 * A pull secret, classified for both shapes it can arrive in.
 *
 * Unexpanded, the whole file is one credential-classified string. Expanded
 * through `expandDockerConfigJson`, the leaves are `auths.<registry>.<field>`,
 * and the rules match on the leaf key name rather than the dot path, because a
 * registry hostname contains dots and would otherwise have to be anticipated by
 * a pattern. Registry hostnames are container keys and never become leaves, so
 * they are never classified at all.
 */
function dockerSpec(key: string): Spec {
  return {
    fields: { [key]: 'credential' },
    rules: [
      { pattern: /^(auth|password|identitytoken|registrytoken)$/i, klass: 'credential' },
      { pattern: /^username$/i, klass: 'sensitive' },
      // An email address in a pull secret is the account it was created with.
      // It is not a credential and it is not public, so it lands in the middle.
      { pattern: /^email$/i, klass: 'sensitive' },
    ],
    fallback: 'credential',
  };
}

/**
 * The classification for a well-known Secret type.
 *
 * @example
 * ```ts
 * const tls = await k8s.getAll('ingress-tls', k8sSecretTypeSpec('kubernetes.io/tls'));
 *
 * tls.plain.get('tls.crt');    // string. A certificate is public.
 * tls.fields.get('tls.key');   // SensitiveString<'credential'>
 * ```
 */
export function k8sSecretTypeSpec(type: K8sSecretType): GetAllOptions {
  const spec = SPECS[type];

  return {
    ...(spec.fields === undefined ? {} : { fields: { ...spec.fields } }),
    ...(spec.rules === undefined ? {} : { rules: [...spec.rules] }),
    fallback: spec.fallback,
  };
}

/** Whether a `type` string from a Secret is one this package has a spec for. */
export function isKnownSecretType(type: string | undefined): type is K8sSecretType {
  return type !== undefined && (K8S_SECRET_TYPES as readonly string[]).includes(type);
}
