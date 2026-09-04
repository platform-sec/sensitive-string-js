/**
 * Vault and OpenBao, as one package with a flavor flag.
 *
 * OpenBao is the Linux Foundation fork of Vault, taken from the codebase before
 * the license change. For everything this package does it is the same API: the
 * KV v1 and v2 endpoints, `sys/leases`, dynamic secret backends, and response
 * wrapping all have the same paths and the same response shapes.
 *
 * A separate package would be a re-export under a different name and would
 * double a test matrix that has nothing different to test. The rule about one
 * package per target is about keeping a user's dependency tree free of SDKs
 * they do not use, and there is no second SDK here: the transport is a handful
 * of endpoints over `fetch`.
 */

export type VaultFlavor = 'vault' | 'openbao';

/** One row of the compatibility claim, with the version it was checked against. */
export interface FlavorDivergence {
  readonly area: string;
  readonly vault: string;
  readonly openbao: string;
  readonly handling: string;
  /**
   * What each side was verified against.
   *
   * A row with `undefined` is a row nobody has checked, which is the honest
   * state for everything here until the container matrix runs. A compatibility
   * claim made once is a claim that rots.
   */
  readonly verified: string | undefined;
}

/**
 * The divergences that matter to this package, and what each row was checked
 * against.
 *
 * The namespace row is the one with teeth, and the measurement moved it. On
 * OpenBao 2.6.2 the header is not ignored: a read that answers 200 without it
 * answers 404 with it, so the failure there is a not-found rather than a wrong
 * secret. The silent wrong-secret case turned out to be Vault 1.21.4 Community
 * Edition, which accepts `X-Vault-Namespace`, ignores it, and serves the root
 * namespace with a 200. This package cannot tell Community from Enterprise
 * without letting a server response decide how the client behaves, which is
 * what the flavor flag exists to avoid, so the OpenBao case throws at
 * construction and the Vault Community case is documented.
 *
 * The token header row moved too. `X-Bao-Token` is refused with 403 by OpenBao
 * 2.6.2, so `X-Vault-Token` is the compatible header because it is the only
 * accepted one rather than because it is one of two.
 */
export const FLAVOR_DIVERGENCE: readonly FlavorDivergence[] = [
  {
    area: 'Namespaces',
    vault: 'Enterprise feature, X-Vault-Namespace. Community Edition ignores the header',
    openbao: 'Not present. The header turns a 200 into a 404',
    handling: 'namespace with flavor openbao throws at construction',
    verified: 'Vault 1.21.4 CE, OpenBao 2.6.2',
  },
  {
    area: 'Token header',
    vault: 'X-Vault-Token',
    openbao: 'X-Vault-Token. X-Bao-Token is refused with 403',
    handling: 'X-Vault-Token is sent for both, because it is the only header either accepts',
    verified: 'Vault 1.21.4 CE, OpenBao 2.6.2',
  },
  {
    area: 'KV v2 read shape',
    vault: 'data.data with data.metadata.version',
    openbao: 'Identical',
    handling: 'one parser for both',
    verified: 'Vault 1.21.4 CE, OpenBao 2.6.2',
  },
  {
    area: 'Response wrapping',
    vault: 'X-Vault-Wrap-TTL, wrap_info.token, sys/wrapping/unwrap',
    openbao: 'Identical',
    handling: 'one code path for both',
    verified: 'Vault 1.21.4 CE, OpenBao 2.6.2',
  },
  {
    area: 'Version reporting',
    vault: 'sys/health version string, 1.x series',
    openbao: 'sys/health version string, 2.x series',
    handling: 'recorded on metadata for the audit trail, never used to switch behaviour',
    verified: 'Vault 1.21.4 CE, OpenBao 2.6.2',
  },
  {
    area: 'Enterprise-only backends',
    vault: 'Some',
    openbao: 'None',
    handling: 'out of scope for this package either way',
    verified: undefined,
  },
];

/**
 * The authentication header name for a flavor.
 *
 * Both accept `X-Vault-Token` today, so one name covers both. It is a function
 * rather than a constant so the OpenBao row of the table has somewhere to
 * change if the container matrix says otherwise.
 */
export function tokenHeader(_flavor: VaultFlavor): string {
  return 'X-Vault-Token';
}

export class VaultFlavorError extends Error {
  override readonly name = 'VaultFlavorError';
}

/**
 * Reject a configuration a flavor cannot honour.
 *
 * `flavor` is required rather than detected. Detection would mean a response
 * from the server decides how the client behaves, and what is being decided
 * here is which compatibility assumptions hold.
 */
export function checkFlavor(flavor: VaultFlavor, namespace: string | undefined): void {
  if (flavor === 'openbao' && namespace !== undefined) {
    throw new VaultFlavorError(
      'OpenBao has no namespaces, so `namespace` cannot be honoured. Sending the header ' +
        'anyway would resolve every read against the root namespace and return the wrong ' +
        'secret or a not-found, silently. Remove `namespace`, or use `flavor: "vault"`.'
    );
  }
}
