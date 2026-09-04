/**
 * @platform-sec/sensitive-string-infisical
 *
 * Infisical as a `SecretSource`.
 *
 * A folder in an Infisical environment mixes secrets with ordinary
 * configuration, so the shared layer's required `fallback` applies: neither
 * fail-closed nor fail-open is right for a store like this, and only the caller
 * knows which keys are which.
 *
 * The ref is what Infisical scopes a read by. `prod/backend` reads the
 * `/backend` folder of the `prod` environment; with `environment` configured,
 * the ref is the folder alone.
 *
 * @example
 * ```ts
 * import { InfisicalSecretSource } from '@platform-sec/sensitive-string-infisical';
 *
 * const infisical = new InfisicalSecretSource({
 *   token: infisicalToken,
 *   projectId: 'a1b2c3',
 *   environment: 'prod',
 * });
 *
 * const config = await infisical.getAll('/backend', {
 *   rules: [{ pattern: /KEY|TOKEN|SECRET|PASSWORD|DSN/i, klass: 'credential' }],
 *   fallback: 'plain',
 * });
 * ```
 *
 * @packageDocumentation
 */

export { InfisicalSecretSource } from './source.js';
export type { InfisicalSecretSourceOptions } from './source.js';

export { DEFAULT_ENDPOINT, InfisicalRequestError, fetchTransport } from './transport.js';
export type {
  FetchTransportOptions,
  InfisicalRequest,
  InfisicalResponse,
  InfisicalTransport,
} from './transport.js';
