/**
 * @platform-sec/sensitive-string-doppler
 *
 * Doppler as a `SecretSource`.
 *
 * A Doppler config is a flat map that mixes secrets with ordinary
 * configuration, so it is the store the shared layer's required `fallback` was
 * argued about: fail-closed wraps `LOG_LEVEL` and breaks the application in a
 * way that looks like a configuration bug, and fail-open leaves the API keys
 * beside it unwrapped. Only the caller knows which keys are which.
 *
 * @example
 * ```ts
 * import { DopplerSecretSource } from '@platform-sec/sensitive-string-doppler';
 *
 * const doppler = new DopplerSecretSource({ token: dopplerToken, project: 'payments' });
 *
 * const config = await doppler.getAll('prod', {
 *   fields: { LOG_LEVEL: 'plain', PORT: 'plain' },
 *   rules: [{ pattern: /KEY|TOKEN|SECRET|PASSWORD|DSN/i, klass: 'credential' }],
 *   fallback: 'plain',
 * });
 * ```
 *
 * @packageDocumentation
 */

export { DopplerSecretSource, DOPPLER_RESERVED_KEYS } from './source.js';
export type { DopplerSecretSourceOptions } from './source.js';

export { DEFAULT_ENDPOINT, DopplerRequestError, fetchTransport } from './transport.js';
export type {
  DopplerRequest,
  DopplerResponse,
  DopplerTransport,
  FetchTransportOptions,
} from './transport.js';
