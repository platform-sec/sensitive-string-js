/**
 * @platform-sec/sensitive-string-ky
 *
 * ky integration for `SensitiveString`.
 *
 * ```ts
 * import ky from 'ky';
 * import { bearer, createSensitiveKy } from '@platform-sec/sensitive-string-ky';
 *
 * const api = createSensitiveKy(ky, {
 *   prefixUrl: 'https://api.example.com',
 *   allowedHosts: ['api.example.com'],
 *   responseFields: { 'customer.email': 'sensitive' },
 * });
 *
 * const body = await api.post('/charges', { amount, card: { number: cardNumber } }, {
 *   headers: { authorization: bearer(token) },
 * }).json<{ customer: { email: unknown } }>();
 * ```
 *
 * ky is the client where the error scrub is on a common path rather than an
 * exceptional one: it throws on every non-2xx by default, and its `HTTPError`
 * carries the `Request`, whose headers hold the revealed credential and which
 * `util.inspect` prints. Its success path needs nothing, because a `Response`
 * carries no request headers; measured, not assumed.
 *
 * Peer range `^2.0.0`. ky 1.x is excluded because `beforeRequest` changed from
 * `(request, options)` to a single state object, and nothing else in this
 * design needs a ky 2 feature.
 *
 * @packageDocumentation
 */

export { createSensitiveKy } from './client.js';
export type {
  SensitiveKy,
  SensitiveKyOptions,
  SensitiveKyRequestConfig,
  SensitiveResponsePromise,
} from './client.js';

export { scrubError, scrubResponse } from './scrub.js';

export {
  InsecureTransportError,
  MarkerLeakError,
  RedirectHostNotAllowedError,
  ResponseDecodeError,
  SensitiveHttpError,
  SensitiveScrubError,
  TooManyRedirectsError,
  UnserializableBodyError,
  apiKey,
  basic,
  bearer,
} from '@platform-sec/sensitive-string-http';
export type { AuthHeader, ScrubPlan } from '@platform-sec/sensitive-string-http';
