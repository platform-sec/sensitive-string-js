/**
 * @platform-sec/sensitive-string-got
 *
 * got integration for `SensitiveString`.
 *
 * ```ts
 * import got from 'got';
 * import { bearer, createSensitiveGot } from '@platform-sec/sensitive-string-got';
 *
 * const api = createSensitiveGot(got.extend({ prefixUrl: 'https://api.example.com' }), {
 *   reason: 'billing sync',
 *   allowedHosts: ['api.example.com'],
 *   responseFields: { 'customer.email': 'sensitive' },
 * });
 *
 * const res = await api.post('/charges', { amount, card: { number: cardNumber } }, {
 *   headers: { authorization: bearer(token) },
 * });
 * ```
 *
 * got is the client that most needs the response half of this package. Its
 * `ParseError` propagates `JSON.parse`'s message, which quotes the first
 * characters of the body, and appends the full request URL to it, so a short
 * API key echoed back by a misconfigured endpoint lands whole in an error
 * string next to the endpoint that produced it. The wrapper installs
 * `parseJson` and rewrites that into a `ResponseDecodeError` naming the request
 * and carrying none of the body, with no `cause` chain for a reporter to walk.
 *
 * Three got options the wrapper owns, each named in the README:
 * `retry.limit` (driven here, one audit per attempt), `hooks.beforeRedirect`
 * (the host check) and `parseJson` (the decoder rewrite and response wrapping).
 *
 * @packageDocumentation
 */

export { createSensitiveGot } from './client.js';
export type {
  SensitiveGot,
  SensitiveGotOptions,
  SensitiveGotRequestConfig,
  SensitiveGotResponse,
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
