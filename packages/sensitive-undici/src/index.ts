/**
 * @platform-sec/sensitive-string-undici
 *
 * undici dispatcher integration for `SensitiveString`. Covers
 * `undici.request`, `Client`, `Pool` and `Agent`.
 *
 * ```ts
 * import { bearer, sensitiveRequest } from '@platform-sec/sensitive-string-undici';
 *
 * const res = await sensitiveRequest('https://api.example.com/charges', {
 *   method: 'POST',
 *   headers: { authorization: bearer(token) },
 *   json: { amount, card: { number: cardNumber } },
 *   allowedHosts: ['api.example.com'],
 * });
 *
 * const charge = await res.json<{ id: string }>();
 * ```
 *
 * This is the smallest package in the row, because undici is the only client
 * that already fails closed: it rejects a `SensitiveString` with
 * `InvalidArgumentError` rather than stringifying it, for headers and for
 * bodies. That behaviour is the rule the other four packages had to be built to
 * reproduce, and it is why an application on the dispatcher API finds the
 * problem in development rather than in production.
 *
 * `markerGuard()` is a dispatcher interceptor for callers who use the
 * dispatcher directly. It cannot reveal, because by then the caller has already
 * produced strings, but it refuses to send a marker.
 *
 * @packageDocumentation
 */

export { sensitiveRequest } from './client.js';
export type {
  SensitiveUndiciOptions,
  SensitiveUndiciRequestOptions,
  SensitiveUndiciResponse,
} from './client.js';

export { markerGuard } from './interceptor.js';
export { scrubError } from './scrub.js';

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
