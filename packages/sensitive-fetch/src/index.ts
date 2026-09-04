/**
 * @platform-sec/sensitive-string-fetch
 *
 * `fetch` integration for `SensitiveString`, covering Node 22's global `fetch`
 * and `undici.fetch`.
 *
 * ```ts
 * import { bearer, sensitiveFetch } from '@platform-sec/sensitive-string-fetch';
 *
 * const body = await sensitiveFetch('https://api.example.com/charges', {
 *   method: 'POST',
 *   headers: { authorization: bearer(token) },
 *   sensitiveJson: { amount, card: { number: cardNumber } },
 *   allowedHosts: ['api.example.com'],
 * }).json<{ id: string }>();
 * ```
 *
 * `sensitiveJson` rather than `body` is deliberate. A `RequestInit`'s `body` is
 * already serialized by the time `fetch` receives it, and accepting a
 * structured value there would mean silently ignoring a `Content-Type` the
 * caller set. `body` still means what it means everywhere else, and is scanned
 * for markers rather than rebuilt.
 *
 * `fetch` has no hooks at all, which makes it the clearest case for the shape
 * every package in this row takes: the wrapper owns the call because there is
 * nowhere else to stand.
 *
 * @packageDocumentation
 */

export { sensitiveFetch, sensitiveHeaders } from './client.js';
export type { SensitiveFetchInit, SensitiveFetchOptions, SensitiveFetchResult } from './client.js';

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
