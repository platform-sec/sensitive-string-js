/**
 * @platform-sec/sensitive-string-axios
 *
 * axios integration for `SensitiveString`.
 *
 * ```ts
 * import axios from 'axios';
 * import { bearer, createSensitiveAxios } from '@platform-sec/sensitive-string-axios';
 *
 * const api = createSensitiveAxios(axios.create({ baseURL: 'https://api.example.com' }), {
 *   reason: 'charge authorization',
 *   allowedHosts: ['api.example.com'],
 *   responseFields: { 'customer.email': 'sensitive' },
 * });
 *
 * const res = await api.post('/charges', { amount, card: { number: cardNumber } }, {
 *   headers: { Authorization: bearer(token) },
 * });
 *
 * res.data.customer.email; // SensitiveString<'sensitive'>
 * ```
 *
 * Three things this package does that a bare axios does not, each of them a
 * measured leak rather than a hypothetical one:
 *
 * 1. It reveals before `client.request()` is called, so `AxiosHeaders` never
 *    sees an instance and `[REDACTED:credential]` never reaches a socket.
 * 2. It scrubs `config` on **both** settlement paths, which fixes
 *    `error.toJSON()` for free because that is what `toJSON()` reads, and which
 *    is the only thing that keeps `console.log(res)` after a *successful* call
 *    from printing the credential.
 * 3. It turns axios's silent non-JSON fallback into a `ResponseDecodeError`
 *    that names the URL and the content type and carries none of the body.
 *
 * Two behaviour changes to know about, both conditional on the request actually
 * carrying a sensitive value:
 *
 * - `response.request` is `undefined` and `error.request` is deleted. A Node
 *   `ClientRequest` keeps its own copy of the header block in internal state
 *   that no supported API rewrites, so it cannot be handed back.
 * - A response body that is not JSON is an error when `responseFields` is
 *   configured, where axios would have handed back the raw string.
 *
 * @packageDocumentation
 */

export { createSensitiveAxios } from './client.js';
export type {
  SensitiveAxios,
  SensitiveAxiosOptions,
  SensitiveAxiosRequestConfig,
  SensitiveAxiosResponse,
} from './client.js';

export { scrubError, scrubResponse } from './scrub.js';

// Re-exported so a caller installs and imports one package for one client.
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
