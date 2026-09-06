/**
 * @platform-sec/sensitive-string-http
 *
 * The shared layer under the HTTP client integrations.
 *
 * An HTTP client is the one integration category where this library's default
 * is actively wrong for the caller's intent. Everywhere else redaction fails
 * closed: a log line loses information and nobody is harmed. At the wire the
 * caller's intent is to transmit the value, so `` `Bearer ${token}` `` sends
 * `Bearer [REDACTED:credential]`, the client does not throw, the server answers
 * 401, and the first person to debug it pastes the raw token back in. The
 * library has then made the codebase less safe than it was before anyone
 * adopted it.
 *
 * So the integration has to reveal, and revealing is where the second problem
 * starts. Measured on axios 1.20.0, got 16.0.0 and ky 2.1.0, a revealed value
 * survives the call: on the rejection in `error.config.headers`,
 * `error.options.headers` and `error.request`, in `error.toJSON()` for axios,
 * and on the **resolution** for axios and got, so a successful call leaves the
 * credential printable by the next `console.log(res)`. The error tracking
 * integration that ranks above this row does not catch any of it, because by
 * then the value is a plain `string` and `containsSensitive` returns `false`.
 *
 * This package is the answer to both, once rather than five times: one reveal
 * walker that records where it revealed, one marker guard in three encodings,
 * auth headers as descriptors so the encoding is owned rather than
 * interpolated, one scrub driven by that record on both settlement paths, the
 * redirect and transport checks, and the response decoder that names the
 * request instead of quoting the body.
 *
 * You do not normally install this directly. Install the package for your
 * client, which depends on this one.
 *
 * @example
 * ```ts
 * import axios from 'axios';
 * import { createSensitiveAxios } from '@platform-sec/sensitive-string-axios';
 * import { bearer } from '@platform-sec/sensitive-string-http';
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
 * ```
 *
 * @packageDocumentation
 */

export {
  InsecureTransportError,
  MarkerLeakError,
  RedirectHostNotAllowedError,
  ResponseDecodeError,
  SensitiveHttpError,
  SensitiveScrubError,
  TooManyRedirectsError,
  UnserializableBodyError,
} from './errors.js';
export type { DecodeSite } from './errors.js';

export {
  BASE64_NEEDLES,
  MARKER_PREFIX,
  assertNoMarker,
  containsMarker,
  markerMatchers,
} from './marker.js';
export type { MarkerScanOptions } from './marker.js';

export {
  STRIPPED_HEADERS,
  apiKey,
  basic,
  bearer,
  isAuthHeader,
  isStrippedAcrossOrigins,
  measuredClients,
  renderAuthHeader,
} from './auth.js';
export type { AuthHeader } from './auth.js';

export { isSensitive, revealForm, revealHeaders, revealOutgoing, revealQuery } from './reveal.js';

export {
  EMPTY_PLAN,
  PlanBuilder,
  assertHeadersScrubbed,
  markerFor,
  planIsEmpty,
  readHeader,
  scrubBody,
  scrubHeaderBag,
  scrubMessage,
  scrubQuery,
  scrubUrlString,
  splitPath,
} from './scrub.js';
export type { PlanEntry, PlanRecorder, PlanSection, ScrubPlan } from './scrub.js';

export {
  REDIRECT_STATUSES,
  assertHopAllowed,
  assertTransport,
  headersWithout,
  hostAllowed,
  isCrossOrigin,
  isLoopback,
  isRedirect,
  redirectMethod,
  resolveRedirectPolicy,
} from './redirect.js';
export type { RedirectPolicy, ResolvedRedirectPolicy } from './redirect.js';

export { assertDecoded, decodeJson, safeUrl, wrapResponseFields } from './response.js';

export { buildAttemptContext } from './context.js';

export { prepareRequest, scanPassThrough } from './request.js';
export type { PrepareOptions, PreparedRequest } from './request.js';

export type {
  ContextOption,
  ContextOverrides,
  OutgoingRequest,
  RequestDescriptor,
  SensitiveClientOptions,
  SensitiveHeaderValue,
  SensitiveHeaders,
  SensitiveQuery,
  SensitiveQueryValue,
} from './types.js';
