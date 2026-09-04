import { wrapSensitiveByPath } from '@platform-sec/sensitive-string-core';
import type { SensitiveFieldConfig } from '@platform-sec/sensitive-string-core';

import { ResponseDecodeError } from './errors.js';
import type { DecodeSite } from './errors.js';

/**
 * The way back in.
 *
 * Two problems, measured. A response body that is not the JSON the caller
 * expected is often the credential they sent, echoed back, and `JSON.parse`
 * quotes the first characters of it into its message: a 14-character API key is
 * disclosed whole. got propagates that message and appends the full request
 * URL, so the endpoint ends up next to the value in one string. axios is not
 * better, only differently wrong: it swallows the parse failure and hands the
 * caller the raw body as `response.data`, so a raw secret becomes an ordinary
 * string in application code with no class, no label and no audit trail.
 *
 * And a response field the caller knows is sensitive exists as a loose `string`
 * in their frame unless something wraps it before the `await` resolves.
 */

/**
 * Parse a response body, or throw an error that names the request and not the body.
 *
 * @throws ResponseDecodeError. The original `SyntaxError` is deliberately not
 *   chained through `cause`: every reporter that walks a cause chain would put
 *   the quoted body back into the report.
 */
export function decodeJson(text: string, site: Omit<DecodeSite, 'byteLength'>): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ResponseDecodeError({ ...site, byteLength: Buffer.byteLength(text, 'utf8') });
  }
}

/**
 * Wrap the configured response paths, before the caller's `await` resolves.
 *
 * `wrapSensitiveByPath` is core's, so the path syntax, the `{ klass, label }`
 * value form and the `__proto__` guards are core's and are not reimplemented
 * here. It walks the configured paths rather than the response tree, so the
 * cost is the number of paths and not the size of the body.
 */
export function wrapResponseFields<T>(body: T, fields: SensitiveFieldConfig | undefined): T {
  if (fields === undefined || body === null || typeof body !== 'object') {
    return body;
  }

  return wrapSensitiveByPath(body as unknown as object, fields) as unknown as T;
}

/**
 * axios's silent non-JSON fallback, rewritten.
 *
 * axios does not throw on a body that is not JSON; it hands back the raw string
 * as `response.data`. When the caller declared response fields, they told us
 * the body is an object, so a string is a decode failure that axios chose not
 * to report.
 *
 * @throws ResponseDecodeError
 */
export function assertDecoded(
  body: unknown,
  fields: SensitiveFieldConfig | undefined,
  site: Omit<DecodeSite, 'byteLength'>
): void {
  if (fields === undefined || typeof body !== 'string') {
    return;
  }

  throw new ResponseDecodeError({ ...site, byteLength: Buffer.byteLength(body, 'utf8') });
}

/** The request URL with its query string and fragment removed, for an error message. */
export function safeUrl(url: string): string {
  try {
    const parsed = new URL(url);

    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return url.split('?')[0] ?? url;
  }
}
