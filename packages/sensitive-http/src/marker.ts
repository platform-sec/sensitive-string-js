import { MARKER_PREFIX, redactionMatchers } from '@platform-sec/sensitive-string-core';

import { MarkerLeakError } from './errors.js';

/**
 * The guard: refuse to send bytes that still carry a redaction marker.
 *
 * It is the one invariant that does not vary by environment, and it is
 * `undici`'s behaviour generalized. undici's dispatcher is the only client in
 * the measured set that rejects a `SensitiveString` rather than stringifying
 * it, which means an application on it finds the problem at the first request
 * in development instead of at the first 401 in production. The other four
 * stringify, so the marker in the outgoing bytes is the only evidence left, and
 * this module is what reads it.
 *
 * What a marker looks like is core's question and is answered by
 * `redactionMatchers()`, which derives it from the policy registry. What is
 * this package's own is the encodings a request applies on the way out, which
 * is the rest of this file.
 */

export { MARKER_PREFIX };

/**
 * Every needle the guard should look for.
 *
 * Core's, unchanged. It was derived here first and moved down once a second and
 * third row needed the same answer; the two written for a database missed
 * `markerPattern`, which is the field core added for this guard.
 */
export const markerMatchers = redactionMatchers;

/**
 * Base64 needles for `MARKER_PREFIX`, one per byte alignment.
 *
 * Base64 encodes three bytes at a time, so where the prefix starts inside the
 * encoded payload decides which of its characters land in fully determined
 * groups. These are the fully determined groups for each of the three
 * alignments, and they hold for `base64url` as well because none of them
 * contains `+` or `/`.
 *
 * | Alignment of the prefix | Determined bytes | Needle |
 * |---|---|---|
 * | 0 mod 3 | `[REDACTED` | `W1JFREFDVEVE` |
 * | 1 mod 3 | `EDACTE` | `RURBQ1RF` |
 * | 2 mod 3 | `REDACTED:` | `UkVEQUNURUQ6` |
 */
export const BASE64_NEEDLES: readonly string[] = ['W1JFREFDVEVE', 'RURBQ1RF', 'UkVEQUNURUQ6'];

export interface MarkerScanOptions {
  /**
   * Also scan the percent-decoded form. Default true.
   *
   * A query string and an `application/x-www-form-urlencoded` body carry
   * `%5BREDACTED%3Acredential%5D`, and axios's `params` serializer produces the
   * partly encoded `%5BREDACTED:credential%5D`, which contains neither the
   * literal marker nor the fully encoded one. Decoding once covers all three.
   */
  readonly decodeForms?: boolean;
  /**
   * Also scan for the base64 encoding of the marker prefix. Default false.
   *
   * Off by default because it is a heuristic layered on a heuristic. The eight
   * characters of the shortest needle are 48 bits of specific content, so a
   * false positive is vanishingly unlikely, but it would block a legitimate
   * request, and a caller doing their own base64 has already left the path
   * where this package can help. The real answer for `Basic` auth is that the
   * auth helpers own the encoding and check the components as plain text.
   */
  readonly base64?: boolean;
}

function findLiteral(wire: string, matchers: readonly (string | RegExp)[]): boolean {
  for (const matcher of matchers) {
    // `search` rather than `test`: a caller-supplied pattern may carry the `g`
    // flag, and `test` on a global regex advances `lastIndex`, so the second
    // call against the same matcher would start mid-string and miss.
    if (typeof matcher === 'string' ? wire.includes(matcher) : wire.search(matcher) !== -1) {
      return true;
    }
  }

  return false;
}

/**
 * Percent-decode for scanning, treating an undecodable input as itself.
 *
 * A body that is not valid percent-encoding throws `URIError` from
 * `decodeURIComponent`, and a guard that throws on a legitimate binary body
 * would be worse than the leak it prevents. `+` is mapped to a space first, so
 * a form body encoded the `application/x-www-form-urlencoded` way decodes the
 * way a server would read it.
 */
function percentDecoded(wire: string): string {
  try {
    return decodeURIComponent(wire.replace(/\+/g, ' '));
  } catch {
    return wire;
  }
}

/**
 * Throw if `wire` carries a redaction marker in any scanned encoding.
 *
 * @param wire - The outgoing representation, as this package produced it.
 * @param where - Human-readable position, used in the error and never a value.
 *
 * @throws MarkerLeakError before the request is sent.
 *
 * @remarks
 * What this cannot see, stated here because each README repeats it: any
 * encoding applied after the bytes leave this package. gzip and other content
 * encodings, a protobuf or MessagePack body, a stream body that is not
 * buffered, an encrypted payload. For those the package checks the inputs
 * before encoding and says so, rather than claiming the outgoing bytes were
 * checked.
 */
export function assertNoMarker(wire: string, where: string, options?: MarkerScanOptions): void {
  if (wire === '') {
    return;
  }

  const matchers = markerMatchers();

  if (findLiteral(wire, matchers)) {
    throw new MarkerLeakError(where, 'literal');
  }

  if (options?.decodeForms !== false) {
    const decoded = percentDecoded(wire);

    if (decoded !== wire && findLiteral(decoded, matchers)) {
      throw new MarkerLeakError(where, 'percent');
    }
  }

  if (options?.base64 === true) {
    for (const needle of BASE64_NEEDLES) {
      if (wire.includes(needle)) {
        throw new MarkerLeakError(where, 'base64');
      }
    }
  }
}

/**
 * Report whether `wire` carries a marker, without throwing.
 *
 * For the undici dispatcher interceptor, which has to decide per header value
 * and wants to name the header in its own refusal.
 */
export function containsMarker(wire: string, options?: MarkerScanOptions): boolean {
  try {
    assertNoMarker(wire, 'value', options);

    return false;
  } catch {
    return true;
  }
}
