import { SecretPayloadError } from './errors.js';
import type { ResolvedSecretRef } from './types.js';

/**
 * Parse a JSON payload without putting it into an error.
 *
 * `JSON.parse` puts its input into the `SyntaxError` message. Measured on Node
 * 22.15.0:
 *
 * | Input | Message |
 * |---|---|
 * | 20 characters or fewer, not JSON | `Unexpected token 'S', "SSSSSSSSSSSSSSSSSSSS" is not valid JSON` |
 * | More than 20 characters, not JSON | `Unexpected token 'S', "SSSSSSSSSS"... is not valid JSON` |
 * | Well-formed prefix, truncated | `Expected ',' or '}' after property value in JSON at position 56` |
 *
 * An input of 20 characters or fewer is echoed whole. The truncated-JSON case
 * reports only a position and is safe, which is what makes this easy to miss in
 * review: the failure mode that leaks is the one where the secret is not JSON
 * at all, and that is exactly what happens when somebody calls a JSON read on a
 * secret holding a bare API key. A 20-character key is a common length, and it
 * is disclosed in full into a `SyntaxError` that goes straight to the error
 * tracker.
 */
export function parsePayload(raw: string, ref: ResolvedSecretRef): Record<string, unknown> {
  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  } catch {
    // The original SyntaxError carries up to 20 characters of `raw`. It is
    // discarded here and never chained through `cause`, which would put it back
    // into the report. This looks like an oversight and is not one.
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}' is not valid JSON. ` +
        `Use get() if this secret holds a bare string.`,
      ref.path,
      ref.version
    );
  }

  return asObject(parsed, ref);
}

/**
 * Require a decoded payload to be a JSON object.
 *
 * A payload that decodes to an array, a number, or null is a spec-and-payload
 * disagreement rather than a value to coerce, and coercing it would produce
 * field names like `0` and `1`.
 */
export function asObject(parsed: unknown, ref: ResolvedSecretRef): Record<string, unknown> {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}' is not a JSON object.`,
      ref.path,
      ref.version
    );
  }

  return parsed as Record<string, unknown>;
}

/**
 * The standard base64 alphabet, padded or not, and nothing else.
 *
 * Padding is optional because encoders disagree about it and both forms decode
 * to the same bytes. A tail of one character is rejected here rather than by
 * the round trip, since no group of six-bit units can produce it.
 */
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}(?:==)?|[A-Za-z0-9+/]{3}=?)?$/;

/**
 * Decode base64, validating first.
 *
 * `Buffer.from(x, 'base64')` is lenient: it skips characters outside the
 * alphabet rather than failing, so a value that was never base64 decodes to
 * garbage and travels downstream as a secret nobody can use. Validating the
 * alphabet and then checking the round trip catches both the wrong-encoding
 * case and the truncated case, and the failure names the field rather than its
 * content.
 */
export function decodeBase64(raw: string, ref: ResolvedSecretRef, field?: string): string {
  const where = field === undefined ? '' : ` field '${field}'`;

  if (!BASE64.test(raw)) {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}'${where} is not valid base64.`,
      ref.path,
      ref.version
    );
  }

  const buffer = Buffer.from(raw, 'base64');

  if (buffer.toString('base64').replace(/=+$/, '') !== raw.replace(/=+$/, '')) {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}'${where} did not survive a base64 round trip.`,
      ref.path,
      ref.version
    );
  }

  return buffer.toString('utf8');
}

/**
 * Decode a map whose values are base64, as a Kubernetes Secret's `data` is.
 *
 * Every failure routes through `SecretPayloadError` with the path, the version,
 * and the field name, so no decoder in this layer reports content.
 */
export function decodeBase64Map(
  data: Readonly<Record<string, unknown>>,
  ref: ResolvedSecretRef
): Record<string, string> {
  const decoded: Record<string, string> = {};

  for (const [field, value] of Object.entries(data)) {
    if (typeof value !== 'string') {
      throw new SecretPayloadError(
        `Secret '${ref.path}' version '${ref.version}' field '${field}' is not a string.`,
        ref.path,
        ref.version
      );
    }

    decoded[field] = decodeBase64(value, ref, field);
  }

  return decoded;
}

/**
 * Run a third-party decoder without letting its error escape.
 *
 * The rule generalizes past `JSON.parse`: a YAML parser reports the offending
 * line, and any decoder that fails on content puts content in its error. A
 * provider package that reaches for a parser routes it through here so its
 * failure carries the path and the version and nothing else.
 */
export function guardDecode<T>(decode: () => T, ref: ResolvedSecretRef, what: string): T {
  try {
    return decode();
  } catch {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${ref.version}' could not be decoded as ${what}.`,
      ref.path,
      ref.version
    );
  }
}
