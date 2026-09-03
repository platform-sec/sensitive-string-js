import { getPolicy, hasPolicy } from './policy.js';
import type { SensitivityClass } from './types.js';

/**
 * Recognition and redaction of a `serialize()` result, shared by every walk
 * that must not emit one.
 *
 * `serialize()` produces `{ __sensitive: true, klass, value }` with the raw
 * value, for service-to-service transport. Placed in a log line or a response
 * body it is the one shape `toJSON()` cannot catch, because it is a plain
 * object and `JSON.stringify` emits it faithfully.
 */

/**
 * Whether an object is a serialized sensitive value, judged by its marker
 * alone so that a malformed or truncated copy of one is still replaced rather
 * than emitted.
 */
export function carriesSerializedMarker(value: object): boolean {
  return (value as { __sensitive?: unknown }).__sensitive === true;
}

/**
 * The registered sensitivity class a serialized value names, or `undefined`
 * when it names none or one that is not registered.
 */
export function serializedClass(value: object): SensitivityClass | undefined {
  const { klass } = value as { klass?: unknown };

  return typeof klass === 'string' && hasPolicy(klass as SensitivityClass)
    ? (klass as SensitivityClass)
    : undefined;
}

/**
 * The redaction the named class would produce for the raw value, so a custom
 * policy's marker is honoured here as it is by `toString()`. A class that is
 * not registered gets a generic marker: echoing the unknown name would put
 * input the library did not produce into the output.
 */
export function redactSerialized(value: object): string {
  const klass = serializedClass(value);

  if (klass === undefined) {
    return '[REDACTED]';
  }

  const { value: raw } = value as { value?: unknown };

  return getPolicy(klass).redact(typeof raw === 'string' ? raw : '');
}
