import { getPolicy, hasPolicy } from './policy.js';
import { probeProperty } from './probe.js';
import { notifyRedaction, redactionObservers } from './redaction-observer.js';
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
 *
 * The read goes through `probeProperty` because it runs against every object a
 * walk reaches, and an object that refuses the question is not a `serialize()`
 * result: that shape is a plain object this library built.
 */
export function carriesSerializedMarker(value: object): boolean {
  return probeProperty(value, '__sensitive') === true;
}

/**
 * The registered sensitivity class a serialized value names, or `undefined`
 * when it names none or one that is not registered.
 */
export function serializedClass(value: object): SensitivityClass | undefined {
  const klass = probeProperty(value, 'klass');

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

  const raw = probeProperty(value, 'value');
  const rendering = getPolicy(klass).redact(typeof raw === 'string' ? raw : '');

  // Only the walkers call this, so the surface is always 'structure'. The
  // class is the registered one the shape named, which the early return above
  // already refused to echo when it was not. The label is not passed: in a
  // wire shape it is data, and an event carrying it would let whoever built
  // the payload choose a metric dimension. A shape naming no registered class
  // rendered the generic marker above and is not an event, since there is no
  // class to report it under.
  if (redactionObservers.observers.length !== 0) {
    notifyRedaction(klass, undefined, 'structure');
  }

  return rendering;
}
