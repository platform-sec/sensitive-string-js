/**
 * Name a value's type for an error message without touching the value.
 *
 * Decorator errors are thrown on assignment and on method entry, which are the
 * two places a raw secret is most likely to be the offending value. Formatting
 * it with `String()` or a template would run a caller-supplied `toString()` and
 * put whatever it returns into a message that a logger will happily record, so
 * these messages describe types and never render values.
 */
export function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}
