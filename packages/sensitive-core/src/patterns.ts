/**
 * Anchored, linear-time regular expressions for common sensitive-value formats.
 *
 * These patterns provide structural checks only. They do not prove that a value
 * exists, is deliverable, or is otherwise trustworthy. Each property returns
 * a fresh RegExp so callers cannot mutate shared pattern state.
 */
export const patterns = Object.freeze({
  /** A practical structural email check with exactly one non-empty `@` boundary. */
  get email(): RegExp {
    // `$` also matches before a final line terminator in JavaScript. The
    // negative lookahead makes the end assertion absolute.
    return /^[^@\s]+@[^@\s]+$(?![\s\S])/;
  },
});
