/**
 * The base every refusal this library raises extends.
 *
 * A caller wants one of two things from an error: to catch one specific
 * failure, or to catch any refusal from this library without enumerating
 * them. A class per failure serves the first, and this base serves the second.
 * `code` is the flat form of the same information, for a log line or a metric
 * that wants a string rather than a prototype chain.
 *
 * A refused operation is what belongs here: an expired value read, a renewal
 * denied, a payload that cannot cross a thread. A failed assertion from
 * `sensitive-testing` does not, and stays outside the hierarchy on purpose: a
 * handler written to swallow refusals must never swallow a leak assertion.
 */
export abstract class SensitiveStringError extends Error {
  /**
   * Stable, greppable discriminator for this kind of refusal.
   *
   * Safe to log: it names the condition and never carries a value.
   */
  abstract readonly code: string;
}
