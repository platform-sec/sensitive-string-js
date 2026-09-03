import type { SensitivityClass, SensitiveString } from '@platform-sec/sensitive-string-core';

/**
 * Canary values, keyed by the instance created from them.
 *
 * A leak check needs the raw value to search for. Reading it back through
 * `reveal()` works, but it runs the class policy's authorization hook, fires
 * the active audit context, and throws once the value has expired, so an
 * assertion about output would fail for reasons that have nothing to do with
 * the output. Because this package generated these values in the first place,
 * it can simply remember them.
 *
 * The map holds values this package created, not values an application loaded.
 * It is module private and keyed by object identity, so nothing outside these
 * functions can enumerate it, and an entry becomes unreachable with the
 * instance it belongs to. A value passed to `createTestSecret` through the
 * `value` option is remembered the same way, which is a reason to keep real
 * secrets out of that option.
 */
const canaries = new WeakMap<SensitiveString<SensitivityClass>, string>();

/** Record the raw value this package generated for an instance. */
export function rememberCanary(secret: SensitiveString<SensitivityClass>, raw: string): void {
  canaries.set(secret, raw);
}

/** The remembered raw value, or undefined for an instance from anywhere else. */
export function recallCanary(secret: SensitiveString<SensitivityClass>): string | undefined {
  return canaries.get(secret);
}

/**
 * The raw value of a secret, for a check that has to search for it.
 *
 * A value this package created is read from the canary registry. Anything else
 * is revealed under an explicit, named context, so the reveal is attributable
 * and does not silently inherit an ambient context the test set up for its own
 * assertions.
 *
 * A class policy whose `checkRevealAllowed` rejects unknown contexts will
 * refuse these reveals. Such a policy should allow the names exported as
 * `TESTING_CONTEXT_NAMES`, or the test should build its secrets with
 * `createTestSecret`, which needs no reveal at all.
 */
export function rawValueOf(secret: SensitiveString<SensitivityClass>, contextName: string): string {
  const remembered = recallCanary(secret);
  if (remembered !== undefined) {
    return remembered;
  }

  try {
    return secret.reveal({ name: contextName });
  } catch (cause) {
    // Without this the caller sees an ExpiredSensitiveValueError, or whatever
    // the policy threw, reported from inside an assertion about output. That
    // reads as an unrelated failure, and the dangerous reading of it is that
    // the check ran and found nothing. It did not run at all.
    throw new UnreadableSecretError(secret.klass, secret.label, contextName, cause);
  }
}

/**
 * Raised when a check could not read the value it was asked to look for.
 *
 * This is not a leak report and not a clean result. It means the assertion did
 * not run, which matters because the alternative reading of a silent pass is
 * that nothing leaked.
 */
export class UnreadableSecretError extends Error {
  constructor(
    readonly klass: SensitivityClass,
    readonly label: string | undefined,
    /** The context the reveal was attempted under. */
    readonly contextName: string,
    cause: unknown
  ) {
    super(
      [
        'Cannot check this value: reading it for the check was refused.',
        `  Label:   ${label ?? '(none)'}`,
        `  Class:   ${klass}`,
        `  Context: ${contextName}`,
        `  Cause:   ${describeCause(cause)}`,
        '  A value from createTestSecret is remembered when it is created and needs',
        '  no reveal, so this check would have run on one. This value came from',
        '  elsewhere, so the check had to reveal it, and its deadline or its class',
        '  policy refused. Build the value with createTestSecret, or allow the',
        '  context names in TESTING_CONTEXT_NAMES.',
      ].join('\n'),
      { cause }
    );
    this.name = 'UnreadableSecretError';
  }
}

function describeCause(cause: unknown): string {
  return cause instanceof Error ? `${cause.name}: ${cause.message}` : String(cause);
}

/** Context name used when a leak assertion has to reveal a foreign value. */
export const LEAK_CHECK_CONTEXT = '__test-leak-check__';

/** Context name used when a redaction assertion has to reveal a foreign value. */
export const REDACTION_CHECK_CONTEXT = '__test-redaction-check__';

/** Context name used when a matcher has to reveal a foreign value. */
export const MATCHER_CONTEXT = '__test-matcher__';

/** Context name used when `toContainSensitive` has to reveal a foreign value. */
export const CONTAINS_CHECK_CONTEXT = '__test-contains-check__';

/**
 * Every context name this package reveals under, so a strict policy can
 * allowlist them in one place.
 */
export const TESTING_CONTEXT_NAMES: readonly string[] = [
  LEAK_CHECK_CONTEXT,
  REDACTION_CHECK_CONTEXT,
  MATCHER_CONTEXT,
  CONTAINS_CHECK_CONTEXT,
];
