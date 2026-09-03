import type { SensitivityClass, SensitiveString } from '@platform-sec/sensitive-string-core';
import { LEAK_CHECK_CONTEXT, REDACTION_CHECK_CONTEXT, rawValueOf } from './canary.js';
import { collectFragments, findRawValue, findRawValueIn, joinFragments } from './leak-scan.js';

/** How much of a target is quoted when a redaction placeholder is missing. */
const OUTPUT_PREVIEW = 300;

/**
 * Raised when a raw sensitive value was found somewhere it should not be.
 *
 * The message names the value by label and class and says where it was found.
 * It never contains the value itself, so a failing security test does not put
 * the secret it is guarding into a CI log.
 */
export class LeakageDetectedError extends Error {
  constructor(
    readonly label: string | undefined,
    readonly klass: SensitivityClass,
    /** Index in the argument list of the target that leaked. */
    readonly targetIndex: number,
    /** Path within that target, such as `.headers['authorization']`. */
    readonly path: string,
    /** Surrounding text, with the value replaced by `[LEAKED VALUE]`. */
    readonly context: string
  ) {
    super(
      [
        'Sensitive value leaked.',
        `  Label:   ${label ?? '(none)'}`,
        `  Class:   ${klass}`,
        `  Target:  [${targetIndex}]${path}`,
        `  Context: ${context}`,
        '  The value itself is withheld so this message is safe to log.',
      ].join('\n')
    );
    this.name = 'LeakageDetectedError';
  }
}

/**
 * Assert that the raw value of a secret appears in none of the targets.
 *
 * Targets are walked rather than serialized with `JSON.stringify`, because
 * `JSON.stringify` asks each object what it wants to show. An object whose
 * `toJSON` omits the field holding a leaked copy would pass a check built on
 * it, and a `SensitiveString` would always render as its redacted form whether
 * or not a plain copy sat next to it. See `collectFragments` for what the walk
 * reaches and what it cannot.
 *
 * A value that is still wrapped in a `SensitiveString` is not a leak and is not
 * reported as one.
 *
 * @throws LeakageDetectedError if the raw value is found.
 *
 * @example
 * ```ts
 * const apiKey = createTestSecret('credential', 'api_key');
 * const response = await handler(apiKey);
 *
 * expectNotLeaked(apiKey, response, logger.entries, JSON.stringify(response));
 * ```
 */
export function expectNotLeaked(
  secret: SensitiveString<SensitivityClass>,
  ...targets: unknown[]
): void {
  const raw = rawValueOf(secret, LEAK_CHECK_CONTEXT);

  for (let index = 0; index < targets.length; index += 1) {
    const location = findRawValue(targets[index], raw);

    if (location !== undefined) {
      throw new LeakageDetectedError(
        secret.label,
        secret.klass,
        index,
        location.path,
        location.context
      );
    }
  }
}

/**
 * Options for `expectRedacted`.
 */
export interface RedactionOptions {
  /**
   * Pattern the output must match instead of the class policy's redaction.
   *
   * Use it when the output transforms the redacted form, such as a log format
   * that truncates it or a template that wraps it in quotes.
   */
  customPattern?: RegExp;
}

/**
 * Assert that output holds a redacted rendering of a secret and not its value.
 *
 * The rendering that must be present is the one the class policy actually
 * produces, read from the instance rather than assumed to be `[REDACTED:class]`.
 * A custom policy, a per-label redaction, or a future deterministic redaction
 * therefore passes this assertion without the test knowing the format, and a
 * policy change that stops redacting fails it.
 *
 * @throws LeakageDetectedError if the raw value is present.
 * @throws Error if the redacted rendering is absent.
 *
 * @example
 * ```ts
 * const email = createTestSecret('sensitive', 'email');
 * expectRedacted(formatUserLog({ email }), email);
 * ```
 */
export function expectRedacted(
  output: string | object,
  secret: SensitiveString<SensitivityClass>,
  options: RedactionOptions = {}
): void {
  const fragments = collectFragments(output);
  const raw = rawValueOf(secret, REDACTION_CHECK_CONTEXT);
  const location = findRawValueIn(fragments, raw);

  if (location !== undefined) {
    throw new LeakageDetectedError(secret.label, secret.klass, 0, location.path, location.context);
  }

  const text = joinFragments(fragments);
  const expected = options.customPattern ?? redactionOf(secret);

  if (matches(text, expected)) {
    return;
  }

  throw new Error(
    [
      'Expected a redaction placeholder in the output, but found none.',
      `  Label:    ${secret.label ?? '(none)'}`,
      `  Class:    ${secret.klass}`,
      `  Expected: ${typeof expected === 'string' ? JSON.stringify(expected) : String(expected)}`,
      `  Output:   ${preview(text)}`,
    ].join('\n')
  );
}

/**
 * The rendering the class policy produces for this value.
 *
 * `toString()` is the same call every redacting path in core makes, so this
 * stays correct for a policy whose redaction depends on the value or the label.
 */
function redactionOf(secret: SensitiveString<SensitivityClass>): string {
  return secret.toString();
}

function matches(text: string, expected: string | RegExp): boolean {
  return typeof expected === 'string' ? text.includes(expected) : expected.test(text);
}

function preview(text: string): string {
  return text.length > OUTPUT_PREVIEW ? `${text.slice(0, OUTPUT_PREVIEW)}...` : text;
}
