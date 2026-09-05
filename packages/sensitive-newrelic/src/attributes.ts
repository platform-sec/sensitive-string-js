import {
  resolveScrubPolicy,
  scrubPayload,
  type ResolvedScrubPolicy,
  type ScrubPolicy,
} from '@platform-sec/sensitive-string-scrub';

/**
 * The papercut fix, and the only place this package walks anything.
 *
 * Measured on `newrelic` 14.3.10: `VALID_ATTR_TYPES` is `string`, `number`,
 * `boolean`, and an attribute of any other type hits
 * `logger.debug('Not adding attribute %s with %s value type...')` and is gone.
 * Through `addCustomAttribute`, `addCustomAttributes` and the second argument
 * of `noticeError`:
 *
 * | Attribute value | Reached the payload |
 * |---|---|
 * | Raw string | Yes, verbatim |
 * | Number | Yes |
 * | `SensitiveString` | No. Silently dropped |
 * | `serialize()` result | No. Silently dropped |
 * | `{ token: secret, rawToken: canary }` | No. Silently dropped, raw member included |
 *
 * That is safe, and it is also a papercut. An application that adds a wrapped
 * value expecting `[REDACTED:credential]` gets an attribute that does not
 * exist, finds out in production, and the obvious fix a hurried engineer
 * reaches for is `reveal()`. So this exists to make the informative answer the
 * easy one.
 *
 * It is opt-in, and an application that never calls it is exactly as safe.
 */

/** What the agent will accept as an attribute value. */
export type NewRelicAttributeValue = string | number | boolean;

/**
 * Compiled policies, held per policy object.
 *
 * Resolution folds in the defaults and builds three Sets, and this runs
 * wherever an application records attributes, which for a busy service is per
 * request. The entry lives only as long as the caller's policy object does, so
 * a policy built per call is collected with it and a hoisted one is resolved
 * once. Reuse goes by object identity: two equal policy objects resolve
 * separately.
 */
const resolved = new WeakMap<ScrubPolicy, ResolvedScrubPolicy>();

/** The policy used when a caller passes none, resolved once. */
let defaultPolicy: ResolvedScrubPolicy | undefined;

function policyFor(policy: ScrubPolicy | undefined): ResolvedScrubPolicy {
  if (policy === undefined) {
    defaultPolicy ??= resolveScrubPolicy();

    return defaultPolicy;
  }

  const cached = resolved.get(policy);

  if (cached !== undefined) {
    return cached;
  }

  const compiled = resolveScrubPolicy(policy);

  resolved.set(policy, compiled);

  return compiled;
}

/**
 * Scrub an attribute bag and coerce it to what the agent accepts.
 *
 * Stage 1 replaces every `SensitiveString` and every `serialize()` result with
 * its marker, then the denylist replaces the values whose key names say they
 * are credentials, and what is left is coerced to the agent's three types. A
 * wrapped value therefore arrives as `[REDACTED:credential]` rather than as
 * nothing.
 *
 * It never reveals. Nothing on any path here reads a `SensitiveString`'s
 * value, and the marker is what the class's own redaction produces.
 *
 * A value that is still not a scalar after scrubbing is JSON-encoded rather
 * than dropped, because dropping is the behaviour this function exists to
 * replace, and by that point the structure has been through both stages so
 * there is nothing left in it to leak. Two shapes cannot be encoded and are
 * omitted with their key: a cycle, and a value whose own `toJSON` throws. The
 * agent's `attributes.value_size_limit` truncates at 256 characters by
 * default, which is data loss and not a redaction, so a large object arrives
 * shortened.
 *
 * `undefined` and `null` are omitted rather than encoded. The agent drops both
 * already, `null` because `typeof null` is `'object'`, and turning them into
 * the strings `"null"` and `"undefined"` would invent a value the application
 * never recorded.
 *
 * @param attributes - The bag the application meant to record
 * @param policy - What to deny, over the shared denylist. Hoist it, or pass
 *                 the same object each time: the compiled form is held against
 *                 that object's identity.
 * @returns A new object. The input is not modified.
 *
 * @example
 * ```ts
 * newrelic.addCustomAttributes(sensitiveAttributes({
 *   tenant: tenantId,
 *   token: apiToken,        // a SensitiveString
 *   session: serializedTok, // a serialize() result
 * }));
 * ```
 */
export function sensitiveAttributes(
  attributes: Readonly<Record<string, unknown>>,
  policy?: ScrubPolicy
): Record<string, NewRelicAttributeValue> {
  const compiled = policyFor(policy);
  const { payload, report } = scrubPayload(attributes, compiled, 'event');

  if (compiled.onScrub !== undefined) {
    try {
      compiled.onScrub(report);
    } catch {
      // A reporting callback that throws must not take the attributes with it.
      // Reporting that the reporter threw would call the reporter.
    }
  }

  const out: Record<string, NewRelicAttributeValue> = {};

  for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
    const coerced = coerce(value);

    if (coerced !== undefined) {
      out[key] = coerced;
    }
  }

  return out;
}

/** One scrubbed value as the agent will accept it, or `undefined` to omit the key. */
function coerce(value: unknown): NewRelicAttributeValue | undefined {
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return value;
    case 'number':
      // The agent accepts a number, and `NaN` and the infinities survive JSON
      // encoding as `null`, so neither is worth transmitting under a name that
      // says a measurement happened.
      return Number.isFinite(value) ? value : undefined;
    case 'bigint':
      // Not one of the three accepted types, and `JSON.stringify` throws on
      // one. The decimal form is what an operator expects to read.
      return value.toString();
    case 'undefined':
    case 'function':
    case 'symbol':
      return undefined;
    default:
      return value === null ? undefined : encode(value as object);
  }
}

/**
 * Encode a structure the agent would otherwise drop.
 *
 * Safe by the time it runs: the walk has already replaced every wrapped value
 * with its marker and censored every denied key at every depth. What is left
 * is the application's own data, and the choice is between the application
 * seeing it and the application seeing nothing.
 */
function encode(value: object): string | undefined {
  try {
    const json = JSON.stringify(value);

    // `JSON.stringify` answers `undefined` rather than throwing for a value
    // that has no representation, which for an object means one whose `toJSON`
    // returned `undefined`.
    return json;
  } catch {
    // A cycle, a `toJSON` that threw, or a `BigInt` nested inside. Omitted
    // rather than replaced, because a placeholder here would say a value was
    // censored when it was only unencodable.
    return undefined;
  }
}
