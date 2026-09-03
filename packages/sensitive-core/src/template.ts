import type { RevealContext, SensitivityClass } from './types.js';
import { SENSITIVITY_PRECEDENCE } from './types.js';
import { deriveSensitiveString, SensitiveString } from './sensitive-string.js';
import { defaultCombineClasses, getPolicy } from './policy.js';

/**
 * A value that may be interpolated into a sensitive template.
 *
 * Everything else, including `null`, `undefined`, `bigint`, `symbol`, functions,
 * and plain objects, is rejected. Coercing them would embed `'undefined'` or
 * `'[object Object]'` in a protected value, and coercing an arbitrary object
 * would hand the template an attacker-controlled `toString()`.
 */
export type TemplateValue = string | number | boolean | SensitiveString<SensitivityClass>;

/**
 * Options for the configured form of {@link sensitiveTemplate}.
 */
export interface SensitiveTemplateOptions<K extends SensitivityClass = SensitivityClass> {
  /** Reveal context for the interpolated values. Defaults to the ambient context. */
  ctx?: RevealContext;
  /** Label for the result. No label is inferred from the interpolations. */
  label?: string;
  /** Class for the result. May only tighten the inherited class, never loosen it. */
  klass?: K;
}

/**
 * The tagged-template function returned by the configured form.
 */
export type SensitiveTemplateTag<K extends SensitivityClass = SensitivityClass> = (
  strings: TemplateStringsArray,
  ...values: TemplateValue[]
) => SensitiveString<K>;

/**
 * Describe a rejected value without disclosing it.
 */
function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

/**
 * Recognized sensitivity classes, so an unrecognized one is named rather than
 * silently compared against the precedence order.
 */
function isSensitivityClass(value: unknown): value is SensitivityClass {
  return (SENSITIVITY_PRECEDENCE as readonly unknown[]).includes(value);
}

/**
 * Values that are safe to coerce with String().
 */
function isCoercible(value: unknown): value is string | number | boolean {
  const type = typeof value;
  return type === 'string' || type === 'number' || type === 'boolean';
}

/**
 * Combine two classes with the rule concat() uses: the accumulated class's
 * policy decides, and the precedence order applies when it has no opinion.
 */
function combine(accumulated: SensitivityClass, next: SensitivityClass): SensitivityClass {
  return (
    getPolicy(accumulated).combineClasses?.(accumulated, next) ??
    defaultCombineClasses(accumulated, next)
  );
}

/**
 * The result of inspecting the template before any value is read.
 */
interface TemplatePlan {
  readonly klass: SensitivityClass;
  readonly sources: readonly SensitiveString<SensitivityClass>[];
  readonly parts: readonly string[];
}

/**
 * Validate the template and derive the resulting class without raw-value access.
 *
 * Everything that can be decided from metadata is decided here, so a rejected
 * template never reaches the reveal pass. A type error or a loosened class that
 * surfaced afterwards would leave audited reveals behind for a value that was
 * never built.
 */
function planTemplate(
  strings: TemplateStringsArray,
  values: readonly unknown[],
  options: SensitiveTemplateOptions
): TemplatePlan {
  // A tagged template always supplies one more part than interpolations. A
  // direct call that disagrees would silently drop values from the result.
  if (strings.length !== values.length + 1) {
    throw new TypeError(
      `sensitiveTemplate: expected ${values.length + 1} template parts for ` +
        `${values.length} interpolations, received ${strings.length}`
    );
  }

  const parts = strings.map((part: unknown, index) => {
    // A part has no cooked value when the template contains an escape sequence
    // the engine could not interpret. Treating it as empty would drop authored
    // text from the protected value.
    if (part === undefined) {
      throw new TypeError(
        `sensitiveTemplate: template part at index ${index} has no cooked value, which ` +
          'means the template contains an invalid escape sequence'
      );
    }

    if (typeof part !== 'string') {
      throw new TypeError(
        `sensitiveTemplate: template part at index ${index} is ${describeType(part)}; ` +
          'expected a string'
      );
    }

    return part;
  });

  let klass: SensitivityClass = 'sensitive';
  const sources: SensitiveString<SensitivityClass>[] = [];

  values.forEach((value, index) => {
    if (value instanceof SensitiveString) {
      klass = combine(klass, value.klass);
      sources.push(value);
      return;
    }

    if (!isCoercible(value)) {
      throw new TypeError(
        `sensitiveTemplate: unsupported interpolation at index ${index} ` +
          `(${describeType(value)}); expected string, number, boolean, or SensitiveString`
      );
    }
  });

  if (options.klass !== undefined) {
    if (!isSensitivityClass(options.klass)) {
      // Naming a string cannot run caller code, so it is quoted. Anything else
      // is described by type: building the message must not invoke a
      // caller-supplied toString().
      const received =
        typeof options.klass === 'string' ? `'${options.klass}'` : describeType(options.klass);

      throw new TypeError(
        `sensitiveTemplate: klass ${received} is not a sensitivity class; expected ` +
          SENSITIVITY_PRECEDENCE.map((name) => `'${name}'`).join(' or ')
      );
    }

    // Precedence order decides this, not the policy hook: a hook must not be
    // able to relax the rule that a class may only be tightened.
    if (defaultCombineClasses(klass, options.klass) !== options.klass) {
      throw new Error(
        `sensitiveTemplate: klass '${options.klass}' is less restrictive than ` +
          `interpolated class '${klass}'; use reclassify() to lower a class`
      );
    }

    klass = options.klass;
  }

  return { klass, sources, parts };
}

/**
 * Plan the template, then reveal and assemble the protected result.
 */
function buildTemplate(
  strings: TemplateStringsArray,
  values: readonly unknown[],
  options: SensitiveTemplateOptions
): SensitiveString<SensitivityClass> {
  const plan = planTemplate(strings, values, options);
  const assembled: string[] = [];

  plan.parts.forEach((part, index) => {
    assembled.push(part);

    if (index < values.length) {
      const value = values[index];
      assembled.push(
        // reveal() authorizes and audits the read; a denial throws before the
        // result exists.
        value instanceof SensitiveString ? value.reveal(options.ctx) : String(value)
      );
    }
  });

  const value = assembled.join('');

  // With no protected interpolations there is nothing to inherit, so the result
  // is a new value rather than a derivative of one.
  return plan.sources.length === 0
    ? new SensitiveString(value, plan.klass, options.label)
    : deriveSensitiveString(value, plan.klass, options.label, plan.sources);
}

/**
 * A template array is the only argument shape the direct form accepts.
 */
function isTemplateStringsArray(value: unknown): value is TemplateStringsArray {
  return Array.isArray(value) && 'raw' in value;
}

/**
 * Build a `SensitiveString` from a template literal.
 *
 * Every interpolated `SensitiveString` is read through `reveal()`, so policy
 * checks and audit hooks run once per value, and the raw values are never
 * exposed to the caller as a plain string. The result inherits the most
 * restrictive interpolated class and retains the state of every value it read.
 *
 * Plain interpolations do not affect the class, but they are part of the
 * protected value: the whole result redacts, message text included. For a log
 * line use an untagged template literal, where `toString()` redacts only the
 * interpolation, or pass the value through `safeLog()` as a structured field.
 *
 * @throws TypeError If an interpolation is not a string, number, boolean, or `SensitiveString`.
 * @throws Error If a policy denies a reveal, or if `klass` would loosen the inherited class.
 *
 * @example
 * ```ts
 * const apiKey = new SensitiveString('sk_live_abc123', 'credential', 'api_key');
 * const userId = new SensitiveString('user_456', 'sensitive', 'user_id');
 *
 * const url = st`https://api.example.com/users/${userId}?key=${apiKey}`;
 * console.log(url.klass); // 'credential'
 * console.log(String(url)); // '[REDACTED:credential]'
 * ```
 *
 * @example
 * ```ts
 * // Configured form: audit context, label, and a tightened class.
 * const url = sensitiveTemplate({
 *   ctx: { name: 'build-api-url', reason: 'constructing external API request' },
 *   label: 'gateway_url',
 *   klass: 'credential',
 * })`https://gateway.example.com/charge?user=${userId}`;
 * ```
 */
export function sensitiveTemplate(
  strings: TemplateStringsArray,
  ...values: TemplateValue[]
): SensitiveString<SensitivityClass>;
export function sensitiveTemplate<K extends SensitivityClass = SensitivityClass>(
  options: SensitiveTemplateOptions<K>
): SensitiveTemplateTag<K>;
export function sensitiveTemplate(
  stringsOrOptions: TemplateStringsArray | SensitiveTemplateOptions,
  ...values: TemplateValue[]
): SensitiveString<SensitivityClass> | SensitiveTemplateTag {
  if (isTemplateStringsArray(stringsOrOptions)) {
    return buildTemplate(stringsOrOptions, values, {});
  }

  // Without this the caller receives a tag function that fails later, inside a
  // template that looks correct at the call site.
  const candidate: unknown = stringsOrOptions;
  if (candidate === null || typeof candidate !== 'object') {
    throw new TypeError(
      'sensitiveTemplate: expected a template literal or an options object, received ' +
        describeType(candidate)
    );
  }

  const options = stringsOrOptions;
  return (strings, ...interpolations) => buildTemplate(strings, interpolations, options);
}

/**
 * Short alias for {@link sensitiveTemplate}.
 */
export const st = sensitiveTemplate;
