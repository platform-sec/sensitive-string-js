import type { MaskAuditDetails, MaskOptions, MaskStrategy, SensitivityClass } from './types.js';

/**
 * The floor on hidden characters, by class.
 *
 * A caller may raise it, never lower it. `mask()` is a partial reveal, and the
 * floor is the only thing that keeps it partial: without it, `showFirst` alone
 * turns masking into an unaudited-looking `reveal()`.
 */
const DEFAULT_MIN_MASKED: Record<SensitivityClass, number> = {
  sensitive: 4,
  credential: 8,
};

/** Recognized strategy names, in documentation order. */
const STRATEGY_NAMES: readonly MaskStrategy[] = ['email', 'phone', 'card', 'ssn', 'uuid', 'custom'];

/** Replacement character used when the caller does not choose one. */
const DEFAULT_MASK_CHAR = '*';

/**
 * Formatting the phone and SSN strategies keep.
 *
 * Everything outside this set that is not part of the visible tail is masked,
 * so a letter in a value that was assumed to be a phone number is hidden rather
 * than shown.
 */
const PRESERVED_SEPARATORS = new Set([' ', '-', '.', '(', ')', '+', '/']);

/** Digits the phone and SSN strategies leave visible at the end. */
const TAIL_DIGITS = 4;

/** Country-code digits the phone strategy keeps after a leading '+'. */
const MAX_COUNTRY_CODE_DIGITS = 3;

/** ISO/IEC 7812 allows 12 to 19 digits in a primary account number. */
const CARD_MIN_DIGITS = 12;
const CARD_MAX_DIGITS = 19;

/** The PCI-DSS maximum: the six-digit BIN and the last four digits. */
const CARD_SHOW_FIRST = 6;
const CARD_SHOW_LAST = 4;

/** Code point counts of the five segments of a canonical UUID. */
const UUID_SEGMENTS: readonly number[] = [8, 4, 4, 4, 12];

/**
 * A validated set of mask options.
 *
 * Producing one requires no access to the raw value, so an invalid call is
 * rejected before anything is revealed or audited.
 */
export interface MaskPlan {
  /** The strategy to apply, or `'positional'` for `showFirst` / `showLast`. */
  readonly strategy: MaskStrategy | 'positional';
  readonly showFirst: number;
  readonly showLast: number;
  readonly maskChar: string;
  readonly minMasked: number;
  readonly customStrategy: ((value: string) => string) | undefined;
}

/**
 * A masked rendering and what it cost.
 */
interface MaskOutcome {
  /** The masked rendering. */
  readonly masked: string;
  /** Code points of the raw value the rendering replaced with the mask. */
  readonly hidden: number;
}

/** Strategies see the value as code points, which is what every count means here. */
type MaskStrategyFn = (chars: readonly string[], plan: MaskPlan) => MaskOutcome;

/**
 * The outcome of a strategy that does not recognize the value.
 *
 * A format strategy exists to show the parts of a known shape that are safe to
 * show. Applied to a value of a different shape it has no idea which parts
 * those are, so it hides nothing and the floor check in {@link applyMask} turns
 * the result into full redaction. Degrading to positional masking instead would
 * disclose a fixed prefix of whatever the value actually is.
 */
const STRATEGY_NOT_APPLICABLE: MaskOutcome = { masked: '', hidden: 0 };

/**
 * Describe a rejected option without disclosing it.
 */
function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

function isDigit(char: string): boolean {
  return char >= '0' && char <= '9';
}

function isHexDigit(char: string): boolean {
  return isDigit(char) || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F');
}

/**
 * Split code points on a separator, keeping empty segments.
 */
function splitOn(chars: readonly string[], separator: string): string[][] {
  const segments: string[][] = [[]];

  for (const char of chars) {
    if (char === separator) {
      segments.push([]);
      continue;
    }

    segments[segments.length - 1]?.push(char);
  }

  return segments;
}

/**
 * Show the leading and trailing characters the plan asks for, hiding the rest.
 *
 * The visible count is clamped so at least `minMasked` characters stay hidden.
 * A value too short to hide that many hides everything, and the floor check in
 * {@link applyMask} then turns the result into full redaction.
 */
function maskPositional(chars: readonly string[], plan: MaskPlan): MaskOutcome {
  const total = chars.length;
  const revealable = Math.max(0, total - plan.minMasked);
  const first = Math.min(plan.showFirst, revealable);
  const last = Math.min(plan.showLast, revealable - first);
  const hidden = total - first - last;

  return {
    masked:
      chars.slice(0, first).join('') +
      plan.maskChar.repeat(hidden) +
      chars.slice(total - last).join(''),
    hidden,
  };
}

/**
 * Keep the first code point of a label and hide the rest.
 *
 * A label of one code point is hidden whole: showing it would disclose the
 * label rather than hint at it.
 */
function maskLabel(chars: readonly string[], plan: MaskPlan): MaskOutcome {
  const [first, ...rest] = chars;

  if (first === undefined || rest.length === 0) {
    return { masked: plan.maskChar.repeat(chars.length), hidden: chars.length };
  }

  return { masked: first + plan.maskChar.repeat(rest.length), hidden: rest.length };
}

/**
 * Hide every digit except the last {@link TAIL_DIGITS}, keeping the caller's
 * separators and hiding anything else.
 *
 * @param preserveBefore - Code point index before which digits stay visible.
 */
function maskDigitTail(
  chars: readonly string[],
  plan: MaskPlan,
  preserveBefore: number
): MaskOutcome {
  let totalDigits = 0;
  for (const char of chars) {
    if (isDigit(char)) {
      totalDigits += 1;
    }
  }

  const maskedDigits = Math.max(0, totalDigits - TAIL_DIGITS);
  const parts: string[] = [];
  let seenDigits = 0;
  let hidden = 0;

  chars.forEach((char, index) => {
    if (isDigit(char)) {
      const visible = index < preserveBefore || seenDigits >= maskedDigits;
      seenDigits += 1;

      if (visible) {
        parts.push(char);
        return;
      }

      parts.push(plan.maskChar);
      hidden += 1;
      return;
    }

    if (PRESERVED_SEPARATORS.has(char)) {
      parts.push(char);
      return;
    }

    parts.push(plan.maskChar);
    hidden += 1;
  });

  return { masked: parts.join(''), hidden };
}

/**
 * Code point index just past a leading country code, or 0 when there is none.
 *
 * A country code is only recognizable when the caller's own formatting
 * delimits it. `+1-555-123-4567` has one; `+15551234567` does not, and treating
 * its leading digits as a country code would show digits of the number itself.
 */
function countryCodeEnd(chars: readonly string[]): number {
  if (chars[0] !== '+') {
    return 0;
  }

  let index = 1;
  while (index < chars.length && index <= MAX_COUNTRY_CODE_DIGITS && isDigit(chars[index] ?? '')) {
    index += 1;
  }

  const digits = index - 1;
  const next = chars[index];

  if (digits === 0 || next === undefined || isDigit(next)) {
    return 0;
  }

  return index;
}

const BUILT_IN_STRATEGIES: Record<Exclude<MaskStrategy, 'custom'>, MaskStrategyFn> = {
  /**
   * Hide the local part and the domain, keeping one character of each and the
   * final domain label. Showing a full domain leaks the employer or provider.
   */
  email: (chars, plan) => {
    // The last '@' separates the domain: a quoted local part may contain one.
    const at = chars.lastIndexOf('@');

    if (at === -1) {
      return STRATEGY_NOT_APPLICABLE;
    }

    const local = maskLabel(chars.slice(0, at), plan);
    const domain = chars.slice(at + 1);
    const lastDot = domain.lastIndexOf('.');
    const head = maskLabel(lastDot === -1 ? domain : domain.slice(0, lastDot), plan);
    const tail = lastDot === -1 ? '' : domain.slice(lastDot).join('');

    return {
      masked: `${local.masked}@${head.masked}${tail}`,
      hidden: local.hidden + head.hidden,
    };
  },

  /** Hide every digit but the last four, keeping formatting and a country code. */
  phone: (chars, plan) => maskDigitTail(chars, plan, countryCodeEnd(chars)),

  /**
   * Show the six-digit BIN and the last four digits, which is the PCI-DSS
   * maximum. This is the only definition of card masking in this repository.
   */
  card: (chars, plan) => {
    const digits = chars.filter(isDigit);

    // Counting digits is not enough to recognize a PAN: a hex token holds
    // twelve or more of them scattered among letters, and rendering those as a
    // card would show ten characters of a value that is not a card at all.
    const shaped =
      digits.length >= CARD_MIN_DIGITS &&
      digits.length <= CARD_MAX_DIGITS &&
      chars.every((char) => isDigit(char) || PRESERVED_SEPARATORS.has(char));

    if (!shaped) {
      return STRATEGY_NOT_APPLICABLE;
    }

    const hidden = digits.length - CARD_SHOW_FIRST - CARD_SHOW_LAST;

    return {
      masked:
        digits.slice(0, CARD_SHOW_FIRST).join('') +
        plan.maskChar.repeat(hidden) +
        digits.slice(digits.length - CARD_SHOW_LAST).join(''),
      hidden,
    };
  },

  /** Hide every digit but the last four, keeping formatting. */
  ssn: (chars, plan) => maskDigitTail(chars, plan, 0),

  /** Show the first segment, which is enough to correlate log lines. */
  uuid: (chars, plan) => {
    const segments = splitOn(chars, '-');
    const [head, ...rest] = segments;

    const canonical =
      head !== undefined &&
      segments.length === UUID_SEGMENTS.length &&
      segments.every(
        (segment, index) => segment.length === UUID_SEGMENTS[index] && segment.every(isHexDigit)
      );

    if (!canonical) {
      return STRATEGY_NOT_APPLICABLE;
    }

    return {
      masked: [head.join(''), ...rest.map((segment) => plan.maskChar.repeat(segment.length))].join(
        '-'
      ),
      hidden: rest.reduce((total, segment) => total + segment.length, 0),
    };
  },
};

/**
 * Reject an option of the wrong type, and any count that is not a whole number
 * of characters.
 */
function requireCount(value: unknown, name: string, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }

  if (typeof value !== 'number') {
    throw new TypeError(
      `SensitiveString.mask: ${name} must be a number, received ${describeType(value)}`
    );
  }

  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError(`SensitiveString.mask: ${name} must be a non-negative integer`);
  }

  return value;
}

function requireMaskChar(value: unknown): string {
  if (value === undefined) {
    return DEFAULT_MASK_CHAR;
  }

  if (typeof value !== 'string') {
    throw new TypeError(
      `SensitiveString.mask: maskChar must be a string, received ${describeType(value)}`
    );
  }

  // Code points, not UTF-16 units, so an emoji is one character and a surrogate
  // pair is never split across a repeat.
  const length = [...value].length;

  if (length !== 1) {
    throw new RangeError(
      `SensitiveString.mask: maskChar must be exactly one character, received ${length}`
    );
  }

  return value;
}

function requireStrategy(value: unknown): MaskStrategy | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'string' || !STRATEGY_NAMES.includes(value as MaskStrategy)) {
    // Naming a string cannot run caller code, so it is quoted. Anything else is
    // described by type: building the message must not invoke a caller-supplied
    // toString().
    const received = typeof value === 'string' ? `'${value}'` : describeType(value);

    throw new TypeError(
      `SensitiveString.mask: strategy ${received} is not a masking strategy; expected ` +
        STRATEGY_NAMES.map((name) => `'${name}'`).join(', ')
    );
  }

  return value as MaskStrategy;
}

/**
 * Validate mask options against the class defaults.
 *
 * Nothing here reads the raw value, so a rejected call produces no audit record
 * for a mask that was never rendered.
 *
 * @throws TypeError If an option has the wrong type or an unknown strategy is named.
 * @throws RangeError If a count is not a whole number, or `minMasked` is below the class floor.
 * @throws Error If positional options are combined with a strategy, or `customStrategy` is misused.
 */
export function planMask(options: MaskOptions, klass: SensitivityClass): MaskPlan {
  const floor = DEFAULT_MIN_MASKED[klass];
  const strategy = requireStrategy(options.strategy);
  const showFirst = requireCount(options.showFirst, 'showFirst', 0);
  const showLast = requireCount(options.showLast, 'showLast', 0);
  const minMasked = requireCount(options.minMasked, 'minMasked', floor);
  const maskChar = requireMaskChar(options.maskChar);

  if (minMasked < floor) {
    throw new RangeError(
      `SensitiveString.mask: minMasked ${minMasked} is below the floor of ${floor} for ` +
        `sensitivity class '${klass}'; the floor may be raised but not lowered`
    );
  }

  // Silently ignoring these would leave the caller believing they narrowed the
  // result when the strategy decided what to show.
  if (
    strategy !== undefined &&
    (options.showFirst !== undefined || options.showLast !== undefined)
  ) {
    throw new Error(
      `SensitiveString.mask: showFirst and showLast do not apply to strategy '${strategy}'`
    );
  }

  if (options.customStrategy !== undefined && typeof options.customStrategy !== 'function') {
    throw new TypeError(
      `SensitiveString.mask: customStrategy must be a function, received ${describeType(
        options.customStrategy
      )}`
    );
  }

  if (options.customStrategy !== undefined && strategy !== 'custom') {
    throw new Error(
      "SensitiveString.mask: customStrategy requires strategy: 'custom'; it receives the raw " +
        'value, so it may not be supplied to a built-in strategy'
    );
  }

  if (strategy === 'custom' && options.customStrategy === undefined) {
    throw new Error("SensitiveString.mask: strategy 'custom' requires customStrategy");
  }

  return {
    strategy: strategy ?? 'positional',
    showFirst,
    showLast,
    maskChar,
    minMasked,
    customStrategy: options.customStrategy,
  };
}

/**
 * The audit record for a plan.
 *
 * Derived from the options alone, so the audit hook runs at the same point in
 * `mask()` as it does in `reveal()`, before the rendering exists.
 */
export function maskAuditDetails(plan: MaskPlan): MaskAuditDetails {
  return Object.freeze({
    operation: 'mask' as const,
    strategy: plan.strategy,
    showFirst: plan.showFirst,
    showLast: plan.showLast,
    minMasked: plan.minMasked,
    maskChar: plan.maskChar,
  });
}

/**
 * Run a caller-supplied formatter over the raw value.
 *
 * The identity check catches the accidental `(value) => value`. It is not a
 * security boundary: the formatter already holds the raw value and can do
 * whatever it likes with it.
 */
function runCustomStrategy(value: string, customStrategy: (value: string) => string): string {
  const masked: unknown = customStrategy(value);

  if (typeof masked !== 'string') {
    throw new TypeError(
      `SensitiveString.mask: customStrategy must return a string, received ${describeType(masked)}`
    );
  }

  if (masked === value) {
    throw new Error('SensitiveString.mask: customStrategy returned the value unmasked');
  }

  return masked;
}

/**
 * Render the masked form of a value.
 *
 * @param value - The raw value, already authorized and audited by the caller.
 * @param plan - Validated options from {@link planMask}.
 * @param redact - The class policy's redaction, used when the floor is unmet.
 */
export function applyMask(
  value: string,
  plan: MaskPlan,
  redact: (value: string) => string
): string {
  if (plan.strategy === 'custom') {
    const { customStrategy } = plan;

    // planMask rejects 'custom' without a formatter, so reaching this is a bug
    // in the package rather than a caller mistake.
    if (customStrategy === undefined) {
      throw new Error("SensitiveString.mask: strategy 'custom' requires customStrategy");
    }

    // A formatter is handed the raw value, so its output cannot be measured
    // against the floor. It is a reveal in all but name.
    return runCustomStrategy(value, customStrategy);
  }

  const chars = [...value];
  const outcome =
    plan.strategy === 'positional'
      ? maskPositional(chars, plan)
      : BUILT_IN_STRATEGIES[plan.strategy](chars, plan);

  // A rendering that cannot hide `minMasked` characters is not a partial view
  // of the value, it is most of the value.
  return outcome.hidden >= plan.minMasked ? outcome.masked : redact(value);
}
