/**
 * Value shape recognizers, opt-in and off by default.
 *
 * Q3 of DESIGN_ERROR_TRACKING_HOOKS.md. Everything else in this package
 * matches on key names and paths and never on values, for a reason invariant 10
 * of the secrets manager design states in one line: a scrubber that decides by
 * looking at a string is a classifier and it is wrong some of the time.
 *
 * The pressure to relax that is real, though. A bearer token forwarded into a
 * field nobody named `authorization` is invisible to a key list, and the shapes
 * below are recognizable without guessing. So they ship, anchored, and default
 * to off.
 *
 * Default-on would be wrong for a reason specific to this category rather than
 * a general dislike of false positives. A false positive censors a value an
 * engineer needed, the error tracker becomes less useful, and the thing a user
 * does about an error tracker that is less useful is turn the scrubbing off
 * entirely. A default that trades a certain small loss for an uncertain large
 * one is a bad trade even when the pattern is good.
 *
 * Three rules every pattern here follows:
 *
 * 1. Anchored at both ends, so a pattern describes the whole value rather than
 *    something found inside it. `Bearer eyJ...` in the middle of a log line is
 *    not matched, because censoring the line would destroy the message and
 *    matching a substring is where a linear scan becomes a scan per position.
 * 2. Linear time. No nested quantifier over a shared character class, so a
 *    pathological subject cannot turn a scrub on the error path into a stall.
 * 3. A prefix that is issued rather than chosen. `ghp_`, `xoxb-`, `AKIA` and a
 *    PEM header are namespaces a vendor controls. A pattern that merely
 *    describes "looks random" is not here and should not be.
 */

/** A pattern name, for `denyValues`. */
export type ValuePatternName =
  | 'jwt'
  | 'bearer'
  | 'basicAuth'
  | 'pemPrivateKey'
  | 'awsAccessKeyId'
  | 'githubToken'
  | 'slackToken'
  | 'openaiKey';

/**
 * The shipped recognizers.
 *
 * Each getter returns a fresh `RegExp`, matching `core`'s `patterns` export, so
 * a caller cannot mutate shared pattern state and no `lastIndex` is carried
 * between subjects. None of them is global, which is the other half of that.
 *
 * `$(?![\s\S])` rather than a bare `$`: in JavaScript `$` also matches before a
 * final line terminator, so a value ending in a newline would otherwise pass an
 * anchored pattern with anything at all on the next line.
 */
export const VALUE_PATTERNS: Readonly<Record<ValuePatternName, RegExp>> = Object.freeze({
  /** Three base64url segments. The header of a JWT is `ey` in every encoding of `{"`. */
  get jwt(): RegExp {
    return /^ey[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{0,}$(?![\s\S])/;
  },

  /** An `Authorization: Bearer` value, which is the header the measured leak carried. */
  get bearer(): RegExp {
    return /^[Bb]earer +[A-Za-z0-9\-._~+/]{8,}=*$(?![\s\S])/;
  },

  /** An `Authorization: Basic` value, whose base64 is a password by construction. */
  get basicAuth(): RegExp {
    return /^[Bb]asic +[A-Za-z0-9+/]{8,}={0,2}$(?![\s\S])/;
  },

  /**
   * A whole PEM private key block, header to footer.
   *
   * Bounded rather than open-ended, and terminated by the footer rather than by
   * the end of the subject. An open `[\s\S]*` after the header would match a
   * key with an entire log file appended, which breaks the both-ends anchoring
   * every other pattern here has. The body is scanned but never ambiguously:
   * the terminator is a literal, so there is nothing to backtrack over.
   */
  get pemPrivateKey(): RegExp {
    return /^-----BEGIN [A-Z ]{0,32}PRIVATE KEY-----[\s\S]{0,16384}-----END [A-Z ]{0,32}PRIVATE KEY-----\s{0,4}$(?![\s\S])/;
  },

  /** An AWS access key id. The four prefixes are the ones AWS documents as long-term or session. */
  get awsAccessKeyId(): RegExp {
    return /^(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}$(?![\s\S])/;
  },

  /** A GitHub token. `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, and the `github_pat_` form. */
  get githubToken(): RegExp {
    return /^(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,})$(?![\s\S])/;
  },

  /** A Slack token. */
  get slackToken(): RegExp {
    return /^xox[abeoprs]-[A-Za-z0-9-]{8,}$(?![\s\S])/;
  },

  /**
   * An OpenAI-style key, which several vendors have since copied.
   *
   * The optional infix excludes `-` deliberately. Written as
   * `(?:[A-Za-z0-9_-]{4,}-)?` it shares the hyphen with the tail class that
   * follows it, so on a dash-heavy subject the group can end at any hyphen and
   * the engine tries every one: measured, `sk-` followed by ten thousand `a-`
   * pairs and a non-matching character took 266ms, and the cost is quadratic in
   * the number of hyphens. Excluding `-` from the infix leaves the group at most
   * one place to end, and the subject that took 266ms now takes under a
   * millisecond.
   */
  get openaiKey(): RegExp {
    return /^sk-(?:[A-Za-z0-9_]{2,32}-)?[A-Za-z0-9_-]{16,}$(?![\s\S])/;
  },
});

/** Every shipped pattern name, for a caller who wants the lot. */
export const ALL_VALUE_PATTERNS: readonly ValuePatternName[] = Object.freeze(
  Object.keys(VALUE_PATTERNS) as ValuePatternName[]
);

/** A compiled recognizer and the name a report calls it by. */
export interface CompiledValuePattern {
  readonly name: string;
  readonly pattern: RegExp;
}

/**
 * Turn a caller's `denyValues` into compiled recognizers, once, at install time.
 *
 * A caller's own `RegExp` is taken as written and reported by its source. It is
 * not validated for anchoring or for linear time: a caller who supplies one has
 * said what they want, and the rules above are what the shipped set follows
 * rather than a contract this function enforces.
 *
 * @throws Error naming an unknown pattern, at install time rather than on the
 *         error path.
 */
export function compileValuePatterns(
  entries: readonly (ValuePatternName | RegExp)[] | undefined
): readonly CompiledValuePattern[] {
  if (entries === undefined || entries.length === 0) {
    return [];
  }

  return entries.map((entry) => {
    if (typeof entry !== 'string') {
      // A global or sticky pattern carries `lastIndex` between calls, so the
      // same subject would match on one payload and not the next. Rebuilt
      // without those flags rather than refused, because the caller's intent is
      // unambiguous and a silent every-other-event miss is not something to
      // hand back to them.
      const flags = entry.flags.replace(/[gy]/g, '');

      return {
        name: String(entry),
        pattern: flags === entry.flags ? entry : new RegExp(entry.source, flags),
      };
    }

    const pattern = Object.prototype.hasOwnProperty.call(VALUE_PATTERNS, entry)
      ? VALUE_PATTERNS[entry]
      : undefined;

    if (pattern === undefined) {
      throw new Error(
        `unknown value pattern '${entry}'; the shipped names are ${ALL_VALUE_PATTERNS.join(', ')}`
      );
    }

    return { name: entry, pattern };
  });
}

/**
 * The first recognizer a string matches, or `null`.
 *
 * First rather than all: the report says which shape was seen and the value is
 * replaced either way, so scanning the rest buys nothing on the error path.
 */
export function matchValue(
  value: string,
  patterns: readonly CompiledValuePattern[]
): CompiledValuePattern | null {
  for (const candidate of patterns) {
    if (candidate.pattern.test(value)) {
      return candidate;
    }
  }

  return null;
}
