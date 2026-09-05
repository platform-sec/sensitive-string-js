import type { SensitivityClass } from '@platform-sec/sensitive-string-core';

import type { CompiledValuePattern, ValuePatternName } from './values.js';

/**
 * The kinds of payload an error tracker or APM agent emits.
 *
 * A vendor SDK does not offer one hook over one payload shape. Sentry alone
 * has six, and a package that scrubs the famous one covers a fraction of what
 * leaves the process. The kind travels with every report so an operator can
 * see which shape a finding came from, and so a vendor suite can assert that
 * every kind its SDK can emit reached the scrubber at all.
 */
export type PayloadKind =
  'event' | 'breadcrumb' | 'transaction' | 'span' | 'log' | 'metric' | 'session';

/** A default denied key the caller has taken back, with the reason recorded. */
export interface ScrubAllowance {
  /** The key name to remove from the resolved denylist, matched case-insensitively. */
  readonly key: string;
  /**
   * Why this key is safe to send. Not used at runtime and not transmitted
   * anywhere: it exists so the line is reviewable in a configuration diff.
   */
  readonly reason: string;
}

/**
 * What to scrub and how to report it.
 *
 * Every field is optional. The defaults close the leak measured in
 * DESIGN_ERROR_TRACKING_HOOKS.md section 1: an `authorization` header, a
 * `cookie` header, and a `token` query parameter reaching a vendor verbatim.
 */
export interface ScrubPolicy {
  /** Key names, matched case-insensitively at any depth. Added to the defaults. */
  denyKeys?: readonly string[];
  /** Key names removed from the defaults. Each requires a reason string. */
  allowKeys?: readonly ScrubAllowance[];
  /**
   * Dotted paths into the vendor's payload shape, matched as whole paths
   * rather than segment by segment. Added to the defaults. A `*` segment
   * matches one path segment, which is how an array element is named.
   */
  denyPaths?: readonly string[];
  /**
   * Where a URL lives. The query parameters whose names are denied are
   * replaced and the rest of the URL is kept, so an event keeps its route.
   *
   * An entry matches either a whole dotted path (`request.url`) or a terminal
   * key name at any depth (`url`, and `http.url`, which is one key containing
   * a dot rather than a path of two).
   */
  urlKeys?: readonly string[];
  /**
   * Value shape recognizers, by name or as a caller's own `RegExp`. Empty by
   * default, which is the whole of this package's answer to "should the
   * denylist ever match on value shape".
   *
   * A string that matches one is replaced wherever it sits, whatever its key is
   * called. See `values.ts` for the shipped names and for why none is on unless
   * a caller asks.
   */
  denyValues?: readonly (ValuePatternName | RegExp)[];
  /** Replacement written in place of a denied value. */
  censor?: string;
  /** What to do on seeing a redaction marker in captured data. Default `'tag'`. */
  onMarker?: 'tag' | 'ignore';
  /** Include the labels of wrapped values in the report. Default `false`. */
  reportLabels?: boolean;
  /** Called once per payload with counts and classes. Never receives a value. */
  onScrub?: (report: ScrubReport) => void;
}

/**
 * A `ScrubPolicy` with the defaults folded in and the matchers compiled.
 *
 * Resolution happens once, at install time. The walk runs on the error path
 * and does no list arithmetic of its own.
 */
export interface ResolvedScrubPolicy {
  /** Lowercased denied key names. */
  readonly denyKeys: ReadonlySet<string>;
  /** Lowercased denied paths, `*` segments included. */
  readonly denyPaths: ReadonlySet<string>;
  /** Lowercased URL paths and key names. */
  readonly urlKeys: ReadonlySet<string>;
  /** Compiled value recognizers, empty unless the caller opted in. */
  readonly denyValues: readonly CompiledValuePattern[];
  readonly censor: string;
  readonly onMarker: 'tag' | 'ignore';
  readonly reportLabels: boolean;
  readonly onScrub: ((report: ScrubReport) => void) | undefined;
}

/**
 * What one payload contained, with nothing of what it said.
 *
 * Classes, key names, and counts only. A key name is something the
 * application's own code chose and an operator already reads off the event;
 * a value is the thing this package exists to keep out of one.
 */
export interface ScrubReport {
  readonly kind: PayloadKind;
  /** `SensitiveString` instances and `serialize()` results found in the payload. */
  readonly instances: number;
  /** The sensitivity classes those instances carried. */
  readonly classes: ReadonlySet<SensitivityClass>;
  /** Present only when `reportLabels` is on. */
  readonly labels?: readonly string[];
  /** The denied key names that actually matched, deduplicated, in encounter order. */
  readonly deniedKeys: readonly string[];
  /**
   * The names of the value recognizers that matched, deduplicated.
   *
   * Names, never the values they matched, and never where they matched either:
   * a path is a key name the application chose and is safe on its own, but a
   * path paired with a pattern name says a JWT sat at `request.data.callback`,
   * and that is a map of where to look. Invariant 2 is that a report carries
   * classes, key names and counts; this is the count of a shape.
   */
  readonly deniedValues: readonly string[];
  /** Redaction markers found in captured data. See the marker rule in `walk.ts`. */
  readonly markersSeen: number;
  /** The classes those markers named, when they named a registered one. */
  readonly markerClasses: ReadonlySet<string>;
  /** True when scrubbing threw and the payload was replaced by a stub. */
  readonly failed: boolean;
}
