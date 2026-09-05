import {
  failedReport,
  reportScrub,
  scrubPayload,
  scrubUrl,
  type ResolvedScrubPolicy,
  type ScrubReport,
} from '@platform-sec/sensitive-string-scrub';

import { classifyTag, isCandidate, isReservedTag } from './paths.js';

/**
 * The hook body, and the two adaptations this seam forces on `guardedScrub`.
 *
 * `dd-trace`'s hooks are real, they run after header tagging and before
 * formatting, and they can write. Measured on 6.14.0 with
 * `headerTags: ['authorization', 'cookie', 'x-api-key']` and a hook writing
 * `[SCRUBBED]` over every `http.*.headers.*` tag: the hook fired on the server
 * span and on the client span, saw `Bearer LEAKED_SECRET_abc123xyz` as a tag
 * value, its `setTag` reached the payload, and no canary reached the agent.
 *
 * **The payload is the tag bag, not the span.** The shared scrubber is
 * value-in, value-out and this seam is mutate-in-place, so the hook reads the
 * span's candidate tags into an object, scrubs that, and writes the result
 * back. Passing the span itself would traverse the agent's own internals and
 * leave nothing to do with the value that came back.
 *
 * **The guard is assembled here rather than taken from `guardedScrub`.** A tag
 * bag is flat: `probe.password` is one key with a dot in it, and the shared
 * walk, which was written for nested payloads, tests exactly that string
 * against the denylist and finds nothing. The key name the denylist is written
 * against is the tag key's last dotted segment, and applying that is the
 * "tag-level matcher inside the hooks" the design assigns to this package. So
 * the walk runs first, for stage 1 and for anything nested inside a tag value,
 * and a second pass over the flat top level applies the denylist and the URL
 * rewriting in Datadog's vocabulary. `failure.ts` exports `reportScrub` and
 * `failedReport` for exactly this: a vendor whose seam does not fit
 * `guardedScrub` runs its own guard and still reports the same way.
 *
 * **The stub returns a censored bag, never `null`.** The shared layer's
 * documentation says `null` is the right answer for a span, on the grounds
 * that a missing span is indistinguishable from a sampled one. That reasoning
 * holds where returning `null` drops the payload. Here it cannot: measured,
 * `web.js` calls `context.config.hooks.request(span, req, res)` and then
 * `context.span.finish()`, discarding the return value, so `null` would mean
 * this package writes nothing back and the span ships with its original,
 * unscrubbed tags. `null` is the one answer that leaks.
 *
 * If even the censoring loop throws, the hook rethrows. Measured, the agent's
 * response to a throwing hook is to drop that span and nothing else: the
 * application's request succeeded, the server and client spans were both
 * absent, a `dns.lookup` span from a plugin with no hooks survived, and no
 * canary reached the payload. That is a deliberate last resort rather than the
 * ordinary failure path, and it is the only place in either package where a
 * hook body is allowed to throw.
 */

/** As much of a `dd-trace` span as a hook body touches. */
export interface DatadogSpan {
  setTag: (key: string, value: unknown) => unknown;
  context: () => DatadogSpanContext;
  finish?: (finishTime?: number) => void;
}

/**
 * Marks a span this package has already scrubbed.
 *
 * A plugin span is reached twice: once by the hook, which runs before
 * `context.span.finish()`, and once by the manual-span wrapper, which runs at
 * finish. Scrubbing twice is harmless and reporting twice is not, since
 * invariant 19 is one report per scrubbed span. The mark is what settles it,
 * and the hook wins because it is the seam the design is built on.
 */
export const SCRUBBED = Symbol.for('@platform-sec/sensitive-string-datadog.scrubbed');

/** As much of a span context as a hook body touches. */
export interface DatadogSpanContext {
  /**
   * The tag bag.
   *
   * Not in the shipped declarations. `SpanContext` declares exactly
   * `toTraceId`, `toSpanId` and `toTraceparent`, and `Span` declares no tag
   * getter at all, so there is no supported way to ask a span what it carries.
   * `getTags()` exists at runtime and returns the bag; `_tags` is the field
   * behind it. Writing is public and reading is not, which is this package's
   * only version-coupled dependency and the reason `readTags` is guarded and
   * the reason the compatibility job of the design's 9.3 exists.
   */
  getTags?: () => Record<string, unknown>;
  _tags?: Record<string, unknown>;
}

/** What one hook invocation did, for the caller's callback. */
export type HookReporter = (report: ScrubReport) => void;

/**
 * Read a span's tags, treating any refusal as "no tags".
 *
 * Degrading rather than throwing is the right response to losing a
 * defence-in-depth layer while the primary one still stands: the known-key
 * censoring of `install.ts` runs through the public `setTag` and does not
 * depend on this.
 */
export function readTags(span: DatadogSpan): Record<string, unknown> | null {
  try {
    const context = span.context();

    if (typeof context.getTags === 'function') {
      const tags = context.getTags();

      return tags !== null && typeof tags === 'object' ? tags : null;
    }

    const fallback = context._tags;

    return fallback !== null && typeof fallback === 'object' ? fallback : null;
  } catch {
    return null;
  }
}

/**
 * Whether tag enumeration works on this `dd-trace`.
 *
 * Called once at install time against a span the caller already has, so a
 * rename in a future release is a startup log line rather than a per-span
 * `try`/`catch` that silently finds nothing.
 */
export function canEnumerateTags(span: DatadogSpan): boolean {
  return readTags(span) !== null;
}

/**
 * Build one plugin hook.
 *
 * @param policy - A policy already resolved and projected into Datadog's
 *                 vocabulary by `install.ts`
 * @param user - The caller's own hook for this plugin, composed after this one
 *               so a hook that adds context cannot add it behind the
 *               scrubber's back
 */
export function buildRequestHook(
  policy: ResolvedScrubPolicy,
  user?: (...args: unknown[]) => unknown
): (span?: DatadogSpan, ...rest: unknown[]) => void {
  const scrub = guardedTagScrub(policy);

  return (span?: DatadogSpan, ...rest: unknown[]): void => {
    if (span !== undefined && !alreadyScrubbed(span)) {
      mark(span);
      scrubSpan(span, policy, scrub);
    }

    if (user === undefined) {
      return;
    }

    try {
      user(span, ...rest);
    } catch {
      // A caller hook that throws must not take the span with it. The agent's
      // response to a throwing hook is to drop the span, and losing a span
      // because somebody's telemetry callback failed is not a trade this
      // package makes on their behalf. Their hook ran after the scrubber, so
      // whatever it meant to add is what is lost, not the scrubbing.
    }
  };
}

/**
 * Build the scrubber the manual-span wrapper runs at `finish()`.
 *
 * Same body as a hook, different trigger. A span from `tracer.startSpan`,
 * `tracer.trace` or `tracer.wrap` never reaches a plugin hook, so without this
 * a `serialize()` result put on one would arrive at the agent with its raw
 * value, which section 2.4 measured and which is the one place in this row
 * where the walk is the only defence rather than defence in depth.
 */
export function buildManualScrubber(policy: ResolvedScrubPolicy): (span: DatadogSpan) => void {
  const scrub = guardedTagScrub(policy);

  return (span: DatadogSpan): void => {
    if (alreadyScrubbed(span)) {
      return;
    }

    mark(span);
    scrubSpan(span, policy, scrub);
  };
}

/** Whether this package has already scrubbed a span. */
export function alreadyScrubbed(span: DatadogSpan): boolean {
  try {
    return (span as unknown as Record<symbol, unknown>)[SCRUBBED] === true;
  } catch {
    return false;
  }
}

function mark(span: DatadogSpan): void {
  try {
    Object.defineProperty(span, SCRUBBED, { value: true, enumerable: false });
  } catch {
    // A frozen span. Scrubbing twice is harmless; only the report doubles.
  }
}

/**
 * Scrub one span in place.
 *
 * The fast path runs first and is the reason invariant 21 holds: an APM hook
 * runs on every span of every request rather than on the error path, so a span
 * with nothing to scrub costs one pass over its keys and no allocation at all.
 * The bag, the copy and the report are built only when something is actually
 * there.
 */
function scrubSpan(
  span: DatadogSpan,
  policy: ResolvedScrubPolicy,
  scrub: (bag: Record<string, unknown>) => {
    payload: Record<string, unknown> | null;
    report: ScrubReport;
  }
): void {
  const tags = readTags(span);

  if (tags === null) {
    return;
  }

  const bag = collectCandidates(tags, policy);

  if (bag === null) {
    return;
  }

  const { payload } = scrub(bag);

  // `guardedTagScrub` answers `null` only when scrubbing threw and then
  // censoring threw as well, which for a loop over an object this file just
  // built means something well outside this package went wrong. Rethrowing is
  // the last resort: at a plugin hook the agent answers it by dropping that
  // span, the application is unaffected, and nothing leaks. `wrapFinish` in
  // `install.ts` catches it, because at `finish()` the caller is the
  // application rather than the agent.
  if (payload === null) {
    throw new Error('sensitive-string-datadog: scrubbing and censoring both failed on a span');
  }

  writeBack(span, bag, payload);
}

/**
 * Empty a span through the public API alone, for the path where everything
 * else has failed.
 *
 * No walk, no copy, no parsing: read the keys, write the placeholder over the
 * ones that are not the agent's own. Every step is guarded, because this runs
 * only after two other guards have already been taken out.
 */
export function censorSpan(span: DatadogSpan): void {
  const tags = readTags(span);

  if (tags === null) {
    return;
  }

  let keys: string[];

  try {
    keys = Object.keys(tags);
  } catch {
    return;
  }

  for (const key of keys) {
    if (isReservedTag(key)) {
      continue;
    }

    try {
      span.setTag(key, CENSOR_PLACEHOLDER);
    } catch {
      // Nothing further to try for this tag.
    }
  }
}

/**
 * The never-throw wrapper for one tag bag.
 *
 * Two passes and one report. The walk handles stage 1 and everything nested
 * inside a tag value; `applyTagRules` handles the flat top level, where the
 * key name is the tag key's last segment. On any failure the bag comes back
 * censored rather than as `null`, because nothing consumes a hook's return
 * value and `null` here would mean the original tags ship unscrubbed.
 */
function guardedTagScrub(policy: ResolvedScrubPolicy): (bag: Record<string, unknown>) => {
  payload: Record<string, unknown> | null;
  report: ScrubReport;
} {
  return (bag) => {
    try {
      const { payload, report } = scrubPayload(bag, policy, 'span');
      const copy = payload as Record<string, unknown>;
      const denied = applyTagRules(copy, bag, policy);
      const merged = withDeniedKeys(report, denied);

      reportScrub(policy, merged);

      return { payload: copy, report: merged };
    } catch {
      const report = failedReport('span', policy);

      reportScrub(policy, report);

      try {
        return { payload: censorBag(bag), report };
      } catch {
        return { payload: null, report };
      }
    }
  };
}

/**
 * Apply the denylist and the URL rewriting to the flat top level.
 *
 * A tag stage 1 already replaced keeps the marker its own policy chose:
 * `[REDACTED:credential]` and the censor are equally safe and the marker says
 * which class stood there. That is the shared walk's rule, applied at this
 * level for the same reason.
 *
 * @returns The key names that matched, for the report
 */
function applyTagRules(
  copy: Record<string, unknown>,
  original: Record<string, unknown>,
  policy: ResolvedScrubPolicy
): string[] {
  const denied: string[] = [];

  for (const key of Object.keys(copy)) {
    const before = original[key];
    const value = copy[key];

    // Stage 1 turns an object into a string and nothing else does, so this is
    // an exact test for "the walk already replaced this one".
    if (typeof before === 'object' && before !== null && typeof value === 'string') {
      continue;
    }

    const decision = classifyTag(key, policy);

    if (decision === 'deny') {
      copy[key] = policy.censor;
      denied.push(key);

      continue;
    }

    if (decision === 'url' && typeof value === 'string') {
      const rewritten = scrubUrl(value, policy.denyKeys, policy.censor);

      if (rewritten !== null) {
        copy[key] = rewritten.value;
        denied.push(...rewritten.replaced);
      }
    }
  }

  return denied;
}

/** The report the walk produced, plus what the tag pass found. */
function withDeniedKeys(report: ScrubReport, denied: readonly string[]): ScrubReport {
  if (denied.length === 0) {
    return report;
  }

  return { ...report, deniedKeys: [...new Set([...report.deniedKeys, ...denied])] };
}

/**
 * The candidate tags, or `null` when there are none.
 *
 * One pass, no allocation until the first candidate is found.
 */
function collectCandidates(
  tags: Record<string, unknown>,
  policy: ResolvedScrubPolicy
): Record<string, unknown> | null {
  let bag: Record<string, unknown> | null = null;
  let keys: string[];

  try {
    keys = Object.keys(tags);
  } catch {
    return null;
  }

  for (const key of keys) {
    // Guarded, because this runs outside the scrub's own guard and a tag whose
    // getter throws would otherwise take the hook with it, which the agent
    // answers by dropping the span. The same rule the shared walk applies to a
    // property that refuses to be read: absent, as far as the scrub is
    // concerned.
    let value: unknown;

    try {
      value = tags[key];
    } catch {
      continue;
    }

    if (!isCandidate(key, value, policy)) {
      continue;
    }

    bag ??= {};
    bag[key] = value;
  }

  return bag;
}

/**
 * Write back only what changed.
 *
 * A tag whose scrubbed value is identical to the one already on the span costs
 * nothing to leave alone, and `setTag` on an unchanged value would still be a
 * write into the agent's bag. Identity is the right comparison: the walk
 * returns the same reference for anything it passed through and a fresh one
 * for anything it descended into or replaced.
 */
function writeBack(
  span: DatadogSpan,
  before: Record<string, unknown>,
  after: Record<string, unknown>
): void {
  for (const key of Object.keys(after)) {
    if (!Object.is(after[key], before[key])) {
      span.setTag(key, after[key]);
    }
  }
}

/**
 * The failure output: every candidate key censored, nothing parsed.
 *
 * A loop with no recursion, no parsing and no allocation beyond the object it
 * returns, over keys the caller already collected. It is what runs when
 * `scrubPayload` threw, and it must not be able to throw for the same reason.
 */
function censorBag(bag: Record<string, unknown>): Record<string, unknown> {
  const censored: Record<string, unknown> = {};

  for (const key of Object.keys(bag)) {
    censored[key] = CENSOR_PLACEHOLDER;
  }

  return censored;
}

/**
 * The value the failure path writes.
 *
 * Deliberately not the policy's censor. A reader of a censored span needs to
 * tell "this value was on the denylist" from "the scrubber broke and this span
 * was emptied", and two findings must not produce the same string. The report
 * carries `failed: true` for anything reading `onScrub`; this is for the
 * person reading the span.
 */
const CENSOR_PLACEHOLDER = '[SCRUB_FAILED]';

export { CENSOR_PLACEHOLDER };
