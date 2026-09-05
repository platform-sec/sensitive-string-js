import type { SensitiveString, SensitivityClass } from '@platform-sec/sensitive-string-core';
import type { ScrubPolicy, ScrubReport } from '@platform-sec/sensitive-string-scrub';

/**
 * How to scrub a request body bound for a model.
 *
 * Every field is optional, and the defaults are the shipped content paths plus
 * `scrub`'s own denylist with this package's envelope keys folded in.
 */
export interface PromptScrubOptions {
  /**
   * Extra denied keys and paths, merged over the package defaults. Same shape
   * as `scrub`'s, and merged with `mergeScrubPolicy`, so the caller wins on
   * the single-valued fields.
   */
  policy?: ScrubPolicy;
  /**
   * Called on each prose position, with the text and the dotted path it sits
   * at. Whatever it returns is trusted verbatim and written into the copy.
   *
   * This is the seam for a DLP classifier the caller already runs. This
   * package ships none: a partial classifier's failure mode is not "some leaks
   * get through", it is "the reviewer stops reading their prompts".
   *
   * Throwing from here fails the whole scrub, which is the fail-closed
   * behaviour the rest of this package has. A hook that cannot decide should
   * return the text unchanged rather than throw.
   */
  transformContent?: (text: string, path: string) => string;
  /**
   * Dotted paths treated as prose rather than as structure, matched the way
   * `scrub` matches a denied path: whole paths, with `*` matching exactly one
   * segment. Defaults to the union of the shipped provider shapes.
   */
  contentPaths?: readonly string[];
}

/**
 * What one request body contained, with nothing of what it said.
 *
 * A `ScrubReport` plus the two facts that only exist for a prompt. `kind` is
 * `'event'`, because `PayloadKind` is the error tracker's seven and none of
 * them is `'prompt'`; adding a member to a shared package for this one
 * consumer is a decision that has not been made, and the fields below carry
 * the meaning in the meantime.
 */
export interface PromptManifest extends ScrubReport {
  /**
   * Entity handles recognized in the prose positions of this payload, by
   * token, deduplicated in encounter order.
   *
   * Recognized, not minted: this function mints nothing. A token is a
   * pseudonym rather than a value, so reporting it discloses that an entity of
   * that kind was in the prompt and nothing about which entity.
   *
   * Read after `transformContent` has run, because the manifest describes the
   * payload the caller is handed rather than the one they passed in.
   */
  readonly handles: readonly string[];
  /**
   * How many string positions the walk classified as prose.
   *
   * Counted whether or not a `transformContent` hook was supplied, and whether
   * or not the string at that position is prose the caller wrote, because the
   * useful reading of this number is "did the body match the shape I think it
   * has". Zero on a body whose schema has moved out from under the shipped
   * content paths, which is the one signal a caller gets for that.
   *
   * So this is not the same as the number of calls `transformContent`
   * received: a position holding a marker structural redaction just wrote is
   * counted here and is not handed to the hook.
   */
  readonly contentPositions: number;
}

/** A scrubbed request body and the manifest describing what was in it. */
export interface PromptScrubResult<P> {
  /**
   * The payload with wrapped values replaced and denied keys censored. The
   * input is not modified at any depth, prose positions included.
   */
  readonly prompt: P;
  /** What was found. Classes, key names, counts, handles. Never a value. */
  readonly removed: PromptManifest;
}

/**
 * A scrubber whose policy and content paths are already resolved.
 *
 * Generic at the call rather than at the factory, so one scrubber serves every
 * body shape an application sends.
 */
export type PromptScrubber = <P>(payload: P) => PromptScrubResult<P>;

/** Where a revealed value is going. */
export interface ExternalSink {
  /**
   * Stable identifier for the destination, recorded in the audit context as
   * `external:<name>`. A provider name, not a URL.
   */
  readonly name: string;
  /** Free-form, recorded alongside the name. A model id belongs here. */
  readonly detail?: string;
}

/** How to authorize one disclosure outside the trust boundary. */
export interface SendToExternalOptions {
  readonly sink: ExternalSink;
  /**
   * Why this value is going to this sink. Required here, though
   * `RevealContext` makes it optional.
   *
   * This is the one call in the library whose entire purpose is to authorize
   * an irreversible disclosure to a party outside the trust boundary, and a
   * required string is the cheapest available forcing function for a moment of
   * thought at the call site.
   */
  readonly reason: string;
  /** Merged into the reveal context's tags, under the sink's own two keys. */
  readonly tags?: Record<string, unknown>;
}

/**
 * The reverse map from handle to value, for one request.
 *
 * A plain `Map`, created by the caller and passed in, because this is a new
 * place raw values accumulate in a package whose purpose is to reduce those
 * and the package holds no module-level state.
 *
 * It holds `SensitiveString` instances rather than strings, so its contents
 * redact if the map is logged and so the values keep their TTL, revocation and
 * reveal counters. A map that outlives a value's lifetime hands back an
 * instance that refuses, which is correct and free.
 *
 * Its lifetime is the request. A cached map turns handles into a cross-user
 * correlation key, and two users whose values collide under truncation get
 * each other's.
 */
export type HandleMap = Map<string, SensitiveString<SensitivityClass>>;

/** How to mint an entity handle. */
export interface EntityHandleOptions {
  /** HMAC key. Required. There is no unkeyed mode. */
  readonly key: Uint8Array | string;
  /**
   * Namespace mixed into the derivation, so the same value in two contexts
   * gets two handles.
   *
   * Scope per conversation unless cross-conversation stability is
   * specifically needed. A stable token is a correlation key, and
   * per-conversation scoping costs nothing while turning the correlation
   * window from "forever" into "this thread".
   */
  readonly scope?: string;
  /** Hex characters retained. Default 12, floor 12, ceiling 64. */
  readonly length?: number;
  /**
   * Token prefix, so a manifest and a rehydrator can recognize the token and
   * a reader can tell what kind of entity it stands for.
   *
   * Defaults to the value's label, or `E` when the label is absent or is not
   * `[A-Za-z0-9_-]{1,32}`. An explicit prefix outside that set is an error
   * rather than a silent fallback.
   */
  readonly prefix?: string;
  /**
   * When supplied, the minted handle is recorded here against the value, for a
   * later {@link HandleMap}-backed rehydration. Per request, never cached.
   */
  readonly record?: HandleMap;
}

/** How to rehydrate handles out of a model's response. */
export interface RehydrateOptions {
  /**
   * The map this request built. A handle the current request did not mint
   * resolves to nothing, which is what makes a forged token inert.
   */
  readonly map: HandleMap;
  /** Label for the resulting value. */
  readonly label?: string;
}

/** What a rehydration substituted, and what it refused to. */
export interface RehydrateResult {
  /**
   * The text with known handles substituted, as a wrapped value.
   *
   * Wrapped, not raw, and that is the whole mitigation: whatever consumes the
   * result goes through the same gate as everything else, so the authorization
   * for acting on a rehydrated value is the consumer's rather than the
   * model's.
   *
   * Wrapped even when nothing was substituted, so a caller's downstream code
   * has one type to handle rather than two.
   */
  readonly text: SensitiveString<SensitivityClass>;
  /** Handles found in the text and present in the map, in encounter order. */
  readonly resolved: readonly string[];
  /**
   * Handle-shaped tokens found in the text and absent from the map, left in
   * place verbatim.
   *
   * A non-empty list is worth an alert. Forging a handle costs nothing, a
   * model echoes spans from the documents in its context, and a document some
   * user uploaded is one of those documents. So this is the count of times
   * something tried to make the substitution step hand back a value it was
   * never given.
   */
  readonly unresolved: readonly string[];
}
