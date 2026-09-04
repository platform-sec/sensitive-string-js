import {
  assertHeadersScrubbed,
  planIsEmpty,
  scrubBody,
  scrubHeaderBag,
  scrubMessage,
  scrubQuery,
  scrubUrlString,
} from '@platform-sec/sensitive-string-http';
import type { ScrubPlan } from '@platform-sec/sensitive-string-http';

/**
 * The got-specific property list.
 *
 * Measured on got 16.0.0 against a local recording server:
 *
 * - A rejection carries the revealed header in `error.options.headers`, and,
 *   unlike the design's note taken against an earlier major,
 *   `JSON.stringify(error)` discloses it too on got 16.
 * - A **resolution** carries it in `response.request.options.headers`. got is
 *   therefore the second client, with axios, whose success path has to be
 *   scrubbed rather than only its errors.
 * - `error.response.request.options` is a third reference to the same shape.
 *
 * `options` is a class instance whose fields are accessors, so
 * `Object.keys(options)` is empty and a generic walk finds nothing. Each
 * property is rewritten by name for that reason.
 */

interface GotLikeOptions {
  headers?: unknown;
  body?: unknown;
  json?: unknown;
  searchParams?: unknown;
  url?: unknown;
  /**
   * got 14 keeps every raw options object it was handed, in order, so the
   * revealed header record the wrapper built is reachable at
   * `error.options._init[1].headers.authorization` even after `options.headers`
   * has been rewritten. got 16 does not expose it under that name; scrubbing it
   * when present is what keeps one implementation correct across both majors.
   */
  _init?: unknown;
}

function scrubOptions(options: unknown, plan: ScrubPlan, where: string, depth = 0): void {
  if (options === null || typeof options !== 'object') {
    return;
  }

  const bag = options as GotLikeOptions;

  scrubHeaderBag(bag.headers, plan);

  try {
    bag.body = scrubBody(bag.body, plan);
    bag.json = scrubBody(bag.json, plan);
  } catch {
    // got validates on assignment, and a setter that refuses is not a reason to
    // fail the call: the assertion below decides whether the object is safe.
  }

  scrubQuery(bag.searchParams, plan);

  if (depth === 0 && Array.isArray(bag._init)) {
    bag._init.forEach((init: unknown, index: number) => {
      scrubOptions(init, plan, `${where}._init[${index}]`, depth + 1);
    });
  }

  // `options.url` is a `URL` on got 16 and can be a string on got 14, so the
  // two shapes are named rather than run through `String()`, which would have
  // stringified anything else to `[object Object]` and silently scrubbed nothing.
  const url = bag.url;
  const text = url instanceof URL ? url.href : typeof url === 'string' ? url : undefined;

  if (text !== undefined) {
    const scrubbed = String(scrubUrlString(text, plan));

    if (scrubbed !== text) {
      try {
        bag.url = url instanceof URL ? new URL(scrubbed) : scrubbed;
      } catch {
        // Same reasoning as above.
      }
    }
  }

  assertHeadersScrubbed(bag.headers, plan, 'got', where);
}

/**
 * Drop the request objects a got response and a got error hang on to.
 *
 * The same call the axios package has to make, for the same reason and one
 * level deeper. Searched rather than assumed, a 200 from got 16 keeps the
 * revealed header in exactly two places once `options.headers` has been
 * rewritten:
 *
 * - `response.req._header`, the outgoing header block as raw text.
 * - `response.req[Symbol(kOutHeaders)].authorization[1]`.
 *
 * Both are Node internals on the `ClientRequest`. Rewriting them means keying
 * off `_header` and a symbol whose name is not API, and a silent break there
 * means the credential stays. Dropping the reference is the honest answer, and
 * it is the same trade the axios package makes for `response.request`.
 *
 * got's own `Request` is dropped alongside it, because it is a stream over the
 * same `ClientRequest`.
 *
 * Conditional on a non-empty plan, so a call site that has not adopted a
 * `SensitiveString` still gets got's own object back, `request` included.
 */
function dropRequest(holder: unknown): void {
  if (holder === null || typeof holder !== 'object') {
    return;
  }

  for (const field of ['request', 'req'] as const) {
    try {
      (holder as Record<string, unknown>)[field] = undefined;
    } catch {
      // Non-writable. The header assertion is what decides safety.
    }
  }
}

/**
 * The URL got copies onto the response, and the redirect chain beside it.
 *
 * A got `Response` carries `url` and `redirectUrls`, both holding the request
 * URL in full. A credential in a query parameter is therefore on the response
 * and on `error.response` regardless of what `options` says. Found by the deep
 * leak walk in the security suite; `util.inspect` at depth 8 does not reach it
 * on a rejection.
 */
function scrubResponseUrls(response: unknown, plan: ScrubPlan): void {
  if (response === null || typeof response !== 'object' || plan.queryKeys.length === 0) {
    return;
  }

  const bag = response as { url?: unknown; redirectUrls?: unknown };

  try {
    if (typeof bag.url === 'string') {
      bag.url = scrubUrlString(bag.url, plan);
    }

    if (Array.isArray(bag.redirectUrls)) {
      bag.redirectUrls = bag.redirectUrls.map((entry: unknown) =>
        entry instanceof URL
          ? new URL(String(scrubUrlString(entry.toString(), plan)))
          : scrubUrlString(entry, plan)
      );
    }
  } catch {
    // Non-writable. The suite's leak walk is what decides safety.
  }
}

/** `response.request.options`, which is where a 200 keeps the credential. */
export function scrubResponse<T>(response: T, plan: ScrubPlan): T {
  if (planIsEmpty(plan) || response === null || typeof response !== 'object') {
    return response;
  }

  const request = (response as { request?: { options?: unknown } }).request;

  scrubOptions(request?.options, plan, 'response.request.options');
  scrubResponseUrls(response, plan);
  dropRequest(response);

  return response;
}

/**
 * `error.options`, the nested `error.response.request.options`, and the message.
 *
 * @param rawUrl - The revealed request URL, still held by the caller for the
 *   duration of the call. got interpolates it into `HTTPError.message`, which
 *   is the one place a query credential survives every property rewrite.
 */
export function scrubError(error: unknown, plan: ScrubPlan, rawUrl?: string): unknown {
  if (planIsEmpty(plan) || error === null || typeof error !== 'object') {
    return error;
  }

  const got = error as {
    options?: unknown;
    response?: { request?: { options?: unknown } };
    request?: { options?: unknown };
  };

  scrubOptions(got.options, plan, 'error.options');
  scrubOptions(got.request?.options, plan, 'error.request.options');
  scrubOptions(got.response?.request?.options, plan, 'error.response.request.options');

  if (rawUrl !== undefined) {
    scrubMessage(error, rawUrl, String(scrubUrlString(rawUrl, plan)));
  }

  scrubResponseUrls(got.response, plan);
  dropRequest(got.response);
  dropRequest(error);

  return error;
}
