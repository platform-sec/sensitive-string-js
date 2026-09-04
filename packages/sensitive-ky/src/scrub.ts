import {
  markerFor,
  planIsEmpty,
  scrubHeaderBag,
  scrubMessage,
  scrubUrlString,
} from '@platform-sec/sensitive-string-http';
import type { ScrubPlan } from '@platform-sec/sensitive-string-http';

/**
 * The ky-specific property list, which is the smallest of the five.
 *
 * ky runs on `fetch`, and a `Response` carries no request headers, so its
 * success path needs no scrub at all: measured, `util.inspect` on a ky response
 * holding a revealed `Authorization` finds nothing. ky and `fetch` are the two
 * clients where the wrapper returns the client's own object unchanged.
 *
 * The rejection is a different matter. `HTTPError` carries the `Request`, whose
 * headers are readable and, unlike axios's `ClientRequest`, mutable. So the
 * named headers are set to their markers rather than the object being dropped.
 *
 * Two things a `Request` will not let go of:
 *
 * - Its `url` is a getter with no setter. When the plan names a query key, the
 *   request is replaced wholesale with one built from the scrubbed URL.
 * - Its body is a consumed stream by the time an error exists, so a plan naming
 *   a body path also forces the replacement. `error.request.body` is `null` on
 *   a scrubbed error, and the README says so.
 */

function rebuild(request: Request, plan: ScrubPlan): Request {
  const url = String(scrubUrlString(request.url, plan));
  const headers = new Headers(request.headers);

  scrubHeaderBag(headers, plan);

  return new Request(url, { method: request.method, headers });
}

function needsRebuild(request: Request, plan: ScrubPlan): boolean {
  if (plan.bodyPaths.length > 0) {
    return true;
  }

  return String(scrubUrlString(request.url, plan)) !== request.url;
}

/** ky's `HTTPError`, and any error carrying a `Request`. */
export function scrubError(error: unknown, plan: ScrubPlan, rawUrl?: string): unknown {
  if (planIsEmpty(plan) || error === null || typeof error !== 'object') {
    return error;
  }

  const holder = error as { request?: unknown; response?: unknown; options?: unknown };

  // ky 2's `HTTPError` also carries the normalized options, whose `headers` is
  // a `Headers` built from the record this wrapper handed over and whose `body`
  // is the serialized JSON. Found by the suite's leak walk; `error.request`
  // alone is not the whole of it.
  scrubKyOptions(holder, plan);

  if (typeof Request === 'function' && holder.request instanceof Request) {
    try {
      holder.request = needsRebuild(holder.request, plan)
        ? rebuild(holder.request, plan)
        : scrubRequestHeaders(holder.request, plan);
    } catch {
      // A frozen error. The suite's leak walk decides safety.
    }
  }

  // A `Response`'s `url` is read-only, so a query credential cannot be rewritten
  // out of it. Dropping the reference is the same trade the axios package makes
  // for `ClientRequest`, and it applies only when a query value was revealed.
  if (plan.queryKeys.length > 0) {
    try {
      holder.response = undefined;
    } catch {
      // Same reasoning.
    }
  }

  if (rawUrl !== undefined) {
    scrubMessage(error, rawUrl, String(scrubUrlString(rawUrl, plan)));
  }

  return error;
}

/**
 * ky freezes the normalized options object it hangs off the error.
 *
 * `Object.isFrozen(error.options)` is true and `body` is a non-writable own
 * property holding the serialized JSON, so no in-place rewrite reaches it. The
 * `headers` inside it is a `Headers`, which is mutable, which is why the header
 * case looked fixed while the body case was still leaking.
 *
 * So the bag is replaced with a scrubbed shallow copy rather than mutated. The
 * copy is a plain object where ky's was frozen; nothing in ky reads it back
 * after the error is thrown.
 */
function scrubKyOptions(holder: { options?: unknown }, plan: ScrubPlan): void {
  const options = holder.options;

  if (options === null || typeof options !== 'object') {
    return;
  }

  const copy = { ...(options as Record<string, unknown>) };

  scrubHeaderBag(copy['headers'], plan);

  if (plan.bodyPaths.length > 0) {
    for (const field of ['json', 'body'] as const) {
      if (copy[field] !== undefined) {
        copy[field] = '[REDACTED:body]';
      }
    }
  }

  try {
    holder.options = copy;
  } catch {
    // The error itself refuses the assignment. The suite's leak walk decides
    // safety, and the header rewrite above still applied in place.
  }
}

function scrubRequestHeaders(request: Request, plan: ScrubPlan): Request {
  for (const name of plan.headers) {
    try {
      request.headers.set(name, markerFor(plan, 'header', name) ?? '[REDACTED]');
    } catch {
      // A forbidden header name the guard will not let us set. Rebuilding is
      // the fallback, and `needsRebuild` did not ask for it, so report it by
      // leaving the value for the leak assertion to catch rather than hiding it.
    }
  }

  return request;
}

/**
 * The success path, which is a no-op by measurement rather than by omission.
 *
 * Kept as a named export so the ky and `fetch` packages state the fact in code
 * rather than in a comment nobody reads, and so a future ky that starts
 * carrying request state has one place to change.
 */
export function scrubResponse<T>(response: T, _plan: ScrubPlan): T {
  return response;
}
