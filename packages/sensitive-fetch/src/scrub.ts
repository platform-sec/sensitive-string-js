import {
  planIsEmpty,
  scrubHeaderBag,
  scrubMessage,
  scrubUrlString,
} from '@platform-sec/sensitive-string-http';
import type { ScrubPlan } from '@platform-sec/sensitive-string-http';

/**
 * There is almost nothing to scrub, and that is a measurement rather than an omission.
 *
 * A `fetch` rejection is a `TypeError` with a `cause`, and a `Response` carries
 * no request headers, so neither settlement path retains the revealed value the
 * way axios's and got's do. What can retain it is the URL: a network failure's
 * message names the request, and a credential in a query parameter is in that
 * string.
 */
export function scrubError(error: unknown, plan: ScrubPlan, rawUrl: string): unknown {
  if (planIsEmpty(plan) || error === null || typeof error !== 'object') {
    return error;
  }

  scrubMessage(error, rawUrl, String(scrubUrlString(rawUrl, plan)));

  const cause = (error as { cause?: unknown }).cause;

  if (cause !== null && typeof cause === 'object') {
    scrubMessage(cause, rawUrl, String(scrubUrlString(rawUrl, plan)));
  }

  const request = (error as { request?: unknown }).request;

  if (typeof Request === 'function' && request instanceof Request) {
    scrubHeaderBag(request.headers, plan);
  }

  return error;
}

/** The success path, a no-op by measurement. Named so the fact lives in code. */
export function scrubResponse<T>(response: T, _plan: ScrubPlan): T {
  return response;
}
