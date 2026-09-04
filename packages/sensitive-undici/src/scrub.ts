import {
  planIsEmpty,
  scrubHeaderBag,
  scrubMessage,
  scrubUrlString,
} from '@platform-sec/sensitive-string-http';
import type { ScrubPlan } from '@platform-sec/sensitive-string-http';

/**
 * undici attaches the outgoing headers to some of its errors, and the URL to
 * the message of others. Both are covered here; there is nothing else, because
 * a dispatcher response is a status, a header bag and a stream, and none of
 * them carries the request.
 */
export function scrubError(error: unknown, plan: ScrubPlan, rawUrl: string): unknown {
  if (planIsEmpty(plan) || error === null || typeof error !== 'object') {
    return error;
  }

  scrubHeaderBag((error as { headers?: unknown }).headers, plan);
  scrubMessage(error, rawUrl, String(scrubUrlString(rawUrl, plan)));

  const cause = (error as { cause?: unknown }).cause;

  if (cause !== null && typeof cause === 'object') {
    scrubMessage(cause, rawUrl, String(scrubUrlString(rawUrl, plan)));
  }

  return error;
}
