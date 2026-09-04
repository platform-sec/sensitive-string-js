import {
  assertHeadersScrubbed,
  planIsEmpty,
  scrubBody,
  scrubHeaderBag,
  scrubQuery,
  scrubUrlString,
} from '@platform-sec/sensitive-string-http';
import type { ScrubPlan } from '@platform-sec/sensitive-string-http';
import type { AxiosError, AxiosResponse } from 'axios';

/**
 * The axios-specific property list.
 *
 * Measured on axios 1.20.0 against a local recording server:
 *
 * - A rejection carries the revealed header in `error.config.headers`, and
 *   `error.toJSON()` includes it. `toJSON()` is what every axios-aware logger
 *   and error reporter calls, so this is the one client whose leak survives
 *   `JSON.stringify(error)` as well as `util.inspect`.
 * - A **resolution** carries it too, in `response.config.headers`. So
 *   `console.log(res)` after a successful call prints the credential and no
 *   error ever existed for an error handler to scrub.
 * - Both carry a Node `ClientRequest` on `request`, which holds its own copy of
 *   the header block in internal state that no supported API rewrites.
 *
 * Overwriting `config` fixes `toJSON()` with no separate patch, because
 * `toJSON()` reads from `config`. The `ClientRequest` cannot be fixed, so it is
 * dropped: `response.request` becomes `undefined` and `error.request` is
 * deleted. That is a deliberate break in drop-in behaviour, and it is scoped as
 * narrowly as it can be, to a request whose plan is non-empty.
 */

interface AxiosLikeConfig {
  headers?: unknown;
  data?: unknown;
  params?: unknown;
  url?: unknown;
}

function scrubConfig(config: AxiosLikeConfig | undefined, plan: ScrubPlan, where: string): void {
  if (config === undefined || config === null) {
    return;
  }

  scrubHeaderBag(config.headers, plan);
  config.data = scrubBody(config.data, plan);
  scrubQuery(config.params, plan);
  // The wrapper merges the revealed query into the URL, so `config.url` is a
  // third place the value survives, on both settlement paths.
  config.url = scrubUrlString(config.url, plan);
  assertHeadersScrubbed(config.headers, plan, 'axios', where);
}

/** Rewrite both the response's own config and any nested one, then drop `request`. */
export function scrubResponse<T>(response: AxiosResponse<T>, plan: ScrubPlan): AxiosResponse<T> {
  if (planIsEmpty(plan)) {
    // Invariant 9.2, item 1: a request that carried nothing sensitive gets the
    // client's own object back, `request` included, so the wrapper can be
    // adopted one call site at a time.
    return response;
  }

  scrubConfig(response.config as AxiosLikeConfig, plan, 'response.config');

  // A `ClientRequest`'s header state is internal and not safely rewritable.
  // Returning it would leave the credential printable through
  // `util.inspect(res)` after a successful call.
  (response as { request?: unknown }).request = undefined;

  return response;
}

/** The same, plus the nested `error.response`, which axios gives its own config. */
export function scrubError(error: unknown, plan: ScrubPlan): unknown {
  if (planIsEmpty(plan) || error === null || typeof error !== 'object') {
    return error;
  }

  const axiosError = error as AxiosError;

  scrubConfig(axiosError.config as AxiosLikeConfig | undefined, plan, 'error.config');

  if (axiosError.response !== undefined) {
    scrubConfig(axiosError.response.config as AxiosLikeConfig, plan, 'error.response.config');
    (axiosError.response as { request?: unknown }).request = undefined;
  }

  delete (axiosError as { request?: unknown }).request;

  return axiosError;
}
