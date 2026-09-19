import { createChildContext } from '@platform-sec/sensitive-string-core';
import type { RevealContext } from '@platform-sec/sensitive-string-core';

import type { ContextOption, RequestDescriptor } from './types.js';

/**
 * The per-attempt reveal context.
 *
 * Per attempt, not per call, so `tags.attempt` is meaningful and a retry storm
 * is visible in the audit log as what it is. Invariant: exactly one reveal per
 * outgoing value per attempt, and one audit record per reveal, so the audit
 * count matches the number of times the value crossed a socket.
 *
 * Two things about `createChildContext` the call site has to get right, and
 * both of them are why this function exists rather than an inline spread.
 *
 * It reads the ambient context itself and returns the overrides alone when
 * there is none, so a reveal here always runs under a named context and there
 * is no undefined case to handle. This package never invents a parent.
 *
 * And it merges by spread, so a `reason` key present with the value `undefined`
 * overwrites an inherited `reason` with `undefined` rather than falling back to
 * it. The overrides object below is therefore assembled by omitting absent
 * keys, not by assigning `undefined` to them. `exactOptionalPropertyTypes`
 * catches that at the type level for an object literal and not for one
 * assembled at run time from user options, which is exactly what this is.
 */
export function buildAttemptContext(
  request: RequestDescriptor,
  client: string,
  option: ContextOption | undefined,
  reason: string | undefined
): RevealContext {
  const supplied = typeof option === 'function' ? option(request) : option;

  const overrides: Partial<RevealContext> & { name: string } = {
    name: supplied?.name ?? `${request.method} ${request.url}`,
    tags: {
      ...(supplied?.tags ?? {}),
      // Set on every reveal these packages perform, and read by core's
      // destination binding: a value constructed with `destinations` is
      // revealed only under a context whose `sink` and `host` it allows, so
      // these two must describe the real destination of this attempt. `host`
      // is `URL.host`, which is the form a binding's entries are written in.
      sink: 'http',
      host: request.host,
      client,
      attempt: request.attempt,
      hop: request.hop,
    },
  };

  const resolvedReason = supplied?.reason ?? reason;

  if (resolvedReason !== undefined) {
    overrides.reason = resolvedReason;
  }

  // `auditReveal` is declared as a method on `RevealContext` and used as a
  // callback everywhere in this library, so carrying the reference forward is
  // the point rather than an accident of scoping.
  // eslint-disable-next-line @typescript-eslint/unbound-method -- see above.
  const auditReveal = (supplied as RevealContext | undefined)?.auditReveal;

  if (typeof auditReveal === 'function') {
    overrides.auditReveal = auditReveal;
  }

  return createChildContext(overrides);
}
