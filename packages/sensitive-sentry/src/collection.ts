import type { NodeOptions } from '@sentry/node';

/**
 * What Sentry collects, and why this package does not change it for you.
 *
 * `@sentry/core` 10.73.0 replaced `sendDefaultPii` with a `dataCollection`
 * object of per-category switches and marks `sendDefaultPii` for removal in
 * v11. The categories that matter here, with the defaults the SDK documents:
 *
 * | Category | Default | Note |
 * |---|---|---|
 * | `httpHeaders` | `{ request: true, response: true }` | The measured `authorization` leak |
 * | `cookies` | `true` | Measured |
 * | `urlQueryParams` | `true` | Measured |
 * | `httpBodies` | all four targets | Request and response bodies both ways |
 * | `stackFrameVariables` | `true` | Gated by `includeLocalVariables` |
 * | `databaseQueryData` | `true` | Query parameters and inline literals |
 * | `userInfo` | `false` | |
 * | `genAI` | `{ inputs: true, outputs: true }` | Prompts and completions |
 *
 * Read that against the measurement: `sendDefaultPii` defaults to `false`, and
 * headers, cookies and query strings were still captured verbatim at stock
 * settings, because these category defaults are what governs collection. An
 * operator who has read the `sendDefaultPii` documentation and concluded that
 * no PII is sent has concluded something the SDK does not do.
 *
 * Silently changing what an error tracker collects is a large behavioural
 * change to make on someone's behalf from inside a scrubbing package, and a
 * user who finds their events emptier than expected must be able to find the
 * line that did it in their own code. So this is an object to spread, not a
 * default to inherit.
 */
export const recommendedDataCollection: NonNullable<NodeOptions['dataCollection']> = {
  /**
   * Headers are still collected. The denylist covers the credential-bearing
   * ones by name and the rest of a header set is most of what makes an error
   * report actionable.
   */
  httpHeaders: { request: true, response: true },

  /**
   * Off. A cookie jar is credentials by construction, the names are the
   * application's rather than anything a list can describe, and the scrubber
   * censors the whole subtree anyway. Not collecting it is cheaper and does
   * not depend on the scrubber running.
   */
  cookies: false,

  /**
   * On. Query parameters are scrubbed by name and the route is what makes the
   * URL worth having.
   */
  urlQueryParams: true,

  /**
   * Off. A request body is arbitrary application shape, and a key denylist
   * over an arbitrary shape is weaker than not collecting it. This is the one
   * category where the design's own open question, Q4, leans toward not
   * collecting rather than scrubbing after the fact.
   */
  httpBodies: [],

  /**
   * Off. Query parameters and inline literals in a statement are values the
   * application put there, and a parameter has no name to match on.
   */
  databaseQueryData: false,

  /**
   * Off, and it is already the SDK default. Named here so a reader of this
   * object sees the whole decision rather than the part that changes.
   */
  userInfo: false,

  /**
   * Off. Prompts and completions are the 3.8 problem in Sentry's envelope,
   * and this package has no scrubber for free-form model text.
   */
  genAI: { inputs: false, outputs: false },
};

/**
 * The categories this object turns off, for the README and for a test that
 * keeps the two in step.
 */
export const TIGHTENED_CATEGORIES: readonly string[] = [
  'cookies',
  'httpBodies',
  'databaseQueryData',
  'genAI',
];
