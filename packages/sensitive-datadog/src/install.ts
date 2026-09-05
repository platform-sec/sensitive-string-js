import { createRequire } from 'node:module';

import {
  mergeScrubPolicy,
  resolveScrubPolicy,
  type ResolvedScrubPolicy,
  type ScrubPolicy,
} from '@platform-sec/sensitive-string-scrub';

import {
  composeQueryObfuscation,
  planHeaderCapture,
  type QueryStringObfuscation,
} from './config.js';
import { buildManualScrubber, buildRequestHook, censorSpan, type DatadogSpan } from './hooks.js';
import {
  DATADOG_POLICY,
  REQUEST_HEADER_PREFIX,
  RESPONSE_HEADER_PREFIX,
  projectHeaderPaths,
} from './paths.js';
import { COVERED_PLUGINS } from './seams.js';

/**
 * The entry point.
 *
 * An options wrapper is not available, the way it is for Sentry. `tracer.init()`
 * takes the agent's options and `tracer.use()` takes each plugin's, and the
 * header list this package cares about lives in the second. So the entry point
 * is a function taking the tracer, and it calls `tracer.use()` once per plugin
 * it covers.
 *
 * It can run before or after `tracer.init()`. Measured on `dd-trace` 6.14.0,
 * both orders scrub identically: 19 hook invocations either way, both header
 * tags rewritten, no canary in the payload. Worth measuring rather than
 * assuming, because `tracer.use()` before `init()` returns without any
 * indication it was accepted and the plugin manager's stored config reads
 * `hooks: {}` when inspected afterwards, which looks exactly like a silently
 * discarded option. It is not one.
 */

/** As much of a `dd-trace` tracer as this package touches. */
export interface DatadogTracer {
  use: (plugin: string, config: unknown) => unknown;
  startSpan?: (name: string, options?: unknown) => DatadogSpan;
  [key: string]: unknown;
}

/** What `installSensitiveScrubbing` was asked to do. */
export interface InstallOptions extends ScrubPolicy {
  /**
   * Headers to capture, routed through this package rather than set beside it.
   *
   * `dd-trace`'s own `headerTags` is an allowlist with an empty default, so a
   * user who names none gets none and this row's leak never happens. Routing
   * the list through here is what lets the package refuse the ones on the
   * denylist by default: a name that resolves to a denied key is still
   * captured, so the tag exists and its presence stays diagnostic, and the
   * hook replaces its value.
   *
   * A `headerTags` set in `tracer.init()` is picked up as well when the
   * tracer's resolved configuration can be read, so a caller who sets it there
   * and installs this package separately is covered either way.
   */
  readonly captureHeaders?: readonly string[];
  /**
   * Called once when something the package depends on is not available.
   *
   * The one case today is tag enumeration, which reads a field that appears in
   * no shipped type declaration. Defaults to a `console.warn`.
   */
  readonly onDegraded?: (message: string) => void;
  /**
   * Also scrub spans the application creates itself. Default true.
   *
   * A span from `tracer.startSpan`, `tracer.trace` or `tracer.wrap` never
   * reaches a plugin hook, and section 2.4's leak is a `serialize()` result on
   * a span tag, which is the one thing in this row the structural walk is the
   * only defence against. So `startSpan` is wrapped and the scrub runs at
   * `finish()`, after the application has had every chance to set tags.
   *
   * Turn it off to leave the tracer object untouched, at the cost of that
   * coverage. Plugin spans are unaffected either way.
   */
  readonly scrubManualSpans?: boolean;
}

/** What one installation covers, returned so a caller can assert on it. */
export interface Installation {
  /** The plugin ids this call configured. */
  readonly plugins: readonly string[];
  /** The header names handed to the agent. */
  readonly capturedHeaders: readonly string[];
  /** The subset of those whose values the hook censors. */
  readonly censoredHeaders: readonly string[];
  /** The composed query obfuscator handed to each plugin. */
  readonly queryStringObfuscation: QueryStringObfuscation;
  /** Whether the span tag walk is available, per the feature check. */
  readonly enumeratesTags: boolean;
  /** Whether spans the application creates itself are scrubbed at `finish()`. */
  readonly scrubsManualSpans: boolean;
  /** False when this call was a no-op because the tracer was already installed into. */
  readonly applied: boolean;
}

/** Marks a tracer this function already installed into. */
const APPLIED = Symbol.for('@platform-sec/sensitive-string-datadog.applied');

/**
 * Node core modules the agent instruments, re-required after `init()`.
 *
 * Measured on `dd-trace` 6.14.0: an application that required `http` before
 * `init()` and never requires it again runs with **no HTTP instrumentation at
 * all**, silently. No warning, no error, and manually created spans in the
 * same process export normally, so the trace payload looks healthy.
 *
 * The mechanism is not the one the documented requirement implies, and the
 * difference is why a repair is possible. The agent patches the `http` module
 * object **in place**: `require('http')` before and after `init()` returns the
 * identical object with identical `Server` and `request` properties, and
 * `Server.prototype.emit` is unchanged by `init()` and changed by the next
 * `require('http')`. So what is missing is not a patched reference, it is the
 * patch, and the agent's hook sits on module loading and fires on a require
 * and nothing else.
 *
 * Measured, four processes making one instrumented request each:
 *
 * | Variant | Spans |
 * |---|---|
 * | `require('http')` before `init()`, application uses that reference | None |
 * | `require('node:http')` before `init()` | None. The prefix makes no difference |
 * | re-required after `init()`, application uses the new reference | `web.request`, `http.request` |
 * | re-required after `init()` and the result **discarded** | `web.request`, `http.request` |
 *
 * The last row is the informative one: the application held the pre-init
 * reference throughout and was instrumented anyway. So one require anywhere
 * after `init()` repatches the shared object for every reference already
 * handed out, which is what this list does.
 *
 * Deliberately core modules only. Requiring `undici` or `next` speculatively
 * would throw for an application that does not have them, and the `catch`
 * would then be hiding a real error rather than an absent optional runtime.
 *
 * This does not transfer to ESM, where the requirement is
 * `--import dd-trace/initialize.mjs` and an import cannot be re-run for its
 * side effect. The README says so.
 */
const REPAIRED_MODULES = ['http', 'https', 'http2', 'net', 'dns'] as const;

/**
 * Install scrubbing into a `dd-trace` tracer.
 *
 * @param tracer - The tracer, initialized or not
 * @param options - What to scrub, over this package's Datadog-shaped defaults
 *                  and the shared denylist
 * @returns What was installed. A second call on the same tracer returns
 *          `applied: false` and changes nothing.
 *
 * @throws ScrubPolicyError when the policy cannot be resolved, which happens
 *         at install time where the stack trace points at the caller rather
 *         than at a span six hours later.
 *
 * @example
 * ```ts
 * import tracer from 'dd-trace';
 * import { installSensitiveScrubbing } from '@platform-sec/sensitive-string-datadog';
 *
 * tracer.init({ service: 'payments' });
 *
 * installSensitiveScrubbing(tracer, {
 *   denyKeys: ['x-internal-signature'],
 *   captureHeaders: ['authorization', 'x-request-id'],
 *   onScrub: (report) => metrics.increment('sensitive.scrubbed', report.deniedKeys.length),
 * });
 * ```
 */
export function installSensitiveScrubbing(
  tracer: DatadogTracer,
  options: InstallOptions = {}
): Installation {
  if (isApplied(tracer)) {
    // Idempotent, and marked on the tracer rather than in a module-level set,
    // so two copies of this package in one dependency tree still compose once.
    return {
      plugins: [],
      capturedHeaders: [],
      censoredHeaders: [],
      queryStringObfuscation: false,
      enumeratesTags: false,
      scrubsManualSpans: false,
      applied: false,
    };
  }

  const policy = resolvePolicy(options);
  const existing = readTracerConfig(tracer);

  const { capture, censored } = planHeaderCapture(
    [...(options.captureHeaders ?? []), ...(existing.headerTags ?? [])],
    policy
  );

  const queryStringObfuscation = composeQueryObfuscation(existing.queryStringObfuscation, policy);
  const enumeratesTags = checkEnumeration(tracer, options.onDegraded);
  const plugins: string[] = [];

  for (const covered of COVERED_PLUGINS) {
    const previous = readPluginConfig(tracer, covered.plugin);

    tracer.use(covered.plugin, {
      ...previous,
      // Only when there is a list. The plugin manager builds a plugin's config
      // as `{...sharedConfig, ...pluginConfig}`, and the shared config's
      // `headers` is the tracer's own `headerTags`, so writing an empty array
      // here would *replace* it and silently turn off a capture the operator
      // configured. That is the shape a caller who installs before
      // `tracer.init()` is in, since the resolved configuration does not exist
      // yet to be read. Omitting the key lets the agent's own list stand, and
      // the hook scrubs whatever it finds either way.
      ...(capture.length === 0 ? {} : { headers: capture }),
      queryStringObfuscation,
      hooks: {
        ...(previous?.['hooks'] as Record<string, unknown> | undefined),
        request: enumeratesTags
          ? buildRequestHook(policy, userHook(previous))
          : blindHook(policy, censored, userHook(previous)),
      },
    });

    plugins.push(covered.plugin);
  }

  const scrubsManualSpans =
    options.scrubManualSpans !== false &&
    enumeratesTags &&
    wrapManualSpans(tracer, buildManualScrubber(policy), options.onDegraded);

  repairCoreModules();

  Object.defineProperty(tracer, APPLIED, { value: true, enumerable: false });

  return {
    plugins,
    capturedHeaders: capture,
    censoredHeaders: censored,
    queryStringObfuscation,
    enumeratesTags,
    scrubsManualSpans,
    applied: true,
  };
}

/**
 * Wrap `startSpan` so a span the application made is scrubbed when it finishes.
 *
 * On the **inner** tracer where that is reachable, and on the exported proxy
 * otherwise. The difference is coverage rather than style: measured on
 * `dd-trace` 6.14.0, `tracer.trace()` and `tracer.wrap()` reach
 * `DatadogTracer.prototype.startSpan` through the inner tracer and never
 * through the proxy, so wrapping only the proxy would cover `startSpan` and
 * miss the two convenience wrappers most applications actually use.
 *
 * `finish` is wrapped per span rather than on the prototype. The prototype is
 * shared with every span the agent creates for itself, and patching it would
 * put this package on the path of spans nobody asked it to touch; wrapping the
 * span that was just handed out costs one property assignment on an object
 * that is about to be written to anyway.
 *
 * @returns Whether the wrap took
 */
function wrapManualSpans(
  tracer: DatadogTracer,
  scrub: (span: DatadogSpan) => void,
  onDegraded: ((message: string) => void) | undefined
): boolean {
  const target = manualSpanTarget(tracer);

  if (target === null) {
    degrade(
      onDegraded,
      'sensitive-string-datadog: this dd-trace does not expose a startSpan to wrap, so ' +
        'spans the application creates itself are not scrubbed. Spans from instrumented ' +
        'requests still are. See the README section on manual spans.'
    );

    return false;
  }

  const original = target.startSpan;

  target.startSpan = function wrapped(this: unknown, ...args: unknown[]): DatadogSpan {
    const span = (original as (...rest: unknown[]) => DatadogSpan).apply(this, args);

    wrapFinish(span, scrub);

    return span;
  };

  return true;
}

/** The object whose `startSpan` every manual span goes through, or `null`. */
function manualSpanTarget(tracer: DatadogTracer): { startSpan: unknown } | null {
  try {
    const inner = tracer['_tracer'] as { startSpan?: unknown } | undefined;

    if (typeof inner?.startSpan === 'function') {
      return inner as { startSpan: unknown };
    }

    if (typeof tracer.startSpan === 'function') {
      return tracer as unknown as { startSpan: unknown };
    }
  } catch {
    // Falls through.
  }

  return null;
}

/**
 * Scrub at `finish()`, then finish, whatever happens.
 *
 * The scrub has to run before the agent formats the span, and `finish` is the
 * last moment the application can still have set a tag.
 *
 * The `try`/`catch` is the part that matters, and it is not symmetry with the
 * hook. A hook body is called by the agent, which answers a throw by dropping
 * that one span; `finish()` is called by the **application**, which would
 * answer a throw by propagating it into whatever was recording a span. So the
 * deliberate last-resort rethrow of `hooks.ts` must not escape here. It is
 * caught, the span is emptied through the public `setTag` instead, and the
 * span is finished either way: a caller who wrote `span.finish()` gets a
 * finished span, not an exception and a span that never closes.
 */
function wrapFinish(span: DatadogSpan, scrub: (span: DatadogSpan) => void): void {
  const original = span.finish;

  if (typeof original !== 'function') {
    return;
  }

  try {
    span.finish = function finish(this: DatadogSpan, finishTime?: number): void {
      try {
        scrub(this);
      } catch {
        censorSpan(this);
      }

      original.call(this, finishTime);
    };
  } catch {
    // A frozen span. Plugin spans are unaffected.
  }
}

/** Whether `installSensitiveScrubbing` already ran against this tracer. */
export function isApplied(tracer: DatadogTracer): boolean {
  return (tracer as unknown as Record<symbol, unknown>)[APPLIED] === true;
}

/**
 * Resolve the policy, then project it into Datadog's tag vocabulary and
 * resolve again.
 *
 * Twice, and both at install time. The first pass folds the defaults in and
 * tells the projection which key names are denied; the second turns those into
 * exact denied tag paths, so the flat key
 * `http.request.headers.authorization` matches a denylist entry written as
 * `authorization`. Neither pass happens per span.
 */
function resolvePolicy(options: InstallOptions): ResolvedScrubPolicy {
  const merged = mergeScrubPolicy(DATADOG_POLICY, options);
  const first = resolveScrubPolicy(merged);

  return resolveScrubPolicy({
    ...merged,
    denyPaths: [...(merged.denyPaths ?? []), ...projectHeaderPaths(first.denyKeys)],
  });
}

/**
 * The two tracer settings this package composes with, read defensively.
 *
 * `_config` is not in the shipped declarations and does not exist at all
 * before `init()`. Both are ordinary: a caller installing before `init()` has
 * not configured anything yet, and a caller who set `headerTags` in `init()`
 * has, and this reads it so the two lists are not silently split. When the
 * read fails the caller's own `captureHeaders` still applies, which is the
 * list this package documents.
 */
function readTracerConfig(tracer: DatadogTracer): {
  headerTags?: readonly string[];
  queryStringObfuscation?: QueryStringObfuscation;
} {
  try {
    const inner = tracer['_tracer'] as Record<string, unknown> | undefined;
    const config = (inner?.['_config'] ?? tracer['_config']) as Record<string, unknown> | undefined;

    if (config === undefined) {
      return {};
    }

    const headerTags = config['headerTags'];
    const obfuscation = config['DD_TRACE_OBFUSCATION_QUERY_STRING_REGEXP'];

    return {
      ...(Array.isArray(headerTags) ? { headerTags: headerTags as readonly string[] } : {}),
      ...(typeof obfuscation === 'string' || typeof obfuscation === 'boolean'
        ? { queryStringObfuscation: obfuscation }
        : {}),
    };
  } catch {
    return {};
  }
}

/**
 * The config already stored for one plugin, so `tracer.use()` composes.
 *
 * `configurePlugin` replaces `_configsByName[name]` outright; its own source
 * carries a `// TODO: merge config instead of replacing`. So a caller who ran
 * `tracer.use('http', { hooks: { request } })` before this package would lose
 * their hook, and invariant 12 is that a user hook is composed and never
 * replaced. Reading the stored config back is what keeps that true, and it is
 * guarded because the field is private.
 */
function readPluginConfig(
  tracer: DatadogTracer,
  plugin: string
): Record<string, unknown> | undefined {
  try {
    const inner = tracer['_tracer'] as Record<string, unknown> | undefined;
    const manager = (inner?.['_pluginManager'] ?? tracer['_pluginManager']) as
      Record<string, unknown> | undefined;
    const configs = manager?.['_configsByName'] as Record<string, unknown> | undefined;
    const stored = configs?.[plugin];

    return stored !== null && typeof stored === 'object'
      ? (stored as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/** The caller's own `hooks.request` for one plugin, if they set one. */
function userHook(
  previous: Record<string, unknown> | undefined
): ((...args: unknown[]) => unknown) | undefined {
  const hooks = previous?.['hooks'] as Record<string, unknown> | undefined;
  const request = hooks?.['request'];

  return typeof request === 'function' ? (request as (...args: unknown[]) => unknown) : undefined;
}

/**
 * Whether the span tag walk is available on this `dd-trace`.
 *
 * One throwaway span at install time, rather than a per-span `try`/`catch`
 * that silently finds nothing. A tracer with no `startSpan` is one that has
 * not been initialized yet, and enumeration is assumed available: the field
 * this checks for exists in every 6.x release, and the alternative would be to
 * degrade every caller who installs before `init()`, which the README
 * recommends they do.
 */
function checkEnumeration(
  tracer: DatadogTracer,
  onDegraded: ((message: string) => void) | undefined
): boolean {
  if (typeof tracer.startSpan !== 'function') {
    return true;
  }

  try {
    const span = tracer.startSpan('sensitive-string.feature-check');
    const context = span.context();
    const tags = typeof context.getTags === 'function' ? context.getTags() : context._tags;

    // Finished immediately. A span this short is sampled like any other and
    // carries nothing, which is the point: it exists to be asked a question.
    (span as unknown as { finish?: () => void }).finish?.();

    if (tags !== null && typeof tags === 'object') {
      return true;
    }
  } catch {
    // Falls through to the degraded path below.
  }

  degrade(
    onDegraded,
    'sensitive-string-datadog: this dd-trace does not expose span tags through ' +
      'span.context().getTags(), so application-set span tags are not scrubbed. ' +
      'Captured header values still are. See the README section on tag enumeration.'
  );

  return false;
}

function degrade(onDegraded: ((message: string) => void) | undefined, message: string): void {
  try {
    if (onDegraded === undefined) {
      // The default, because a package that loses a defence layer silently is
      // the failure this message exists to prevent. Pass `onDegraded` to route
      // it into a real logger.
      // eslint-disable-next-line no-console
      console.warn(message);

      return;
    }

    onDegraded(message);
  } catch {
    // A degradation callback that throws must not take the install with it.
  }
}

/**
 * The hook used when tag enumeration is unavailable.
 *
 * It censors the header tags it knows can exist, through the public `setTag`
 * alone, which covers the leak this row exists for. It cannot tell whether a
 * given header was actually present, so it writes a censored tag either way.
 * A tag saying a credential header was censored when the request carried none
 * is a false positive in a span; the alternative is a real credential in one,
 * and that is not a close call.
 */
function blindHook(
  policy: ResolvedScrubPolicy,
  censored: readonly string[],
  user?: (...args: unknown[]) => unknown
): (span?: DatadogSpan, ...rest: unknown[]) => void {
  const keys = censored.flatMap((name) => [
    `${REQUEST_HEADER_PREFIX}${name}`,
    `${RESPONSE_HEADER_PREFIX}${name}`,
  ]);

  return (span?: DatadogSpan, ...rest: unknown[]): void => {
    if (span !== undefined) {
      for (const key of keys) {
        span.setTag(key, policy.censor);
      }
    }

    if (user === undefined) {
      return;
    }

    try {
      user(span, ...rest);
    } catch {
      // As in `buildRequestHook`: a caller hook that throws costs their
      // addition, not the span.
    }
  };
}

/**
 * Repair the instrumentation an early `require` silently disabled.
 *
 * Looks like a no-op and is not one; see `REPAIRED_MODULES`. Idempotent, cheap,
 * and each module in its own `try`/`catch` because `http2` is absent on some
 * runtimes.
 *
 * This is the one thing in either package that helps a user who has not made a
 * mistake this library knows about. The README says plainly that it is a
 * `dd-trace` repair rather than a redaction feature, so nobody installs this
 * package for it.
 */
function repairCoreModules(): void {
  let require_: NodeRequire;

  try {
    require_ = createRequire(process.cwd() + '/');
  } catch {
    return;
  }

  for (const id of REPAIRED_MODULES) {
    try {
      require_(id);
    } catch {
      // Not available on this runtime.
    }
  }
}
