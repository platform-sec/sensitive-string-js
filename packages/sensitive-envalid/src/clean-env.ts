import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  accessorMiddleware,
  customCleanEnv,
  EnvMissingError,
  strictProxyMiddleware,
} from 'envalid';
import type { CleanedEnv, ReporterOptions } from 'envalid';

import { EnvValidationError, SensitiveFormatError } from './errors.js';
import type { EnvVariableFailure } from './errors.js';
import { sensitiveMeta } from './validators.js';

/**
 * `cleanEnv` with a report that never prints a value and never exits.
 *
 * Three options exist for intercepting envalid's error path, and which one is
 * right turns on a detail worth measuring rather than assuming:
 *
 * | Option | Measured result, envalid 8.2.0 |
 * |---|---|
 * | `reporter: null` | envalid rethrows the first failure and stops. One bad variable per run, and the value is in the thrown message |
 * | Replace the logger | Not possible from outside. `console.error.bind(console)` is captured at import |
 * | Replace the reporter | It receives every failure at once, in `errors`, and a throw from it propagates out of `cleanEnv` |
 *
 * The third is the hook. The first is what a first pass reaches for and should
 * not: `reporter: null` gives up envalid's most useful behaviour, which is
 * naming every misconfigured variable in one run.
 *
 * Two behaviours are deliberately not preserved. envalid's default reporter
 * calls `process.exit(1)`, which takes the decision to exit away from the entry
 * point. And a custom reporter that neither exits nor throws makes `cleanEnv`
 * return `{}` with every declared variable missing; combined with the strict
 * proxy, that surfaces much later as `ReferenceError: [envalid] Env var not
 * found: DB_PASSWORD` from whatever code touched it first, at which point
 * nothing points back at the validation that did not happen. So this always
 * throws on a failure and never exits.
 */

export interface CleanEnvSafeOptions {
  /**
   * Extra property names the strict proxy should answer rather than throw for.
   *
   * Passed to envalid's `strictProxyMiddleware`. Useful for a framework that
   * probes the object for a name it did not declare.
   */
  readonly extraInspectables?: readonly string[];
}

/**
 * Validate an environment into a typed, redacting object.
 *
 * @throws EnvValidationError when any variable is invalid or absent. Every
 *   failure from the run is on the error, the message names each variable and
 *   its class, and no message holds a value.
 *
 * @example
 * ```ts
 * import { port } from 'envalid';
 * import { cleanEnvSafe, credential } from '@platform-sec/sensitive-string-envalid';
 *
 * const env = cleanEnvSafe(process.env, {
 *   DB_PASSWORD: credential({ label: 'db_password' }),
 *   PORT: port(),
 * });
 *
 * env.DB_PASSWORD.reveal({ name: 'connect', reason: 'open the pool' });
 * ```
 */
export function cleanEnvSafe<S>(
  source: unknown,
  validators: S,
  options: CleanEnvSafeOptions = {}
): CleanedEnv<S> {
  const bound = bindValidatorNames(validators);

  const reporter = (report: ReporterOptions<S>): void => {
    const failures = collectFailures(report.errors, validators);

    if (failures.length > 0) {
      throw new EnvValidationError(failures);
    }
  };

  const proxyOptions =
    options.extraInspectables === undefined
      ? undefined
      : { extraInspectables: [...options.extraInspectables] };

  return customCleanEnv(
    source,
    bound,
    (cleaned, rawEnv) => {
      wrapSensitiveDefaults(cleaned, validators);

      // `applyDefaultMiddleware` is these two in this order and takes no proxy
      // options, so the composition is spelled out rather than wrapped.
      return strictProxyMiddleware(accessorMiddleware(cleaned, rawEnv), rawEnv, proxyOptions);
    },
    { reporter }
  ) as CleanedEnv<S>;
}

/**
 * Rebind each sensitive validator's parse function to its own variable name.
 *
 * The name is the default audit label, and this is the only place it is known:
 * envalid calls `spec._parse(rawValue)` and passes nothing else.
 */
function bindValidatorNames<S>(validators: S): S {
  if (validators === null || typeof validators !== 'object') {
    return validators;
  }

  const bound: Record<string, unknown> = {};

  for (const [name, spec] of Object.entries(validators)) {
    const meta = sensitiveMeta(spec);

    bound[name] =
      meta === undefined ? spec : { ...(spec as Record<string, unknown>), _parse: meta.bind(name) };
  }

  return bound as S;
}

/**
 * Wrap the values envalid filled from a `sensitiveDefault`.
 *
 * Runs on the cleaned object before it is frozen and proxied. A sensitive
 * validator's parse function always returns an instance, so a marked name that
 * came back as a raw `string` can only have come from the default path, which
 * envalid assigns without validating. That makes the test exact rather than a
 * guess.
 */
function wrapSensitiveDefaults<S>(cleaned: unknown, validators: S): void {
  if (validators === null || typeof validators !== 'object') {
    return;
  }

  const target = cleaned as Record<string, unknown>;

  for (const [name, spec] of Object.entries(validators)) {
    const meta = sensitiveMeta(spec);

    if (meta === undefined) {
      continue;
    }

    const current = target[name];

    if (typeof current === 'string') {
      target[name] = new SensitiveString(current, meta.klass, meta.label ?? name);
    }
  }
}

/**
 * Turn envalid's error map into failures that carry no value.
 *
 * The rebuild is not uniform, because the two error types do not carry the same
 * thing.
 *
 * | Error | Message | Treatment |
 * |---|---|---|
 * | `EnvError` (invalid) | `Invalid port input: "..."`, holding the value | Replaced with the name and the class |
 * | `SensitiveFormatError` (invalid) | Written by this package, holding no value | Passed through |
 * | `EnvMissingError` (absent) | `formatSpecDescription(spec)` | Passed through |
 *
 * An `EnvMissingError` message is built from the caller's own `desc`, `example`
 * and `docs` and from nothing the environment supplied, so passing it through
 * discloses nothing and keeps the half of envalid's output that is actually
 * actionable. Only the invalid case loses detail, and it loses it for every
 * variable rather than per name, because deciding per name means being wrong
 * once. The `PORT` case is where that stings: a mistyped port is an ordinary
 * configuration error whose message would have been useful.
 */
function collectFailures<S>(
  errors: Partial<Record<keyof S, Error>>,
  validators: S
): EnvVariableFailure[] {
  const failures: EnvVariableFailure[] = [];
  const specs = (validators ?? {}) as Record<string, unknown>;

  for (const [variable, error] of Object.entries(errors)) {
    if (error === undefined) {
      continue;
    }

    const meta = sensitiveMeta(specs[variable]);
    const klass = meta?.klass ?? 'plain';

    if (error instanceof EnvMissingError) {
      const described = error.message;

      failures.push({
        variable,
        klass,
        kind: 'missing',
        // envalid builds this from `${spec.desc}` even when `desc` is absent,
        // so an undescribed variable arrives with the literal text
        // "undefined". Its own formatter has the same fallback.
        detail: described === '' || described === 'undefined' ? '(required)' : described,
      });
      continue;
    }

    failures.push({
      variable,
      klass,
      kind: 'invalid',
      detail:
        error instanceof SensitiveFormatError
          ? error.message
          : 'value rejected; the message is withheld because every built-in envalid validator ' +
            'embeds the raw input in it',
    });
  }

  return failures;
}
