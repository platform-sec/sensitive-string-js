import { compileClassification } from '@platform-sec/sensitive-string-core';
import type {
  ClassificationSpec,
  CompiledClassification,
  FieldClass,
} from '@platform-sec/sensitive-string-core';

import type { GetAllOptions, GetJsonOptions, FieldMap } from './types.js';

/**
 * The fallback policy this layer applies over core's spec and matcher.
 *
 * `core` holds the type and the precedence only. The policy lives here because
 * this package requires an explicit fallback for a discovered key set and the
 * config and environment integration requires `'plain'` for the environment,
 * and neither default would be right in the other place.
 */

/**
 * A declared key set defaults to `'credential'`.
 *
 * The caller named a secret and declared its fields. A payload that grows a
 * field is the common case, and the failure that matters is a new secret
 * arriving unwrapped.
 */
export const DECLARED_FALLBACK: FieldClass = 'credential';

/** The spec for a `getJson` call. */
export function jsonSpec<F extends FieldMap>(options: GetJsonOptions<F>): CompiledClassification {
  const spec: ClassificationSpec = {
    fields: options.fields,
    ...(options.rules === undefined ? {} : { rules: options.rules }),
    fallback: options.fallback ?? DECLARED_FALLBACK,
  };

  return compileClassification(spec);
}

/**
 * The spec for a `getAll` call.
 *
 * There is no default here and the option is typed as required, so this
 * function has nothing to decide. The reason is in `GetAllOptions.fallback`:
 * fail-closed breaks a mixed config store in a way that looks like a
 * configuration bug, and fail-open under-protects a store where everything is
 * secret by construction. Requiring the option is the one place in this design
 * where no default is better than either default.
 */
export function allSpec(options: GetAllOptions): CompiledClassification {
  if (options.fallback === undefined) {
    throw new Error(
      'getAll requires an explicit fallback. Use `plain` for a store that mixes ' +
        'configuration with secrets, and `credential` for one where everything is secret.'
    );
  }

  const spec: ClassificationSpec = {
    ...(options.fields === undefined ? {} : { fields: options.fields }),
    ...(options.rules === undefined ? {} : { rules: options.rules }),
    fallback: options.fallback,
  };

  return compileClassification(spec);
}
