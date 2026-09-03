import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { extractSensitive, type RequestPartSpec } from './request-part.js';

const SensitiveParamParam = createParamDecorator((spec: RequestPartSpec, ctx: ExecutionContext) =>
  extractSensitive(ctx, 'params', spec)
);

/**
 * Extract a route parameter and wrap it as a `SensitiveString`.
 *
 * Yields `null` when the route parameter is absent or empty, so the parameter type is
 * nullable.
 *
 * A global `ValidationPipe` skips custom parameter decorators unless
 * `validateCustomDecorators: true`. Leave that off: with it on, class-validator
 * is asked to validate a `SensitiveString` carrying no validation metadata,
 * which fails under `forbidUnknownValues`.
 *
 * @param name - Param name to read
 * @param klass - Sensitivity class for the wrapped value
 * @param label - Audit label; defaults to `name`
 *
 * @example
 * ```ts
 * getResource(
 *   \@SensitiveParam('userId', 'credential') value: SensitiveString<'credential'> | null,
 * ) {}
 * ```
 */
export function SensitiveParam(
  name: string,
  klass: SensitivityClass,
  label?: string
): ParameterDecorator {
  return SensitiveParamParam({ name, klass, label } satisfies RequestPartSpec);
}
