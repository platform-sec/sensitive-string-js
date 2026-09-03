import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { extractSensitive, type RequestPartSpec } from './request-part.js';

const SensitiveHeaderParam = createParamDecorator((spec: RequestPartSpec, ctx: ExecutionContext) =>
  extractSensitive(ctx, 'headers', spec)
);

/**
 * Extract a request header and wrap it as a `SensitiveString`.
 *
 * Yields `null` when the request header is absent or empty, so the parameter type is
 * nullable.
 *
 * A global `ValidationPipe` skips custom parameter decorators unless
 * `validateCustomDecorators: true`. Leave that off: with it on, class-validator
 * is asked to validate a `SensitiveString` carrying no validation metadata,
 * which fails under `forbidUnknownValues`.
 *
 * @param name - Header name to read
 * @param klass - Sensitivity class for the wrapped value
 * @param label - Audit label; defaults to `name`
 *
 * @example
 * ```ts
 * getResource(
 *   \@SensitiveHeader('authorization', 'credential') value: SensitiveString<'credential'> | null,
 * ) {}
 * ```
 */
export function SensitiveHeader(
  name: string,
  klass: SensitivityClass,
  label?: string
): ParameterDecorator {
  return SensitiveHeaderParam({ name, klass, label } satisfies RequestPartSpec);
}
