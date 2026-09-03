import type { ExecutionContext } from '@nestjs/common';
import { SensitiveString, type SensitivityClass } from '@platform-sec/sensitive-string-core';

/** What `@SensitiveHeader`, `@SensitiveQuery`, and `@SensitiveParam` carry. */
export interface RequestPartSpec {
  /** Header, query, or route parameter name. */
  name: string;
  /** Sensitivity class for the wrapped value. */
  klass: SensitivityClass;
  /** Audit label; defaults to `name`. */
  label: string | undefined;
}

/** The request container each decorator reads from. */
export type RequestPart = 'headers' | 'query' | 'params';

/**
 * Read one value out of a request container and wrap it.
 *
 * Header names are matched lowercase, which is how both Express and Fastify
 * store them. Repeated headers and repeated query parameters arrive as an
 * array; the first value is used, because a caller asking for one credential
 * cannot act on several.
 *
 * Absent and empty values produce `null` via `SensitiveString.fromOptional`,
 * so the parameter type is nullable and an empty header is not mistaken for a
 * credential of length zero.
 */
export function extractSensitive(
  ctx: ExecutionContext,
  part: RequestPart,
  spec: RequestPartSpec
): SensitiveString<SensitivityClass> | null {
  const request: unknown = ctx.switchToHttp().getRequest();

  if (request === null || typeof request !== 'object') {
    return null;
  }

  const container: unknown = (request as Record<string, unknown>)[part];

  if (container === null || typeof container !== 'object') {
    return null;
  }

  const key = part === 'headers' ? spec.name.toLowerCase() : spec.name;
  const raw: unknown = (container as Record<string, unknown>)[key];
  const value = Array.isArray(raw) ? (raw[0] as unknown) : raw;

  if (typeof value !== 'string') {
    return null;
  }

  return SensitiveString.fromOptional(value, spec.klass, spec.label ?? spec.name);
}
