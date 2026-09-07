/**
 * @platform-sec/sensitive-string-prisma
 *
 * Prisma integration for SensitiveString.
 *
 * Classified columns read back as `SensitiveString` instances, including
 * through relations loaded with `include` or `select`, and every write unwraps
 * through an audited `reveal()` before the statement reaches the driver.
 *
 * @example
 * ```ts
 * import { PrismaClient } from './generated/prisma/client.js';
 * import { sensitiveExtension, sensitiveInput } from '@platform-sec/sensitive-string-prisma';
 * import { SensitiveString } from '@platform-sec/sensitive-string-core';
 *
 * const prisma = new PrismaClient({ adapter }).$extends(
 *   sensitiveExtension({
 *     models: {
 *       User: { email: 'sensitive', passwordHash: 'credential' },
 *     },
 *   })
 * );
 *
 * const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });
 * user.email; // SensitiveString<'sensitive'>
 *
 * await prisma.user.update({
 *   where: { id: 1 },
 *   data: sensitiveInput({ email: new SensitiveString('new@example.com', 'sensitive') }),
 * });
 * ```
 *
 * @packageDocumentation
 */

export { sensitiveExtension } from './extension.js';

export { sensitiveInput } from './types.js';
export type {
  ClassOf,
  SensitiveResultComponent,
  UnwrapSensitive,
  WrappedField,
  WrapRow,
  WrapValue,
} from './types.js';

export { wrapRows } from './raw.js';

export { clientKey, normalizeConfig, normalizeModelFields } from './config.js';
export type {
  ModelFieldConfig,
  NormalizedConfig,
  NormalizedField,
  NormalizedModel,
  SensitiveExtensionConfig,
  SensitiveFieldSpec,
} from './config.js';

export { buildResultComponent } from './result.js';
export type { ComputedField, ResultComponentValue } from './result.js';

export { buildRevealContext, revealArgs, revealRawArgs } from './args.js';
export type { RevealAttribution } from './args.js';

export { assertConfigMatchesSchema, readSchemaModels } from './schema.js';

export {
  assertNoUnwrapped,
  findUnwrapped,
  isSensitiveString,
  isUnwrappedResidue,
} from './guard.js';
export type { UnwrappedResidue } from './guard.js';

export {
  PrismaConfigError,
  PrismaCyclicArgumentError,
  PrismaFieldTypeError,
  PrismaUnknownFieldError,
  PrismaUnknownModelError,
  PrismaUnsafeStatementError,
  PrismaUnwrappedValueError,
} from './errors.js';
