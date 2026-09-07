/**
 * @platform-sec/sensitive-string-typeorm
 *
 * TypeORM integration for SensitiveString.
 *
 * A classified column reads back as a `SensitiveString` and every write unwraps
 * through an audited `reveal()`, both through one `ValueTransformer`. That hook
 * is the right one and it is not sufficient: TypeORM does not call it for a
 * query builder's named parameters, which is the ORM's most-used query API, so
 * `guardParameters()` refuses those at the only place that sees them before the
 * driver does.
 *
 * Three plaintext surfaces sit beside the column and none is reachable from a
 * transformer: the query log, which prints the revealed parameters;
 * `QueryFailedError`, which carries them as an own enumerable property; and the
 * query result cache, which stores whole rows before the read transformer runs.
 * `sensitiveLogger()`, `sanitizeQueryFailedError()` and the refusal in
 * `schema.check()` are those three.
 *
 * @example
 * ```ts
 * import { defineSchema, guardParameters, sensitiveLogger } from '@platform-sec/sensitive-string-typeorm';
 *
 * export const schema = defineSchema({
 *   fields: { 'users.email': 'sensitive', 'users.password_hash': 'credential' },
 *   fallback: 'plain',
 * });
 *
 * @Entity('users')
 * class User {
 *   @Column({ type: 'text', transformer: schema.column('users.email') })
 *   email!: SensitiveString<'sensitive'>;
 * }
 *
 * const ds = new DataSource({ ..., logger: sensitiveLogger(new AdvancedConsoleLogger(), schema) });
 * await ds.initialize();
 * guardParameters(ds);
 * schema.check(ds);
 * ```
 *
 * @packageDocumentation
 */

export { defineSchema } from './schema.js';
export type {
  ColumnMetadataLike,
  DataSchema,
  DataSourceLike,
  EntityMetadataLike,
} from './schema.js';

export { brandOf, resetPlainWriteReports, sensitiveColumn } from './transformer.js';

export { assertParametersSafe, guardParameters } from './guard.js';

export {
  PARAMETER_CENSOR,
  redactParameters,
  sensitiveLogger,
  touchesClassifiedColumn,
} from './logger.js';
export type { LoggerLike } from './logger.js';

export { ERROR_PARAMETER_CENSOR, sanitizeQueryFailedError } from './sanitize.js';

export { typeormScrubFragment } from './scrub.js';

export { hydrateRawRows } from './raw.js';

export { containsRedactionMarker, redactionMarkers, resetMarkerCache } from './marker.js';

export { SENSITIVE_TRANSFORMER } from './types.js';
export type {
  CheckOptions,
  DataSchemaSpec,
  HydrateRawOptions,
  PlainWriteInfo,
  SensitiveColumnOptions,
  SensitiveTransformer,
  TransformerBrand,
  ValueTransformerLike,
} from './types.js';

export {
  TypeOrmCacheRefusedError,
  TypeOrmConfigError,
  TypeOrmDriftError,
  TypeOrmMarkerReadError,
  TypeOrmParameterRefusedError,
  TypeOrmWriteRefusedError,
} from './errors.js';
export type { DriftFinding } from './errors.js';
