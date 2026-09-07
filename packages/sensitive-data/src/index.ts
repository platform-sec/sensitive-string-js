/**
 * The shared layer under the data layer integrations.
 *
 * Nothing installs this package on its own. It holds what every ORM package
 * needs and nothing that depends on which ORM: the bound-parameter walk that
 * refuses a value the column mapping never saw, the redactor the query logger
 * drives, the identifier scan that decides whether a statement is one to censor,
 * the descriptor machinery that takes revealed parameters back out of a query
 * error, and the reveal context a write is audited under.
 *
 * It was extracted from three consumers rather than one, and that was the point.
 * `scrub` and `secrets` were each designed against a single first consumer and
 * both held up, because their consumers are homogeneous. ORM hooks are not: a
 * Drizzle `customType`, a TypeORM `ValueTransformer` and a Prisma client
 * extension have almost nothing in common at the seam, and a layer extracted
 * from any one of them would have encoded that one's shape. Each of the pieces
 * here differs from what any single consumer had, and two of them close a gap
 * that was invisible to the suite of the consumer that had it.
 *
 * What is deliberately not here, because three consumers proved it is not
 * shared: the column specification, which is a path map in one, a model-keyed
 * object in another and a schema declaration in the third; the drift check,
 * which reads entity metadata, the runtime data model and registered column
 * objects respectively; and the `sensitive-scrub` fragments, which name
 * different properties on different errors. Each consumer keeps its own error
 * types too, because they carry different context and are caught by different
 * code.
 */

export { findUnsafeParameter, parameterEntries, redactParameters } from './parameters.js';
export type { Offence, OffenceKind } from './parameters.js';

export {
  STATEMENT_LIMIT,
  identifiersIn,
  indexClassifiedPaths,
  touchesClassifiedColumn,
  truncateStatement,
} from './statement.js';
export type { TouchOptions } from './statement.js';

export { sanitizeQueryError } from './driver-error.js';
export type { SanitizeShape } from './driver-error.js';

export { buildWriteContext } from './context.js';
export type { WriteAttribution, WriteOperation } from './context.js';
