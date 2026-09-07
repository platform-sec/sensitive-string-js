import { SensitiveStringError } from '@platform-sec/sensitive-string-core';

/**
 * A configuration this package refuses to build an extension from.
 *
 * Thrown by `sensitiveExtension()` before a client exists, so a typo in a
 * sensitivity class or a malformed field entry stops the process at startup
 * rather than producing a value with no policy behind it.
 */
export class PrismaConfigError extends SensitiveStringError {
  readonly code = 'PRISMA_INVALID_CONFIG';

  constructor(message: string) {
    super(message);
    this.name = 'PrismaConfigError';
  }
}

/**
 * A configured column returned something other than a string.
 *
 * Raised from the computed field, which is the first place the mismatch is
 * visible: the configuration named a field the schema does not type as
 * `String`. The message names the model and field and reports only the
 * JavaScript type of what arrived, never the value.
 */
export class PrismaFieldTypeError extends SensitiveStringError {
  readonly code = 'PRISMA_FIELD_NOT_A_STRING';

  constructor(
    readonly model: string,
    readonly field: string,
    received: string
  ) {
    super(
      `${model}.${field} is configured as sensitive, but the column returned ${received}. ` +
        `Only String columns can be wrapped; remove the field from the configuration or change its type.`
    );
    this.name = 'PrismaFieldTypeError';
  }
}

/**
 * A `SensitiveString` was passed as the statement text of a raw query.
 *
 * `$queryRawUnsafe(sql, ...params)` interpolates its first argument into the
 * statement with no binding. Revealing a secret there would splice it into
 * SQL, so the walk refuses instead of unwrapping. A secret belongs in a
 * parameter, which is bound.
 */
export class PrismaUnsafeStatementError extends SensitiveStringError {
  readonly code = 'PRISMA_SENSITIVE_STATEMENT';

  constructor(operation: string) {
    super(
      `${operation} received a SensitiveString as the statement text. A raw statement is ` +
        `interpolated, not bound, so revealing it would write the value into SQL. ` +
        `Pass the value as a parameter instead.`
    );
    this.name = 'PrismaUnsafeStatementError';
  }
}

/**
 * A `SensitiveString` reached a Prisma operation without being unwrapped.
 *
 * The value is already gone by the time this is raised. Prisma copies query
 * arguments before any extension sees them and the copy cannot reach an ES
 * private field, so what the extension found was the flattened remains of an
 * instance: its class and label, and no value.
 *
 * The fix is at the call site, because that is the last place the value still
 * exists: wrap the argument in `sensitiveInput()`.
 */
export class PrismaUnwrappedValueError extends SensitiveStringError {
  readonly code = 'PRISMA_UNWRAPPED_VALUE';

  constructor(
    readonly model: string | undefined,
    readonly operation: string,
    /** Argument path of the offending value, such as `data.passwordHash`. */
    readonly path: string,
    /** Sensitivity class the flattened value declared. */
    readonly klass: string
  ) {
    const where = model === undefined ? operation : `${operation} on ${model}`;
    super(
      `${where} received a SensitiveString at '${path}' that was never unwrapped. ` +
        `Prisma copies query arguments before an extension sees them and the copy drops the ` +
        `private value, so the extension cannot unwrap it here and the write would have ` +
        `persisted the redaction marker. Wrap the argument in sensitiveInput() at the call site.`
    );
    this.name = 'PrismaUnwrappedValueError';
  }
}

/**
 * A configured model is not on the client the extension was applied to.
 *
 * Prisma ignores a `result` component keyed by a name it does not recognise, so
 * without this the configuration would classify nothing and report nothing, and
 * every column it named would read back as a plain string.
 */
export class PrismaUnknownModelError extends SensitiveStringError {
  readonly code = 'PRISMA_UNKNOWN_MODEL';

  constructor(
    readonly model: string,
    /** The client property the model name resolves to. */
    readonly clientKey: string,
    hint = ''
  ) {
    super(
      `Model '${model}' is configured but the Prisma client has no '${clientKey}'.${hint} ` +
        `Prisma ignores a result extension keyed by an unknown model, so every column ` +
        `configured under it would read back unwrapped.`
    );
    this.name = 'PrismaUnknownModelError';
  }
}

/**
 * A configured field is not a scalar column of its model.
 *
 * Prisma adds a computed field under whatever name it is given, so a misspelled
 * one appears alongside the real column instead of replacing it: the result
 * carries a wrapped value nobody reads and the real column stays plain.
 */
export class PrismaUnknownFieldError extends SensitiveStringError {
  readonly code = 'PRISMA_UNKNOWN_FIELD';

  constructor(
    readonly model: string,
    readonly field: string,
    hint = ''
  ) {
    super(
      `${model}.${field} is configured but is not a scalar field of '${model}' in the Prisma ` +
        `schema.${hint} A computed field under an unknown name is added beside the real column ` +
        `rather than replacing it, so the real column would read back unwrapped. Relation ` +
        `fields cannot be configured.`
    );
    this.name = 'PrismaUnknownFieldError';
  }
}

/**
 * A query argument contains a cycle.
 *
 * There is no correct answer for the back edge: its rebuild is unfinished, so
 * the only reference available still holds the wrapped values. Prisma cannot
 * serialise a cyclic argument either, and its own argument copy recurses until
 * the stack ends, so this refusal is both earlier and easier to act on.
 */
export class PrismaCyclicArgumentError extends SensitiveStringError {
  readonly code = 'PRISMA_CYCLIC_ARGUMENT';

  constructor(
    /** Argument path at which the cycle closed. */
    readonly path: string
  ) {
    super(
      `A query argument refers back to itself at '${path}'. Prisma cannot serialise a cyclic ` +
        `argument, and unwrapping one would leave part of it still wrapped. Build the argument ` +
        `as a tree.`
    );
    this.name = 'PrismaCyclicArgumentError';
  }
}
