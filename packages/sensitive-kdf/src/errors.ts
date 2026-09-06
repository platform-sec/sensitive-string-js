/**
 * A KDF that needs a native module the application has not installed.
 *
 * Argon2 and bcrypt are optional peer dependencies rather than dependencies:
 * both compile native code, most applications need exactly one of them, and
 * scrypt needs neither. The cost of that choice is this error, and it is worth
 * making it say what to install rather than surfacing an unresolved specifier
 * from three frames deeper.
 */
export class MissingKdfModuleError extends Error {
  override readonly name = 'MissingKdfModuleError';
  /** The npm package that is missing. */
  readonly module: string;
  /** What the module was wanted for. */
  readonly algorithm: string;

  constructor(module: string, algorithm: string, cause?: unknown) {
    super(
      `The '${module}' package is required for ${algorithm} hashing and could not be loaded. ` +
        `Install it (pnpm add ${module}), or use algorithm: 'scrypt', which needs only node:crypto.`,
      cause === undefined ? undefined : { cause }
    );

    this.module = module;
    this.algorithm = algorithm;
  }
}

/**
 * A stored hash this package cannot read.
 *
 * The offending string is deliberately absent from the message. It is a
 * credential-classed value, an error message is the least controlled output
 * path in any application, and knowing which of three prefixes was missing
 * tells the caller everything the string itself would.
 */
export class UnknownStoredHashError extends Error {
  override readonly name = 'UnknownStoredHashError';

  constructor(detail = 'it matches none of the argon2, bcrypt or scrypt formats') {
    super(
      `The stored hash could not be read because ${detail}. It is not repeated here, ` +
        'because a stored hash is a credential.'
    );
  }
}
