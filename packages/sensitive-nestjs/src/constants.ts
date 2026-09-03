/**
 * Metadata keys and dependency-injection tokens.
 *
 * The keys are strings rather than symbols because `reflect-metadata` and
 * NestJS's `Reflector` both key on them, and a string survives the two copies
 * of this package that a duplicate install would produce. Reading metadata
 * written by another copy is the benign outcome; a symbol would silently read
 * nothing instead.
 */

/** `reflect-metadata` key holding a DTO class's `SensitiveFieldMap`. */
export const SENSITIVE_FIELDS_KEY = 'platform-sec:sensitive-fields';

/** `Reflector` key holding a handler's or controller's `HandlerRevealContext`. */
export const REVEAL_CONTEXT_KEY = 'platform-sec:reveal-context';

/**
 * Injection token for the request-level `RevealContextFactory`.
 *
 * Optional: with no provider under this token, `SensitiveContextInterceptor`
 * still applies whatever `@WithRevealContext` declares.
 *
 * The value is namespaced because a NestJS container is shared with every
 * other library in the application, and a bare `'SENSITIVE_CONTEXT_FACTORY'`
 * is exactly the sort of string two of them would pick.
 */
export const SENSITIVE_CONTEXT_FACTORY = 'platform-sec:sensitive-context-factory';
