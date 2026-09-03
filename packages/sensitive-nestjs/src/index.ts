/**
 * @platform-sec/sensitive-string-nestjs
 *
 * NestJS integration for SensitiveString: DTO properties are wrapped by a
 * pipe, reveal context is established by an interceptor, and response bodies
 * are redacted on the way out.
 *
 * @example
 * ```ts
 * // app.module.ts
 * @Module({
 *   providers: [
 *     // Validate plain strings first, then wrap. Both through APP_PIPE, so
 *     // the order is the registration order.
 *     {
 *       provide: APP_PIPE,
 *       useFactory: () =>
 *         new ValidationPipe({
 *           transform: true,
 *           whitelist: true,
 *           // class-validator attaches the raw value and the whole object to
 *           // every ValidationError by default. Turn that off so exception
 *           // factories and filters cannot echo a secret.
 *           validationError: { target: false, value: false },
 *         }),
 *     },
 *     { provide: APP_PIPE, useClass: SensitiveTransformPipe },
 *
 *     { provide: SENSITIVE_CONTEXT_FACTORY, useValue: contextFactory },
 *     { provide: APP_INTERCEPTOR, useClass: SensitiveContextInterceptor },
 *     { provide: APP_INTERCEPTOR, useClass: SensitiveResponseInterceptor },
 *   ],
 * })
 * export class AppModule {}
 *
 * // login.dto.ts
 * export class LoginDto {
 *   @Sensitive('sensitive', 'email') @IsEmail() email!: SensitiveString<'sensitive'>;
 *   @Sensitive('credential', 'password') @MinLength(8) password!: SensitiveString<'credential'>;
 * }
 * ```
 *
 * @packageDocumentation
 */

// Metadata keys and DI tokens
export {
  REVEAL_CONTEXT_KEY,
  SENSITIVE_CONTEXT_FACTORY,
  SENSITIVE_FIELDS_KEY,
} from './constants.js';

// Types
export type { HandlerRevealContext, RevealContextFactory } from './types.js';

// DTO decorators
export { Sensitive, getSensitiveFields } from './decorators/sensitive.decorator.js';
export type {
  SensitiveFieldMap,
  SensitiveFieldMetadata,
} from './decorators/sensitive.decorator.js';

// Handler decorator
export { WithRevealContext } from './decorators/with-reveal-context.decorator.js';

// Parameter decorators
export { SensitiveHeader } from './decorators/sensitive-header.decorator.js';
export { SensitiveParam } from './decorators/sensitive-param.decorator.js';
export { SensitiveQuery } from './decorators/sensitive-query.decorator.js';

// Pipe
export { SensitiveTransformPipe } from './pipes/sensitive-transform.pipe.js';

// Interceptors
export { SensitiveContextInterceptor } from './interceptors/sensitive-context.interceptor.js';
export { SensitiveResponseInterceptor } from './interceptors/sensitive-response.interceptor.js';
