/**
 * @platform-sec/sensitive-string-decorators
 *
 * Framework-agnostic Stage 3 decorators for SensitiveString. `@Sensitive`
 * marks a class field so every value it receives is protected, and
 * `@WithRevealContext` runs a method inside a named reveal context so the
 * reveals it reaches are audited.
 *
 * Stage 3 decorators only, which means TypeScript 5.0 or later compiling with
 * `experimentalDecorators` off, or any runtime that implements the standard.
 * Legacy decorators are a different, incompatible model and a file compiles
 * under one or the other, never both; NestJS applications, which require the
 * legacy model, get the same two decorator names from
 * `@platform-sec/sensitive-string-nestjs`.
 *
 * @example
 * ```ts
 * import { Sensitive, WithRevealContext } from '@platform-sec/sensitive-string-decorators';
 * import { SensitiveString } from '@platform-sec/sensitive-string-core';
 *
 * class User {
 *   @Sensitive('sensitive', 'email') accessor email!: SensitiveString<'sensitive'>;
 *   @Sensitive('credential') accessor passwordHash!: SensitiveString<'credential'>;
 * }
 *
 * class PaymentProcessor {
 *   @WithRevealContext({ name: 'payment-processing', reason: 'charging card' })
 *   async processPayment(card: SensitiveString<'credential'>) {
 *     await gateway.charge(card.reveal());
 *   }
 * }
 * ```
 *
 * @packageDocumentation
 */

// Field decorator
export { Sensitive } from './sensitive.js';
export type { SensitiveAccessorValue } from './sensitive.js';

// Method decorator
export { WithRevealContext } from './with-reveal-context.js';
export type { RevealContextFactory, RevealContextInput } from './with-reveal-context.js';
