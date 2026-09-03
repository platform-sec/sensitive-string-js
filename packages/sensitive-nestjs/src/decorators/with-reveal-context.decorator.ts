import { SetMetadata } from '@nestjs/common';
import { REVEAL_CONTEXT_KEY } from '../constants.js';
import type { HandlerRevealContext } from '../types.js';

/**
 * Declare the reveal context for a handler or a whole controller.
 *
 * A method decorator has no access to NestJS's `ExecutionContext`, so this one
 * only attaches metadata. `SensitiveContextInterceptor` reads it and merges it
 * over the request-level context from `SENSITIVE_CONTEXT_FACTORY`. Without
 * that interceptor registered the decorator is a no-op.
 *
 * Method metadata overrides class metadata. Within a merge, `name`, `reason`,
 * and `auditReveal` from here replace the request-level values, and `tags` are
 * merged with these winning on conflict, matching `createChildContext` in
 * core.
 *
 * @example
 * ```ts
 * \@Post('charge')
 * \@WithRevealContext({ name: 'payment-processing', reason: 'charging card' })
 * async charge(\@Body() dto: PaymentDto) {}
 * ```
 *
 * @example Reading the request
 * ```ts
 * \@WithRevealContext((ctx) => ({
 *   name: 'refund-processing',
 *   tags: { orderId: ctx.switchToHttp().getRequest().params.orderId },
 * }))
 * ```
 */
export function WithRevealContext(context: HandlerRevealContext): MethodDecorator & ClassDecorator {
  return SetMetadata(REVEAL_CONTEXT_KEY, context);
}
