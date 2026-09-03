import {
  Inject,
  Injectable,
  Optional,
  type CallHandler,
  type ExecutionContext,
  type NestInterceptor,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { withRevealContext, type RevealContext } from '@platform-sec/sensitive-string-core';
import type { Observable } from 'rxjs';
import { REVEAL_CONTEXT_KEY, SENSITIVE_CONTEXT_FACTORY } from '../constants.js';
import type { HandlerRevealContext, RevealContextFactory } from '../types.js';

/**
 * Establish the reveal context for the rest of the request.
 *
 * The context covers the pipes, the handler, and the `intercept()` call of
 * every interceptor registered after this one, because NestJS binds that part
 * of the chain to the async context active when `next.handle()` is called.
 *
 * Two documented gaps:
 *
 * - Middleware and guards run before any interceptor, so there is no scope for
 *   them to inherit.
 * - The rxjs operators an inner interceptor puts on the response (`tap`,
 *   `map`, and so on) run outside the scope. NestJS emits the handler result
 *   from a subscriber function that is not part of the bound region, and those
 *   operators run before this interceptor's own boundary on the way out, so
 *   nothing here can restore it for them.
 *
 * Code in either position that needs to reveal a value passes an explicit
 * `RevealContext` to `reveal()`.
 *
 * The request-level context comes from a `RevealContextFactory` provided under
 * `SENSITIVE_CONTEXT_FACTORY`, which leaves this class free of construction
 * arguments so it can be registered with `useClass`. With no factory provided,
 * only `@WithRevealContext` metadata applies; with neither, the interceptor
 * establishes no context at all rather than an empty one.
 */
@Injectable()
export class SensitiveContextInterceptor implements NestInterceptor {
  constructor(
    private readonly reflector: Reflector,
    @Optional()
    @Inject(SENSITIVE_CONTEXT_FACTORY)
    private readonly factory?: RevealContextFactory
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const base = this.factory?.(context);
    const declared = this.reflector.getAllAndOverride<HandlerRevealContext | undefined>(
      REVEAL_CONTEXT_KEY,
      [context.getHandler(), context.getClass()]
    );
    const override = typeof declared === 'function' ? declared(context) : declared;
    const merged = mergeContexts(base, override);

    // next.handle() is called inside the callback rather than before it: the
    // Observable it returns is what the downstream chain is bound to, and
    // building it outside the scope would leave the handler without one.
    return merged ? withRevealContext(merged, () => next.handle()) : next.handle();
  }
}

/**
 * Merge a handler context over the request-level one.
 *
 * Same semantics as `createChildContext` in core, reimplemented because that
 * helper reads the active `AsyncLocalStorage` store and nothing is active yet
 * at this point in the request.
 */
function mergeContexts(
  base: RevealContext | undefined,
  override: RevealContext | undefined
): RevealContext | undefined {
  if (!base) {
    return override;
  }

  if (!override) {
    return base;
  }

  return {
    ...base,
    ...override,
    tags: { ...base.tags, ...override.tags },
  };
}
