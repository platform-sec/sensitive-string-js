import { AsyncLocalStorage } from 'node:async_hooks';
import type { RevealContext } from './types.js';

/**
 * AsyncLocalStorage instance for reveal context propagation.
 * Allows context to flow through async call chains without explicit threading.
 */
const revealContextStorage = new AsyncLocalStorage<RevealContext>();

/**
 * Execute a function within a reveal context.
 * The context will be available via getCurrentRevealContext() for the duration of fn.
 *
 * @param ctx - The reveal context to set
 * @param fn - The function to execute within the context
 * @returns The return value of fn
 *
 * @example
 * ```ts
 * const result = await withRevealContext(
 *   { name: 'api-handler', reason: 'processing payment' },
 *   async () => {
 *     // sensitiveString.reveal() will use this context
 *     return processPayment(sensitiveString);
 *   }
 * );
 * ```
 *
 * @remarks
 * Context does NOT propagate to Worker threads.
 * If your application uses workers, you must explicitly pass context.
 */
export function withRevealContext<T>(ctx: RevealContext, fn: () => T): T {
  return revealContextStorage.run(ctx, fn);
}

/**
 * Get the current reveal context, if any.
 *
 * @returns The current RevealContext or null if none is set
 */
export function getCurrentRevealContext(): RevealContext | null {
  return revealContextStorage.getStore() ?? null;
}

/**
 * Create a child context that inherits from the current context.
 * Useful for adding context-specific tags while preserving parent context.
 *
 * @param overrides - Properties to override in the child context
 * @returns A new RevealContext with merged properties
 */
export function createChildContext(
  overrides: Partial<RevealContext> & { name: string }
): RevealContext {
  const current = getCurrentRevealContext();
  if (!current) {
    return overrides as RevealContext;
  }

  return {
    ...current,
    ...overrides,
    tags: {
      ...current.tags,
      ...overrides.tags,
    },
  };
}

/**
 * Convenience function to run with an audit callback.
 * Creates a context that logs all reveal operations.
 *
 * @param name - Context name
 * @param auditFn - Function called on each reveal
 * @param fn - The function to execute
 * @returns The return value of fn
 *
 * @example
 * ```ts
 * await withAuditedReveals('payment-processing', (value) => {
 *   logger.info('Revealed sensitive value', { class: value.klass });
 * }, async () => {
 *   // All reveals in this scope will be audited
 * });
 * ```
 */
export function withAuditedReveals<T>(
  name: string,
  auditFn: (value: { readonly klass: string }) => void,
  fn: () => T
): T {
  return withRevealContext(
    {
      name,
      auditReveal: auditFn,
    },
    fn
  );
}
