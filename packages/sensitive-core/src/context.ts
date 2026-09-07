import { AsyncLocalStorage } from 'node:async_hooks';
import type { RevealContext, RevealDetails } from './types.js';
import { getGlobalSingleton } from './global-state.js';

/**
 * AsyncLocalStorage instance for reveal context propagation.
 * Allows context to flow through async call chains without explicit threading.
 */
const revealContextStorage = getGlobalSingleton(
  'reveal-context-storage',
  () => new AsyncLocalStorage<RevealContext>()
);

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
 * Context does NOT propagate to worker threads or child processes: the store is
 * per isolate. `toWorkerPayload()` carries the `name`, `reason` and `tags` of
 * the active context across the boundary alongside the values, and
 * `withWorkerPayload()` installs them on the far side with that side's own
 * `auditReveal`, which is the one field that cannot cross.
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
    return overrides;
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
 * await withAuditedReveals('payment-processing', (value, details) => {
 *   logger.info('Revealed sensitive value', { class: value.klass, op: details.operation });
 * }, async () => {
 *   // All reveals in this scope will be audited
 * });
 * ```
 */
export function withAuditedReveals<T>(
  name: string,
  auditFn: (value: { readonly klass: string }, details: RevealDetails) => void,
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
