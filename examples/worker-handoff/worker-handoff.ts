/**
 * Worker Handoff - moving a signing key into a worker thread without unwrapping it
 *
 * A `SensitiveString` handed to a `Worker` through `workerData` arrives as a
 * plain `{ klass, label }`: structured clone keeps the public fields and drops
 * the private one, and nothing throws until the first method call, in another
 * thread. The fix everybody reaches for is `workerData: { key: key.reveal() }`,
 * which works and leaves the plaintext in a plain string for the life of the
 * thread, with no class, no deadline and no audit record.
 *
 * This example shows the shape the handoff gives that instead. The main thread
 * builds a payload, which is a reveal audited as a `worker-handoff`; the worker
 * rebuilds the instance under the carried context with its own audit hook, and
 * the payload object stops holding plaintext once it has.
 *
 * @example
 * ```ts
 * // main thread
 * const worker = new Worker(SIGNER_FILE, { workerData: signerPayload(signingKey, batch) });
 *
 * // worker thread
 * parentPort.postMessage(signBatch(workerData, auditReveal));
 * ```
 */

import { createHmac } from 'node:crypto';
import {
  SensitiveString,
  toWorkerPayload,
  withWorkerPayload,
} from '@platform-sec/sensitive-string-core';
import type { RevealContext, WorkerPayload } from '@platform-sec/sensitive-string-core';

/** The worker's entry file, recorded in the audit record as the destination. */
export const SIGNER_FILE = './signer.js';

/** What the worker needs that is sensitive. */
export interface SignerValues {
  readonly signingKey: SensitiveString<'credential'>;
}

/** What the worker needs that is not. */
export interface SignerBatch {
  readonly documents: readonly string[];
}

/**
 * Main thread: the value for `new Worker(SIGNER_FILE, { workerData })`.
 *
 * Pass the result straight into the constructor rather than binding it, so the
 * sender's copy is unreachable as soon as it is cloned. The context defaults to
 * the ambient one, so a request handler running inside `withRevealContext()`
 * needs no argument for it.
 */
export function signerPayload(
  signingKey: SensitiveString<'credential'>,
  batch: SignerBatch,
  context?: RevealContext
): WorkerPayload<SignerValues> {
  return toWorkerPayload<SignerValues>(
    { signingKey },
    context === undefined
      ? { worker: SIGNER_FILE, data: batch }
      : { worker: SIGNER_FILE, data: batch, context }
  );
}

/**
 * Worker thread: sign every document in the batch.
 *
 * `require` makes the key's presence a boundary failure rather than a
 * `TypeError` inside the loop, and the hook is mandatory in the signature
 * because the sender's hook cannot cross: a worker that consumed an audited
 * payload without one would throw, and one that passed `allowUnaudited`
 * would be reported by the lint rule.
 */
export function signBatch(
  workerData: unknown,
  auditReveal: NonNullable<RevealContext['auditReveal']>
): string[] {
  return withWorkerPayload<SignerValues, string[]>(
    workerData,
    { auditReveal, require: ['signingKey'] },
    ({ signingKey }, data) => {
      const batch = requireBatch(data);

      // One reveal for the batch, inside the carried context, rather than one
      // per document: the audit record then says what happened once.
      const key = signingKey.reveal();

      return batch.documents.map((document) =>
        createHmac('sha256', key).update(document).digest('hex')
      );
    }
  );
}

function requireBatch(data: unknown): SignerBatch {
  if (
    typeof data !== 'object' ||
    data === null ||
    !Array.isArray((data as { documents?: unknown }).documents)
  ) {
    throw new TypeError('signer: workerData.data must be a batch of documents');
  }

  return data as SignerBatch;
}
