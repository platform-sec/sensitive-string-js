/**
 * A worker that consumes payloads sent after start, and builds one to send
 * back.
 *
 * Two shapes of message:
 * - `{ mode: 'build', value }` builds a payload under an audited worker-side
 *   context and posts it, which is the reverse direction of the handoff.
 * - anything else is taken to be a payload and consumed.
 *
 * See `worker-consume.mjs` for why this imports the package by name.
 */
import { parentPort } from 'node:worker_threads';
import {
  SensitiveString,
  toWorkerPayload,
  withRevealContext,
  withWorkerPayload,
} from '@platform-sec/sensitive-string-core';

parentPort.on('message', (message) => {
  if (message?.mode === 'build') {
    const payload = withRevealContext(
      { name: 'worker-scope', reason: 'results', auditReveal() {} },
      () =>
        toWorkerPayload(
          { result: new SensitiveString(message.value, 'sensitive', 'result') },
          { worker: 'parent' }
        )
    );

    parentPort.postMessage({ payload });
    return;
  }

  try {
    const revealed = withWorkerPayload(message, { auditReveal() {} }, ({ token }) =>
      token.reveal()
    );

    parentPort.postMessage({
      ok: true,
      revealed,
      consumed: message.consumed === true,
      json: JSON.stringify(message),
    });
  } catch (error) {
    parentPort.postMessage({
      ok: false,
      error: { name: error?.name, code: error?.code, message: error?.message },
    });
  }
});
