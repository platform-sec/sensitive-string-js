/**
 * A forked child that consumes a payload sent over `child_process` IPC.
 *
 * IPC serializes as JSON rather than structured clone, so this is the one
 * transport the `transport` option exists for. It reports the type a `Date`
 * in `data` arrived as, which is how the suite pins the gap the option
 * cannot close: a payload built under the default `'clone'` check passes and
 * the Date arrives here as a string.
 *
 * See `worker-consume.mjs` for why this imports the package by name.
 */
import { withWorkerPayload } from '@platform-sec/sensitive-string-core';

process.on('message', (message) => {
  try {
    const out = withWorkerPayload(message, { auditReveal() {} }, ({ token }, data) => ({
      revealed: token.reveal(),
      klass: token.klass,
      label: token.label,
      whenType: typeof data?.when,
      when: data?.when ?? null,
    }));

    process.send({ ok: true, ...out, consumed: message.consumed === true });
  } catch (error) {
    process.send({
      ok: false,
      error: { name: error?.name, code: error?.code, message: error?.message },
    });
  }
});
