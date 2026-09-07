/**
 * A worker that consumes the payload it was started with.
 *
 * Imports the package by name, which resolves through its `exports` map to
 * `dist`, so the suite that starts this worker needs a build. That is the
 * price of a real thread: Vitest's transform does not reach a `Worker`, and a
 * mocked boundary reproduces none of the cross-isolate behaviour this fixture
 * exists to observe.
 *
 * It reports what the two sinks that leak, `JSON.stringify` and
 * `util.inspect`, contain before and after consumption, because that
 * difference is the whole of what consumption buys.
 *
 * `workerData.data` steers it:
 * - `delayMs` waits before consuming, so a deadline can pass in transit.
 * - `allowUnaudited` and `require` are passed through to `fromWorkerPayload`.
 * - `mode: 'throw-consumed'` consumes a second time and lets the library's
 *   own error cross to the parent's `'error'` handler uncaught.
 */
import { inspect } from 'node:util';
import { parentPort, workerData } from 'node:worker_threads';
import {
  SensitiveString,
  fromWorkerPayload,
  getCurrentRevealContext,
  getRegisteredClasses,
  withWorkerPayload,
} from '@platform-sec/sensitive-string-core';

const data = workerData?.data ?? {};

function snapshot() {
  return {
    json: JSON.stringify(workerData),
    inspect: inspect(workerData, { depth: null }),
  };
}

function describeError(error) {
  return { name: error?.name, code: error?.code, message: error?.message };
}

const before = snapshot();

if (typeof data.delayMs === 'number') {
  await new Promise((resolve) => setTimeout(resolve, data.delayMs));
}

const audits = [];
const options = {
  auditReveal(value, details) {
    audits.push({ klass: value.klass, label: value.label, ...details });
  },
};

if (data.allowUnaudited === true) {
  options.allowUnaudited = true;
}

if (Array.isArray(data.require)) {
  options.require = data.require;
}

try {
  const result = withWorkerPayload(workerData, options, (values, received) => {
    const context = getCurrentRevealContext();
    const out = {};

    for (const [key, value] of Object.entries(values)) {
      out[key] = {
        isInstance: value instanceof SensitiveString,
        klass: value.klass,
        label: value.label,
        expiresAt: value.expiresAt?.toISOString() ?? null,
        revealed: value.reveal(),
        revealCount: value.revealCount,
      };
    }

    return {
      values: out,
      context:
        context === null
          ? null
          : { name: context.name, reason: context.reason, tags: context.tags },
      data: received,
    };
  });

  if (data.mode === 'throw-consumed') {
    fromWorkerPayload(workerData);
  }

  parentPort.postMessage({
    ok: true,
    result,
    audits,
    before,
    after: snapshot(),
    consumed: workerData.consumed === true,
    registered: getRegisteredClasses(),
  });
} catch (error) {
  if (data.mode === 'throw-consumed') {
    throw error;
  }

  parentPort.postMessage({
    ok: false,
    error: describeError(error),
    before,
    after: snapshot(),
    consumed: workerData.consumed === true,
    registered: getRegisteredClasses(),
  });
}
