/**
 * The worker handoff, across a real boundary.
 *
 * Every finding that matters about `workerData` is a cross-isolate one: that
 * it is one mutable object shared by every module in the thread, that the
 * policy registry starts empty there, that an error crossing back carries its
 * message and stack. A mocked boundary would reproduce none of them, so these
 * suites start a real `Worker`, fork a real child, and drive a `MessageChannel`
 * and a `BroadcastChannel`.
 *
 * The fixtures under `fixtures/` import the package by name, which resolves
 * through its `exports` map to `dist`, so this file needs `pnpm build` to
 * have run for `sensitive-core`. It says so rather than failing inside a
 * thread.
 */
import { fork } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import {
  SensitiveString,
  UnauditedWorkerError,
  fromWorkerPayload,
  registerPolicy,
  resetPolicies,
  toWorkerPayload,
  withRevealContext,
} from '../index.js';
import type { RevealDetails, SensitivityClass, WorkerPayload } from '../index.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const OTHER_CANARY = 'LEAKED_OTHER_def456uvw';

/**
 * This package's directory, from the working directory rather than from
 * `import.meta.url`, because the package emits CommonJS and `import.meta` is
 * not available there.
 */
const PACKAGE_DIR = existsSync(join(process.cwd(), 'packages', 'sensitive-core'))
  ? join(process.cwd(), 'packages', 'sensitive-core')
  : process.cwd();

const FIXTURES = join(PACKAGE_DIR, 'src', '__tests__', 'fixtures');
const DIST_ENTRY = join(PACKAGE_DIR, 'dist', 'index.js');

/** What `worker-consume.mjs` posts back. */
interface ConsumeReport {
  readonly ok: boolean;
  readonly result?: {
    readonly values: Record<
      string,
      {
        readonly isInstance: boolean;
        readonly klass: string;
        readonly label: string | undefined;
        readonly expiresAt: string | null;
        readonly revealed: string;
        readonly revealCount: number;
      }
    >;
    readonly context: { name: string; reason?: string; tags?: unknown } | null;
    readonly data: unknown;
  };
  readonly error?: { name: string; code: string; message: string };
  readonly audits?: (RevealDetails & { klass: string; label: string | undefined })[];
  readonly before: { json: string; inspect: string };
  readonly after: { json: string; inspect: string };
  readonly consumed: boolean;
  readonly registered: string[];
}

const workers: Worker[] = [];

/** Start a worker on a fixture and resolve with its first message, or reject with its error. */
function runWorker<T>(fixture: string, workerData: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(join(FIXTURES, fixture), { workerData });
    workers.push(worker);
    worker.once('message', (message: T) => resolve(message));
    worker.once('error', reject);
  });
}

/** The first message a running worker posts after being sent one. */
function exchange<T>(worker: Worker, message: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    worker.once('message', (reply: T) => resolve(reply));
    worker.once('error', reject);
    worker.postMessage(message);
  });
}

function token(value = CANARY): SensitiveString<'credential'> {
  return new SensitiveString(value, 'credential', 'api_key');
}

beforeAll(() => {
  if (!existsSync(DIST_ENTRY)) {
    throw new Error(
      `${DIST_ENTRY} is missing. The worker fixtures import the package by name, which resolves ` +
        'to dist, so run `pnpm --filter @platform-sec/sensitive-string-core build` first.'
    );
  }
});

afterEach(async () => {
  resetPolicies();
  await Promise.all(workers.splice(0).map((worker) => worker.terminate()));
});

describe('workerData', () => {
  it('round-trips class, label, deadline, context and data through a real thread', async () => {
    const expiresAt = new Date(Date.now() + 60_000);
    const audits: RevealDetails[] = [];

    const report = await runWorker<ConsumeReport>(
      'worker-consume.mjs',
      toWorkerPayload(
        {
          token: token(),
          otp: new SensitiveString(OTHER_CANARY, 'sensitive', 'otp', { expiresAt }),
        },
        {
          worker: 'worker-consume.mjs',
          context: {
            name: 'req-42',
            reason: 'sign the batch',
            tags: { userId: 'u1' },
            auditReveal: (_value, details) => {
              audits.push(details);
            },
          },
          data: { batchSize: 100 },
        }
      )
    );

    expect(report.ok).toBe(true);
    expect(report.result?.values['token']).toEqual({
      isInstance: true,
      klass: 'credential',
      label: 'api_key',
      expiresAt: null,
      revealed: CANARY,
      revealCount: 1,
    });
    expect(report.result?.values['otp']?.expiresAt).toBe(expiresAt.toISOString());
    expect(report.result?.values['otp']?.revealed).toBe(OTHER_CANARY);
    expect(report.result?.context).toEqual({
      name: 'req-42',
      reason: 'sign the batch',
      tags: { userId: 'u1' },
    });
    expect(report.result?.data).toEqual({ batchSize: 100 });

    // The sender's hook saw the handoff; the worker's own hook saw the reveals.
    expect(audits.map((details) => details.operation)).toEqual([
      'worker-handoff',
      'worker-handoff',
    ]);
    expect(report.audits?.map((details) => details.operation)).toEqual(['reveal', 'reveal']);
    expect(JSON.stringify(report.audits)).not.toContain(CANARY);
  });

  it('holds the plaintext in workerData until consumption, and not after', async () => {
    // This is the test that proves consumption closes the two sinks measured
    // as leaking. It has to run in a real worker: `workerData` being one live
    // object shared by every module in the thread is what makes it work.
    const report = await runWorker<ConsumeReport>(
      'worker-consume.mjs',
      toWorkerPayload({ token: token() })
    );

    expect(report.ok).toBe(true);
    expect(report.before.json).toContain(CANARY);
    expect(report.before.inspect).toContain(CANARY);
    expect(report.after.json).not.toContain(CANARY);
    expect(report.after.inspect).not.toContain(CANARY);
    expect(report.consumed).toBe(true);
    // The marker and the class stay, so the consumed payload still reads as
    // a redaction to the walks.
    expect(report.after.json).toContain('"__sensitive":true');
    expect(report.after.json).toContain('"klass":"credential"');
  });

  it('a payload with no context and no data arrives under a context named worker', async () => {
    const report = await runWorker<ConsumeReport>(
      'worker-consume.mjs',
      toWorkerPayload({ token: token() })
    );

    expect(report.result?.context).toEqual({ name: 'worker', reason: undefined, tags: undefined });
    expect(report.result?.data).toBeUndefined();
  });

  it('require holds on the far side, and a missing key is refused there by name', async () => {
    const report = await runWorker<ConsumeReport>(
      'worker-consume.mjs',
      toWorkerPayload({ token: token() }, { data: { require: ['token', 'dsn'] } })
    );

    expect(report.ok).toBe(false);
    expect(report.error?.code).toBe('missing-value');
    expect(report.error?.message).toContain("'dsn'");
    expect(report.error?.message).not.toContain(CANARY);
  });

  it('a class registered on the main thread does not exist in the worker, and the message says so', async () => {
    registerPolicy({ name: 'pii' as SensitivityClass, redact: () => '[PII]' });

    const report = await runWorker<ConsumeReport>(
      'worker-consume.mjs',
      toWorkerPayload({ ssn: new SensitiveString(CANARY, 'pii' as SensitivityClass, 'ssn') })
    );

    expect(report.registered).toEqual(['sensitive', 'credential']);
    expect(report.ok).toBe(false);
    expect(report.error?.name).toBe('UnregisteredClassError');
    expect(report.error?.code).toBe('unregistered-class');
    expect(report.error?.message).toContain("'pii'");
    expect(report.error?.message).toContain('registerPolicy()');
    expect(report.error?.message).toContain('sensitive, credential');
    expect(report.error?.message).not.toContain(CANARY);
    // Refused before consumption, so a bootstrap that registers the class
    // could retry; the plaintext is still there, which the walks still redact.
    expect(report.consumed).toBe(false);
  });

  it('a value that expires during the thread start is refused at the boundary by key', async () => {
    const report = await runWorker<ConsumeReport>(
      'worker-consume.mjs',
      toWorkerPayload(
        { otp: new SensitiveString(CANARY, 'credential', 'otp', { ttl: 20 }) },
        { data: { delayMs: 60 } }
      )
    );

    expect(report.ok).toBe(false);
    expect(report.error?.name).toBe('ExpiredSensitiveValueError');
    expect(report.error?.code).toBe('expired-value');
    expect(report.error?.message).toContain("payload key 'otp'");
    expect(report.error?.message).not.toContain(CANARY);
    // Expiry cannot be fixed by retrying, so the payload was consumed on the
    // way out rather than left holding plaintext for the life of the thread.
    expect(report.consumed).toBe(true);
    expect(report.after.json).not.toContain(CANARY);
  });

  it('an audited payload is refused in a worker that installs no hook, unless allowed', async () => {
    // `worker-consume.mjs` always installs a hook, so the refusal is driven
    // through `withWorkerPayload` in-thread and the acceptance through the
    // worker with `allowUnaudited`; the refusal itself is pinned in
    // `worker-payload.test.ts` and needs no isolate.
    const report = await runWorker<ConsumeReport>(
      'worker-consume.mjs',
      toWorkerPayload(
        { token: token() },
        {
          context: { name: 'audited', auditReveal: () => undefined },
          data: { allowUnaudited: true },
        }
      )
    );

    expect(report.ok).toBe(true);
    expect(report.result?.values['token']?.revealed).toBe(CANARY);
  });

  it("the library's own error crossing back to the parent carries no canary", async () => {
    // The worker consumes, then consumes again and lets the resulting error
    // go uncaught, so it is serialized into the parent's 'error' event.
    await expect(
      runWorker<ConsumeReport>(
        'worker-consume.mjs',
        toWorkerPayload({ token: token() }, { data: { mode: 'throw-consumed' } })
      )
    ).rejects.toSatisfy((error: unknown) => {
      const crossed = error as Error;
      expect(crossed.message).toContain('already been consumed');
      expect(crossed.message).not.toContain(CANARY);
      expect(crossed.stack ?? '').not.toContain(CANARY);
      return true;
    });
  });
});

describe('postMessage after start', () => {
  it('the same payload works through postMessage, with the shorter window', async () => {
    const worker = new Worker(join(FIXTURES, 'worker-echo.mjs'));
    workers.push(worker);

    const reply = await exchange<{
      ok: boolean;
      revealed: string;
      consumed: boolean;
      json: string;
    }>(worker, toWorkerPayload({ token: token() }));

    expect(reply.ok).toBe(true);
    expect(reply.revealed).toBe(CANARY);
    expect(reply.consumed).toBe(true);
    expect(reply.json).not.toContain(CANARY);
  });

  it('consumes per copy: a second worker sent the same payload gets a whole one', async () => {
    // The limitation, pinned rather than wished away. Every transport clones,
    // so consumption in one thread cannot reach the sender's object or any
    // other copy of it. A reader who took "consumed once, dead forever" from
    // the error's name would build a use-once token out of something that is
    // not one, so the suite states the real behaviour.
    const payload = toWorkerPayload({ token: token() });
    const first = new Worker(join(FIXTURES, 'worker-echo.mjs'));
    const second = new Worker(join(FIXTURES, 'worker-echo.mjs'));
    workers.push(first, second);

    const firstReply = await exchange<{ ok: boolean; revealed: string; consumed: boolean }>(
      first,
      payload
    );
    const secondReply = await exchange<{ ok: boolean; revealed: string }>(second, payload);

    expect(firstReply.ok).toBe(true);
    expect(firstReply.consumed).toBe(true);
    expect(secondReply.ok).toBe(true);
    expect(secondReply.revealed).toBe(CANARY);

    // The sender's own object was never touched by either thread.
    expect(payload.consumed).toBeUndefined();
    expect(JSON.stringify(payload)).toContain(CANARY);
  });

  it('but the copy that was consumed refuses wherever it is passed on', async () => {
    const payload = toWorkerPayload({ token: token() });
    const worker = new Worker(join(FIXTURES, 'worker-echo.mjs'));
    workers.push(worker);

    // Consumed in-process, as a module sharing the object would, then sent on.
    // Here the deletion does travel, because this is the object being cloned.
    fromWorkerPayload(payload);

    const reply = await exchange<{ ok: boolean; error?: { code: string } }>(worker, payload);

    expect(reply.ok).toBe(false);
    expect(reply.error?.code).toBe('consumed-payload');
  });
});

describe('the reverse direction', () => {
  it('a payload built in the worker is consumed in a parent handler that has an ambient hook, with no options', async () => {
    const audits: RevealDetails[] = [];
    let revealed: string | undefined;

    await withRevealContext(
      {
        name: 'parent-scope',
        auditReveal: (_value, details) => {
          audits.push(details);
        },
      },
      async () => {
        const worker = new Worker(join(FIXTURES, 'worker-echo.mjs'));
        workers.push(worker);

        const { payload } = await exchange<{ payload: WorkerPayload }>(worker, {
          mode: 'build',
          value: OTHER_CANARY,
        });

        expect(payload.audited).toBe(true);
        expect(payload.context).toEqual({ name: 'worker-scope', reason: 'results' });

        // The parent-side hook is ambient here, which satisfies the audited
        // payload without any option at all.
        const received = fromWorkerPayload<{ result: SensitiveString<'sensitive'> }>(payload);

        withRevealContext(received.context, () => {
          revealed = received.values.result.reveal();
        });
      }
    );

    expect(revealed).toBe(OTHER_CANARY);
    expect(audits).toEqual([{ operation: 'reveal' }]);
  });

  it('and throws unaudited-worker in a parent handler that has none', async () => {
    const worker = new Worker(join(FIXTURES, 'worker-echo.mjs'));
    workers.push(worker);

    const { payload } = await exchange<{ payload: WorkerPayload }>(worker, {
      mode: 'build',
      value: OTHER_CANARY,
    });

    expect(() => fromWorkerPayload(payload)).toThrow(UnauditedWorkerError);
    expect(JSON.stringify(payload)).toContain(OTHER_CANARY);
  });
});

describe('the other clone transports', () => {
  it('a MessageChannel port delivers a payload that rebuilds', async () => {
    const { port1, port2 } = new MessageChannel();

    const received = new Promise<WorkerPayload>((resolve) => {
      port2.once('message', (payload: WorkerPayload) => resolve(payload));
    });

    port1.postMessage(toWorkerPayload({ token: token() }, { data: { via: 'MessageChannel' } }));

    const payload = await received;
    const { values, data } = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(payload);

    expect(values.token.reveal()).toBe(CANARY);
    expect(data).toEqual({ via: 'MessageChannel' });
    expect(JSON.stringify(payload)).not.toContain(CANARY);
    port1.close();
    port2.close();
  });

  it('a BroadcastChannel delivers a payload that rebuilds', async () => {
    const name = `sensitive-string-${process.pid}-${Date.now()}`;
    const sender = new BroadcastChannel(name);
    const receiver = new BroadcastChannel(name);

    const received = new Promise<WorkerPayload>((resolve) => {
      receiver.onmessage = (event: unknown) => resolve((event as { data: WorkerPayload }).data);
    });

    sender.postMessage(toWorkerPayload({ token: token() }));

    const payload = await received;
    const { values } = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(payload);

    expect(values.token.reveal()).toBe(CANARY);
    sender.close();
    receiver.close();
  });
});

describe('child_process IPC', () => {
  interface ChildReply {
    readonly ok: boolean;
    readonly revealed?: string;
    readonly klass?: string;
    readonly label?: string;
    readonly whenType?: string;
    readonly when?: unknown;
    readonly consumed?: boolean;
    readonly error?: { name: string; code: string; message: string };
  }

  function askChild(payload: WorkerPayload): Promise<ChildReply> {
    return new Promise((resolve, reject) => {
      const child = fork(join(FIXTURES, 'child-ipc.mjs'), [], { stdio: 'pipe' });
      child.once('message', (reply: ChildReply) => {
        child.kill();
        resolve(reply);
      });
      child.once('error', reject);
      child.send(payload);
    });
  }

  it('transport json: the values rebuild and reveal in a forked child', async () => {
    const reply = await askChild(
      toWorkerPayload({ token: token() }, { transport: 'json', data: { batch: 3 } })
    );

    expect(reply.ok).toBe(true);
    expect(reply.revealed).toBe(CANARY);
    expect(reply.klass).toBe('credential');
    expect(reply.label).toBe('api_key');
    expect(reply.consumed).toBe(true);
  });

  it('a Date in data under the default clone check arrives at the child as a string', async () => {
    // The one gap the transport option cannot close: forgetting it. Pinned
    // here so the doc comment is backed by a measurement rather than a claim.
    const when = new Date(0);
    const payload = toWorkerPayload({ token: token() }, { data: { when } });

    const reply = await askChild(payload);

    expect(reply.ok).toBe(true);
    expect(reply.whenType).toBe('string');
    expect(reply.when).toBe(when.toISOString());
    // And the json check would have refused the same payload.
    expect(() =>
      toWorkerPayload({ token: token() }, { data: { when }, transport: 'json' })
    ).toThrow('data.when');
  });
});
