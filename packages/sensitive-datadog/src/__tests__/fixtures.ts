import { execFile, execFileSync } from 'node:child_process';
import { closeSync, existsSync, openSync, readdirSync, rmSync, statSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';

import { decodeMsgpack } from './msgpack.js';

/**
 * The real agent, driven end to end, with the trace agent replaced by a local
 * HTTP server and the msgpack decoded.
 *
 * No test here contacts Datadog. `dd-trace` runs as it would in production,
 * patches the modules the suite then calls, formats and encodes real spans,
 * and posts them to `PUT /v0.4/traces` on a socket this file owns. Every
 * measurement in this package's comments was taken this way.
 *
 * Reading the encoded bytes rather than the formatted spans is deliberate.
 * The encoder is a second, independent filter, and the error tracking design
 * had it the wrong way round: `#encodeMetaEntries` skips any `meta` entry that
 * is not a string or a number, which is stricter than `JSON.stringify` rather
 * than looser. A suite that intercepted the formatter would not have seen
 * that.
 *
 * Measured against `dd-trace` 6.14.0 on Node 22.15.0.
 */

/** The agent version every measurement in this suite was taken against. */
export const AGENT_VERSION = '6.14.0';

/** One span, as the agent encoded it. */
export interface EncodedSpan {
  readonly name: string;
  readonly resource?: string;
  readonly meta?: Record<string, string>;
  readonly metrics?: Record<string, number>;
  readonly [key: string]: unknown;
}

/** A local stand-in for the Datadog trace agent. */
export interface FakeAgent {
  readonly url: string;
  readonly port: number;
  /** Every span the agent has received so far, across every flush. */
  spans: () => EncodedSpan[];
  /**
   * Spans the application produced, with the agent's own traffic removed.
   *
   * The fake agent is an HTTP server in the same process, so `dd-trace`
   * instruments it too and every trace submission produces its own
   * `web.request`. Those are noise here and would otherwise dominate every
   * assertion.
   */
  applicationSpans: () => EncodedSpan[];
  close: () => Promise<void>;
}

/** Start the stand-in agent on an ephemeral port. */
export async function startFakeAgent(): Promise<FakeAgent> {
  const received: EncodedSpan[] = [];

  const server = createServer((request, response) => {
    const chunks: Buffer[] = [];

    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      if (request.url?.startsWith('/v0.4/traces') === true) {
        const traces = decodeMsgpack(Buffer.concat(chunks));

        if (Array.isArray(traces)) {
          for (const trace of traces) {
            if (Array.isArray(trace)) {
              received.push(...(trace as EncodedSpan[]));
            }
          }
        }
      }

      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ rate_by_service: {} }));
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const port = addressPort(server);

  return {
    url: `http://127.0.0.1:${port}`,
    port,
    spans: () => [...received],
    applicationSpans: () =>
      received.filter((span) => !String(span.meta?.['http.url'] ?? '').includes(`:${port}`)),
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

function addressPort(server: Server): number {
  const address = server.address();

  if (address === null || typeof address === 'string') {
    throw new Error('the server is not listening on a TCP port');
  }

  return address.port;
}

/**
 * This package's directory, found by walking up to the workspace root.
 *
 * Neither `import.meta.url` nor `__dirname` exists under both the Vitest
 * transform and the NodeNext CommonJS type-check, and the suite runs from the
 * repository root and from the package directory alike.
 */
export function packageRoot(): string {
  let directory = process.cwd();

  for (;;) {
    if (existsSync(join(directory, 'pnpm-workspace.yaml'))) {
      return join(directory, 'packages', 'sensitive-datadog');
    }

    const parent = dirname(directory);

    if (parent === directory) {
      throw new Error(`Could not find the workspace root above ${process.cwd()}.`);
    }

    directory = parent;
  }
}

/** A `require` rooted in this package, for reaching into the agent's own files. */
export function agentRequire(): NodeRequire {
  return createRequire(join(packageRoot(), 'package.json'));
}

/**
 * Compile this package so the child can require it.
 *
 * The child is a `dd-trace` deployment and loads CommonJS, so it needs the
 * built output rather than the sources Vitest transforms in this process.
 * Building here rather than relying on a prior `pnpm build` is what keeps a
 * stale `dist` from reporting green on code that just changed, which is the
 * exact failure a compiled artifact in a test path invites. Spawning `tsc`
 * from a suite already has a precedent in `sensitive-fastify`.
 *
 * Skipped when every output is newer than every source, so the second test
 * file in a run pays nothing.
 */
export function ensureBuilt(): string {
  const root = packageRoot();
  const dist = join(root, 'dist', 'install.js');

  if (isFresh(dist, root)) {
    return dist;
  }

  const lock = join(root, 'dist.build.lock');
  let held: number;

  try {
    // Vitest runs test files in parallel workers, and two of them compiling
    // into the same `dist` at once is a real way to read a half-written file.
    // `wx` is the cheap mutex: whoever creates the lock builds, and the rest
    // wait for the output to appear.
    held = openSync(lock, 'wx');
  } catch {
    return waitForBuild(dist, root, lock);
  }

  try {
    const tsc = agentRequire().resolve('typescript/bin/tsc');

    execFileSync(process.execPath, [tsc, '-p', '.'], { cwd: root, stdio: 'pipe' });
  } finally {
    closeSync(held);
    rmSync(lock, { force: true });
  }

  return dist;
}

function isFresh(dist: string, root: string): boolean {
  return existsSync(dist) && statSync(dist).mtimeMs >= newestSource(join(root, 'src'));
}

/** Wait for whoever holds the lock to finish, then trust their output. */
function waitForBuild(dist: string, root: string, lock: string): string {
  const deadline = Date.now() + 120_000;

  while (Date.now() < deadline) {
    if (!existsSync(lock) && isFresh(dist, root)) {
      return dist;
    }

    // Synchronous, because `ensureBuilt` is called from module scope and from
    // `beforeAll` alike, and an async version would have to infect both.
    execFileSync(process.execPath, ['-e', 'setTimeout(() => {}, 100)']);
  }

  throw new Error(`timed out waiting for another worker to build ${dist}`);
}

function newestSource(dir: string): number {
  let newest = 0;

  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '__tests__' || entry.name === 'node_modules') {
      continue;
    }

    const path = join(dir, entry.name);

    newest = Math.max(newest, entry.isDirectory() ? newestSource(path) : statSync(path).mtimeMs);
  }

  return newest;
}

/** What one driver process should do. */
export interface DriverSpec {
  readonly canary: string;
  /** Where to post traces. Filled in by `runDriver`. */
  agentUrl?: string;
  /** `headerTags` for `tracer.init()`, which is the opt-in this row is about. */
  readonly headerTags?: readonly string[];
  /** A caller `queryStringObfuscation` for `tracer.init()`. */
  readonly queryStringObfuscation?: boolean | string;
  /** Install this package. Off for the leaking companion of every sweep. */
  readonly install?: boolean;
  /** Options handed to `installSensitiveScrubbing`. */
  readonly installOptions?: Record<string, unknown>;
  /** Install before `tracer.init()` rather than after. */
  readonly installBeforeInit?: boolean;
  /** Register a caller `hooks.request` on `http` first, to test composition. */
  readonly userHook?: boolean;
  /** Variant A of the load-order measurement: require `http` before `init()`. */
  readonly preRequireHttp?: boolean;
  /** Write the application-set span tags of sections 2.3 and 2.4. */
  readonly applicationTags?: boolean;
  /**
   * Install a value recognizer that throws, for the failure path.
   *
   * The walk and `redactCopy` guard every read they make, so hostile data does
   * not reach the failure path; a caller's own `denyValues` `RegExp` is the one
   * thing in a policy that is not guarded and cannot be.
   */
  readonly hostileRecognizer?: boolean;
  /** Serve the request through express rather than bare `http`. */
  readonly framework?: 'express';
  /** Skip the HTTP request entirely. */
  readonly request?: boolean;
  readonly settleMs?: number;
}

/** What one driver process reported about itself. */
export interface DriverResult {
  readonly userHookCalls: number;
  readonly degraded: readonly string[];
  readonly reports: readonly {
    kind: string;
    instances: number;
    classes: string[];
    deniedKeys: string[];
    markersSeen: number;
    failed: boolean;
    labels?: string[];
  }[];
  readonly notes: Record<string, unknown>;
}

/** One process, one case: its self-report plus every span it produced. */
export interface DriverRun {
  readonly result: DriverResult;
  readonly spans: EncodedSpan[];
  readonly stdout: string;
}

const execFileAsync = promisify(execFile);

/**
 * Run one case in its own process against a fresh stand-in agent.
 *
 * A fresh agent per case, because the spans have to be attributable to one
 * process and `dd-trace` submits on its own schedule.
 *
 * The spawn is asynchronous, and that is not a style preference. The stand-in
 * agent is an HTTP server in *this* process, so a synchronous spawn blocks the
 * event loop that has to answer the child's `PUT /v0.4/traces`: the child
 * times out, drops every span, and the suite sees an empty payload it would
 * happily read as "nothing leaked".
 */
export async function runDriver(spec: DriverSpec): Promise<DriverRun> {
  ensureBuilt();

  const agent = await startFakeAgent();

  try {
    const { stdout } = await execFileAsync(
      process.execPath,
      [
        join(packageRoot(), 'src', '__tests__', 'driver.cjs'),
        JSON.stringify({ ...spec, agentUrl: agent.url }),
      ],
      { cwd: packageRoot(), encoding: 'utf8', timeout: 60_000 }
    );

    return { result: parseResult(stdout), spans: agent.applicationSpans(), stdout };
  } finally {
    await agent.close();
  }
}

function parseResult(stdout: string): DriverResult {
  const line = stdout
    .split('\n')
    .find((candidate) => candidate.startsWith('SENSITIVE_DRIVER_RESULT'));

  if (line === undefined) {
    throw new Error(`the driver produced no result. stdout was:\n${stdout}`);
  }

  return JSON.parse(line.slice('SENSITIVE_DRIVER_RESULT '.length)) as DriverResult;
}

/**
 * The server span for an application request, and the client span beside it.
 *
 * Both are selected by `http.method`, not by `span.kind` alone. One request
 * also produces `dns.lookup` and `tcp.connect` spans, and both of those are
 * client-kind, so a plain kind filter picks whichever the agent flushed first
 * and the header assertions then read `undefined` off a DNS span.
 */
export function serverSpan(spans: readonly EncodedSpan[]): EncodedSpan {
  return named(
    spans,
    (span) => span.meta?.['span.kind'] === 'server' && span.meta?.['http.method'] !== undefined,
    'an HTTP server span'
  );
}

export function clientSpan(spans: readonly EncodedSpan[]): EncodedSpan {
  return named(
    spans,
    (span) => span.meta?.['span.kind'] === 'client' && span.meta?.['http.method'] !== undefined,
    'an HTTP client span'
  );
}

function named(
  spans: readonly EncodedSpan[],
  matches: (span: EncodedSpan) => boolean,
  what: string
): EncodedSpan {
  const found = spans.find(matches);

  if (found === undefined) {
    throw new Error(`no ${what} among ${spans.map((span) => span.name).join(', ') || '(none)'}`);
  }

  return found;
}

/** Every header tag on a span, request and response directions together. */
export function headerTags(span: EncodedSpan): Record<string, string> {
  const found: Record<string, string> = {};

  for (const [key, value] of Object.entries(span.meta ?? {})) {
    if (key.includes('.headers.')) {
      found[key] = value;
    }
  }

  return found;
}
