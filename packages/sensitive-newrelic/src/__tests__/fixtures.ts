import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { gunzipSync } from 'node:zlib';

/**
 * The real agent, driven end to end, with no network and no mock.
 *
 * No test here contacts New Relic. The agent runs in its serverless mode,
 * which gzips and base64-encodes onto stdout exactly the payload it would
 * otherwise post to the collector, so the suite reads the real attribute
 * filter, the real header renaming and the real payload sections rather than a
 * reproduction of them. INTEGRATION_IDEAS.md's rule about never mocking the
 * real class extends here to never mocking the real agent.
 *
 * It has to be a child process. The agent reads its configuration once, at
 * require time, from `NEW_RELIC_HOME`, and installs module-loading hooks that
 * cannot be undone; a suite that required it twice in one process would get
 * the first case's configuration for every later case. One process per case is
 * what keeps the destination matrix honest.
 *
 * Measured against `newrelic` 14.3.10 on Node 22.15.0.
 */

/** The agent version every measurement in this suite was taken against. */
export const AGENT_VERSION = '14.3.10';

/**
 * This package's directory, found by walking up to the workspace root.
 *
 * Neither `import.meta.url` nor `__dirname` exists under both the Vitest
 * transform and the NodeNext CommonJS type-check, and the suite runs from the
 * repository root and from the package directory alike. Same approach as
 * `sensitive-fastify`'s.
 */
export function packageRoot(): string {
  let directory = process.cwd();

  for (;;) {
    if (existsSync(join(directory, 'pnpm-workspace.yaml'))) {
      return join(directory, 'packages', 'sensitive-newrelic');
    }

    const parent = dirname(directory);

    if (parent === directory) {
      throw new Error(`Could not find the workspace root above ${process.cwd()}.`);
    }

    directory = parent;
  }
}

/** A `require` rooted in this package, for reaching into the agent's own modules. */
export function agentRequire(): NodeRequire {
  return createRequire(join(packageRoot(), 'src', 'index.ts'));
}

const HERE = join(packageRoot(), 'src', '__tests__');

/** What one invocation should put in the payload beyond the request itself. */
export interface InvocationSpec {
  /** The canary this run uses. Every position below carries it. */
  readonly canary: string;
  /** Add `{ password, token, api_key, tenant }` through `addCustomAttributes`. */
  readonly deniedAttributes?: boolean;
  /** Add a raw string under a name no denylist covers, which must leak. */
  readonly unnamedAttribute?: boolean;
  /** Add a `SensitiveString` through `addCustomAttribute`, uncoerced. */
  readonly wrappedAttribute?: boolean;
  /** Add a `serialize()` result through `addCustomAttribute`, uncoerced. */
  readonly serializedAttribute?: boolean;
  /**
   * Attributes already through `sensitiveAttributes`, added verbatim.
   *
   * Computed in the test process, where the `SensitiveString` instances live.
   * The output is scalars, so it crosses the process boundary as JSON.
   */
  readonly coerced?: Readonly<Record<string, string | number | boolean>>;
  /** Attach `{ password }` as `noticeError`'s second argument. */
  readonly errorAttributes?: boolean;
  /** Custom span attributes, added through `addCustomSpanAttributes`. */
  readonly spanAttributes?: Readonly<Record<string, string | number | boolean>>;
}

/** One decoded serverless payload. */
export interface ServerlessPayload {
  readonly metadata: Record<string, unknown>;
  readonly data: Record<string, unknown>;
}

/**
 * Run one invocation under a given agent configuration.
 *
 * @param config - The object a `newrelic.js` would export under `config`
 * @param spec - What the handler should record beyond the request itself
 * @returns The decoded payload the agent would have posted
 */
export function runServerless(
  config: Readonly<Record<string, unknown>>,
  spec: InvocationSpec
): ServerlessPayload {
  const home = mkdtempSync(join(tmpdir(), 'sensitive-newrelic-'));

  try {
    writeFileSync(
      join(home, 'newrelic.js'),
      `exports.config = ${JSON.stringify(baseConfig(config))};\n`
    );

    const stdout = execFileSync(
      process.execPath,
      [join(HERE, 'driver.cjs'), home, JSON.stringify(spec)],
      { cwd: HERE, encoding: 'utf8', timeout: 60_000 }
    );

    return decodePayload(stdout);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

/**
 * The settings every case shares, under the caller's own.
 *
 * A licence key and an app name are required for the agent to start at all,
 * logging is off so the suite's output is the payload and nothing else, and
 * `allow_all_headers` is on because that is the opt-in this row exists for: at
 * stock defaults the agent collects six headers and none of them is a
 * credential, so a canary sweep with it off would prove nothing.
 *
 * Distributed tracing is on because without it the agent emits four payload
 * sections rather than five: `span_event_data` is absent entirely, and with it
 * every span attribute position the sweep is supposed to cover. It needs an
 * `account_id` to stay on, measured: `_serverlessDT` turns it back off without
 * one, logs a warning nothing here would have read, and the suite would then
 * have asserted about a section the agent never emitted.
 */
function baseConfig(config: Readonly<Record<string, unknown>>): Record<string, unknown> {
  return {
    app_name: ['probe'],
    license_key: 'x'.repeat(40),
    logging: { enabled: false },
    allow_all_headers: true,
    account_id: '1',
    primary_application_id: '1',
    trusted_account_key: '1',
    distributed_tracing: { enabled: true },
    span_events: { enabled: true },
    ...config,
  };
}

/**
 * Pull the payload out of the child's stdout.
 *
 * `ServerlessCollector` writes `[version, "NR_LAMBDA_MONITORING", base64]` on
 * one line. Anything else the child printed is ignored, so a stray warning
 * from the agent does not fail the decode.
 */
function decodePayload(stdout: string): ServerlessPayload {
  const line = stdout.split('\n').find((candidate) => candidate.includes('NR_LAMBDA_MONITORING'));

  if (line === undefined) {
    throw new Error(`the agent emitted no payload. stdout was:\n${stdout}`);
  }

  const parsed: unknown = JSON.parse(line);

  if (!Array.isArray(parsed) || typeof parsed[2] !== 'string') {
    throw new Error(`unexpected payload envelope: ${line.slice(0, 200)}`);
  }

  return JSON.parse(
    gunzipSync(Buffer.from(parsed[2], 'base64')).toString('utf8')
  ) as ServerlessPayload;
}

/**
 * Every attribute bag in a payload, from every section that carries one.
 *
 * The five sections are `metric_data`, `error_data`, `error_event_data`,
 * `span_event_data` and `analytic_event_data`, and they carry attributes in
 * two shapes. `error_data` names them: an entry's fourth member is an object
 * with `userAttributes`, `agentAttributes` and `intrinsics` keys. The three
 * event sections are positional: an event is `[intrinsics, userAttributes,
 * agentAttributes]`, with no key to recognise them by.
 *
 * Both are collected, so a position in either shape shows up in the sweep.
 * Anything else in the payload is ignored, which keeps a metric name from
 * being read as an attribute.
 */
const NAMED_BAGS = new Set(['userAttributes', 'agentAttributes', 'intrinsics']);

export function attributeBags(payload: ServerlessPayload): Record<string, unknown>[] {
  const bags: Record<string, unknown>[] = [];

  collect(payload.data, bags, new WeakSet());

  return bags;
}

function collect(value: unknown, bags: Record<string, unknown>[], seen: WeakSet<object>): void {
  if (value === null || typeof value !== 'object' || seen.has(value)) {
    return;
  }
  seen.add(value);

  if (Array.isArray(value)) {
    // The positional event triple. Three plain objects in a row is the shape
    // and there is nothing else in the payload that has it.
    if (value.length === 3 && value.every(isPlainObject)) {
      bags.push(...value);
    }

    for (const item of value) {
      collect(item, bags, seen);
    }

    return;
  }

  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (NAMED_BAGS.has(key) && isPlainObject(item)) {
      bags.push(item);
    }

    collect(item, bags, seen);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** The attribute names present anywhere in a payload, deduplicated and sorted. */
export function attributeNames(payload: ServerlessPayload): string[] {
  const names = new Set<string>();

  for (const bag of attributeBags(payload)) {
    for (const key of Object.keys(bag)) {
      names.add(key);
    }
  }

  return [...names].sort();
}
