import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { AddressInfo } from 'node:net';

/**
 * The recording server the client suites assert against.
 *
 * Every security assertion in this row is about bytes, not about the client's
 * view of what it sent. A test that reads `config.headers` back from axios
 * proves that axios remembers what it was told, which is not the question. So
 * the harness records the raw request line, the raw header block and the raw
 * body, and the suites search those.
 *
 * Exported from `@platform-sec/sensitive-string-http/testing` so five client
 * packages do not grow five servers that differ in which bytes they keep.
 */

export interface RecordedRequest {
  readonly method: string;
  /** The request target exactly as it appeared on the request line. */
  readonly target: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  /** Request line, header block and body, joined. What a leak assertion searches. */
  readonly raw: string;
}

export interface ServerReply {
  status?: number;
  headers?: Record<string, string>;
  body?: string;
}

export interface RecordingServer {
  readonly origin: string;
  readonly host: string;
  readonly requests: readonly RecordedRequest[];
  /** Everything every request carried, joined. The one string a canary check scans. */
  readonly transcript: string;
  /** Reply to the next request with this. Repeats until replaced. */
  reply(reply: ServerReply): void;
  /** Reply to the next request only, then fall back to the standing reply. */
  replyOnce(reply: ServerReply): void;
  reset(): void;
  close(): Promise<void>;
}

/**
 * Start a recording server on an ephemeral loopback port.
 *
 * Loopback, so the transport check in `assertTransport` does not refuse the
 * suite's own `http://` requests. A test that wants to exercise that refusal
 * points at a non-loopback host and asserts that nothing is recorded here.
 */
export async function startRecordingServer(initial?: ServerReply): Promise<RecordingServer> {
  const requests: RecordedRequest[] = [];
  const queue: ServerReply[] = [];
  let standing: ServerReply = initial ?? { status: 200, body: '{"ok":true}' };

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];

    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const headers: Record<string, string> = {};

      for (const [name, value] of Object.entries(req.headers)) {
        headers[name] = Array.isArray(value) ? value.join(', ') : (value ?? '');
      }

      const headerBlock = Object.entries(headers)
        .map(([name, value]) => `${name}: ${value}`)
        .join('\n');

      requests.push({
        method: req.method ?? '',
        target: req.url ?? '',
        headers,
        body,
        raw: `${req.method ?? ''} ${req.url ?? ''}\n${headerBlock}\n\n${body}`,
      });

      const reply = queue.shift() ?? standing;

      res.writeHead(reply.status ?? 200, {
        'content-type': 'application/json',
        ...(reply.headers ?? {}),
      });
      res.end(reply.body ?? '{"ok":true}');
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  const address = server.address() as AddressInfo;
  const host = `127.0.0.1:${address.port}`;

  return {
    origin: `http://${host}`,
    host,
    get requests() {
      return requests;
    },
    get transcript() {
      return requests.map((request) => request.raw).join('\n---\n');
    },
    reply(next) {
      standing = next;
    },
    replyOnce(next) {
      queue.push(next);
    },
    reset() {
      requests.length = 0;
      queue.length = 0;
    },
    close() {
      return new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

/** The needles a marker assertion looks for, in every encoding the guard covers. */
export const MARKER_NEEDLES: readonly string[] = [
  '[REDACTED:',
  '%5BREDACTED%3A',
  '%5BREDACTED:',
  'W1JFREFDVEVE',
  'RURBQ1RF',
  'UkVEQUNURUQ6',
];

/** Assert that no recorded byte carries a redaction marker in any encoding. */
export function findMarker(transcript: string): string | undefined {
  return MARKER_NEEDLES.find((needle) => transcript.includes(needle));
}
