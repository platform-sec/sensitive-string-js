import { execFile } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Socket } from 'node:dgram';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { MetricsCollector, createMetricsCollector } from './collector.js';
import { StatsDExporter } from './statsd.js';

const CANARY = 'LEAKED_SECRET_metrics_statsd_qwerty';

const collectors: MetricsCollector[] = [];
const exporters: StatsDExporter[] = [];
const sockets: Socket[] = [];

function started(...args: ConstructorParameters<typeof MetricsCollector>): MetricsCollector {
  const created = createMetricsCollector(...args);
  collectors.push(created);
  created.start();
  return created;
}

/**
 * A real StatsD server on loopback.
 *
 * Real rather than a mocked socket, because half of what this exporter does is
 * produce bytes a server has to accept: the assertions below are on datagrams
 * that actually crossed a socket, not on a string an internal method returned.
 */
async function listener(): Promise<{
  port: number;
  received: string[];
  drain: () => Promise<string[]>;
}> {
  const socket = createSocket('udp4');
  const received: string[] = [];

  sockets.push(socket);
  socket.on('message', (message) => {
    received.push(message.toString('utf8'));
  });

  const port = await new Promise<number>((resolve) => {
    socket.bind(0, '127.0.0.1', () => {
      resolve(socket.address().port);
    });
  });

  return {
    port,
    received,
    // UDP delivery on loopback is effectively immediate but not synchronous,
    // so the datagrams are collected after the event loop has turned rather
    // than read straight after `flush()`.
    drain: async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
      return received.flatMap((packet) => packet.split('\n'));
    },
  };
}

function exporter(
  collector: MetricsCollector,
  config: ConstructorParameters<typeof StatsDExporter>[1]
): StatsDExporter {
  const created = new StatsDExporter(collector, config);
  exporters.push(created);
  return created;
}

afterEach(() => {
  for (const created of exporters.splice(0)) {
    created.stop();
  }
  for (const created of collectors.splice(0)) {
    created.stop();
  }
  for (const socket of sockets.splice(0)) {
    socket.close();
  }
});

describe('StatsDExporter', () => {
  // MET-T009 and MET-I002 in one: the packet format, asserted on bytes that
  // reached a server.
  it('sends DogStatsD counter lines a server receives', async () => {
    const server = await listener();
    const metrics = started();
    const statsd = exporter(metrics, {
      host: '127.0.0.1',
      port: server.port,
      prefix: 'myapp.',
      globalTags: ['env:production'],
    });

    const secret = new SensitiveString(CANARY, 'credential', 'api_key');
    void String(secret);
    void String(secret);

    statsd.flush();

    expect(await server.drain()).toContain(
      'myapp.sensitive_redactions_total:2|c|#env:production,class:credential,surface:toString,label:api_key'
    );
  });

  it('sends the change since the last flush, because a StatsD counter is a delta', async () => {
    const server = await listener();
    const metrics = started();
    const statsd = exporter(metrics, { host: '127.0.0.1', port: server.port });
    const secret = new SensitiveString(CANARY, 'credential', 'api_key');

    void String(secret);
    statsd.flush();
    void String(secret);
    void String(secret);
    statsd.flush();

    const lines = await server.drain();
    const redactions = lines.filter((line) => line.startsWith('sensitive_redactions_total:'));

    expect(redactions).toEqual([
      'sensitive_redactions_total:1|c|#class:credential,surface:toString,label:api_key',
      'sensitive_redactions_total:2|c|#class:credential,surface:toString,label:api_key',
    ]);
  });

  it('sends nothing for a series that did not move', async () => {
    const server = await listener();
    const metrics = started();
    const statsd = exporter(metrics, { host: '127.0.0.1', port: server.port });

    void String(new SensitiveString(CANARY, 'credential', 'api_key'));
    statsd.flush();
    statsd.flush();

    const lines = await server.drain();

    expect(lines.filter((line) => line.startsWith('sensitive_redactions_total:'))).toHaveLength(1);
  });

  it('treats a total that went backwards as a restart rather than sending a negative delta', async () => {
    const server = await listener();
    const metrics = started();
    const statsd = exporter(metrics, { host: '127.0.0.1', port: server.port });
    const secret = new SensitiveString(CANARY, 'credential', 'api_key');

    void String(secret);
    void String(secret);
    void String(secret);
    statsd.flush();

    metrics.reset();
    void String(secret);
    statsd.flush();

    const lines = await server.drain();

    expect(lines).not.toContain(expect.stringContaining(':-'));
    expect(lines.filter((line) => line.startsWith('sensitive_redactions_total:'))).toEqual([
      'sensitive_redactions_total:3|c|#class:credential,surface:toString,label:api_key',
      'sensitive_redactions_total:1|c|#class:credential,surface:toString,label:api_key',
    ]);
  });

  it('folds two labels that sanitize to one tag, instead of inflating the counter every flush', async () => {
    // Sanitizing is many-to-one: 'a:b' and 'a,b' both become 'a_b'. Left as two
    // series they each compute their delta against the other's baseline, and
    // the counter grows by the difference on every flush and never recovers.
    const server = await listener();
    const metrics = started();
    const statsd = exporter(metrics, { host: '127.0.0.1', port: server.port });

    const first = new SensitiveString(CANARY, 'credential', 'a:b');
    const second = new SensitiveString(CANARY, 'credential', 'a,b');

    for (let index = 0; index < 5; index++) {
      void String(first);
    }
    void String(second);

    statsd.flush();
    statsd.flush();
    statsd.flush();

    const deltas = (await server.drain())
      .filter((line) => line.startsWith('sensitive_redactions_total:'))
      .map((line) => Number(line.slice(line.indexOf(':') + 1, line.indexOf('|'))));

    expect(deltas.reduce((total, delta) => total + delta, 0)).toBe(6);
    expect(metrics.getRedactionCount()).toBe(6);
  });

  it('sends a gauge as an absolute value', async () => {
    const server = await listener();
    const metrics = started({ trackInstances: true });
    const statsd = exporter(metrics, { host: '127.0.0.1', port: server.port });

    statsd.flush();

    expect(await server.drain()).toContain('sensitive_values_tracked:0|g');
  });

  describe('sanitizing, which is the same defence the Prometheus exporter needs', () => {
    it('cannot forge a metric line through a label value', async () => {
      const server = await listener();
      const metrics = started();
      const statsd = exporter(metrics, { host: '127.0.0.1', port: server.port });

      // Unescaped, this ends the metric and writes a second one, with tags of
      // its own taken from the rest of the label.
      void String(new SensitiveString(CANARY, 'credential', 'a\nintruder:99|c|#x:y'));
      statsd.flush();

      const lines = await server.drain();

      expect(lines.some((line) => line.startsWith('intruder:'))).toBe(false);
      expect(lines.filter((line) => line.startsWith('sensitive_redactions_total:'))).toEqual([
        'sensitive_redactions_total:1|c|#class:credential,surface:toString,label:a_intruder_99_c__x_y',
      ]);
    });

    it('truncates a label long enough to fill a datagram on its own', async () => {
      const server = await listener();
      const metrics = started();
      const statsd = exporter(metrics, { host: '127.0.0.1', port: server.port });

      void String(new SensitiveString(CANARY, 'credential', 'x'.repeat(5000)));
      statsd.flush();

      const [line] = (await server.drain()).filter((entry) =>
        entry.startsWith('sensitive_redactions_total:')
      );

      expect(line?.length).toBeLessThan(400);
    });

    it('sanitizes a global tag without losing the colon that makes it a pair', async () => {
      const server = await listener();
      const metrics = started();
      const statsd = exporter(metrics, {
        host: '127.0.0.1',
        port: server.port,
        globalTags: ['env:prod,forged:yes'],
      });

      void String(new SensitiveString(CANARY, 'credential', 'api_key'));
      statsd.flush();

      const lines = await server.drain();

      expect(lines[0]).toContain('#env:prod_forged_yes,');
    });
  });

  it('splits its output across datagrams rather than sending one too large to arrive', async () => {
    const server = await listener();
    const metrics = started();
    const statsd = exporter(metrics, {
      host: '127.0.0.1',
      port: server.port,
      maxPacketSize: 200,
    });

    for (let index = 0; index < 40; index++) {
      void String(new SensitiveString(CANARY, 'credential', `label_${String(index)}`));
    }

    statsd.flush();
    await server.drain();

    expect(server.received.length).toBeGreaterThan(1);
    for (const packet of server.received) {
      expect(Buffer.byteLength(packet)).toBeLessThanOrEqual(200);
    }
  });

  it('flushes the last window on stop, so a SIGTERM handler does not lose it', async () => {
    const server = await listener();
    const metrics = started();
    const statsd = exporter(metrics, { host: '127.0.0.1', port: server.port });

    void String(new SensitiveString(CANARY, 'credential', 'api_key'));
    statsd.stop();

    expect(
      (await server.drain()).some((line) => line.startsWith('sensitive_redactions_total:'))
    ).toBe(true);
  });

  it('sends nothing more once stopped', async () => {
    const server = await listener();
    const metrics = started();
    const statsd = exporter(metrics, { host: '127.0.0.1', port: server.port });

    statsd.stop();
    void String(new SensitiveString(CANARY, 'credential', 'api_key'));
    statsd.flush();

    expect(await server.drain()).toEqual([]);
  });

  it('reports a transport failure instead of throwing out of a flush', async () => {
    const metrics = started();
    const onError = vi.fn();
    // A hostname that cannot resolve, so the send fails asynchronously.
    const statsd = exporter(metrics, {
      host: 'statsd.invalid.',
      port: 8125,
      onError,
    });

    void String(new SensitiveString(CANARY, 'credential', 'api_key'));

    expect(() => statsd.flush()).not.toThrow();

    await new Promise((resolve) => setTimeout(resolve, 100));

    expect(onError).toHaveBeenCalled();
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(Error);
  });

  it('never lets a broken onError take the process down', async () => {
    const metrics = started();
    const statsd = exporter(metrics, {
      host: 'statsd.invalid.',
      port: 8125,
      onError: () => {
        throw new Error('the error handler is broken too');
      },
    });

    void String(new SensitiveString(CANARY, 'credential', 'api_key'));

    expect(() => statsd.flush()).not.toThrow();
    await new Promise((resolve) => setTimeout(resolve, 100));
  });

  it('starts one timer however many times start() is called, and does not hold the process open', () => {
    const metrics = started();
    const statsd = exporter(metrics, { host: '127.0.0.1', port: 8125 });

    expect(statsd.start(50)).toBe(statsd);
    expect(statsd.start(50)).toBe(statsd);
  });

  it('gets the final datagram out of a process that stops and exits', async () => {
    // The shutdown path end to end, in a process that actually exits rather
    // than one a test runner is holding open. What it pins is that stop()
    // does not close the socket out from under its own final flush. It does
    // not need stop() to ref anything: measured on Node 22.15.0, a pending
    // send holds the loop open through the request rather than the handle, so
    // an unreffed socket still delivers.
    const dist = resolve(process.cwd(), 'packages/sensitive-metrics/dist/index.js');
    const coreDist = resolve(process.cwd(), 'packages/sensitive-core/dist/index.js');

    if (!existsSync(dist) || !existsSync(coreDist)) {
      // Skipped rather than passed. CI builds before it tests.
      expect(true).toBe(true);
      return;
    }

    const server = await listener();
    const script = [
      `const { createMetricsCollector, StatsDExporter } = require(${JSON.stringify(dist)});`,
      `const { SensitiveString } = require(${JSON.stringify(coreDist)});`,
      'const m = createMetricsCollector();',
      'm.start();',
      "String(new SensitiveString('x', 'credential', 'api_key'));",
      `const s = new StatsDExporter(m, { host: '127.0.0.1', port: ${String(server.port)} });`,
      's.stop();',
    ].join('\n');

    await new Promise<void>((done, fail) => {
      execFile(process.execPath, ['-e', script], (error, _stdout, stderr) => {
        if (error) {
          fail(new Error(`the child process failed: ${stderr}`));
          return;
        }

        done();
      });
    });

    expect(
      (await server.drain()).some((line) => line.startsWith('sensitive_redactions_total:'))
    ).toBe(true);
  });

  it.each([
    [{ host: 42 }, 'a host'],
    [{ host: '127.0.0.1', port: 0 }, 'port'],
    [{ host: '127.0.0.1', port: 70000 }, 'port'],
  ])('refuses %o at construction', (config, message) => {
    expect(() => new StatsDExporter(started(), config as never)).toThrow(message);
  });
});
