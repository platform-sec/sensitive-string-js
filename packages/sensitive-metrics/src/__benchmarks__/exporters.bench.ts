/**
 * What an export costs, which is the cost paid once per scrape or per flush
 * rather than once per redaction.
 *
 * These are the tasks in this package that the harness can actually see. A
 * single `inc` is below the tinybench floor and has to be batched; a scrape
 * over a hundred series is hundreds of microseconds and needs no help. Read
 * them as absolutes with a grain of salt and as ratios across series counts
 * with rather more confidence: the shape of the curve, whether an exporter is
 * linear in series count, survives being measured on a different machine.
 *
 * The number that matters operationally is not any single figure here. It is
 * whether a scrape at your series count fits inside your scrape interval with
 * room to spare, and every figure here is microseconds against an interval of
 * seconds.
 */

import { createSocket } from 'node:dgram';
import type { Socket } from 'node:dgram';
import { bench, describe } from 'vitest';
import type { MetricsCollector } from '../collector.js';
import { PrometheusExporter } from '../prometheus.js';
import { StatsDExporter } from '../statsd.js';
import { SERIES_COUNTS, benchFloor, collectorWithSeries, consume } from './fixtures.js';

benchFloor();

/**
 * A scrape, by how many series it renders.
 *
 * Every call does the full work: the exporter holds no state, so there is no
 * warm second call and nothing to invalidate. This is the honest cost of the
 * `/metrics` handler.
 */
describe('prometheus scrape by series count', () => {
  for (const count of SERIES_COUNTS) {
    let collector: MetricsCollector | undefined;
    let exporter: PrometheusExporter | undefined;

    bench(
      `${String(count)} series`,
      () => {
        consume(exporter?.export());
      },
      {
        setup: () => {
          collector = collectorWithSeries(count);
          exporter = new PrometheusExporter(collector, { prefix: 'bench_' });
        },
        teardown: () => {
          collector?.stop();
          collector = undefined;
          exporter = undefined;
        },
      }
    );
  }
});

/**
 * The same scrape with the labels a real deployment adds.
 *
 * `defaultLabels` are escaped once at construction and pasted per series, so
 * the gap against the group above is the paste rather than the escape. Worth
 * knowing before adding a sixth label to every series in the fleet.
 */
describe('prometheus scrape, 1000 series, by default label count', () => {
  const labelSets = [
    { name: 'none', labels: {} },
    { name: 'two', labels: { service: 'payment-api', env: 'production' } },
    {
      name: 'five',
      labels: {
        service: 'payment-api',
        env: 'production',
        region: 'eu-west-1',
        cluster: 'a',
        version: '1.4.2',
      },
    },
  ];

  for (const { name, labels } of labelSets) {
    let collector: MetricsCollector | undefined;
    let exporter: PrometheusExporter | undefined;

    bench(
      name,
      () => {
        consume(exporter?.export());
      },
      {
        setup: () => {
          collector = collectorWithSeries(1000);
          exporter = new PrometheusExporter(collector, { defaultLabels: labels });
        },
        teardown: () => {
          collector?.stop();
          collector = undefined;
          exporter = undefined;
        },
      }
    );
  }
});

/**
 * A flush, by how many series it walks.
 *
 * Steady state, and deliberately so: after the first flush nothing has moved,
 * so every task here measures the full two-pass fold and delta computation
 * over every series and sends nothing. That is what a flush costs on a timer
 * in a process whose counters are idle, which is the flush a service performs
 * most of the time. A flush that does send is this plus the packing and the
 * `send` call, which the socket makes asynchronous anyway.
 *
 * The datagrams go to a bound loopback socket that reads and discards, so the
 * kernel is not dropping them and the figures are not measuring an error path.
 */
describe('statsd flush by series count', () => {
  for (const count of SERIES_COUNTS) {
    let collector: MetricsCollector | undefined;
    let exporter: StatsDExporter | undefined;
    let server: Socket | undefined;

    bench(
      `${String(count)} series`,
      () => {
        exporter?.flush();
        consume(count);
      },
      {
        setup: async () => {
          const socket = createSocket('udp4');
          socket.on('message', () => undefined);

          const port = await new Promise<number>((done) => {
            socket.bind(0, '127.0.0.1', () => {
              done(socket.address().port);
            });
          });

          server = socket;
          collector = collectorWithSeries(count);
          exporter = new StatsDExporter(collector, {
            host: '127.0.0.1',
            port,
            onError: () => undefined,
          });

          // The first flush is the one that sends; every timed one after it
          // finds nothing changed, which is the case being measured.
          exporter.flush();
        },
        teardown: () => {
          exporter?.stop();
          collector?.stop();
          server?.close();
          exporter = undefined;
          collector = undefined;
          server = undefined;
        },
      }
    );
  }
});
