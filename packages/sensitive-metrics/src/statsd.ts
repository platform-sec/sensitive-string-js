import { createSocket } from 'node:dgram';
import type { Socket as UdpSocket } from 'node:dgram';
import { connect } from 'node:net';
import type { Socket as TcpSocket } from 'node:net';
import type { MetricsCollector } from './collector.js';

/**
 * StatsD, in the DogStatsD dialect, over UDP or TCP with no third-party
 * client.
 *
 * Two things make this more than a formatting exercise.
 *
 * The first is that StatsD counters are *deltas*. The collector holds
 * cumulative totals, because that is what a Prometheus scrape needs, so this
 * exporter keeps the last value it sent per series and sends the difference.
 * A collector that was reset, or a series whose total went backwards for any
 * other reason, is treated as a fresh start rather than sent as a negative
 * delta, which every StatsD server would either reject or subtract.
 *
 * The second is that the protocol is line-oriented and delimiter-separated,
 * which puts it in the same position as the Prometheus exposition format: one
 * of the tag values is the label whoever wrapped the value chose. A newline in
 * it splits one metric into two, and a `|` or a `,` rewrites the tags of the
 * metric it is in. Every name and every tag goes through the sanitizer below
 * for that reason and not for tidiness.
 */

const DEFAULT_PORT = 8125;

/**
 * Fits inside one Ethernet frame, so a UDP datagram is not fragmented.
 *
 * 1432 is the widely used figure: 1500 bytes of MTU less 20 of IPv4 header,
 * 8 of UDP header and 40 of headroom for tunnelling. A fragmented datagram is
 * not merely slower; losing one fragment loses the whole packet, so metrics
 * arrive in bursts of nothing.
 */
const DEFAULT_MAX_PACKET_SIZE = 1432;

/** Long enough for any sensible label, short enough that one cannot fill a packet. */
const MAX_TAG_VALUE_LENGTH = 200;

/**
 * How much unwritten TCP payload to hold before dropping metrics instead.
 *
 * A `write` to a socket the far end is not reading returns `false` and buffers
 * in the process. Ignoring that is how a metrics exporter becomes a memory
 * leak: measured on Node 22.15.0 against a server that accepts and never
 * reads, twenty thousand writes buffered 193 MB, and nothing frees it while
 * the connection stays open. Dropping metrics is the correct failure for this
 * component; growing the heap of the process it is measuring is not.
 */
const MAX_TCP_BUFFERED_BYTES = 1_000_000;

export interface StatsDExporterConfig {
  host: string;
  /** Default `8125`. */
  port?: number;
  /**
   * Prepended to every metric name. Include the trailing separator you want:
   * `'myapp.sensitive.'` yields `myapp.sensitive.sensitive_redactions_total`.
   */
  prefix?: string;
  /** Added to every metric, as `key:value` strings. */
  globalTags?: readonly string[];
  /** Default `'udp'`. */
  protocol?: 'udp' | 'tcp';
  /** Bytes per datagram, UDP only. Default `1432`. */
  maxPacketSize?: number;
  /** Milliseconds between flushes when {@link StatsDExporter.start} is called with no argument. Default `10000`. */
  flushInterval?: number;
  /**
   * Called with any transport error.
   *
   * Without one, the first error is reported through `process.emitWarning` and
   * the rest are swallowed. A metrics exporter must not be able to take a
   * process down because a StatsD agent was restarted, so there is no mode in
   * which these throw.
   */
  onError?: (error: Error) => void;
}

/**
 * Make a string safe to appear in a metric name.
 *
 * StatsD keys are dot-separated, so a dot is kept and everything outside the
 * conservative set becomes an underscore.
 */
function sanitizeName(value: string): string {
  return value.replaceAll(/[^a-zA-Z0-9_.]/g, '_');
}

/**
 * Make a string safe to appear in a tag.
 *
 * `|` separates the fields of a metric line, `,` separates tags, `#`
 * introduces the tag section, and a newline ends the metric. Any of them
 * inside a caller-chosen label or context name would let that string write
 * metrics of its own, so all four go, along with the rest of the control
 * characters and anything else outside the set a StatsD server will accept.
 *
 * Truncated as well, so no single tag can consume a datagram.
 */
function sanitizeTag(value: string): string {
  const cleaned = value.replaceAll(/[^a-zA-Z0-9_\-./]/g, '_');

  return cleaned.length > MAX_TAG_VALUE_LENGTH ? cleaned.slice(0, MAX_TAG_VALUE_LENGTH) : cleaned;
}

/**
 * Refuse a millisecond or byte count that is not a positive finite number.
 *
 * `setInterval` and the packet packer both accept nonsense and turn it into
 * behaviour rather than an error, which is the reason to check here.
 */
function requirePositive(value: number, name: string): void {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new TypeError(
      `StatsDExporter: ${name} must be a positive finite number, received ${String(value)}`
    );
  }
}

/**
 * One series folded onto the key it will be sent under.
 *
 * The fold is not an optimization. Sanitizing a tag value is many-to-one, so
 * two distinct label tuples can land on one key: `a:b` and `a,b` both become
 * `a_b`. Left as two series they each compute their delta against the other's
 * baseline, and the counter inflates by the difference on every flush, forever.
 */
interface Pending {
  readonly name: string;
  readonly suffix: string;
  readonly type: 'counter' | 'gauge';
  value: number;
}

/**
 * Pushes a collector's numbers to a StatsD agent.
 *
 * @example
 * ```ts
 * const statsd = new StatsDExporter(metrics, {
 *   host: 'statsd.internal',
 *   prefix: 'myapp.sensitive.',
 *   globalTags: ['env:production', 'service:payment-api'],
 * });
 *
 * statsd.start(10_000);
 *
 * process.on('SIGTERM', () => {
 *   statsd.stop();   // flushes the last window before closing
 * });
 * ```
 */
export class StatsDExporter {
  readonly #collector: MetricsCollector;
  readonly #host: string;
  readonly #port: number;
  readonly #prefix: string;
  readonly #globalTags: readonly string[];
  readonly #protocol: 'udp' | 'tcp';
  readonly #maxPacketSize: number;
  readonly #flushInterval: number;
  readonly #onError: ((error: Error) => void) | undefined;

  /** The cumulative value last sent per series, so a counter can be sent as a delta. */
  #sent = new Map<string, number>();
  #timer: NodeJS.Timeout | undefined;
  #udp: UdpSocket | undefined;
  #tcp: TcpSocket | undefined;
  #warned = false;
  #closed = false;
  /** Datagrams handed to the socket whose callback has not run yet. */
  #inFlight = 0;
  #closeWhenDrained = false;

  constructor(collector: MetricsCollector, config: StatsDExporterConfig) {
    if (typeof config !== 'object' || config === null || typeof config.host !== 'string') {
      throw new TypeError('StatsDExporter requires a configuration object with a host');
    }

    if (typeof collector?.collect !== 'function') {
      throw new TypeError('StatsDExporter requires a metrics collector as its first argument');
    }

    const port = config.port ?? DEFAULT_PORT;

    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new TypeError(
        `StatsDExporter: port must be between 1 and 65535, received ${String(port)}`
      );
    }

    const flushInterval = config.flushInterval ?? 10_000;
    const maxPacketSize = config.maxPacketSize ?? DEFAULT_MAX_PACKET_SIZE;

    // Refused rather than clamped. `setInterval` treats a negative or NaN delay
    // as one millisecond, so the mistake does not fail: it produces an exporter
    // flushing a thousand times a second at whatever the far end is, which is a
    // worse outage than a refused constructor and much harder to attribute.
    requirePositive(flushInterval, 'flushInterval');
    requirePositive(maxPacketSize, 'maxPacketSize');

    this.#collector = collector;
    this.#host = config.host;
    this.#port = port;
    this.#prefix = config.prefix ?? '';
    this.#globalTags = (config.globalTags ?? []).map((tag) => sanitizeTagPair(tag));
    this.#protocol = config.protocol ?? 'udp';
    this.#maxPacketSize = maxPacketSize;
    this.#flushInterval = flushInterval;
    this.#onError = config.onError;
  }

  /**
   * Flush every `intervalMs`, and keep flushing until {@link stop}.
   *
   * The timer is `unref`ed, so it never keeps the process alive on its own: a
   * script that finishes its work exits, rather than sitting in an event loop
   * held open by a metrics exporter.
   */
  start(intervalMs: number = this.#flushInterval): this {
    requirePositive(intervalMs, 'start(intervalMs)');

    if (this.#timer !== undefined) {
      return this;
    }

    this.#timer = setInterval(() => {
      this.flush();
    }, intervalMs);
    this.#timer.unref();

    return this;
  }

  /**
   * Send what is pending, stop the timer, and close the socket.
   *
   * Flushes first, so the last window is not lost when this runs from a
   * `SIGTERM` handler, and closes only once those datagrams have left. Closing
   * a UDP socket with sends outstanding discards them, which would have made
   * the flush above decorative on exactly the path it exists for.
   *
   * Nothing here needs to `ref` the socket. Measured on Node 22.15.0: a
   * pending `send` holds the event loop open by itself, through the request
   * rather than the handle, so a process whose last act is this one still gets
   * the datagrams out even though the socket was opened unreffed. A handler
   * that calls `process.exit()` on the next line loses them; nothing at this
   * layer can help with that.
   *
   * After this the exporter is finished. Build another one to resume.
   */
  stop(): void {
    if (this.#timer !== undefined) {
      clearInterval(this.#timer);
      this.#timer = undefined;
    }

    this.flush();
    this.#closed = true;
    this.#closeWhenDrained = true;
    this.#closeIfDrained();

    // `end` rather than `destroy`: a destroy discards whatever Node has
    // buffered for the connection, which on this path is the final flush.
    this.#tcp?.end();
    this.#tcp = undefined;
  }

  /**
   * Send the change since the last flush.
   *
   * Counters go as deltas and gauges as absolute values. A flush that sends
   * nothing because nothing changed is normal and costs one pass over the
   * series.
   */
  flush(): void {
    if (this.#closed) {
      return;
    }

    let lines: string[];

    try {
      lines = this.#render();
    } catch (error) {
      this.#report(error);
      return;
    }

    if (lines.length === 0) {
      return;
    }

    if (this.#protocol === 'tcp') {
      this.#sendTcp(`${lines.join('\n')}\n`);
      return;
    }

    for (const packet of this.#packets(lines)) {
      this.#sendUdp(packet);
    }
  }

  /**
   * Every line this flush should send, and the baseline the next one reads.
   *
   * Two passes. The first folds each series onto the key it will actually be
   * sent under, summing counters that collide there, for the reason on
   * {@link Pending}. The second turns each folded entry into a delta.
   *
   * The baseline is advanced here rather than on delivery, so a datagram the
   * network drops takes its delta with it and the count is short by that much
   * from then on. That is inherent to fire-and-forget UDP and is what every
   * StatsD client does; `protocol: 'tcp'` narrows it without closing it.
   */
  #render(): string[] {
    const pending = new Map<string, Pending>();

    for (const family of this.#collector.collect()) {
      const name = sanitizeName(`${this.#prefix}${family.name}`);

      for (const series of family.series) {
        const tags = [
          ...this.#globalTags,
          ...Object.entries(series.labels)
            .filter(([, value]) => value !== '')
            .map(([key, value]) => `${sanitizeName(key)}:${sanitizeTag(value)}`),
        ];

        const suffix = tags.length === 0 ? '' : `|#${tags.join(',')}`;
        const key = `${name}${suffix}`;
        const existing = pending.get(key);

        if (existing === undefined) {
          pending.set(key, { name, suffix, type: family.type, value: series.value });
        } else if (family.type === 'gauge') {
          // A gauge is a reading rather than an accumulation, so a collision
          // takes the last one rather than their sum. No gauge here carries a
          // dimension, so this is unreachable today and is here to stay
          // correct if one ever does.
          existing.value = series.value;
        } else {
          existing.value += series.value;
        }
      }
    }

    const lines: string[] = [];
    // Rebuilt rather than updated in place, so a series the collector no
    // longer has stops occupying an entry. Without that, a long-lived process
    // whose labels churn would grow this map past the bound the collector
    // itself keeps.
    const sent = new Map<string, number>();

    for (const [key, entry] of pending) {
      sent.set(key, entry.value);

      if (entry.type === 'gauge') {
        lines.push(`${entry.name}:${String(entry.value)}|g${entry.suffix}`);
        continue;
      }

      const previous = this.#sent.get(key) ?? 0;
      // A total that went backwards is a reset, not a negative delta. Sending
      // the current value is what a StatsD client does on a restart, and it is
      // the reading that loses the least.
      const delta = entry.value < previous ? entry.value : entry.value - previous;

      if (delta !== 0) {
        lines.push(`${entry.name}:${String(delta)}|c${entry.suffix}`);
      }
    }

    this.#sent = sent;

    return lines;
  }

  /**
   * Pack lines into datagrams no larger than the configured maximum.
   *
   * A single line longer than the maximum goes out on its own, oversized: a
   * metric line cannot be split across datagrams, and dropping it would lose a
   * count silently where an oversized datagram merely risks fragmentation.
   * Reaching that needs a great many global tags, since a label is truncated at
   * {@link MAX_TAG_VALUE_LENGTH}.
   */
  *#packets(lines: readonly string[]): Generator<string> {
    let packet = '';

    for (const line of lines) {
      const addition = packet === '' ? line : `\n${line}`;

      if (
        packet !== '' &&
        Buffer.byteLength(packet) + Buffer.byteLength(addition) > this.#maxPacketSize
      ) {
        yield packet;
        packet = line;
        continue;
      }

      packet += addition;
    }

    if (packet !== '') {
      yield packet;
    }
  }

  #sendUdp(packet: string): void {
    try {
      this.#udp ??= this.#openUdp();
      this.#inFlight++;
      this.#udp.send(packet, this.#port, this.#host, (error) => {
        this.#inFlight--;

        if (error) {
          this.#report(error);
        }

        this.#closeIfDrained();
      });
    } catch (error) {
      this.#report(error);
    }
  }

  /** Close the UDP socket once `stop()` has run and nothing is still in flight. */
  #closeIfDrained(): void {
    if (!this.#closeWhenDrained || this.#inFlight > 0) {
      return;
    }

    this.#closeWhenDrained = false;
    this.#udp?.close();
    this.#udp = undefined;
  }

  #openUdp(): UdpSocket {
    const socket = createSocket('udp4');
    socket.on('error', (error) => {
      this.#report(error);
    });
    socket.unref();
    return socket;
  }

  #sendTcp(payload: string): void {
    try {
      if (this.#tcp === undefined) {
        const socket = connect({ host: this.#host, port: this.#port });
        socket.setNoDelay(true);
        socket.unref();
        socket.on('error', (error) => {
          this.#report(error);
          // Dropped rather than retried here. The next flush opens a fresh
          // connection, which is a retry with a natural backoff already
          // attached: the flush interval.
          socket.destroy();
          if (this.#tcp === socket) {
            this.#tcp = undefined;
          }
        });
        this.#tcp = socket;
      }

      // Node buffers writes made before the connection completes, so there is
      // no connecting state to handle here. What it does not do is stop
      // buffering, so the backlog is what has to be checked: a far end that
      // accepts the connection and never reads it, or one that never finishes
      // connecting, otherwise grows this process without bound.
      if (this.#tcp.writableLength > MAX_TCP_BUFFERED_BYTES) {
        this.#report(
          new Error(
            `StatsD TCP backlog exceeded ${String(MAX_TCP_BUFFERED_BYTES)} bytes; ` +
              'dropping this flush. The far end is not reading.'
          )
        );
        return;
      }

      this.#tcp.write(payload);
    } catch (error) {
      this.#report(error);
    }
  }

  #report(error: unknown): void {
    const reported = error instanceof Error ? error : new Error(String(error));

    if (this.#onError !== undefined) {
      try {
        this.#onError(reported);
      } catch {
        // An onError that throws is the one thing left that could take the
        // process down from here, and it does not get to.
      }
      return;
    }

    if (this.#warned) {
      return;
    }

    this.#warned = true;

    process.emitWarning(
      `StatsDExporter could not send to ${this.#host}:${String(this.#port)} ` +
        `(${reported.name}: ${reported.message}). Metrics are being dropped; later failures are ` +
        'silent. Pass onError to handle these yourself.',
      'SensitiveStringMetricsWarning'
    );
  }
}

/**
 * Sanitize a caller-supplied `key:value` global tag without losing its colon.
 *
 * A global tag is configuration rather than data off a request, so this is
 * hygiene rather than defence, but it goes through the same rules: a global
 * tag read out of an environment variable is one deployment mistake away from
 * carrying a newline.
 */
function sanitizeTagPair(tag: string): string {
  const separator = tag.indexOf(':');

  if (separator === -1) {
    return sanitizeTag(tag);
  }

  return `${sanitizeName(tag.slice(0, separator))}:${sanitizeTag(tag.slice(separator + 1))}`;
}
