# @platform-sec/sensitive-string-metrics

Aggregated counts of what this library did, with no third-party dependency and no OpenTelemetry.

The first metric is `sensitive_redactions_total{class, label, surface}`, and the order matters. A
reveal is the sanctioned path and is audited already. A *redaction* is a place a plain string would
have been written and a marker went instead, and until core grew `observeRedactions()` nothing
counted it. That is the number a deployment is judged on, and the one an enterprise can read before
it has wrapped a single field.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-metrics
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` 0.5+ (peer dependency)

Core is a peer dependency rather than a regular one, and the reason is narrower than the usual one.
Measured against two physical copies of core loaded into one process:

- The **redaction counter survives it.** Core's observer registry is keyed on `Symbol.for()`
  precisely so duplicate installs share it, so a collector subscribed through one copy counts
  renderings from the other. This is the counter that matters most, and it is the one that is safe.
- The **refusal counter does not.** `recordRefusal` recognises a refusal with
  `instanceof SensitiveStringError`, and an error raised by the other copy is not an instance of your
  copy's class. It is silently not counted, and `recordRefusal` returns `false` exactly as it does
  for an unrelated error.

So a duplicate install degrades this package quietly rather than loudly, which is the argument for
keeping core a peer and letting your package manager dedupe it.

This package has no third-party runtime dependency, and StatsD goes out over `node:dgram` rather than
a client library.

## Quick start

```typescript
import { createMetricsCollector, PrometheusExporter } from '@platform-sec/sensitive-string-metrics';

const metrics = createMetricsCollector();
metrics.start();

const exporter = new PrometheusExporter(metrics, {
  prefix: 'myapp_',
  defaultLabels: { service: 'payment-api', env: process.env.NODE_ENV ?? 'unknown' },
});

app.get('/metrics', (_req, res) => {
  res.set('Content-Type', exporter.contentType).send(exporter.export());
});
```

That is the whole of the measurement-first deployment. Nothing else has to change, no call site is
touched, and the redaction counter is complete from `start()` onward.

## The three counters do not have the same coverage

This is the one thing to understand before building a dashboard on them.

| Counter | Source | What it sees |
|---|---|---|
| `sensitive_redactions_total` | core's `observeRedactions()` | every rendering of a marker in this isolate, from `start()` onward |
| `sensitive_reveals_total` | the `auditReveal` hook | only operations under a context carrying this collector |
| `sensitive_refusals_total` | `recordRefusal()` | only what your `catch` blocks hand over |

"in this isolate" is not a technicality if you use worker threads. See
[Worker threads](#worker-threads).

**Do not divide one into another.** A reveals-per-redaction ratio measures how much of your code you
wired up, not how your system behaves.

The asymmetry is not a gap waiting to be closed. Core delivers an audit record through the context an
operation ran under and nowhere else, deliberately, so a reveal made under no context has nothing to
report to. And a refusal leaves the library by throwing, before the audit hook and before anything is
charged, precisely so a denied read is not logged as a reveal; there is no hook on that path and this
package does not invent one.

## The catalog

### `sensitive_redactions_total{class, label, surface}`

Counter. Every rendering of a redaction marker.

`surface` is not a detail, and a dashboard that collapses it misreads the number:

| Surface | What produced it | How to read it |
|---|---|---|
| `toString` | a coercion: a template literal, `String()`, concatenation | ambiguous. A prevented log line, **or** an outbound request that carried the marker instead of the value (T13) |
| `toJSON` | `JSON.stringify`, or a serializer honouring `toJSON()` | a JSON logger and a JSON request body both arrive here |
| `inspect` | `util.inspect`, `console.log` | a prevented log line |
| `structure` | a walker replaced the value: `redactInStructure`, `safeLog`, `safeStringify`, the winston format, the pino serializer | unambiguously a sink that installed redaction |

A rising `structure` count is the library working. A rising `toString` count is worth looking at
before it is worth celebrating: install the HTTP wrappers, and what is left there is the prevented
log lines.

A `serialize()` result a walker replaced reports under `structure` with **no label**. The label in a
wire shape is data off the wire, and an event carrying it would let whoever built a request body
choose one of your metric dimensions.

### `sensitive_reveals_total{class, label, operation, context}`

Counter. Every audited operation, under a metered context.

`operation` is `reveal`, `mask`, `hash`, `hmac`, `renew`, `revoke`, `clear` or `worker-handoff`, or
`unknown` for anything a later core release adds. The name says `reveals` because that is core's own
vocabulary for the hook and its record type; use `{operation="reveal"}` for full reveals alone.

`context` is off by default. See [Wiring the reveal counter](#wiring-the-reveal-counter).

### `sensitive_refusals_total{class, code, label}`

Counter. Refusals your code reported, by core's stable error `code`: `expired-value`,
`revoked-value`, `reveal-limit-exceeded`, `cleared-value`, and the rest. Safe to record, since core
documents `code` as a slug that never carries a value.

### `sensitive_values_tracked`

Gauge, off by default, and honestly named. It is core's `trackedInstanceCount()`, which needs
`setMemoryHygiene({ trackInstances: true })` on the core side as well or it publishes a flat zero.

**Read it as a ceiling, not a census.** The registry is pruned by a `FinalizationRegistry`, which
needs at least two GC cycles and two macrotask turns, so a value that became garbage a moment ago is
still in this number and there is no bound on how long it stays. There is no `class` dimension for a
related reason: splitting the set by class means calling `deref()` on every entry, and a `deref()`
that returns an instance keeps that instance alive to the end of the job, so a gauge scraped every
fifteen seconds would extend the life of everything it measured.

### The collector's own numbers

`sensitive_metrics_events_aggregated_total`, `sensitive_metrics_events_dropped_total` and
`sensitive_metrics_recording_errors_total`. Without them the cardinality cap and the never-throw
contract are promises with no way to check them from a dashboard. The last one should be zero.

## Worker threads

A collector counts its own isolate and nothing else. Core's observer registry is a `globalThis`
singleton, and a worker thread has its own `globalThis`, so a collector on the main thread sees
**none** of a worker's redactions. Measured on Node 22.15.0: a worker rendering five markers left the
main thread's collector reporting zero.

That matters more here than a limitation usually does, because it silently inverts the headline
number. An application that does its real work in a worker pool, deploys this on the main thread and
reads a near-zero `sensitive_redactions_total` has not learned that the library prevented nothing. It
has learned that it instrumented the wrong isolate.

The fix is one collector per isolate. Whether that composes depends on the exporter:

- **StatsD composes.** Each worker builds its own collector and its own `StatsDExporter` pointed at
  the same agent, and the server sums the deltas. Measured: a worker's five redactions arrive at the
  agent as `sensitive_redactions_total:5|c|#...` with no involvement from the main thread.
- **Prometheus does not.** The endpoint is served by whichever isolate holds the HTTP server, and it
  can only export the collector in that isolate. Move the numbers yourself over `postMessage`, or use
  StatsD for the workers.

```typescript
// worker.ts
const metrics = createMetricsCollector();
metrics.start();
const statsd = new StatsDExporter(metrics, { host: 'statsd.internal' });
statsd.start(10_000);
process.on('exit', () => statsd.stop());
```

Reveal contexts do not cross the boundary either, for the same reason: `AsyncLocalStorage` is per
isolate. Core's `toWorkerPayload()` / `withWorkerPayload()` carry values and the portable context
across, and the receiving side installs its own hook, so a metered context on the far side is the
one you build there.

## Wiring the reveal counter

The obvious wiring is wrong:

```typescript
// Don't. This replaces the ambient context wholesale, so whatever audit sink
// your application installed further up the stack is silently gone for
// everything inside.
withRevealContext({ name: 'payment', auditReveal: metrics.auditReveal }, fn);
```

Use `withMeteredReveals`, which builds the context through `createChildContext`, inherits the ambient
tags, and chains the hooks so every one of them runs:

```typescript
await metrics.withMeteredReveals({ name: 'payment', reason: 'charging a card' }, async () => {
  await chargeCard(card.reveal());
});
```

The counter runs last in the chain. A hook that throws stops the reveal, so counting last means a
reveal an audit sink refused is not counted as one that happened.

`meteredContext(overrides)` returns the context without running anything, for a framework that
installs it itself. It reads the ambient context at the moment you call it, not at the moment the
context is installed, so build it where you intend it to inherit from.

A started collector is reachable from core's process-global observer registry, which means it stays
alive until `stop()` runs. Build one per process, or per isolate; a collector per request that is
never stopped is a leak, and its counters keep accumulating besides.

### The context dimension is opt-in

```typescript
const metrics = createMetricsCollector({ dimensions: ['label', 'context'] });
```

A context name is free-form text chosen at the call site, where a request id or a user identifier is
also at hand, and a metrics store keeps what it is given for months and shows it to everyone. So it
is off until you have decided what your context names are. `label` is on by default: it is a
classification the wrapping code declared, and it is what makes the redaction counter readable.

There is no `context.tags.*` dimension and there will not be one. Tags hold request ids and user ids.

## Counting refusals

```typescript
try {
  return token.reveal(ctx);
} catch (error) {
  metrics.recordRefusal(error, 'credential');
  throw error;
}
```

Or, as a tee that rethrows the error untouched:

```typescript
return metrics.meterRefusals(() => token.reveal(ctx), 'credential');
```

Anything that is not one of this library's refusals is ignored and reported as `false`, so either
form can sit in a `catch` that also sees ordinary application errors.

## Cardinality

Two dimensions carry text this library does not choose: `label`, and `context` where you turned it
on. A metrics store creates a series per distinct value, so an application that labels a value with a
user id turns a counter into a table of its users.

```typescript
createMetricsCollector({ maxSeries: 1000, onCardinalityExceeded: 'aggregate' });
```

- `'aggregate'` (default) folds the caller-supplied dimensions into `__other__` and keeps the
  library's own. **Totals stay correct**; only the breakdown is lost, and it is lost visibly.
- `'drop'` stops counting past the cap and records how much under
  `sensitive_metrics_events_dropped_total`. Totals go wrong.
- `'warn'` is `'aggregate'` plus one `process.emitWarning` per counter, the first time it folds.

Folded series are admitted past `maxSeries`, since the point of a fold is that it has somewhere to
go, and a hard ceiling of twice `maxSeries` sits under both.

A cap on how *many* series there are says nothing about how *large* one is, so caller-supplied
dimension values are also truncated to 200 characters when they are recorded. Without that, a
thousand perfectly legal series still make a scrape as big as your labels are long. Truncation
happens at the collector rather than in an exporter on purpose: the truncated value is then the
series identity, so two labels sharing a 200-character prefix become one series everywhere and the
exporters agree. Truncating in the Prometheus exporter instead would hand it two distinct series with
identical label sets, which is a duplicate series and a scrape the server rejects outright.

## What the exporters escape, and why it matters

Both output formats are line-oriented, and one of the label values is whatever your code passed as a
label. Unescaped, this is not a rendering problem:

```typescript
new SensitiveString(token, 'credential', 'k",surface="x"} 99\nintruder_total{a="b');
```

That label closes the brace, ends the line, and writes a metric of its own into the scrape. The
Prometheus exporter escapes `\`, `"`, `\n` and `\r`; the StatsD exporter replaces anything outside
`[a-zA-Z0-9_-./]`, because `|`, `,`, `#` and a newline each rewrite a StatsD line. Each suite drives an injection built for its own format, and asserts that the result is
not a line: the label value is still in the output, escaped, inside one set of quotes.

The Prometheus exporter also refuses, at construction rather than at the first scrape, a prefix that
is not a legal metric-name start, a default label name the format would not accept, and a default
label that would overwrite one of the collector's own dimensions.

## StatsD

```typescript
import { StatsDExporter } from '@platform-sec/sensitive-string-metrics';

const statsd = new StatsDExporter(metrics, {
  host: 'statsd.internal',
  prefix: 'myapp.sensitive.',
  globalTags: ['env:production', 'service:payment-api'],
});

statsd.start(10_000);

process.on('SIGTERM', () => {
  statsd.stop();   // flushes the last window, then closes once it has left
});
```

StatsD counters are deltas and the collector holds cumulative totals, so the exporter keeps the last
value it sent per series and sends the difference. A total that went backwards, which is what
`reset()` produces, is treated as a restart rather than sent as a negative delta.

Sanitizing is many-to-one, so two labels can arrive at one tag: `a:b` and `a,b` both become `a_b`.
Those series are summed into one before any delta is computed, because a StatsD server is going to
see them as one series whatever this exporter does, and leaving them separate makes each flush
compute its delta against the other's baseline. The same two labels stay distinct in Prometheus,
which escapes rather than replaces, so the two exporters can legitimately disagree on the breakdown.

The baseline advances when a datagram is handed to the socket, not when it arrives, so a datagram the
network drops takes its delta with it and the count stays short by that much. That is inherent to
fire-and-forget UDP; `protocol: 'tcp'` narrows it without closing it.

The socket and the timer are `unref`ed, so neither holds a process open. `stop()` flushes and then
closes only once the datagrams have actually left, because closing a UDP socket with sends
outstanding discards them, which would make the shutdown flush decorative on exactly the path it
exists for. It does not need to `ref` anything: a pending send holds the event loop open through the
request rather than the handle. A handler that calls `process.exit()` on the next line still loses
them.

DogStatsD tag syntax, UDP by default and TCP through `protocol: 'tcp'`. A transport failure reaches
`onError` if you passed one, and otherwise warns once through `process.emitWarning` and is silent
after; there is no mode in which a flush throws.

Under TCP, a flush is dropped once more than a megabyte is queued unwritten. A `write` to a socket
the far end has stopped reading returns `false` and buffers in your process: measured on Node
22.15.0 against a server that accepts and never reads, twenty thousand writes held 193 MB, and none
of it is freed while the connection stays open. Dropping metrics is the right failure for this
component; growing the heap of the process it is measuring is not. The drop is reported through
`onError`.

## Reading the numbers programmatically

```typescript
const snapshot = metrics.getSnapshot();
// { redactions: { total, byClass, bySurface, byLabel },
//   reveals:    { total, byClass, byOperation, byLabel, byContext },
//   refusals:   { total, byClass, byCode, byLabel },
//   valuesTracked: number | null,
//   meta: { started, eventsAggregated, eventsDropped, recordingErrors } }

metrics.getRedactionCount({ klass: 'credential', surface: 'toString' });
metrics.getRevealCount({ operation: 'reveal', context: 'payment' });
metrics.getRefusalCount({ code: 'expired-value', label: 'otp' });
```

`collect()` returns the metric families an exporter reads, which is the whole seam: a CloudWatch or
OpenTelemetry exporter needs nothing else from the collector. If you write one, read `DIMENSION_NAMES`
too and refuse any caller-configured label that collides with one. In Prometheus that collision is
not a misread row, it is a scrape the server rejects whole.

## Alert rules

```yaml
groups:
  - name: sensitive-data
    rules:
      # A rendering on the toString surface is either a log line this library
      # saved or a request that went out carrying a marker. Both are worth a
      # look; the second is an outage.
      - alert: MarkerOnTheCoercionSurface
        expr: rate(sensitive_redactions_total{surface="toString"}[5m]) > 0
        for: 10m
        labels: { severity: warning }

      - alert: HighCredentialRevealRate
        expr: rate(sensitive_reveals_total{class="credential",operation="reveal"}[5m]) > 100
        for: 2m
        labels: { severity: warning }

      - alert: SensitiveValueRefusals
        expr: rate(sensitive_refusals_total[5m]) > 10
        for: 1m
        labels: { severity: critical }

      # The collector telling you its own numbers are wrong.
      - alert: MetricsRecordingErrors
        expr: increase(sensitive_metrics_recording_errors_total[15m]) > 0
        labels: { severity: warning }
```

## What it costs

Benchmarks live in `src/__benchmarks__/` and run with `pnpm bench`. Read them as ratios inside a
group; the absolute figures below were taken on Node 22.15.0 on one machine and describe it as much
as the code.

Per redaction, which is the cost a process pays continuously:

| | ns |
|---|---|
| rendering, nothing observing | ~157 |
| one no-op observer, which is core's cost to notify | ~213 |
| one metrics collector | ~283 |
| two collectors, as a process running a second exporter has | ~372 |

So the collector adds roughly 70 ns to a rendering, and a second subscriber roughly the same again.
The tinybench floor is about 100 ns of that, so treat the gaps rather than the absolutes as the
measurement. A single `inc` into an existing series, timed in a tight loop instead, is about 16 ns.

Per scrape, which is paid once per interval rather than per log line: about 37 µs for 100 series and
about 2.8 ms for 1000, near enough linear, against a scrape interval measured in seconds. A StatsD
flush is within noise of the same figures.

Getting there needed one non-obvious thing. Series are held in nested `Map`s, one level per
dimension, rather than in a single map keyed on the dimension values joined together. The joined key
is the obvious implementation and it was the first one, and it is about twenty times slower on the
per-redaction path. The cost is not the string building, it is the hashing: a freshly built key has
no cached hash, so every lookup hashes the whole string, where the dimension values themselves are
repeated strings V8 has already hashed. Measured, three dimensions: 96 ns to build a key, 257 ns to
build it and look it up, 12 ns to walk three nested maps and build nothing.

## Two collectors are fine

A collector is a subscriber, not a singleton, and core does not know it exists. A process can run
this collector and an OpenTelemetry exporter side by side, each subscribing for itself, neither
knowing about the other, and there is no process-global collector for anything to reconfigure behind
your back.

## What is not here

- **No latency or lifetime histograms.** Every histogram in the original catalog needs a bracket
  around an operation, and the only hook that exists fires at one instant inside the gate, after
  authorization and before the value is materialized. Timing from there would measure the hook's own
  dispatch. Time `reveal()` at your call site; the library adds nothing.
- **No creation, comparison or destruction counters.** Each needs an emission point in core the way
  redactions got one, and none exists. When they arrive they will be subscriptions, one per event
  kind, never a static on the `SensitiveString` class.
- **No `sensitive_reveals_total` for unaudited reveals.** See the coverage table above.

## What this does not protect against

The library cannot tell a label from a secret. If your code writes
`new SensitiveString(v, 'credential', v)`, the value becomes a metric dimension, and this package
records it. The same goes for a context name you pass to `withMeteredReveals`, and for the `code` on
a `SensitiveStringError` subclass of your own. The mitigations are real but partial: the context
dimension is off by default, the cardinality cap bounds how many such values accumulate, the length
cap bounds how large each one is, and no dimension is ever derived from the value itself. Label your
values with classifications, not with data.

It is also not an audit log, and the two are not interchangeable. A counter answers "how many"; it
cannot answer "who, when, and why", and a dimension fine-grained enough to try is the cardinality
problem above wearing a different hat. Core's `auditReveal` is where that question is answered.
