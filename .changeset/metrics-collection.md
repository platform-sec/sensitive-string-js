---
'@platform-sec/sensitive-string-metrics': minor
'@platform-sec/sensitive-string-core': minor
---

Count what the library prevented, and price the rest against the emission points that exist.

`@platform-sec/sensitive-string-metrics` is the collector the redaction observer was built for. It
subscribes to `observeRedactions()` and publishes
`sensitive_redactions_total{class, label, surface}` first in its catalog, because every rendering of
a marker is a place a plain string would have been written, and that is the number a deployment is
judged on. Installing the package, calling `start()` and mounting a Prometheus endpoint is the whole
of a measurement-first deployment: no call site changes, and the counter is complete from `start()`
onward.

The rest of the catalog is smaller than the design asked for, and each omission has the same reason.
Core has three emission points, and only three. `observeRedactions()`, process-wide. The
`auditReveal` hook, which fires for the eight operations in `RevealDetails` and only under a context
carrying it. And the memory hygiene `WeakRef` count. A refusal fires nothing at all, deliberately:
the gate throws before the policy hook and before the audit hook so that a denied read is not logged
as a reveal. Construction and `equals()` fire nothing either.

So three counters ship rather than six. `sensitive_reveals_total{class, label, operation, context}`
carries the operation as a dimension, since one hook reports all eight, which makes the design's
separate revocations counter a dimension value and makes the expirations counter impossible: a value
does not expire, a read finds it expired and throws. `sensitive_refusals_total{class, code}` is fed
by the caller through `recordRefusal(error)` or the `meterRefusals` tee, and the README says so
rather than implying a coverage it does not have. The three histograms are not built, because each
needs a bracket around an operation and the one hook available fires at a single instant inside the
gate, so timing from it would measure the hook's own dispatch.

The three counters have three different coverages, which is the fact most likely to be misread, so
the README leads with the table and the instruction not to divide one into another. A
reveals-per-redaction ratio measures how much of your code you wired up, not how your system behaves.

`withMeteredReveals` exists because the obvious wiring is wrong. Installing a context with
`auditReveal: metrics.auditReveal` replaces the ambient context wholesale and silently drops whatever
audit sink the application put higher up the stack, which is a bad trade for a counter. It builds
through `createChildContext`, inherits the ambient tags, and chains the hooks, calling each through
the object it was declared on rather than extracting it, since `auditReveal` is a method in
`RevealContext` and core invokes it as one. The counter runs last, so a reveal an audit sink refused
is not counted as one that happened.

Two dimensions carry text the library does not choose, and both are treated as such. The `context`
dimension is **off by default**: a context name is free-form text from a call site where a request id
is also at hand, and a metrics store keeps it for months. There is no `context.tags.*` dimension.
`maxSeries` folds the caller-supplied dimensions into `__other__` rather than dropping events, so the
total stays right and only the breakdown is lost, and a hard ceiling underneath makes the bound hold
even where the non-folding dimensions are fed by hand.

Both exposition formats are line-oriented and one of the label values is caller text, so the escaping
is the point rather than a detail. A label of `k",surface="x"} 99\nintruder_total{a="b` closes the
brace, ends the line, and writes a metric of its own into a scrape; the StatsD equivalent is a
newline followed by `intruder:99|c|#x:y`. Each suite drives the injection its own format is
vulnerable to and asserts that the result is not a line, and the StatsD suite asserts on bytes that
crossed a real loopback socket rather than on a string an internal method returned.

Five defects found while building, and every one is the same mistake: a label value is caller text,
and the code treated it as a well-behaved identifier. A breakdown accumulated on an ordinary object
read `toString` off the prototype and rendered `"function toString() { [native code] }1"` as a metric
value, and would have rewritten the object's prototype for a label of `__proto__`. `StatsDExporter`
closed its socket in the same turn as its final flush, discarding the datagrams on exactly the
`SIGTERM` path that flush exists for. `PrometheusExporter` reserved five of its six dimension names
against `defaultLabels` and missed `context`, and a series carrying one label name twice is a scrape
Prometheus rejects outright, so a single misconfigured default label would take the whole `/metrics`
endpoint down. `StatsDExporter` also computed a delta per collector series, but sanitizing a tag is
many-to-one, so `a:b` and `a,b` both land on `a_b` and each computed its delta against the other's
baseline, inflating the counter on every flush and never recovering. And `collect()` documented an
ordering it did not implement.

Two more were resource defects rather than formatting ones. The StatsD TCP path ignored what `write`
returned, so a far end that accepts the connection and stops reading made Node buffer every payload
in this process: measured, twenty thousand writes held 193 MB, none of it freed while the connection
stayed open. And the cardinality cap bounded how many series a counter held but nothing about how
large one was, so a thousand legal series still made a scrape as large as the caller's labels were
long; dimension values are now truncated at ingest, where the truncated value becomes the series
identity and the two exporters cannot be handed series that render identically.

A third pass asked where the guarantees stop rather than what an input renders as or costs, and found
four more. Two were false sentences in the README about behaviour that was already correct, and both
concern a boundary. `sensitive_redactions_total` covers **one isolate**, not the process: measured, a
worker thread rendering five markers left a main-thread collector reporting zero, which inverts the
headline number for anyone whose real work happens in a worker pool. A collector plus a StatsD
exporter per worker composes, measured, because the agent sums the deltas; a Prometheus endpoint does
not, because it exports only the isolate serving it. And the stated reason core is a peer dependency
was backwards: two physical copies of core **share** the observer registry, because core keys it on
`Symbol.for()`, so redactions from both are counted; what does not survive is `recordRefusal`, which
recognises a refusal by `instanceof` and silently misses the other copy's. Both are now asserted,
which rule R6 asks for anyway. The other two were unvalidated configuration: `flushInterval` and
`maxPacketSize` accepted zero, negative and `NaN`, and `setInterval` turns any of those into a
one-millisecond timer rather than an error, so the mistake shipped as a flush loop; and both
exporters accepted a non-collector and failed at the first scrape instead of at boot.

A fourth pass added benchmarks and asked what recording costs, which found the largest defect of the
lot. Series were held in one `Map` keyed on the dimension values joined into a length-prefixed
composite, and that cost about 450 ns per redaction against a rendering core prices at 17 to 26 ns.
The expense is not the string building, it is the hashing: a freshly built key has no cached hash, so
every lookup hashes the whole string, where the dimension values are repeated strings V8 has already
hashed. Measured over three dimensions, 96 ns to build a key, 257 ns to build it and look it up, and
12 ns to walk three nested maps and build nothing. The counter now holds series in nested maps, one
level per dimension: `inc` into an existing series went from 1022 ns to 16 ns in a tight loop, and
the collector's end-to-end cost from about 450 ns to about 70 ns over a no-op observer. The shape is
collision-free by construction too, rather than needing the length prefix to earn it.

That rewrite changed one behaviour and three existing tests caught it. The composite key coerced its
inputs, so a non-string label, which core permits, threw on the way into the key and was counted as a
recording error; a trie has no such step and would have stored it, moving the failure to export time
where it is a broken `/metrics` response rather than a counted error. The check is explicit now, in
the one function every caller-supplied dimension passes through.

Eleven of the twelve were found by review after the suite was already green: four past 100 passing
tests, two past 109, three past 114, one past 129. Each has a test confirmed red against the unfixed
code, except the two that were wrong sentences rather than wrong lines, whose tests pin the measured
behaviour instead.

StatsD goes out over `node:dgram` and `node:net`, so both exporters ship in one package with no
third-party runtime dependency, against the design's proposal to split them. `collect()` is the
public seam between collection and export, and a CloudWatch or OpenTelemetry exporter needs nothing
else from a collector.

Rule R6 does not apply to the collector, which is where the design was wrong about it: a subscriber
is not a singleton. There is no process-global collector to reconfigure, nothing for a duplicate
install to split, and no reset to gate. Two collectors in one process are two independent sets of
numbers, which is what lets this package and a future OpenTelemetry one run side by side.

In core, `trackedRefCount()` becomes the public `trackedInstanceCount()`, which is the only new
export. The gauge over it is `sensitive_values_tracked` rather than the design's
`sensitive_values_active{class}`, on both counts deliberately: the `WeakRef` set is pruned by a
`FinalizationRegistry` that needs at least two GC cycles and two macrotask turns, so `active` is a
claim the number cannot support, and a per-class split needs a `deref()` on every entry, which keeps
its target alive to the end of the job. A gauge that extended the life of what it measured would be a
strange thing to put in a memory-hygiene metric.
