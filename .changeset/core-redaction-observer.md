---
'@platform-sec/sensitive-string-core': minor
---

Add `observeRedactions()`, a process-wide subscription to every rendering of a redaction marker.

```ts
const stop = observeRedactions(({ klass, label, surface }) => {
  redactions.inc({ klass, label: label ?? '', surface });
});
```

A reveal was always audited. A redaction was recorded nowhere, and it is the number that says what
the library prevented: every time `toString()`, `toJSON()` or the inspect hook rendered a marker,
some caller was about to write the plain string somewhere and the marker went instead. The
rendering runs on the `'safe'` read, which fires no audit hook, charges no budget and consults no
policy, and that stays so: a log line must not need authorization. Observation sits beside the
rendering rather than inside the gate, after the rendering succeeds, so a policy whose `redact`
throws reports nothing, because nothing was written.

The event carries the class, the label and the surface, frozen, and never the value or its
rendering. Under a deterministic-redaction policy the marker is a pseudonym of the value, and a
metric dimension is the wrong place for one. The four surfaces separate the readings an operator
has to make differently:

- `'toString'` is a coercion: a template literal, concatenation, `String()`. It is the surface T13
  describes, where a rendering may be a prevented log line or a broken outbound request, and the
  event cannot tell the two apart. A count here is meaningful only once the HTTP guard is installed.
- `'toJSON'` is `JSON.stringify()`, which a JSON logger and a JSON request body both reach.
- `'inspect'` is `util.inspect()` and `console.log()`.
- `'structure'` is a walker: `redactInStructure`, `redactCopy`, `safeStringify`, `safeLog`, the
  winston format and the pino serializer. This is the one surface that is unambiguously a sink that
  installed redaction, and a `serialize()` result a walker replaced reports here too, with no label,
  since the label in a wire shape is data off the wire and an event carrying it would let whoever
  built the payload choose a metric dimension.

The walkers render through the class's own path now rather than through `String(value)`. That is
what gives them their own surface, and it closes a gap on the way: an own `toString` on an unfrozen
instance, or a subclass override, used to decide what `redactInStructure` and `redactCopy` wrote. A
value a walker was asked to clean comes out clean whatever its `toString` says; the coercion itself
is still the instance's own business, which is what `freezeInstances` exists for.

An observer that throws is warned about once through `process.emitWarning` and its later throws are
swallowed, because a redaction is a log line and a log line must never throw. An observer's own
redactions are not observed, so a dashboard that logs a wrapped value inside its observer does not
recurse. The list is replaced rather than mutated on subscribe and unsubscribe, so a notification in
flight sees the list it started with. The registry is process-global under rule R6 and keyed on
`Symbol.for()`, so a second installed copy of core shares it; it protects a dashboard against a
missing subscription, not a secret against a hostile caller, since no event ever carried one.

What an unobserved process pays is one array-length read per rendering. Priced on Node 22.15.0 the
way the reveal counter was, two copies of `dist` with the read commented out of one, two million
`toString()` calls per round, twelve rounds interleaved, median taken: across three runs the delta
was 0.0, 0.7 and 1.5 ns on a rendering of 17 to 26 ns, inside the run-to-run spread. The observed
path adds one frozen object and one call per observer; `redaction.bench.ts` carries the ratio
between a no-op observer and a counting one, which is the exporter's cost rather than the library's.

34 cases across two suites. The security file asserts the event shape on every surface and through
every walker, that a renderer deriving its marker from the value leaves nothing of it in the event,
that a throwing, mutating or returning observer changes no rendering, that an observer's own
redactions and mid-notification subscriptions do not reach the notification in flight, and that an
own or subclass `toString` no longer reaches a walker. Nine mutations were run against the
mechanism list, each caught by at least one named test.
