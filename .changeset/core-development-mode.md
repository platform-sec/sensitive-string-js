---
'@platform-sec/sensitive-string-core': minor
---

Add development mode: what a value's own history was, for the engineer debugging it.

A reveal that fails, or one that should never have happened, says very little on its own. The stack
names the caller of `reveal()` and nothing else: not where the value came from, not how often it has
already been read, not which of the four `SensitiveString`s in scope this one is. `setDevMode()`
turns on recording of exactly that, `getDevModeConfig()` reads the resolved configuration back, and
`withDevMode(config, fn)` installs one for the length of a call, which is what a test wants.

```ts
setDevMode({
  enabled: true,
  captureStackTraces: true,
  captureCreationStack: true,
  warnOnMissingContext: true,
  warnOnRepeatedReveal: { threshold: 5, window: 60_000 },
  logReveals: { enabled: true, showPartialValue: true },
});
```

The history is also readable, through a new `__devInfo` getter: `createdAt`, `creationStack`,
`revealCount`, `revealTimestamps` and `lastRevealStack`. It is `undefined` when development mode is
off rather than a missing property, so debugging code written against it compiles and runs in
production. Records live in a `WeakMap` keyed by the instance, so a value's history is collected
with the value, and a record is only kept for a value constructed while development mode was on.

Everything is off until it is turned on. What a process that never calls `setDevMode` pays is one
property read in the constructor and one in the raw-value gate.

What counts as an exposure is exactly what an audit hook sees, because the recording sits in the
same gate, immediately after the audit call: `reveal()`, `mask()`, `serialize()`, `map()` and the
string, regex and template operations count, and each is reported under its own operation name.
`equals()` does not, because a comparison reads the value without disclosing it, and neither does
redaction. A read the gate refused, or one an audit hook stopped by throwing, is not counted: a
denied reveal is not a reveal.

Five decisions differ from the design document, all in the same direction.

`showPartialValue` prints a prefix of the raw value, which is a real disclosure and the reason the
flag is off by default and capped at eight characters. It is bounded a second time, by the same
floor on hidden characters that `mask()` enforces for the class: four for `sensitive`, eight for
`credential`. A ten-character credential shows two characters rather than the four asked for, and an
eight-character one shows nothing at all rather than most of itself. Counts are code points, so a
prefix never ends inside a surrogate pair. This is still a wider disclosure than `mask()` allows,
which refuses `credential` outright, and the README says so.

Repeated reveals are counted per value in fixed windows rather than a sliding one, and the warning
fires as the threshold is crossed and then stays quiet for the rest of the window. The design's
sketch warns on every reveal past the threshold, which floods the console for exactly the runaway
loop the feature exists to find; one line per window is the useful form of the same signal. It also
answers the design's open question about timestamp memory in the process: the window needs two
numbers, so `revealTimestamps` is free to be a plain 64-entry ring, which is what bounds a value
revealed in a loop for an hour to a fixed amount of memory. `revealCount` stays exact.

Captured stacks are trimmed by file rather than by matching the string `sensitive-core` in a frame,
which would also match an application directory of that name and would match nothing at all once a
frame has been rewritten by a bundler. This module reads its own file out of a stack at load time,
drops its own frames, and then drops the contiguous run of frames belonging to whichever module
called into it, which is the raw-value gate. A build that inlines the two into one file leaves
nothing after the filter, and the unfiltered frames are kept instead.

An error thrown by a configured logger is swallowed. Without that, a broken logger turns a
successful reveal into a failed one, after the audit hook has already recorded it as successful, and
only in development: the one environment where the difference would be mistaken for a bug in the
caller.

One item from the design is deliberately absent. Its open questions propose that `setDevMode` warn
when the configuration changes while `SensitiveString`s already exist, and nothing can answer that
question: records live in a `WeakMap`, so whether any instance is still alive is exactly what cannot
be observed. The nearest implementable version, a flag set the first time anything is recorded,
would fire on every `withDevMode` call in a test suite, which is the use case the neighbouring open
question adds `withDevMode` to support.

The design's `<1%` overhead tests are `src/__benchmarks__/dev-mode.bench.ts` rather than assertions,
for the reason the timing analysis is not part of `pnpm test`: a wall clock verdict depends on how
busy the machine is and must not gate a release. Each group holds a development-mode-off control,
and the gap between it and the guarded path is the whole production price of the feature. The bound
on memory is asserted, because that one is deterministic.

Measured on this machine at Node 22.15.0, with the harness floor subtracted: a reveal costs 195ns
with development mode off and 187ns with it on over a value it never recorded, which is the same
figure and is what the guard is worth. Recording one costs 334ns, the repeated-reveal window 578ns,
logging 629ns, a partial rendering 1949ns, and capturing the stack 214us, which is the whole of the
gap and is why the two capture options are separate flags. That last figure is inflated by the
runner's source-map-aware `Error.prepareStackTrace`: the same capture in a plain Node process
measures 13.5us. Construction is 6.8x with recording on and 795x with the creation stack.

The benchmark hooks are worth one warning. Vitest hands a benchmark's third argument to the
tinybench `Bench` constructor rather than to the `Task`, so `beforeAll` is accepted by the type
checker through a non-literal and then silently ignored; the first version of this file used it,
installed no configuration at all, and reported capturing a creation stack as cheaper than capturing
none. `setup` and `teardown` are the hooks that run. The same file also revealed a value built
before development mode was on, which has no record, so the group measured the guard six times over
rather than the recording; that case is now a labelled task of its own.

58 cases across `src/dev-mode.test.ts` and `src/__tests__/dev-mode-security.test.ts`, including
canaries that the full value reaches no log line under every option at once, that it is in nothing
`__devInfo` exposes, and that every redacted rendering, the wire format included, is byte for byte
what it was with development mode off.
