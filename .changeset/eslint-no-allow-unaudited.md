---
'@platform-sec/eslint-plugin-sensitive-string': minor
---

`no-allow-unaudited` reports a worker accepting a payload without the audit hook its sender asked
for.

Core's worker handoff (ROADMAP 1.6) carries a value and its context across a thread boundary, and
the one thing it cannot carry is the context's `auditReveal`, because a function survives neither
structured clone nor JSON. A payload built under an audited context therefore arrives marked, and
`fromWorkerPayload()` refuses it unless the receiving side installs a hook of its own.
`allowUnaudited: true` is the way past that refusal, and what it means is exact: the sender asked
for every reveal of this value to be recorded, and reveals in this thread will not be.

The flag exists because that is sometimes the right call, and this rule exists because it is never
a call to make by accident. It reports the property on `fromWorkerPayload()` and
`withWorkerPayload()`, whatever its value short of a literal `false` or an explicit `undefined`,
since `allowUnaudited: flag` is still a decision to sometimes skip the audit. Error in both presets
rather than warn: the finding is never wrong, and a disable comment on the line is where the reason
belongs.

Syntax only, like the other rules that read a call's shape: an object property in a call, matched
by the function's name. An options object built elsewhere and passed by name is invisible, the
page says so, and `payloadFunctions` renames the functions for a project that wraps the two in one
of its own. This makes seven untyped rules and nine in all; the design decided the rule ships with
the escape hatch it makes defensible rather than following it.
