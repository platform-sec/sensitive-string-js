---
'@platform-sec/sensitive-string-core': minor
---

Add the worker handoff: a `SensitiveString` that crosses a thread or process boundary and arrives as
one, with its context.

ROADMAP 1.6. `structuredClone` keeps an instance's public fields and drops the private one, so
`workerData: { token }` delivered a plain `{ klass, label }` that answered `klass` correctly and
failed at the first method call, in another thread, in a stack that named neither the boundary nor
the library. The fix everybody reached for, `workerData: { token: token.reveal() }`, worked and left
the plaintext in a plain string for the life of the thread with no class, no deadline and no audit
record. And `AsyncLocalStorage` is per isolate, so the work moved into a worker because it was
expensive, which is the work whose reveals matter most, was the work that silently stopped being
recorded.

`toWorkerPayload({ token }, { worker, context, data, transport })` builds a payload out of the wire
format, so every marker-aware walk in the library already redacts it, and carries the context's
`name`, `reason` and `tags`. Building it is a reveal of each value through the ordinary gate: an
expired, revoked or policy-denied value refuses on the sending side, and each value produces one
audit record with `operation: 'worker-handoff'`, the payload key and the destination. The access
kind stays `expose` rather than gaining a `handoff` of its own, because the raw value does reach the
caller and a policy that refuses `expose` today must keep refusing it here; a new kind would have
routed handoffs around every such policy on the day it shipped.

`fromWorkerPayload(workerData, { auditReveal })` and `withWorkerPayload(workerData, options, fn)`
rebuild the instances on the far side. The audit hook is the one field that cannot cross, since a
function survives neither structured clone nor JSON, so a payload built under an audited context
arrives marked and the receiver is required to install its own: `UnauditedWorkerError` rather than
a warning, because a warning from a worker is a line on the parent's stderr that nothing reads, and
what it would report is a security control the sender asked for being dropped in silence.
`allowUnaudited: true` is the spellable opt-out and the new `no-allow-unaudited` lint rule reports
it. The reverse direction needs no options at all: a parent handler registered inside
`withRevealContext()` already has an ambient hook, and the returned context forwards it rather than
replacing it with nothing.

Neither `data` nor the context's `tags` may carry a protected value. Both get the same two checks,
which is a correction found in review: `tags` had only the portability one, so a wire object could
ride across inside the context, and because consumption clears `values` alone it stayed in the
payload after `fromWorkerPayload()` had returned. That is plaintext in `workerData` for the life of
a thread, in the one place the feature promises there is none.

Consumption is the part that needed a real thread to prove. `workerData` is one mutable object
shared by every module in the thread, so `fromWorkerPayload()` deletes the raw values from it and
marks it consumed: a later `console.log(workerData)` or a crash handler serializing it no longer
reads them, and a second call throws `ConsumedWorkerPayloadError` rather than rebuilding anything.
Deleting rather than overwriting is deliberate, since a sentinel would still deserialize into an
instance that looks valid.

Consumption is per copy, and the README says so rather than implying otherwise. Every transport
clones, so a payload posted to two workers arrives twice and whole, and the sender's own object is
untouched by either; it shortens how long one thread holds plaintext and is not a use-once token.
It is also best-effort, because it runs after the instances have been rebuilt: a frozen payload
keeps its values rather than turning a successful call into a throw that leaves the caller with
nothing and the plaintext still there.

What it does not do is erase the string from the heap, and the README says so, next to the three
other things the boundary does not close: `process.env` is copied into every worker by default, an
application error crossing back carries whatever its message holds, and a value that crosses leaves
the sending side's revocation reach entirely.

That last one is broader than a missing registry, and it is measured against a real thread rather
than reasoned about. An instance `revoke()` is per copy; `revokeByLabel()` and `revokeByPattern()`
act on module state, which is per isolate for the same reason policies are; and a
`revocationRegistry` is a function table, so it does not clone, and nothing on the receiving side can
bind one back, since `deserialize()` takes no options. What still reaches the copy is the worker's
own label list, matched on the label that crossed, so a worker that must honour revocation keeps
one. Revoking before the handoff is not a way round it: the gate refuses to read a revoked value, so
no payload is built. The wire format's `revoked` flag is for a payload assembled by hand or by a
gateway that checked its own list, and `serialize()` never emits it.

Three refusals the boundary adds. Policies are per isolate, so a class registered on the main
thread does not exist in a worker; `UnregisteredClassError` names the class and says to register it
in the worker's own bootstrap, since a payload that could install a policy could install one that
returns its input. A reveal limit is a counter shared by reference and a thread has no reference to
share, so `toWorkerPayload()` refuses a value carrying `maxReveals` or a rate-limit window with
`UnshareableConstraintError` before reading anything, rather than handing every worker a fresh
budget. And the two transports disagree in both directions, measured: `child_process` IPC drops a
function silently where structured clone throws, and turns a `Date` into a string and a `Map` into
`{}` where the clone keeps all three, so `transport: 'json'` validates `data` and `tags` against
the serializer that will actually run. A `DataCloneError`'s own message quotes the source of the
function it could not clone, so `UnportableDataError` names the failing path and discards the
runtime's message rather than wrapping it.

`SensitiveStringError` is new, and every refusal `core` raises now extends it and carries a `code`:
the seven worker errors, and `ExpiredSensitiveValueError`, `RenewalNotAllowedError`,
`RevealLimitExceededError`, `RevealRateLimitError`, `RevokedSensitiveValueError` and
`RevealDuringRedactionError`, reparented. `instanceof Error` and each class's own `instanceof` hold
as before. A caller wants either one specific failure or any refusal from this library, and a base
plus a flat code serves both where either alone serves one. `ExpiredSensitiveValueError` also
gained an optional `key`, so the boundary can name the payload key of a value that expired in
transit without misreporting its label. `RevealDetails` gained the `WorkerHandoffAuditDetails`
variant, and development mode names the operation `Worker handoff`.

`withWorkerPayload()` declares its return type with a default, because TypeScript has no partial
type argument inference: naming only the values type would otherwise be a hard error rather than a
call whose result is `unknown`, and naming only the values type is the shape everybody writes. The
checked example under `examples/worker-handoff/` pins all three call forms, which is what caught it.

Neither helper imports `node:worker_threads`, so `core` gains no dependency and the same pair works
over `workerData`, `postMessage`, a `MessagePort`, a `BroadcastChannel` and a forked child. The
suite drives each of those for real; the fixtures under `src/__tests__/fixtures/` import the package
by name and so need a build, which the suite says rather than failing inside a thread.
