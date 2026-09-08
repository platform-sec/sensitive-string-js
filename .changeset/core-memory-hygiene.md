---
'@platform-sec/sensitive-string-core': minor
---

Add memory hygiene: `clear()` to destroy a value at a point the caller chooses, a bulk clear for a
shutdown or incident path, and optional instance freezing.

```ts
token.clear();
token.isCleared;   // true
token.clearedAt;   // Date
token.toString();  // '[REDACTED:credential]', unchanged
token.reveal();    // throws ClearedSensitiveValueError

setMemoryHygiene({ trackInstances: true, freezeInstances: true });
clearAllSensitiveValues();  // returns how many it destroyed
```

**`clear()` drops the library's reference and nothing else.** It is not zeroing. JavaScript cannot
overwrite the backing store of a string it holds a reference to, and there is no primitive that
would let it. Whether the library's was the last reference is a property of the calling code, which
is why the documentation leads with the two shapes rather than with the API: a credential decrypted
into a local and cleared after use really does leave the heap, and a route that wraps
`req.body.token` while the handler keeps the parsed body gains nothing, because `req.body.token` and
the instance's value are the same string object. No integration fixes the second shape, and it is
worth being exact about why: a body has to be parsed into strings before any field can be
classified, and `wrapSensitiveByPath` returns primitives by reference, so the wrapped value holds
the string the pre-wrap body holds.

The check lives in the raw-value gate, as rule R2 requires, and goes first among the lifecycle
checks. Ahead of revocation as well as expiry, and not because a destruction outranks a revocation:
it is the only one of the three that reads a plain field, so asking a `revocationRegistry` about a
value this process already destroyed would let a registry outage decide which refusal a destroyed
value reports. `renew()` takes the same check first too, ahead of its own `derived` refusal, so a
derivative of a cleared origin now reports `ClearedSensitiveValueError` rather than
`RenewalNotAllowedError`.

Redaction survives a clear, because logging a sensitive value must never throw: an error handler
doing `logger.error({ err, token })` on a cleared token would otherwise raise a second error from
inside the first and lose the diagnostic. `clear()` snapshots the redacted rendering from the live
value immediately before dropping it. That snapshot is not decoration: under a
deterministic-redaction policy, every cleared value in the process would otherwise redact to the
HMAC of the empty string, and one shared tag across unrelated values is a false correlation in an
audit log, which is worse than no correlation. Its cost is that a policy re-registered after a clear
does not change what a cleared value renders.

`length` and `isEmpty()` refuse instead of answering from the empty string. `0` and `true` are wrong
answers rather than degraded ones, and a caller branching on `if (!token.length)` would read a
destroyed credential as an absent one. The length is deliberately not snapshotted alongside the
rendering: the rendering is retained because a copy of it is already in a log file, and no
equivalent argument covers the length.

Derived values are refused, not released, and the distinction is the finding the roadmap sketch did
not have. Clearing an origin refuses everything descended from it, because they share the state
object the clear writes; clearing a derivative refuses only that derivative. The traffic also runs
the other way: a derivative of 13 characters or more is a V8 `SlicedString` pinning the origin's
entire backing store, and a `concat()` result is a cons string pinning both operands, so the
origin's own `clear()` releases nothing at all until the derivatives are cleared too. Measured end
to end in the retention suite. That is what makes `trackInstances` more than a convenience:
derivatives are usually short-lived locals whose holder a caller cannot name, and walking the
tracked set is the only way to break a pin like that. Derivations are not flattened to avoid the
pin: the three idioms that actually work cost between 20x and 88x the derivation itself, on the path
every string method routes through, and each makes its own transient plaintext copy while it runs.

No policy is consulted. Clearing reduces exposure, so there is no confidentiality outcome a denial
protects, and the same caller could drop the reference by letting it go out of scope. It is audited
after the fact with `{ operation: 'clear', propagated }`, and a sink that throws is swallowed, as
`revoke()` already does: a sweep in a `SIGTERM` handler must not stop halfway because one sink is
down, which is when a sink is most likely to be down. A policy whose `redact` throws does not
prevent a clear either; the instance falls back to the class's default marker.

Both switches are off by default and read at construction, so they belong beside `registerPolicy` in
the entry module. `trackInstances` costs about 202 bytes per instance, roughly 87% on top of the
instance itself, which a service wrapping a few dozen credentials at boot will never notice and a
service wrapping a value per request will. `freezeInstances` costs about 51 ns per construction and
blocks four real tamper paths, two of which the roadmap did not mention: an own `toJSON` replaces
redaction outright on the path most likely to reach a log aggregator, and a `klass` rewrite
downgrades a credential to a class with different redaction, permitted partial queries, permitted
masking and no constant-time comparison. It is off by default because it is a breaking change for
any consumer that decorates an instance, not because of the 51 ns. It does not touch `#private`
fields, so `clear()` works on a frozen instance, and it does not freeze the lifecycle: `renew()`
still moves a frozen value's deadline, because the deadline lives in a state object the instance
references rather than on the instance.

The tracked set is a `WeakRef` set pruned by a `FinalizationRegistry`, so tracking never keeps alive
the thing it exists to destroy, and its size is a lagging indicator with no bound worth promising:
a prune pass that calls `deref()` keeps every target it touches alive to the end of the turn, and
finalizer callbacks were measured needing two GC cycles and two macrotask turns before a set of
5,005 entries fell to 5. `clearAllSensitiveValues()` therefore clears what it can reach and does not
claim the set is empty afterwards.

A cleared value cannot be serialized: the wire format is read through the gate, so there is nothing
to send, and no field a cleared state could cross on. The registry and both switches are per
isolate, like every other process-global here.

69 cases across three suites. The security file drives the two enumerating tables the TTL and
revocation suites established, so an operation added later that forgets the gate fails there rather
than shipping as a bypass: 36 that reach the raw value, each refused and leaking nothing in the
message or the stack, and 24 that derive a new protected value, each inheriting the origin's cleared
state. One of them is the guarantee that would be easiest to break quietly: a cleared value, and a
derivative that only inherited the clear, through `redactInStructure`, `safeStringify`, `safeLog`,
`containsSensitive`, `sensitiveClassesIn` and `redactCopy`, none of which may throw.

Eight cases measure the collector rather than behaviour, and all eight live under `pnpm test:timing`
with `--expose-gc`: five search a heap snapshot for a canary held nowhere else, and three check that
tracking never keeps an instance alive, that the finalizer prunes the set, and that a swept instance
is not counted twice. They belong there rather than in the functional suite because `pnpm test` has
no `global.gc`, and a test guarded by `typeof global.gc` that returns early reports a pass for a
measurement it never took. `describe.skipIf` reports a skip instead.
