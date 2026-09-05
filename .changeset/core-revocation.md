---
'@platform-sec/sensitive-string-core': minor
'@platform-sec/sensitive-string-zod': patch
---

Add revocation: a way to stop a value being read after it is rotated or compromised, including
instances a caller no longer holds a reference to.

After a rotation the old secret is still in memory, still held by whatever closed over it, and still
works. `revoke()` ends one value. `revokeByLabel()` and `revokeByPattern()` end every value in the
process built under a label, without needing a reference to any of them. A `revocationRegistry`
passed at construction is consulted on every read, which is where a store-backed list belongs.

```ts
apiKey.revoke('Rotated 2026-08-01');
apiKey.reveal();          // throws RevokedSensitiveValueError
apiKey.isRevoked;         // true
apiKey.revocationReason;  // 'Rotated 2026-08-01'

revokeByLabel('api_key', 'Emergency rotation');
revokeByPattern(/^session:/, 'User logged out');
```

There is no way back. No `unrevoke`, no reset, no options object and no wire payload that lifts one.
`pruneRevocations()` shrinks the process-global lists, and it cannot resurrect anything that has
already been refused: a value latches its own revocation the first time it observes one, so pruning
only ever drops entries nothing has matched yet. That is also the rule for when pruning is safe, and
the only condition under which it is.

The check lives in the raw-value gate, as rule R2 requires and as the design's sketch did not: the
sketch put it at the top of `reveal()`, where `secret.map(v => v).reveal()` walks past it. Every
exposing read refuses, and so does `equals()`, which R2 names explicitly: a comparison reads the
value, and a rotated credential must not still be able to answer whether a guess matches it.
Redaction and metadata keep working, because a value that can no longer be used still has to be safe
to log. `renew()` refuses too, though it reads nothing: a lifecycle control that keeps working on a
revoked value is one somebody will eventually mistake for the value working.

Revocation runs along derivation edges in both directions, which is the decision R2 leaves to each
feature. A derivative is revoked by its sources, and revoking a derivative revokes its sources and
their other derivatives. That is the opposite of `renew()`, which refuses on a derivative, and the
reason for the asymmetry is which way each fails: refusing to extend a lifetime fails closed,
refusing to end one does not. An incident responder holding a substring, a `matchGroups()` result or
a template result has no way to know it is derived, and refusing them would leave the credential
alive. It is also the honest reading of what a derivative is: it carries its sources' material, so a
leaked substring is a leaked secret.

Label and pattern revocation match the label a value was **constructed** with, and a derived value
is matched against its sources' labels rather than the one the derivation gave it. Revoking
`api_key` reaches every substring, match group and template built from that value; revoking the
combined label `a/b` that `concat()` produced matches nothing, because no value was ever constructed
under it.

When both a revocation and a deadline would refuse, the revocation is reported. `ExpiredSensitiveValueError`
invites a renewal and a retry, and a revoked value must never look renewable.

Nothing may refuse a revocation. No policy hook is consulted, and the audit record is reported after
the fact with anything the sink throws swallowed, which is the mirror image of `renew()`: that one
audits first so a sink *can* stop it. A second `revoke()` on an already-revoked value changes
nothing and reports nothing, keeping the first reason and timestamp, because a revocation is a fact
that already happened.

Three things the design sketch had to change. `RevocationRegistry` ships as the interface the option
accepts rather than a class to subclass, so a store-backed registry in another package satisfies it
structurally; the in-process implementation is `RevocationList`. A registry that throws denies the
read, as specified, and so does one that answers with anything but a boolean: an `async isRevoked`
returns a Promise, which is truthy and not `true`, so reading it either way silently revokes
everything or nothing. And `revoke()` does not clear the value, against the design's recommendation:
it would make `length` lie about a value that is still there, and it cannot actually erase a string
from the V8 heap, which is memory hygiene's problem rather than revocation's.

`revokeByPattern` rejects a pattern that applies an unbounded quantifier to a group that can match
the same input more than one way. A stored pattern is tested against every label a value carries, on
a thread nothing can interrupt, so `(a+)+` in the list is a process that hangs on the first read
after somebody revokes something. The heuristic is deliberately strict and rejects some safe
patterns; the message says what to rewrite. Patterns are also copied out of the caller's RegExp with
`g` and `y` dropped, which would otherwise make a stored pattern match every other time it was
consulted.

Instance revocation crosses the wire as a flag that can only tighten. `serialize()` never writes it,
because the gate refuses to read a revoked value at all; `deserialize()` honours it, and rejects
`revoked: false` rather than reading it as permission. The zod `zSensitiveDeserialize()` schema
declares both fields, because an object schema strips what it does not declare, and stripping these
would turn a payload that says "do not use this" into one that says nothing.

The process-global lists follow rule R6: one `Symbol.for()` singleton so duplicate installs of core
share it, with a test that reads it back through that key, and documentation saying it defends
against a stale secret and a misconfiguration rather than against code already running in the
process. `pruneRevocations` is the only way to shrink them, in test builds or otherwise, which is
what a test uses to isolate itself.

The cost to a process that revokes nothing is a generation counter. A value that has looked once
compares one integer instead of searching the label map and walking the pattern list, and both that
comparison and the registry guard are inline, so the common read reaches no call at all. Measured
against a build with the check removed, on Node 22.15.0: roughly 2 to 4ns on a read of about 20ns,
close enough to the machine's own drift between rounds that it takes the paired measurement to see.
Before the guards were inlined the same measurement showed 5 to 24ns. What the counter is avoiding
is in the benchmark: against 200 revoked labels and 20 patterns, a value reading for the first time,
which is the one case that has to search, is 2.5x slower than one with no label to look up.

84 cases. The security file drives the two tables the TTL and reveal-budget suites do, so an
operation added later that forgets the gate fails there rather than shipping as a bypass: 33 that
expose the raw value, each refused by an instance, a label and a pattern revocation and leaking
nothing in the message, the stack or the inspection, and 22 that derive a new protected value, each
inheriting the parent's revocation and each able to revoke the parent.
