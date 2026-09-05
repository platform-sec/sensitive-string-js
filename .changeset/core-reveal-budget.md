---
'@platform-sec/sensitive-string-core': minor
---

Add reveal counting and rate limiting: a token that can only be read once, and a way to notice one
being read in a loop.

A bootstrap token or a reset link is meant to be used once, and nothing enforced that. A secret read
thousands of times a second is a retry storm or a caching layer that stopped caching, and nothing
noticed. `maxReveals` is the lifetime limit, `revealWindow` and `maxRevealsPerWindow` are a sliding
window, and both are optional fields on the same `SensitiveStringOptions` the TTL options live on.

```ts
const bootstrap = new SensitiveString(key, 'credential', 'bootstrap', { maxReveals: 1 });

bootstrap.reveal();         // works
bootstrap.revealsRemaining; // 0
bootstrap.isExhausted();    // true
bootstrap.reveal();         // throws RevealLimitExceededError

const apiKey = new SensitiveString(key, 'credential', 'api_key', {
  revealWindow: 60_000,
  maxRevealsPerWindow: 100,
});
// throws RevealRateLimitError, whose `retryAfter` says how long to wait
```

The two errors are separate because a caller recovers from them differently: one waits, the other
fetches a new secret. When both would refuse, the lifetime limit is reported, being the condition
waiting will not clear.

The check lives in the raw-value gate, so `mask()`, `serialize()`, `map()` and every string, regex
and template operation are charged alongside `reveal()`, one per call. `equals()` is not charged and
is not refused by a spent budget: a comparison reads the value without disclosing it, and it is the
operation to reach for in place of a reveal, so a stored credential stays usable for the only thing
it is stored to do. Redaction and metadata are not charged either, so a spent value is still safe to
log.

Derived values share the counter rather than copying it, which is what makes the limit mean
anything: `secret.substring(0).reveal()` throws, because the substring spent the budget and shares
it. A value built from two constrained sources is charged against both, reports the highest count
and the smallest remainder, and is exhausted as soon as either source is. `revealCount` is kept for
every value, whether or not it limits anything, since returning zero forever for an unlimited value
would be a lie in an API declared to return a number.

Counters do not cross the wire. `serialize()` charges the sender, `deserialize()` starts a fresh
count with no limits, and a payload claiming `maxReveals` for itself is ignored rather than obeyed.
Nothing resets a count, in test builds or otherwise: a control the process can switch off is not a
control, and a test wanting a fresh budget constructs a fresh value.

Five decisions differ from the design document.

The charge happens after the policy and audit hooks, where the design incremented before both. The
gate already refuses ahead of the hooks because a denied read is not a reveal; the same rule one step
later says a read an audit sink stopped by throwing is not one either, so a broken sink cannot
quietly spend a single-use token. The consequence is documented rather than defended: an audit hook
that re-enters the gate to read the same value sees the pre-charge count. Reading a value from an
audit hook already recursed without bound before this feature existed, and `RevealContext.auditReveal`
now carries the same warning `checkRevealAllowed` does.

`revealWindow` and `maxRevealsPerWindow` are a construction error apart. The design guarded the rate
limit with `if (window && limit)`, so either alone silently configured nothing and `revealWindow: 0`
disabled the limit rather than tightening it, which is the truthiness defect the TTL work found in
`ttl: 0` pointing the other way. `maxRevealsPerWindow: 0` is rejected outright: it describes a value
that can never be exposed, which `maxReveals: 0` says without ambiguity, and it would raise an error
whose `retryAfter` no waiting could satisfy.

There is no `__resetForTesting()`. The design proposed one gated on `NODE_ENV`, which is a string any
code in the process can assign.

The window is a ring with a head index rather than an array rebuilt by `filter` on every check. The
design's version allocates per reveal and stays as large as the burst that filled it; amortized
compaction bounds the backing array at twice the limit however long the value lives, and the bound is
asserted over 10,000 charges rather than argued.

`#value` is not cleared when a value is exhausted. The design recommended it. It would break
`equals()` and `toString()`, both of which stay available on purpose, and it would not do what it
sounds like: dropping a reference to a JavaScript string does not erase the string, which the threat
model already lists as out of scope. Memory hygiene is its own roadmap item.

`src/__benchmarks__/reveal-budget.bench.ts` measures what this costs, as ratios within each group
rather than as absolute figures, because the machine it ran on was not idle and four runs disagreed
about the nanoseconds while agreeing about the shape. Against the unbudgeted control on the cleanest
run, at Node 22.15.0: a lifetime limit is within 2% of the control, which is to say indistinguishable
from it, since the limit is one comparison. A sliding window costs 25% and both limits together 27%,
which is the timestamp push and the prune. Two budgeted sources cost 11%, being the same work over a
second state. Redaction, comparison and construction do not move, because none of them is charged. A
refusal is roughly 40x a successful reveal, which is the error's stack capture and is not on anyone's
hot path.

That group cannot price the counter, because its control pays for it too. Measured separately, by
timing two million reveals against a build with the charge removed: a reveal on an unbudgeted value
costs about 20ns and about 26ns with the counter, so the counter is roughly 6ns. Inlining the walk
for the single-state case, which is every value that was not built by `concat`, measured the same, so
that is the increment rather than the call. It is what an honest `revealCount` costs on a value that
configures nothing, and the alternative is an API declared to return a number that returns zero
forever. Both figures are a tight loop rather than the benchmark harness, whose per-call floor is
several times the whole operation.

66 cases across `src/reveal-budget.test.ts` and `src/__tests__/reveal-budget-security.test.ts`. The
security file drives two tables the way the TTL suite does, so an operation added later that forgets
the gate fails there rather than shipping as a bypass: 31 operations that expose the raw value, each
asserted to refuse an exhausted value and a full window and to leak nothing in the message, the
stack, or the inspection, and 22 that derive a new protected value, each asserted to share the
parent's spent budget.
