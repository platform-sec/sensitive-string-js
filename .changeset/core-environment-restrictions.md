---
'@platform-sec/sensitive-string-core': minor
'@platform-sec/sensitive-string-zod': patch
---

Add environment restrictions: a value can say which deployment environment, region or datacenter it
may be read in, and the check runs in the raw-value gate rather than at the application layer.

```ts
setEnvironmentInfo({ environment: process.env.NODE_ENV, region: await instanceRegion() });
lockEnvironmentInfo();

const euCustomer = new SensitiveString(pii, 'sensitive', 'eu_pii', {
  restrictions: { allowedRegions: ['eu-*'] },
});

euCustomer.reveal();   // in us-east-1: throws EnvironmentRestrictedError
```

Six declarative lists, `allowed` and `denied` over environment, region and datacenter, plus a
`custom` predicate asked last and handed the frozen environment. Every field that is present has to
pass, so a name on both lists is denied. Region entries take a trailing `*` as a prefix and nothing
else; a `*` anywhere but the last character is refused at construction, because `*-east-1` matched
as a literal is a denylist that matches nothing.

The check sits in the gate the TTL, revocation and reveal-budget checks sit in, which is what rule
R2 requires and what the design sketch did not do: the sketch put it at the top of `reveal()`, where
`secret.map(v => v).reveal()` walks past it. Every exposing read refuses, and so does `equals()`,
which R2 names explicitly: a value that may not be read in this region must not still be able to
answer whether a guess matches it here. Redaction and metadata keep working, because a value that
cannot be used still has to be safe to log. It is decided after the deadline and before the reveal
budget, so a read in the wrong region costs nothing and a revoked or expired value still reports the
condition that invites the right response.

`renew()` checks it too, and needs its own check because it reads nothing and so does not pass the
gate at all. Revocation already had that check for the same reason; the reason transfers, because
extending the life of a value this deployment may not use is using it. Expiry is the one that does
not transfer: reviving a lapsed deadline is what `renew()` is for.

Restrictions are read at each access, not at construction, and derived values share the state, so a
substring is restricted exactly as its parent is and a value derived from two restricted values
carries both. That makes a derivative at least as restricted as each source, which is R2's
combination rule with nothing left to decide: an intersection is what sharing already gives.

Declarative restrictions cross the wire, as rule R3's default requires, and like the `revoked` flag
they can only tighten: a deserialized value starts with none and there is no spelling of "no
restriction". The wire field is a list, because a value derived from two restricted values carries
two, and carrying only the first would silently drop the other. A payload entry with a key this
receiver does not know is rejected rather than ignored, since enforcing part of a restriction and
reporting nothing about the rest is the failure the feature exists to prevent. The zod
`zSensitiveDeserialize()` schema declares the field for the same reason it declares `revoked`: an
object schema strips what it does not declare, and stripping this one turns a value restricted to
the EU into one readable anywhere.

Four places the sketch had to change, all of them the same shape: it chose to read silence as
permission, and silence is where this feature fails.

- **A custom restriction refuses to cross.** The sketch skipped it on serialize. A function has no
  wire form, so skipping it hands the receiver a value it believes it has fully checked while the
  half that named the actual condition is gone. `serialize()` now refuses such a value before
  reading it, with `UnserializableRestrictionError`, and `toWorkerPayload()` refuses it with
  `UnshareableConstraintError` alongside a reveal budget, which is the error for a constraint that
  cannot cross an isolate. The serialize refusal is deliberately not an
  `EnvironmentRestrictedError`: that one means "not here, try where the value allows" and a caller
  may sensibly retry elsewhere on it, while this one means "not anywhere", and a caller who cannot
  tell them apart retries in every region forever.
- **An empty list is refused at construction.** The sketch specified that `allowedRegions: []`
  allows everything. Read literally it says the opposite, and a security control must not pick one
  of those silently. A caller whose configuration came back empty finds out at the call that wrote
  it. A restriction set that expresses nothing at all is refused for the same reason.
- **A field the environment does not state is refused by an allowlist.** The sketch skipped both
  kinds of list, which makes `allowedRegions: ['eu-*']` inert on any deployment that never sets a
  region, which is the deployment most likely to be the wrong one. An allowlist is the statement
  "only here", and a process that cannot say where it is has not shown that it is here. A denylist
  still passes: "not there" concludes nothing from silence, and refusing would break every laptop
  and CI runner. The first read of a restricted value before `setEnvironmentInfo()` warns once, so
  the quiet half of that asymmetry is audible.
- **A custom function that answers with anything but `true` denies.** A throw denies, for the reason
  a revocation registry that throws does, and an `async` function returns a Promise, which is truthy
  and would otherwise allow every read it was written to refuse.

`EnvironmentRestrictedError` extends `SensitiveStringError` with the code `environment-restricted`,
`EnvironmentLockedError` with `environment-locked`, and `UnserializableRestrictionError` with
`unserializable-restriction`, so all three are catchable as library refusals and greppable in a log. The error names the restriction that refused, the environment's current
value for it, and the configured lists. All of that is configuration and none of it is any part of
the protected value.

The environment itself is process-global state under rule R6: one `Symbol.for()` singleton so
duplicate installs of core declare one environment, with a test that reads it back through that key,
and documentation whose first paragraph says it defends against a deploy to the wrong region rather
than against a caller who wants the value. `lockEnvironmentInfo()` freezes it for the rest of the
process, and `resetEnvironmentInfo()` clears both it and the lock for test isolation, which is the
honest statement of what the lock is worth. Every field is copied and frozen when it is declared, so
neither a caller mutating the object it passed nor a custom restriction reading it can move the
environment after the fact, and the same applies to the lists a value is constructed with.

A process that restricts nothing pays a length check on an empty frozen array, on the same shape the
reveal budget uses.

69 cases across two files. The security file drives the two tables the TTL, reveal-budget and
revocation suites drive, so an operation added later that forgets the gate fails there rather than
shipping as a bypass: 35 that reach the raw value, each refused in the wrong region and leaking
nothing in the message, the stack or the inspection, and 24 that derive a new protected value, each
inheriting the restriction of the value it came from.
