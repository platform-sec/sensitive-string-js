# @platform-sec/sensitive-string-zod

## 0.2.0

### Minor Changes

- b79d660: Move to Zod 4. The peer range is now `zod@^4.0.0`; Zod 3 is not supported, because a v3 schema and a
  v4 schema cannot be composed in either direction and the failure is a raw `TypeError` at schema
  construction rather than a type error.

  Three security-relevant changes come with the port:

  - `zSensitiveDefault` holds its fallback in a closure instead of a `z.string().default(...)`.
    `z.toJSONSchema(schema, { io: 'input' })` reads a schema definition's `default` and emits it
    verbatim, calling a function default to do so, which put the live value of a default such as
    `() => process.env.API_KEY` into any generated OpenAPI document. Every documented behaviour of the
    helper is unchanged.
  - `error-map.ts` is re-derived from Zod 4's issue shapes rather than translated. The enum and literal
    branches are gone, because v4 closed those leaks upstream. `redactZodError` now recurses into the
    issue lists nested under `invalid_key` and `invalid_element` as well as `invalid_union`, redacts
    `invalid_element.key`, and strips `input` from every issue.
  - The three parse helpers use v4's `error` parse option in place of `errorMap`, which v4 accepts and
    silently ignores, and force `reportInput` off.

  The suite now enumerates every issue code Zod 4 can emit, ties that table to `z.ZodIssueCode` so a
  code added upstream fails the build rather than going unredacted, and asserts that a schema this
  package builds emits a canary-free JSON Schema on the input side and refuses the output side.

  Two API changes, both accepting strictly more than before: `zSensitiveWithValidation` and the three
  `*Preprocess` helpers take any string-to-string schema rather than a `z.ZodString`, so Zod 4's format
  constructors (`z.email()`, `z.uuid()`) work without falling back to the deprecated
  `z.string().email()` spelling. `SensitiveParseOptions` is exported for callers who name the parse
  options type.

### Patch Changes

- b362710: Add destination binding: a value can say which sinks and hosts it may be revealed toward, and the
  raw-value gate checks the reveal context against it.

  ```ts
  const registryPassword = new SensitiveString(pw, 'credential', 'registry', {
    destinations: { hosts: ['registry-1.docker.io'] },
  });

  registryPassword.reveal(); // DestinationRestrictedError
  registryPassword.reveal({ name: 'push', tags: { host: 'registry-1.docker.io.attacker.net' } });
  // DestinationRestrictedError
  registryPassword.reveal({ name: 'push', tags: { sink: 'http', host: 'registry-1.docker.io' } });
  // the password
  ```

  Every other check in the gate answers a question about the value or about the process. None asked
  where the plaintext was about to go, so a credential could be wrapped at entry, revealed at exactly
  the call site the design says, audited, and still written to the wrong host. The adoption corpus
  recorded that seven times, twice as the same substring host comparison from unrelated maintainers.

  The destination is the context's `tags.sink` and `tags.host`, which are the tags the integrations
  already write on every reveal: the HTTP clients set both from the request URL per attempt, the data
  layer sets the sink to its driver, and `sendToExternal` sets it to the sink it was given. So a bound
  value works unchanged through `sensitive-axios`, `sensitive-fetch` and the rest, and refuses through
  them when the URL the program computed points somewhere else. A context that states no destination
  refuses, on the allowlist rule the environment restrictions follow; there is no denylist.

  Every operation that hands plaintext out is checked, `hash()`, `mask()`, `map()`, `serialize()` and
  `toWorkerPayload()` included, so serializing a bound value is itself a reveal toward wherever the
  payload goes. `equals()` is not checked: a comparison sends the value nowhere. Derived values carry
  the binding, a value derived from two bound values carries both, and bindings cross the wire and the
  worker handoff as data that can only tighten. `zSensitiveDeserialize()` declares the wire field so an
  object schema does not strip it.

  A host entry is what `new URL(url).host` spells, compared case-insensitively, with the port when it
  is not the scheme's default; `*.example.com` matches at least one label below and not the domain
  itself, with a port as part of the suffix. A URL, a path, a userinfo, a bare `*`, a misplaced
  wildcard, or any spelling the URL parser would change, a Unicode domain or a stated default port,
  is refused at construction, because an entry that can never equal a host tag sits in the list
  matching nothing. `sensitive-fetch`'s standalone `sensitiveHeaders` helper takes no URL and writes
  no host, so a host-bound value refuses through it unless the caller's context names the host.

  Three additions on the same mechanism. `principals` is a third literal list, matched against
  `tags.principal`, whatever identity the application tags its reveals with, so a credential fetched
  for one caller and handed out of a shared cache to another refuses. A `proxy` tag is read the other
  way round: absent means the request goes to its host directly, present means a second machine
  receives the bytes first and has to match the same `hosts` list; `sensitive-http` tags it when a
  client resolves one. And `releasedBy: Promise<boolean>` holds every exposing read with
  `UnreleasedSensitiveValueError` (code `unreleased-value`, `status` `'pending'` or `'refused'`) until
  the promise resolves `true`, for good when it resolves anything else or rejects: a credential whose
  recipient is trusted only after an asynchronous check, an SSH host key against a known-hosts store,
  is constructed with the check in flight and cannot be sent until it says so. A plain boolean is
  refused at construction, `equals()` is not held, and the promise never crosses the wire because an
  unreleased value cannot be serialized and a released one has nothing to carry.

  `DestinationRestrictedError` extends `SensitiveStringError` with the code `destination-restricted`
  and names the tag that refused, what the context stated, and the allowed list, none of which is any
  part of the value. A process that binds nothing pays a length check on an empty frozen array.

- 7de6338: Add environment restrictions: a value can say which deployment environment, region or datacenter it
  may be read in, and the check runs in the raw-value gate rather than at the application layer.

  ```ts
  setEnvironmentInfo({ environment: process.env.NODE_ENV, region: await instanceRegion() });
  lockEnvironmentInfo();

  const euCustomer = new SensitiveString(pii, 'sensitive', 'eu_pii', {
    restrictions: { allowedRegions: ['eu-*'] },
  });

  euCustomer.reveal(); // in us-east-1: throws EnvironmentRestrictedError
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

- f1d6d96: Add revocation: a way to stop a value being read after it is rotated or compromised, including
  instances a caller no longer holds a reference to.

  After a rotation the old secret is still in memory, still held by whatever closed over it, and still
  works. `revoke()` ends one value. `revokeByLabel()` and `revokeByPattern()` end every value in the
  process built under a label, without needing a reference to any of them. A `revocationRegistry`
  passed at construction is consulted on every read, which is where a store-backed list belongs.

  ```ts
  apiKey.revoke('Rotated 2026-08-01');
  apiKey.reveal(); // throws RevokedSensitiveValueError
  apiKey.isRevoked; // true
  apiKey.revocationReason; // 'Rotated 2026-08-01'

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
  audits first so a sink _can_ stop it. A second `revoke()` on an already-revoked value changes
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

- Updated dependencies [3e054e2]
- Updated dependencies [49ad21c]
- Updated dependencies [200a5c9]
- Updated dependencies [b362710]
- Updated dependencies [aa609af]
- Updated dependencies [14ed60e]
- Updated dependencies [7de6338]
- Updated dependencies [e721fbd]
- Updated dependencies [a90709f]
- Updated dependencies [785c101]
- Updated dependencies [f8377ff]
- Updated dependencies [1eb5030]
- Updated dependencies [dfe8ae4]
- Updated dependencies [342f7e4]
- Updated dependencies [1c87ee4]
- Updated dependencies [7de3033]
- Updated dependencies [98fd326]
- Updated dependencies [f1d6d96]
- Updated dependencies [5950b87]
- Updated dependencies [b92ff33]
- Updated dependencies [dbb643a]
- Updated dependencies [59ace7a]
- Updated dependencies [29c6f87]
  - @platform-sec/sensitive-string-core@0.6.0

## 0.1.0

### Minor Changes

- Establish the initial public package baseline. The root changelog records the development
  history leading to this version.
