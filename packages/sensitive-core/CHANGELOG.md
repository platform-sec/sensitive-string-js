# @platform-sec/sensitive-string-core

## 0.6.0

### Minor Changes

- 3e054e2: Hand `auditReveal` the context the operation ran under.

  The hook was called with the value and the operation and nothing else, so a sink could not tell which
  unit of work a reveal belonged to. That is not a gap anyone works around cheaply: `sensitive-prisma`
  tags each unwrap with the model, the operation and the argument path, and `sensitive-typeorm` tags
  each column write with the table and the column, and both had to install their per-value context as
  the ambient one around every single reveal so a sink could recover the tags from
  `getCurrentRevealContext()` inside its own hook. One `AsyncLocalStorage` entry per sensitive value,
  paid to move three strings.

  `auditReveal(value, details, context)` now carries it. The context is the one passed to the call, or
  the ambient one when the call passed none, which is the same context the policy's
  `checkRevealAllowed` was asked to authorize, so an audit record and an authorization decision are
  comparable after the fact. It is not always the context the hook was installed on: a reveal under a
  `createChildContext()` is audited under the child, which is exactly what makes an integration's tags
  reachable. Both packages now reveal plainly, and the entry went with the workaround.

  The argument is typed as `AuditContext`: `name`, `reason` and `tags`, and no `auditReveal`, since the
  sink reading it is that hook. The narrowing is in the type and not in a copy, so a sink may compare
  the context by identity and an audited reveal allocates nothing; `tags` is the caller's own object,
  shared by every reveal under the context, so a sink copies out what it means to keep rather than
  writing to it.

  A hook written with two parameters is unaffected, in types and at runtime. Code that calls a
  context's `auditReveal` itself must pass the third argument; the only such caller in this repository
  was the worker handoff's hook forwarder, which now passes the receiving context through so a
  forwarded sink sees the work the sender named.

  In `sensitive-string-testing`, `AuditCall` gains `context` and `AuditEntry.contextName` is read from
  what core reports rather than from the log's own name, so an entry made under a nested child is
  recorded under the child. The recorded context is a one-level copy: a record pointing at the live
  mock context would close a cycle through `calls` that `JSON.stringify` could not walk. Both helpers
  degrade rather than throw when a caller forwards the hook with two arguments, recording the mock's
  own name; they run inside the reveal gate, where a `TypeError` would surface as a failing reveal in
  somebody's suite rather than as a missing tag.

- 49ad21c: Refuse BSON serialization instead of silently corrupting the document.

  `SensitiveString` now has a `toBSON()` that throws `SensitiveBsonError`. This is a behavior change
  for any application that persists an unrevealed instance to MongoDB today: that write starts
  throwing. Throwing is the point, and what it replaces is worse.

  Measured against `bson` 7.3.2 on Node 22.15.0. BSON honours `toBSON()` on a value and ignores
  `toJSON()`, and the class had neither, so the encoder fell back to the instance's own enumerable
  properties. Those are `klass` and `label`. A write of a classified token stored
  `{ klass: 'credential', label: 'token' }` and dropped the value, with nothing thrown and nothing
  logged, and the column looked populated. The same husk is produced for every value of a given class
  and label, so a filter built from one instance matched a document written from another, which is an
  authentication bypass rather than a storage bug. The refusal covers the top level of a document, a
  subdocument and an array, and therefore every write path, every filter path, both bulk paths and the
  raw driver, since all of them serialise through the same encoder.

  `toJSON()` still redacts and still does not throw, because logging must not throw and a redacted log
  line is useful. BSON is a persistence and matching format, where an unrevealed value has no useful
  degraded outcome. Nothing but a BSON encoder calls `toBSON()`, so no other path pays for it.

  Reveal at the write boundary, where the access is audited:

  ```ts
  await users.updateOne({ _id }, { $set: { apiKey: token.reveal({ name: 'rotate-key' }) } });
  ```

  Two alternatives were rejected. Returning the redaction marker keeps the corruption and makes every
  classified path match the same constant, which is the same bypass with a different value in it.
  Revealing under the ambient context makes writes work everywhere and quietly ships secrets into
  filters, aggregation stages and every log line built from a command.

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

- aa609af: `deterministicRedaction()`: a redacted rendering that tells two values apart.

  ROADMAP 6.1. Three log lines saying `[REDACTED:sensitive]` may be one subject or three, and the
  difference is usually the question being asked. Registering this policy replaces the constant with
  `[REDACTED:sensitive:5f2a91c0b74e]`, a stable tag derived from the value, so the lines that share a
  subject look like they do. It is opt-in through `registerPolicy` and changes nothing for anyone who
  does not register it.

  It changes what redacted output means, which is why it is a decision with a threat model behind it
  rather than a formatting option. Redacted output has until now carried no information at all;
  under this policy it carries a keyed fingerprint. Anyone holding the key and a guess can confirm the
  guess against a log line, and anyone holding neither still learns which lines concern the same
  subject, which is the feature and is still disclosure.

  The tag is an HMAC over `deriveKeyedToken`, and there is no unkeyed mode. That primitive was built
  for this feature and for the LLM package's entity handles, and its rules apply here unchanged: a
  16-byte key floor and a 12-hex-character tag floor. Both override the design sketch, which
  defaulted to a plain SHA-256 with an optional HMAC and an eight-character tag. An email address
  under an unkeyed digest is a wordlist lookup, and a redacted log is exactly where an offline attack
  happens, so the factory refuses without a key instead of defaulting to the dangerous version. The
  sketch's `deterministicRedactors` presets are gone with it, since all three were unkeyed. Eight
  characters is 32 bits, where a one-in-a-thousand collision arrives at about 3,000 distinct values,
  and a collision merges two subjects into one in a log, where it reads as a fact.

  `salt` became `scope`: a domain component mixed in ahead of the value on top of a mandatory key,
  rather than the sketch's alternative to one. It keeps the use case the sketch wanted it for,
  bounding correlation to a session or a tenant, and drops the reading that a salt is a substitute
  for a key, which it is not, because it sits in the same row as the digest.

  `credential` is refused. A password or an API key is guessable by construction, so a stable tag
  turns every log line into an oracle for confirming a guess against, for anyone who later obtains
  the key. The sketch's own "When NOT to Use" section says so; this makes it the behaviour. The
  refusal is hard-coded rather than read from an advisory flag, because every existing flag answers a
  different question, and it is escapable through `createDeterministicRedactor`, the bare
  `(value) => string` primitive, which is one line that shows up in review.

  `deterministicRedaction` starts from the class policy currently registered and replaces only
  `redact`, so `requireConstantTimeEquals`, `allowMask`, `checkRevealAllowed`, the advisory flags and
  every deadline rule survive a registration that would otherwise drop whichever one a hand-written
  policy forgot to name. It also mixes the class into the derivation, the way `entityHandle` does, so
  one string classified two ways gets two tags.

  One registration covers `toString()`, `toJSON()`, `inspect()`, `redactInStructure`, `redactCopy`,
  `safeStringify`, a `mask()` that could not meet its floor, and a `serialize()` payload caught by a
  redaction walk, which renders the same tag as the instance it came from. `expectRedacted` in
  `sensitive-testing` needed no change, because it has always read the expected rendering off the
  instance rather than assuming `[REDACTED:class]`; that claim is now covered by a test rather than
  by a comment.

  That reach is worth naming twice over. It includes output bound for somewhere else: the
  error tracking and APM integrations scrub through `redactCopy`, so an instance in a Sentry event, a
  Bugsnag report, a Rollbar item or a Datadog span carries the tag. And the guards that refuse to send
  a redaction onward learn a policy's marker by redacting two probes and keeping the answer when both
  agree, which a value-dependent policy defeats by construction, so `SensitivityPolicy` gains an
  optional `markerPattern` and this policy declares one. Without it a custom `prefix` would have
  silently blinded `assertNoMarker` in the HTTP clients. The marker recognizers in `llm` and `scrub`
  had a 64-character inner bound that the longest tag overran, and now allow 96.

  The key is not the only way to confirm a guess, which the design's threat model did not say. Anyone
  who can get a value of their own choosing redacted into output they can read has an oracle: submit a
  guess, read its tag, compare it with a tag from the log. HMAC-SHA256 is a PRF, so this does not
  recover the key; it does reduce "an attacker who holds the key" to "an attacker who can reach the
  service".

  Where redaction runs has two consequences, both deliberate and both worth knowing. It is not a
  reveal, so it fires no audit hook, charges no reveal budget, and keeps working on an expired or
  revoked value: a dead value still emits its tag, which is the same disclosure the live one made and
  no new one. And it runs on every rendering with no cache, because a cache keyed by value is a table
  of plaintexts with the lifetime of the process. Measured on Node 22.15.0, a redaction costs about
  20 ns under the constant policy and about 2.6 µs under this one, so the sketch's "negligible
  overhead" holds for a log line and not for a hot loop.

- 14ed60e: Add development mode: what a value's own history was, for the engineer debugging it.

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

- a90709f: Write `allowSendToExternal` explicitly on both default policies, and add the keyed derivation two
  features want.

  `advisory.allowSendToExternal` has been declared on `SensitivityAdvisory` since the beginning and set
  by neither `DEFAULT_POLICIES` entry, so it read `undefined` on every value in a stock installation.
  The two obvious ways to test a flag, `if (flag)` and `if (flag !== false)`, therefore disagreed on
  every value in the library, and the first reader of the field would have picked one of them by
  accident. Both classes now say `false` out loud. That is behaviourally identical once `undefined` is
  defined as a refusal, which is how `@platform-sec/sensitive-string-llm` reads it, and it is
  completely different to somebody reviewing a policy: an absent field looks like an oversight, which
  until now it was. `sensitive` starts closed rather than permissive because the class is deliberately
  coarse and covers a customer email as readily as an internal note; a caller who wants either in a
  prompt registers a policy that says so, in one place, in code that shows up in review. This is the
  last piece of the roadmap's Phase 0.

  `deriveKeyedToken` is `HMAC-SHA256(key, domain[0] || 0x00 || ... || value)`, hex, truncated. It lives
  here rather than in a consumer because two features want the same primitive and a truncated keyed
  HMAC over a low-entropy value has exactly one correct shape: deterministic redaction correlates a
  value across log lines, and an LLM entity handle stands in for a value inside a prompt. Both derive a
  short stable token from something an attacker can guess, and both publish the result where the
  attacker can see it, which is why there is no unkeyed mode and no way to configure one. An email
  address under a plain SHA-256 is recoverable from a wordlist in seconds.

  Three refusals, each of which is a correctness guard as much as a security one. A token shorter than
  12 hex characters: 12 is 48 bits, where a one-in-a-million collision arrives at roughly 24,000
  distinct values, while 8 is 32 bits, where a one-in-a-thousand collision arrives at about 3,000 and a
  collision silently merges two subjects into one. A key under 16 bytes, which is an unkeyed hash with
  extra steps because the key space is enumerable alongside the wordlist the value came from. And a
  domain component containing the NUL separator, without which `['a', 'bc']` and `['ab', 'c']` would
  hash identically and two domains would quietly share a token space.

  The module reads no `SensitiveString`, authorizes nothing and audits nothing: a caller reveals through
  the ordinary gate and hands the result over, so the audit record comes from the reveal rather than
  from a second, quieter path to the same value.

  `assertKeyedDerivationOptions` raises every one of those refusals without deriving anything, for the
  caller who has to read a protected value first. Without it a bad key or length is caught after the
  read, which leaves an audit record for a reveal that produced nothing and gives an auditor
  reconciling reveals against derived tokens one that does not balance. The raw-value gate already
  applies this rule in the other direction, refusing a denied read before the audit hook on the grounds
  that a denied read is not a reveal; this is the same rule one step later.

- f8377ff: `hash()` and `hmac()`: a one-way digest of a protected value, as a protected value.

  ROADMAP 1.2, the `core` half. The alternative was `reveal()` followed by handing the raw value to
  `crypto.createHash`, which is a full reveal recorded as one and a plain string afterwards, for a
  lookup key that never needed the value in the first place. Both methods read through the ordinary
  gate, so the class policy, the deadline, the reveal budget and any revocation all apply, and the
  audit record says `operation: 'hash'` or `'hmac'` with the algorithm and encoding on it.

  `advisory.allowHash` has been declared on `SensitivityAdvisory` since the beginning and read by
  nothing. This is what reads it. `undefined` allows, which is the opposite of how the LLM package
  reads `allowSendToExternal` and is deliberate: hashing is the operation the library wants used in
  place of holding a value, so the flag exists to forbid it for a class where even a digest is too
  much, not to require permission for the safe path.

  The result is `credential` whatever the source class was, and it is a derived value: it carries the
  deadline, the reveal budget and the revocation of what it came from, through the same `#derived`
  path as `substring` and `map`, and the three enumerated security suites now name `hash` and `hmac`
  alongside them. That is the R2 decision this feature had to make, and it goes the way it does
  because a fast digest of a guessable value is that value behind a lookup table. Ten billion Social
  Security numbers hash in under a minute on a laptop, so a digest that started a fresh budget would
  be a way to spend one reveal and keep a recoverable copy of the value forever.

  `hmac()` is the version to reach for when the value is guessable, and it is why the sketch's
  salt-only API was not enough: a salt stops precomputation and nothing else, because it sits in the
  same row as the digest. The key floor is 16 bytes, the constant `deriveKeyedToken` already applies,
  since a key an attacker can enumerate alongside the value is an unkeyed hash that reads as a keyed
  one in review. A `SensitiveString` key is read through its own gate and the result carries the
  constraints of the value and the key both, which is the one place in this class where an argument is
  read before the receiver: a key below the floor produces no digest, and refusing after the receiver
  had been read would charge an exposure for nothing.

  MD5 and SHA-1 are refused by name and with a reason rather than by absence from a list, since a
  caller asking for one has usually copied it from code that predates the break. SHA-3 is checked
  against `getHashes()` before use, because a FIPS build can be without it. A salt is prepended, never
  appended, which is what makes the digest reproducible by anything else computing
  `sha256(salt || value)`, and an empty salt is refused rather than read as no salt at all: it
  produces exactly the unsalted digest and would report as `salted: true` in the audit record.

  Development mode names a digest as a digest. `[SensitiveString] Hash of 'api_key' without context`
  rather than `Reveal of`, because a line telling a developer their value was handed out when it was
  not is worse than no line.

  What is deliberately absent is password storage. `hash('sha256')` is fast by construction, which is
  the one property a stored password must not have, and the functions that are not fast need a native
  module. Those are in `@platform-sec/sensitive-string-kdf`.

- 1eb5030: Add the `url` mask strategy: keep the scheme, host, port and path of a URL, and hide the userinfo,
  every query value and the fragment.

  ```ts
  new SensitiveString(
    'https://x-access-token:ghp_abcdef123456@github.com/org/repo.git',
    'sensitive'
  ).mask({
    strategy: 'url',
  });
  // 'https://***@github.com/org/repo.git'
  ```

  Two corpus records wanted this rendering and could not get it: a clone message should keep which
  repository it names, and a custom policy cannot do it because `validateRedactFunction` refuses a
  `redact` that is the identity on its non-URL canaries. The hidden parts are written at a fixed width
  so the rendering does not disclose a credential's length, and the rendering is the parsed URL written
  back, so it is normalized. The floor applies as to every strategy: a URL with nothing to hide hides
  nothing and redacts in full, which is deliberate. A caller who marked a URL sensitive and wants its
  bare form shown has marked the wrong thing; wrap the credential and keep the URL.

- dfe8ae4: Add memory hygiene: `clear()` to destroy a value at a point the caller chooses, a bulk clear for a
  shutdown or incident path, and optional instance freezing.

  ```ts
  token.clear();
  token.isCleared; // true
  token.clearedAt; // Date
  token.toString(); // '[REDACTED:credential]', unchanged
  token.reveal(); // throws ClearedSensitiveValueError

  setMemoryHygiene({ trackInstances: true, freezeInstances: true });
  clearAllSensitiveValues(); // returns how many it destroyed
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

- 1c87ee4: `containsRedactionMarker()` and `redactionMatchers()` in core, replacing four separate answers to
  the same question: given a string about to be written to a column, sent in a request body or stored
  in a secret, does it carry the text a `SensitiveString` renders as? `sensitive-http` derived its
  answer from the policy registry, `sensitive-typeorm` and `sensitive-drizzle` each shipped a narrower
  copy of that derivation, and `sensitive-secrets/write` used a hardcoded `[REDACTED:`. Core owns the
  format, so the detector lives there and the four call it.

  Two gaps close, both in the database packages and both security-relevant.

  **`markerPattern` was ignored.** Core declares it on `SensitivityPolicy` for a policy whose redaction
  varies with the value, `deterministicRedaction()` sets it, and core's own documentation for the field
  names the http guard as its consumer. The two copies written for a database did not read it, so a
  deployment using deterministic redaction had a marker check in front of its columns that could not
  recognise its own markers.

  **A marker for an unregistered class went unrecognised.** Both copies enumerated the registry and
  looked for `[REDACTED:${klass}]` per class. For a reader that is the ordinary case rather than an
  edge one: the column was written by an older release, or by a service that registered a class this
  process does not have. The detector matches the `[REDACTED:` prefix, which covers those, and also
  catches a marker that a composed transformer altered without destroying.

  `policyRegistryVersion()` is new and exported. The memo is keyed on it rather than on the set of
  registered class names, because an `overwrite` re-registration replaces a policy's `redact` while
  leaving the names identical, and both copies kept answering from the previous policy until something
  else changed.

  `sensitive-typeorm` and `sensitive-drizzle` no longer export `redactionMarkers` or
  `resetMarkerCache`; they re-export core's `redactionMatchers` and `resetRedactionMarkerCache`
  instead. `redactionMatchers()` returns `(string | RegExp)[]` rather than a `Set<string>`, since a
  `markerPattern` is a pattern.

- 7de3033: Add `observeRedactions()`, a process-wide subscription to every rendering of a redaction marker.

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

- 98fd326: Add reveal counting and rate limiting: a token that can only be read once, and a way to notice one
  being read in a loop.

  A bootstrap token or a reset link is meant to be used once, and nothing enforced that. A secret read
  thousands of times a second is a retry storm or a caching layer that stopped caching, and nothing
  noticed. `maxReveals` is the lifetime limit, `revealWindow` and `maxRevealsPerWindow` are a sliding
  window, and both are optional fields on the same `SensitiveStringOptions` the TTL options live on.

  ```ts
  const bootstrap = new SensitiveString(key, 'credential', 'bootstrap', { maxReveals: 1 });

  bootstrap.reveal(); // works
  bootstrap.revealsRemaining; // 0
  bootstrap.isExhausted(); // true
  bootstrap.reveal(); // throws RevealLimitExceededError

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

- 5950b87: Take the structure walkers' accumulators out of their public signatures, and hand
  `withAuditedReveals` the whole value.

  `containsSensitive(obj, seen?)`, `redactInStructure(obj, seen?)` and
  `sensitiveClassesIn(obj, found?, seen?)` published their recursion state as optional parameters,
  documented as "(internal use)" and enforced by nothing. That is not a style point. Measured on the
  built package, passing a `WeakSet` that already holds the root object made `containsSensitive`
  answer `false` about a payload holding a credential, `redactInStructure` return `'[Circular]'` for
  the whole payload, and a primed `found` set made `sensitiveClassesIn` report a class the payload
  does not contain. The first of those is a safety check failing open, and the way a caller reaches it
  is the obvious reason the parameter looked useful: share one `seen` across a walk of a related
  object graph and any object already visited answers `false`.

  Each walk now lives in a private function and the exported one takes the value alone. Three tests
  pin the answers a stray argument used to produce, calling through a cast so an untyped caller is
  covered too. `sensitiveFormat`'s record scan was the only internal user of an accumulator; it unions
  the two sets it collects instead, which it could always have done, since the two walks shared no
  `seen`.

  `withAuditedReveals`'s callback typed its value as `{ readonly klass: string }`, so a sink written
  against the convenience wrapper could not read `label` and so could not say which credential was
  read, where the same sink passed to `auditReveal` directly gets the whole `ISensitiveString`. It is
  the latter now. Widening a callback parameter is compatible in both directions: existing two- and
  three-parameter sinks still compile.

- b92ff33: Add the worker handoff: a `SensitiveString` that crosses a thread or process boundary and arrives as
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

- dbb643a: Add `wrapSensitiveByClassification()` and `checkClassifiedFieldsWrapped()`: bulk wrapping for a
  bag whose keys the caller does not choose.

  ```ts
  // Keep two headers readable, wrap every other one, named or not.
  const headers = wrapSensitiveByClassification(req.headers, {
    fields: { referer: 'plain', host: 'plain' },
    fallback: 'sensitive',
  });

  // A plugin's return value: everything it hands back is a credential.
  const creds = wrapSensitiveByClassification(await plugin.getCredentials(), {
    fallback: 'credential',
  });
  ```

  `wrapSensitiveByPath` takes an enumerated list of the paths that are sensitive, which is the right
  entry when the payload's shape is known and the wrong one for a header bag, a `.env` file, a plugin
  loaded at run time or a provider credential object whose keys are data: a path list over such a bag
  is a denylist turned inside out, and the key nobody named arrives unwrapped, silently. The new entry
  takes the classification spec the secrets and env layers already use, `fields`, then `rules`, then
  `fallback`, and a `fallback` inverts the default so the list a caller maintains is the short one.

  Strings only are wrapped; a number, a boolean and `null` keep their type. Every element of an array
  of strings is wrapped under the array's own name, as the path helper now does at a declared path. An
  already wrapped value is kept, and a protected value handed in as the whole object is refused with a
  `TypeError` by both wrappers rather than walked in place. `constructor`, `prototype` and an own
  `__proto__` are classified like any other key, since a payload chooses its keys and a header named
  `constructor` is legal; the write keeps `__proto__` an own data property. A label may be a fixed
  string or a function of the leaf's path and key, never its value, and construction options apply to
  every wrapped leaf.

  `checkClassifiedFieldsWrapped(obj, spec)` walks the object and asks the spec, which is the direction
  `checkSensitiveFieldsWrapped` cannot look in: that one walks the config and asks the object, so a key
  the object carries and the config never named is invisible to it.

  `wrapSensitiveByPath` now wraps every string element of an array at a declared path too, through
  nested arrays, with the class, label and options the path declares. Declaring
  `'db.replicaUrls': 'credential'` over a list of connection strings used to wrap nothing, silently,
  and the two report functions vouched for it; the report side was fixed first, and this closes the
  gap itself. It is a behaviour change for a configuration that declares a list and relied on it
  passing through: the elements arrive wrapped, which is loud. `unwrapSensitiveByPath` reveals every
  instance in such a list, `validateSensitiveFieldConfig` accepts a list of strings and still reports
  an object, a number, or a list holding either as unwrappable, and `checkSensitiveFieldsWrapped`
  reports a list once, under its path, if anything in it is not an instance.

- 59ace7a: Count what the library prevented, and price the rest against the emission points that exist.

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

- 29c6f87: Add transmission references: send a pointer to a secret instead of the secret.

  ROADMAP 6.5, release one of two. `serialize()` puts the raw value on the wire and asks the transport
  for confidentiality, which is a fair deal for mTLS between two services in one trust domain and a
  poor one everywhere the payload comes to rest. A job in SQS, Kafka, a `jobs` table or a webhook
  retry buffer sits there in plaintext for as long as the retention allows, and a transport that
  terminates at a mesh sidecar, an API gateway or a logging proxy is decrypted somewhere in the
  middle. Where the value came from a store both sides can reach, `toReference(record, { store })`
  sends where it is and the receiver fetches it with its own credentials, so the value never leaves
  the process that read it.

  There is no `token.toReference()`, and the reason is not ergonomic. `#derived` unions the state of
  every source instance into the derivative, which is right for constraints and inverts what
  provenance means: a `toReference()` on the instance would let `token.substring(0, 4)` mint a pointer
  to the whole credential, and the receiver would have no way to tell the difference. The label rule
  is the second reason, since it strips everything identifying the account, project, tenancy or host,
  so an instance knows a path and not which of an organization's stores that path is in, and the same
  logical path usually exists in staging and in production. Minting takes the `ref` a read returned,
  which contains no secret material by construction, and `store` is required rather than derived from
  the source, because inventing one from the endpoint would put an internal hostname into a payload.

  Minting is not a reveal. It performs no I/O and never touches `#value`, and recording it as one
  would make a sink that counts reveals to decide whether a credential is over-used count every
  message that merely mentions the secret. That is the call `SecretLoadEvent` already made for loads,
  for the same reason.

  Resolving is the half with the security content, and it is not `get()` under another name.
  `createReferenceResolver({ store, source, allow }).resolve(ref, { context })` runs in the receiver,
  with the receiver's credentials, against a path a sender chose, which is the shape of every confused
  deputy: unconstrained, it lets anything that can enqueue a job read any secret the receiver's role
  can read, using the receiver as the oracle. So the allowlist is required, there is no permissive
  default, and the empty list is legal and resolves nothing. The checks run in order and each precedes
  the fetch: the caller's own context, then the shape and the format version, the store identity
  compared exactly, a path carrying a traversal, an empty segment, a leading slash or a control
  character, a version outside `[A-Za-z0-9._:-]{1,128}`, an entry covering the path, and an entry that
  resolves this kind of reference and declares this field. Then the class, as the strictest among the
  covering entries and then the more restrictive of that and the reference's: a class on the wire may tighten what the receiver does and may never loosen it, because
  a receiver that took `klass` from a payload would let a sender turn off constant-time comparison for
  a credential, lift the refusal on partial queries, and let `mask()` disclose a prefix.

  A path is refused rather than normalized. Normalizing would mean this library and the provider each
  holding an opinion about what `kv/a/../b` means, and a disagreement between two normalizers is how a
  path that fails the allowlist reaches the store anyway. It is also refused for carrying `%`, `\`,
  `?` or `#`, which is a stronger rule than "no `..` segment" and a measured one rather than a
  cautious one: a provider builds its request as `new URL(base + path)`, which is what
  `sensitive-vault` does, and on Node 22.15.0 the WHATWG parser applies its double-dot rule to the
  percent-decoded segment and reads a backslash as a separator, so both
  `kv/payments/%2e%2e/%2e%2e/auth/token/lookup-self` and `kv/payments/..\..\auth/token/lookup-self`
  leave an allowlisted subtree while passing a check over `/`-split segments, and the second carries
  no percent sign at all. A `?` turns a read of a permitted secret into a different request against
  the same store. The suite pins that parser behaviour next to the refusals, so the rule keeps its
  reason attached. A version is checked against a charset rather than escaped, for the same reason.
  Patterns are a trailing `*` on a segment boundary and nothing else, with no regex, and a malformed
  one throws at construction rather than silently matching nothing.

  Where entries overlap, the class is the strictest among them rather than the first one's. A subtree
  rule and a rule for one path under it are how an operator writes an allowlist, and taking the first
  would make `[{ path: 'kv/*', klass: 'sensitive' }, { path: 'kv/payments/stripe', klass:
'credential' }]` resolve the Stripe key as `sensitive`, which is a security control whose answer
  depends on the order two lines were written in. The allowlist is copied entry by entry and frozen at
  construction for the same kind of reason, so a caller holding the array or an entry cannot widen a
  live resolver afterwards.

  A refusal is a `ReferenceRefusedError` carrying `reason`, and the path is on `error.path` and never
  in `error.message`: a refusal is the case where the sender is least likely to be one this receiver
  trusts, and interpolating what they sent would put attacker-chosen text into the receiver's own
  logs. As everywhere in this package, no error sets `cause`.

  `core` gains the format and nothing else: `SensitiveValueReference`, `isSensitiveValueReference()`,
  `carriesReferenceMarker()` and `referenceFormatVersion()`. It has no minting and no resolving,
  because both need the store, the version and the credentials, and it would have had to model stores
  and accounts to hold them. What the format is doing in `core` is that the walks which must decide
  what to do with a wire object are there, and what they decide for this one is to leave it alone: a
  reference carries no secret material, resolving it needs credentials of the reader's own, and
  redacting it would make a reference-passing system undebuggable for exactly no gain. Those
  assertions are positive in the suite rather than absent from it, so a later change to redact
  everything with a `__sensitive`-shaped marker fails a test instead of shipping.

  Two smaller decisions worth recording. `resolve()` requires its own `RevealContext`, for the reason
  `PutOptions.context` does on the write path, and checks for it before it looks at the reference at
  all, because a receiver that forgot its context has a mistake of its own and reporting that as a
  fault in what arrived would point whoever reads the log at the wrong party. That context is
  installed as a child of the ambient one, so an application's `auditReveal` is inherited rather than
  dropped and a provider that reveals its own token to authenticate the request records that reveal
  under the caller's name. And `pinVersion`
  defaults to true, since a reference stands in for a value and a value does not change between the
  send and the receive, with the cost stated where the option is: a pinned reference outlives the
  rotation that was meant to retire the old version, and queue retention shorter than the rotation
  interval is the honest fix. The `'unknown'` a provider reports when it has no version is a sentinel
  rather than a version, and is never pinned.

  The encrypted envelope, the other half of 6.5, is a separate release and is not in this one.

### Patch Changes

- 200a5c9: Reuse the compiled form of a classification spec instead of rebuilding it per call.

  `classifyField` compiles the spec it is handed, which means building a Map, validating every class
  and recompiling every rule's `RegExp`, and it did that on every call. Over a payload of five keys it
  measured 4339ns against 281ns for the same work through a compiled classification held across the
  loop. The gap is the whole reason `compileClassification` is exported, and it is not a gap a caller
  should have to know about to avoid.

  `compileClassification` now memoizes per spec object in a `WeakMap`. On its own it went from 769ns
  to 17ns, `classifyField` on one key from 868ns to 66ns, and over five keys from 4339ns to 281ns. The
  entry is held only as long as the spec object is, so a spec built per request is collected with it.

  `compileClassification` now also refuses a specification that is not an object, with
  `Invalid classification specification: expected an object, received string.` A primitive reached
  `Object.entries(spec.fields ?? {})`, compiled to a classification that matched nothing and reported
  that to nobody, so a caller who passed the wrong argument got an answer instead of an error. The
  check sits ahead of the memo because `WeakMap` refuses a primitive key and would otherwise report
  the mistake as `Invalid value used as weak map key`, which names an implementation detail rather
  than what the caller did.

  One consequence worth stating, since it is observable. Reuse goes by object identity, so the same
  spec object hands back the same compiled form, two equal specs compile separately, and a spec
  mutated after it has been classified with keeps the form it compiled to the first time. A
  `ClassificationSpec` is `readonly` throughout its type, so mutating one was never supported, but the
  old behaviour would have picked the change up and the new one does not. All three cases are covered
  by tests.

- e721fbd: `equals()` no longer leaks the stored value's length through timing.

  The constant-time path compared lengths first and returned early when they differed, under two
  comments calling that leak unavoidable. It is not unavoidable, and the early return was measurable:
  a comparand of the wrong length answered before any byte was examined, so an attacker who can time
  the call learns the length of the credential by finding the length that costs more. A length is not
  the secret, but it bounds the search for one, and this was the one call site the library advertises
  as safe to hand a credential to without thinking about it.

  Both operands are now hashed to a fixed width before they are compared, so `timingSafeEqual` always
  receives two 32-byte digests and there is no length to check and no path to choose between. The
  per-process key it hashes under is ephemeral and never exported: it exists to make a digest of a
  guessable value worthless if it were ever observed, not to be agreed with anything.

  What remains is the HMAC's own cost, which grows with its input one 64-byte block at a time, over
  the stored value as well as over the comparand. Measured independently, stored values from 8 to 256
  bytes were indistinguishable within the timing analysis's noise floor; 1024 bytes cost about 460ns
  more than 8 and 4096 about 2.5us more. A credential-sized value has its length hidden to the
  resolution anyone has measured. A value hundreds of bytes long has it hidden at block granularity,
  which is a weaker promise than "no dependence" and is what the source comments now say.

  Comparing a wrong-length comparand against a zero-filled buffer of its own length is the more common
  repair and was not used. It moves the branch rather than removing it, since only the mismatch path
  allocates and fills that buffer, so that path becomes the slower one and the signal survives with
  its sign inverted.

  This costs real time. Measured on Node 22.15 with 32-character operands, a `credential` comparison
  went from about 130ns to about 5us, dominated by two `createHmac` calls. That is once per
  authentication event, against a password verification that is four orders of magnitude slower by
  design. A caller matching one credential against many wants `hash()` and an index rather than a
  linear scan of comparisons, which was already true before this change.

  No API changed and no behaviour changed other than the timing: the same comparisons answer the same
  way. The timing analysis run by `pnpm test:timing` now measures the direction an attacker actually
  controls, holding the comparand fixed and varying the stored length, which is the case the previous
  version of that test documented as expected to leak.

- 785c101: Stop paying for a clock read, an ISO rendering and a Set on paths that do not need them.

  Three costs found by the benchmark suite and attributed against the primitives underneath them, all
  measured on this machine at Node 22.15.0 with the harness overhead subtracted.

  `#expiredDeadline` read `Date.now()` before looking at whether any state carried a deadline, so a
  value that cannot expire paid for a clock read on every reveal, comparison, transform, mask and
  serialize. `Date.now()` measured 82ns here, against 141ns for the whole of `reveal()`: the gate spent
  more on asking the time than on everything else together. The loop now reads the clock lazily, at
  most once, and only when a state actually has a deadline. `reveal()` on a value with no deadline
  went from 141ns to 40ns, and `equals()` on a `sensitive` value from 160ns to 75ns.

  `serialize()` called `new Date(deadline).toISOString()` on every call, which measured 1060ns on its
  own, more than the rest of the method put together. The rendering is memoized by the deadline it
  renders, so a renewal misses and re-renders on its own, and the memo is discarded once it passes 256
  entries so a service with many distinct deadlines cannot grow it without bound. A deadline is a
  number that already travels on the wire in exactly this form, so nothing secret is held there.
  `serialize()` on an expiring value went from 1393ns to 153ns.

  Deriving from a single source rebuilt the state list through a `Set` and an `Array.from`, when the
  source's own list is already what the derivative needs. `#states` is assigned once and never
  mutated, and the state objects are shared between derivatives by design, so the single-source case
  now reuses it. `substring()` went from 273ns to 96ns and `concat()` from 359ns to 259ns.

  No behaviour changes. The expiry gate, the wire format and the deadline a derivative inherits are
  all unchanged, and the suite that covers them is unchanged too. Two cases were added to the wire
  format tests: that a renewed value serializes its new deadline rather than the one it first
  rendered, and that more distinct deadlines than the memo holds each serialize correctly across two
  passes. Both fail against a memo keyed wrongly.

- 342f7e4: Documents one case where pino loses the redaction marker, and the one-line remedy.

  No code changed. This is a behaviour of pino that a user of this library will otherwise meet without
  warning, and the README's pino section now describes it where someone configuring pino will read it.

  With a wildcard entry in pino's `redact.paths`, a wrapped value logged as a direct property of the
  merging argument serializes as `[unable to serialize, circular reference is too complex to analyze]`
  rather than as its marker. Three conditions have to hold at once and dropping any one avoids it: a
  wildcard in the path list, since a literal list is unaffected at any depth; a class instance carrying
  an ES private field; and that instance at the top level of the log object, since one level down or
  inside an array renders correctly.

  Nothing is disclosed. The value does not appear in either case. What is lost is the marker, so a line
  that should say a credential was present instead says the serializer gave up, and the diagnostic this
  library exists to preserve is exactly the thing that goes.

  It is not fixable from inside the library. The same failure reproduces with any class carrying a
  `#private` field and no `toJSON` at all, and does not reproduce with the identical class without the
  private field; `Date` and plain objects with a `toJSON` are unaffected. So it is not caused by
  `toJSON`, and `#value` is what makes a wrapped value unreadable by reflection, which is not a
  property to trade away for this.

  The remedy is a `formatters.log` that converts the payload before pino's redaction machinery sees it,
  and it leaves pino's own path redaction working alongside the marker.

  The top-level condition sounds like it should reduce this to nothing, and does not: `logger.info(data,
msg)` is the ordinary pino idiom and puts every field of `data` at exactly that level. It was found
  in two real applications that both reach it that way through their own logging wrappers.

  Measured against pino 10.3.1.

`0.5.0` is the first version published to npm. The `0.2.0` through `0.4.0` entries below are
development milestones rather than releases: they record the four waves of work this package went
through before it was publishable, so that its history is legible from the version it starts at.
Nothing below `0.5.0` was ever on the registry. The root
[`CHANGELOG.md`](../../CHANGELOG.md) carries the full detail for every entry.

## 0.5.0

### Minor Changes

- Adversarial hardening. A policy's `checkRevealAllowed` fails closed when it answers with anything
  but `undefined`, which rejects the `async` form at compile time and refuses a returned Promise as
  a denial. `equals()` compares in constant time when either operand's class requires it, rather
  than letting the receiver alone decide. A `__proto__` key in caller data is copied as the own data
  property it was by every walk that builds a copy. `redactCopy()` copies a `Map` or `Set` entry by
  entry instead of passing it through by reference. A `toJSON()` that reveals gets nothing from a
  redaction walk, refused with `RevealDuringRedactionError`. Every walk's built-in branches are
  guarded against hostile shapes, so no object can make a redaction throw.

## 0.4.0

### Minor Changes

- The substrate the integration packages call. `redactCopy()`, the walk a response body needs before
  a serializer other than `JSON.stringify` sees it. The winston format. `checkRevealAllowed` gains
  the value and the access kind as `(ctx, value, access)`. The field classification spec and
  per-field wrap options. `new SensitiveString()` rejects a non-string. Guarded duck-type probes in
  the redaction walks, so an envalid `cleanEnv()` Proxy can be logged.

## 0.3.0

### Minor Changes

- `SensitiveString` becomes a string-like type with a lifecycle: protected string methods, regex
  operations, template literal support, partial masking, and TTL / expiration. Class instances,
  `Map`, `Set`, and `toJSON()` output are redacted.

## 0.2.0

### Minor Changes

- The public API settles. Five sensitivity classes collapse to two, the envelope API becomes
  `serialize()` / `deserialize()`, `deserialize()` validates untrusted input, and the policy checks
  are enforced on the derived-value methods. Sensitive fields can be wrapped by path.
