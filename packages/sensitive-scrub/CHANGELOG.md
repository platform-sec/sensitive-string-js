# @platform-sec/sensitive-string-scrub

## 0.2.0

### Minor Changes

- f67efd7: Add `onMatch: 'censor' | 'observe'` to the scrub policy. Default `'censor'`, which is what every
  payload got before.

  ```ts
  const policy = resolveScrubPolicy({
    onMatch: 'observe',
    onScrub: (report) => counts.record(report.kind, report.deniedKeys, report.deniedValues),
  });
  ```

  Under `'observe'` a denylist match is left in place and still reported, so a payload reaches the
  vendor as it did before this package was installed and the report says what would have been
  censored. The report is the same one `'censor'` produces for the same payload, asserted across every
  position in the canary sweep, and it still carries no value. This is the measurement mode for the
  weeks before a denylist is trusted: an operator reads the denied key names and matched shapes off
  the reports, adds the `allowKeys` entries their application needs, and flips the switch with a
  number in hand rather than a hope. It is not an operating mode, and the README says so in the first
  sentence.

  It governs stage 2 only. A `SensitiveString` and a `serialize()` result are replaced under either
  setting, because that stage touches nothing the application did not classify itself, and a wrapped
  value renders its marker under every vendor's serializer regardless. Under `'observe'` the failure
  path hands the vendor the payload it was given rather than a stub, since a mode whose promise is to
  change nothing cannot replace an event; the report still says `failed`, which is where the operator
  learns that the walk broke on a shape before `'censor'` would have broken it in the open. A misspelt
  mode censors, so the option fails closed. `mergeScrubPolicy` carries it with the caller winning over
  the vendor package, like the other single-valued fields, and every vendor package accepts it through
  its existing policy argument.

- 48f6213: Opt-in value shape recognizers, and two exports the vendor packages needed.

  `denyValues` takes pattern names or your own `RegExp` and is empty by default, which is the whole of
  this layer's answer to whether a denylist should ever match on value shape. Everything else here
  matches on key names and paths, because a scrubber that decides by looking at a string is a
  classifier and is wrong some of the time, and the thing a user does about an error tracker that hides
  values they needed is turn the scrubbing off entirely. A bearer token forwarded into a field nobody
  named `authorization` is invisible to a key list, though, so the shapes ship: `jwt`, `bearer`,
  `basicAuth`, `pemPrivateKey`, `awsAccessKeyId`, `githubToken`, `slackToken` and `openaiKey`.

  Three rules every shipped pattern follows, each with a test over every pattern rather than an
  argument. Anchored at both ends, including against a trailing newline, since JavaScript's `$` also
  matches before a final line terminator. Linear time, checked against a pathological subject. And a
  prefix a vendor issues rather than a shape that merely looks random. A caller's own `RegExp` is taken
  as written with `g` and `y` stripped, because a sticky pattern carries `lastIndex` between payloads
  and would match on one event and not the next.

  `ScrubReport` gains `deniedValues`, which names the shapes that matched and never the values or the
  paths they matched at: a path is a key name your application chose and is safe on its own, but a path
  paired with a shape name is a map of where to look.

  Also exported: `mergeReports`, which folds a second pass's findings into the report a seam will
  publish while leaving the marker count alone, and `reportScrub`, so a vendor whose callback contract
  is mutate-in-place runs its own guard and still swallows a throwing `onScrub` the same way.

### Patch Changes

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
