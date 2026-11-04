# @platform-sec/sensitive-string-llm

## 0.2.0

### Minor Changes

- dc08fa7: An LLM package: an authorization gate for values leaving the trust boundary, structural prompt
  scrubbing over the shared `@platform-sec/sensitive-string-scrub` walk, and keyed entity handles.

  `sendToExternal` is the feature, and it is the only export in the package that returns a raw string;
  a test enumerates the module's exports to keep it that way. It is the first thing in this repository
  that reads `advisory.allowSendToExternal`, which has been declared on `SensitivityAdvisory` since
  the beginning with no reader. The leak it addresses is not a value nobody wrapped: interpolation into
  an ordinary template literal already redacts. It is `reveal()` followed by concatenation, where every
  existing control has already run and passed, because a prompt leaks when a developer puts the value
  there on purpose and is right to need it. The gate resolves the class's policy, refuses anything but
  a literal `true`, reveals through the ordinary gate so TTL, revocation, counting and the audit hook
  all run, and refuses a revealed form carrying a redaction marker.

  `undefined` is a refusal, which makes a stock installation refuse everything and is the only
  defensible reading of a flag meaning "this data may leave for a third party". The error names the
  class and the policy field to change. The audit context is a child of whatever is ambient, so an
  `auditReveal` installed upstream still fires, and it always carries `external:<sink>` as its name, so
  an audit sink can answer "what left for a third party today" without the application having named its
  contexts well.

  The marker rule runs here in its strictest form in the monorepo, and inverted twice: 3.7 throws on a
  marker at the wire, the error tracking row inverted it because a marker is the desired output at a
  sink, and this restores the original. Every other integration that ships a marker sends a broken
  value to something that rejects it; a model accepts it, answers as though the value were real, and
  the placeholder is then in the conversation history.

  `createPromptScrubber` and `scrubForPrompt` are `scrub`'s walk with this package's envelope keys and
  one extra pass over the prose positions. **The README says in its own section that this closes the
  smaller half of the leak**, and the canary suite asserts a canary is _present_ after scrubbing a
  prose position, because a test that documents a known gap is worth more than a gap nobody wrote down.
  A request body sorts into three positions: wrapped values at keys are already safe, unwrapped strings
  under credential-shaped keys are caught by the denylist, and prose is not reachable by either. The
  key is `content`, the key is always `content`, and denying it denies the request. So the package
  ships no content classifier and offers `transformContent` as the seam for one the caller already
  runs. Failure throws rather than returning a stub, parting from `guardedScrub` deliberately: a stub
  event preserves the signal that an error happened, and a stub prompt is a paid request answering a
  question nobody asked. `onScrub` fires with `failed: true` first, and the thrown error carries the
  stage, the path and the exception type with no message, no stack and no `cause`.

  `entityHandle` mints `HMAC-SHA256(key, scope || 0x00 || klass || 0x00 || value)`, truncated to 12 hex
  characters, over core's new `deriveKeyedToken`. Keyed with no unkeyed mode, since the values that get
  handles are low-entropy by definition and the premise of a handle is that it appears where an offline
  attack can reach it. Refused for `credential`, hard-coded rather than read from a policy flag, with a
  test that keeps it refused when the policy is opened all the way up. 8 hex characters is not
  available: at 32 bits a one-in-a-thousand collision arrives at about 3,000 entities, and a collision
  merges two customers into one in the model's view.

  One thing this package can report and cannot fix, and the README says so under its own heading:
  structural redaction replaces a wrapped value with `[REDACTED:credential]`, which leaks nothing and
  leaves a placeholder where a value belonged, and a model answers as though the placeholder were real.
  A marker in a body is unambiguously wrong for a model and unambiguously right for a log line, and the
  scrubber is handed a body that may become either, so it counts rather than decides. Read
  `removed.instances` before sending and treat a non-zero count as a bug in the calling code.

  Rehydration is the half the roadmap sentence did not mention, and it is a substitution oracle: a
  function taking text an attacker can steer and returning secrets, since a model echoes verbatim spans
  from documents in its context and forging a handle costs nothing. So it resolves only against a map
  the calling request built, returns a `SensitiveString` rather than a raw string so the authorization
  stays with whatever consumes it, takes assembled text rather than a stream, and never runs inside
  `scrubForPrompt`. Substitution is by splitting and reassembly through core's template tag rather than
  `replaceAll`, which interprets `$` patterns in a _string_ replacement even when the pattern is a plain
  string: measured on Node 22.15.0, `` `$` `` and `$'` splice surrounding prompt text into what the
  caller believes is a bare value, and neither throws.

  The per-provider content paths in `shapes.ts` were **not** measured against an installed SDK. No
  provider SDK is a dependency of this package, not even a dev one, and a fixture written from a
  document tests the document rather than the provider. Each shape carries `verified: false` and the
  schema it was written from rather than a version number, and the README says what that does and does
  not affect: content paths decide where a caller's hook runs, not what is redacted.

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
- Updated dependencies [f67efd7]
- Updated dependencies [48f6213]
- Updated dependencies [29c6f87]
  - @platform-sec/sensitive-string-core@0.6.0
  - @platform-sec/sensitive-string-scrub@0.2.0
