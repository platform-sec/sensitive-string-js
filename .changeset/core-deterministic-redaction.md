---
'@platform-sec/sensitive-string-core': minor
'@platform-sec/sensitive-string-llm': patch
'@platform-sec/sensitive-string-scrub': patch
---

`deterministicRedaction()`: a redacted rendering that tells two values apart.

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
