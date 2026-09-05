---
'@platform-sec/sensitive-string-llm': minor
---

An LLM package: an authorization gate for values leaving the trust boundary, structural prompt
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
smaller half of the leak**, and the canary suite asserts a canary is *present* after scrubbing a
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
`replaceAll`, which interprets `$` patterns in a *string* replacement even when the pattern is a plain
string: measured on Node 22.15.0, `` `$` `` and `$'` splice surrounding prompt text into what the
caller believes is a bare value, and neither throws.

The per-provider content paths in `shapes.ts` were **not** measured against an installed SDK. No
provider SDK is a dependency of this package, not even a dev one, and a fixture written from a
document tests the document rather than the provider. Each shape carries `verified: false` and the
schema it was written from rather than a version number, and the README says what that does and does
not affect: content paths decide where a caller's hook runs, not what is redacted.
