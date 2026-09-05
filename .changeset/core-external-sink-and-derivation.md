---
'@platform-sec/sensitive-string-core': minor
---

Write `allowSendToExternal` explicitly on both default policies, and add the keyed derivation two
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
