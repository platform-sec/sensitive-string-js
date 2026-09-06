---
'@platform-sec/eslint-plugin-sensitive-string': minor
---

`require-reveal-context` covers `hash()` and `hmac()`, where types are available.

The library audits a digest exactly as it audits a reveal: the same gate, the same reveal budget,
the same audit record with `operation: 'hash'` on it. An audit line saying a digest of a credential
was taken, with nothing about who took it or why, is the gap this rule exists to close, and until
now the rule only knew about `reveal()`.

Only where the receiver's type can be read, which is the difference between this and the way
`reveal()` is matched. `magician.reveal()` being reported is the standing cost of an untyped rule
and a fair trade, because `.reveal()` is rare. `.hash()` is not: `bcrypt`, `argon2`, `node:crypto`
and half the hashing libraries on npm have one, this repository calls two of them, and a rule that
reported every `.hash()` call would be turned off within the hour. So the rule reads the receiver's
type when a program is there and says nothing about these two methods when it is not.

That makes it the plugin's third kind of rule: it works without types and uses them when present,
where `no-stringify-sensitive` and `prefer-safe-log` cannot run at all without them. It therefore
stays enabled under `disable-type-checked`, doing the half of its job that needs no types, and does
not report missing type information the way those two do, because it is not reduced to silence.

The context argument is read at the position each method takes it in: the first for `reveal()`, the
third for `hash()`, the fourth for `hmac()`. An options object in the position before it is not a
context and is reported as one missing, which is the mistake the argument order invites. A spread
ahead of the context is left alone, since which argument is the context stops being a question
syntax can answer. The two messages now name the method they are about, so a `hash()` finding no
longer says `reveal()`.

`mask()` and `serialize()` take a context too, on the same reasoning, and are not covered yet.

A `sensitiveTypes` option names the wrapper types, defaulting to `SensitiveString`, the same way it
does on the two type-aware rules.
