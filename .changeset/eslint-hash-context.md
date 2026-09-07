---
'@platform-sec/eslint-plugin-sensitive-string': minor
---

`require-reveal-context` covers the other audited reads, and a new rule keeps a password away from
a fast digest.

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

`mask()` and `serialize()` are covered on the same reasoning, and for a plainer motive than the
digests: one returns a partial view as a plain string and the other returns the raw value in a wire
object. What stays out is the transforms, `substring` and `map` and the rest, which audit too and
would make the rule unusable long before they made an audit log better.

A `sensitiveTypes` option names the wrapper types, defaulting to `SensitiveString`, the same way it
does on the two type-aware rules.

`no-password-fast-hash` is new, and it is the one rule in this plugin that reads a name rather than
a shape. It reports `password.hash('sha256')` and points at `hashForStorage()` from the `kdf`
package, because a fast digest is not password storage: a wordlist runs through SHA-256 at billions
of guesses a second, and a salt does nothing about that for whoever has the row it is stored in.
`hmac()` reports too, since a key does not make a fast function slow.

A name, because no type separates a password from an API key: both are
`SensitiveString<'credential'>`. That is a different question from the one `type-info.ts` refuses to
answer by name, where a type does the job properly, and the rule's page says so rather than leaving
the contradiction for a reader to find. The match is a case-insensitive fragment over `password`,
`passwd`, `passphrase` and `pwd`, against the name of the value being hashed rather than whatever
holds it: `user.password.hash()` reports, `passwordService.token.hash()` does not. `secret`, `token`
and `key` are deliberately absent, since those are the values `hash()` is for. Warning in
`recommended`, error in `strict`, which is the honest severity for a check whose only signal is a
name.
