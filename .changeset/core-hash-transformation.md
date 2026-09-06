---
'@platform-sec/sensitive-string-core': minor
---

`hash()` and `hmac()`: a one-way digest of a protected value, as a protected value.

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
