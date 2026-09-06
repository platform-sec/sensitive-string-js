---
'@platform-sec/sensitive-string-core': patch
---

`equals()` no longer leaks the stored value's length through timing.

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
