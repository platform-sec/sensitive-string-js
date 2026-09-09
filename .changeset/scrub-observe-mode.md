---
'@platform-sec/sensitive-string-scrub': minor
---

Add `onMatch: 'censor' | 'observe'` to the scrub policy. Default `'censor'`, which is what every
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
