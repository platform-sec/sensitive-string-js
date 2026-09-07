---
'@platform-sec/sensitive-string-data': patch
'@platform-sec/sensitive-string-typeorm': patch
'@platform-sec/sensitive-string-drizzle': patch
---

Three fixes from reviewing the extracted layer, one of them a leak that existed in
`sensitive-typeorm` before the extraction and was carried into the shared code.

**A nested driver error that would not take the censor in place was returned with its plaintext.**
`sanitizeQueryError` censors the parameter property on the error and on any nested one a shape
names, and falls back to a copy of the outer error when a property will not move. That copy carried
the nested error across by descriptor, so a frozen `driverError`, or one whose parameter property is
a non-configurable accessor, ended up on the returned error with the original values still on it.
The outer error reads as sanitized, which makes this the worst of the three possible outcomes rather
than a partial fix. A censored copy of the nested error now goes onto the outer copy. Neither
package's fixtures had a nested error that resists a write, which is why neither suite saw it.

**The total-failure path dropped a message that was safe to keep.** When everything else fails,
`sanitizeQueryError` returns a minimal error. For a shape that declares no `sanitizeMessage`, which
is a measurement that the ORM's message carries no value rather than a default, the original message
and stack are the diagnosis and are now carried across. This restores what `sensitive-typeorm` did
before the extraction.

**The recovery path could throw from the function whose contract is that it does not.** The `catch`
that produces the minimal error read `message`, `name` and `stack` as plain properties, so a
throwing getter there escaped `sanitizeQueryError` entirely, at the one moment the contract is being
relied on. Every read in that path is now guarded individually, so a single hostile property costs
only that property rather than the whole recovery, and the path as a whole is guarded again beneath
that. Carried in from `sensitive-typeorm`, where the same three reads were unguarded.

**The Drizzle logger scanned each statement twice.** `touchesClassifiedColumn` called the shared
predicate once per column set, and the shared predicate scans the statement for identifiers. It now
scans once and checks both sets against the one result, which is what that package's README already
claimed. This is on the path that runs for every query the process makes.

Two README claims are corrected to match the code. The TypeORM composition section said the write
refusal "does not catch that and cannot" for a reversed transformer array; since the marker detector
moved to core it matches the `[REDACTED:` prefix, so it does catch a transform that leaves the prefix
intact and still cannot catch one that destroys it. Both halves are now asserted. The Drizzle cost
section described the marker memo as keyed on the registered class list, which is no longer how it
works.
