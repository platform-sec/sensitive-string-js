# @platform-sec/sensitive-string-core

`0.5.0` is the first version published to npm. The `0.2.0` through `0.4.0` entries below are
development milestones rather than releases: they record the four waves of work this package went
through before it was publishable, so that its history is legible from the version it starts at.
Nothing below `0.5.0` was ever on the registry. The root
[`CHANGELOG.md`](../../CHANGELOG.md) carries the full detail for every entry.

## 0.5.0

### Minor Changes

- Adversarial hardening. A policy's `checkRevealAllowed` fails closed when it answers with anything
  but `undefined`, which rejects the `async` form at compile time and refuses a returned Promise as
  a denial. `equals()` compares in constant time when either operand's class requires it, rather
  than letting the receiver alone decide. A `__proto__` key in caller data is copied as the own data
  property it was by every walk that builds a copy. `redactCopy()` copies a `Map` or `Set` entry by
  entry instead of passing it through by reference. A `toJSON()` that reveals gets nothing from a
  redaction walk, refused with `RevealDuringRedactionError`. Every walk's built-in branches are
  guarded against hostile shapes, so no object can make a redaction throw.

## 0.4.0

### Minor Changes

- The substrate the integration packages call. `redactCopy()`, the walk a response body needs before
  a serializer other than `JSON.stringify` sees it. The winston format. `checkRevealAllowed` gains
  the value and the access kind as `(ctx, value, access)`. The field classification spec and
  per-field wrap options. `new SensitiveString()` rejects a non-string. Guarded duck-type probes in
  the redaction walks, so an envalid `cleanEnv()` Proxy can be logged.

## 0.3.0

### Minor Changes

- `SensitiveString` becomes a string-like type with a lifecycle: protected string methods, regex
  operations, template literal support, partial masking, and TTL / expiration. Class instances,
  `Map`, `Set`, and `toJSON()` output are redacted.

## 0.2.0

### Minor Changes

- The public API settles. Five sensitivity classes collapse to two, the envelope API becomes
  `serialize()` / `deserialize()`, `deserialize()` validates untrusted input, and the policy checks
  are enforced on the derived-value methods. Sensitive fields can be wrapped by path.
