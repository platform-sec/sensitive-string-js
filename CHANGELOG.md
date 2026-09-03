# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added protected string transformations for trimming, case conversion, padding, slicing,
  splitting, replacement, and character access.
- Added policy-controlled partial queries for prefix, suffix, containment, and index checks.
- Added protected regular-expression matching, named-group extraction, and match iteration.
- Added policy-controlled `test()` and `search()` regex queries and the anchored `patterns.email`
  helper.
- Added the `sensitiveTemplate` tagged template and its `st` alias for building protected values
  from template literals, with optional reveal context, label, and class.
- Added `mask()` for partial masking, with positional `showFirst` / `showLast` options and the
  `email`, `phone`, `card`, `ssn`, `uuid`, and `custom` strategies.
- Added the `minMasked` floor, which defaults to 4 for `sensitive` and 8 for `credential`.
- Added `RevealDetails` to the `auditReveal` callback and to `withAuditedReveals`, so an audit sink
  can tell a full reveal from a mask and see the options that produced it.
- Added expiration: the `ttl`, `expiresAt`, `allowRenewal`, `maxRenewals`, and `onExpire`
  construction options, the `expiresAt` and `renewalCount` properties, and the `isExpired()`,
  `ttlRemaining()`, `isRenewable()`, and `renew()` methods.
- Added the `ExpiredSensitiveValueError` and `RenewalNotAllowedError` error classes, so a caller can
  tell a lapsed deadline from a policy denial and decide whether to fetch a fresh secret.
- Added the `allowRenewal`, `defaultTtl`, `maxTtl`, and `requireExpiration` policy fields, which set
  and cap expiration for a whole sensitivity class.
- Added `expiresAt` to the serialized wire format, and a `renew` audit record carrying both
  deadlines and the renewal count.

### Security

- String transformations preserve sensitivity state and invoke reveal authorization and auditing.
- Partial queries are denied for credentials by default to prevent character-by-character oracle
  attacks.
- Replacement callbacks are rejected because they would receive raw matched content.
- Regex instances are snapshotted before raw access so overridden `exec` and symbol hooks cannot
  receive sensitive values; native match metadata containing the complete input is not returned.
- Regex queries follow `allowPartialQueries`, and credentials deny them by default to prevent
  caller-controlled pattern oracles.
- Template literals reveal each interpolated value through the authorization and audit gate, inherit
  the most restrictive class, and retain the state of every value they read.
- The template `klass` option may only tighten the inherited class, and unsupported interpolations
  are rejected with a `TypeError` that names the index and type but never the value, before any
  value is revealed.
- Masking is a partial reveal: it runs the same authorization and audit hooks as `reveal()`, and it
  follows `allowMask`, which credentials deny by default.
- The `minMasked` floor may be raised but not lowered, and a rendering that cannot hide that many
  characters falls back to the class's full redaction.
- A format strategy applied to a value that is not of that format redacts instead of degrading to a
  positional view, which would disclose a fixed prefix of whatever the value actually is. Counting
  digits is not enough to recognize a card: a hex token holds twelve or more of them among its
  letters.
- The `card` strategy is the only definition of card masking in this repository. It shows the
  six-digit BIN and the last four digits, which is the PCI-DSS maximum.
- The `email` strategy masks the domain as well as the local part, since a full domain leaks the
  employer or provider, and it hides a one-character local part completely.
- `customStrategy` receives the raw value, so it is rejected unless the caller names
  `strategy: 'custom'`, and its output is never measured against the floor.
- Mask options are validated before the value is read, so a rejected call leaves no audit record
  for a mask that was never rendered.
- Expiry is checked in the single gate every path to the raw value goes through, so `equals()`,
  `mask()`, `serialize()`, and every string, regex, and template operation refuse an expired value
  alongside `reveal()`. The check runs before authorization and before the audit hook, so a refusal
  is never logged as a reveal, and it cannot be lifted by overriding or shadowing `isExpired()`.
- Derived values carry the deadlines of every value they were built from and expire with the first
  of them, so a substring of an expired value is expired and a concatenation is usable only while
  both operands are.
- Only the value that owns a deadline may renew it. A derivative shares its sources' state by
  reference, so renewing through one would silently extend the value it came from.
- `ttl: 0` means "already expired" rather than "no TTL", and a value is not usable at its own
  deadline. A negative `ttl` is rejected rather than read as a deadline in the past.
- A policy's `allowRenewal: false` is a prohibition that the construction option cannot lift, and
  `maxTtl` is measured from construction, so no renewal can push an absolute lifetime forward.
- A renewal is audited before it takes effect, so an audit sink that throws stops it, and a renewal
  that a cap swallows entirely throws rather than reporting a success that changed nothing.
- Renewal permission and renewal counts do not cross the wire, so a payload cannot grant the right
  to extend a credential's lifetime; the receiving policy applies its own caps to a received
  deadline.
- An absolute deadline is read once, through the intrinsic `Date.prototype.getTime`, so neither
  mutating the `Date` afterwards nor overriding its `getTime` moves a deadline the library accepted.
- A finite but absurd `ttl` is rejected rather than accepted as a deadline past the largest date a
  `Date` can represent, which would never be reached and would throw on `serialize()`.
- `zSensitiveDeserialize()` reconstructs through `SensitiveString.deserialize()`, so the Zod
  receiving path carries a deadline and rejects an unregistered sensitivity class exactly as the
  core wire format does. It previously rebuilt the value and would have dropped the deadline,
  turning an expiring token into one that never expires.

## [0.1.0] - 2024-XX-XX

### Added

#### @platform-sec/sensitive-string-core
- `SensitiveString` class with ES2022 `#private` fields for true encapsulation
- Automatic redaction in `toString()`, `toJSON()`, and `util.inspect()`
- Sensitivity classification system: `sensitive` and `credential` (with optional labels)
- Policy registry with customizable redaction and security behaviors
- Constant-time comparison for the `credential` class
- `RevealContext` for audit-ready reveal operations
- `withRevealContext()` for AsyncLocalStorage-based context propagation
- `redactInStructure()` and `safeLog()` for safe logging of nested structures
- `SerializedSensitiveString` for service-to-service transmission
- Utility methods: `concat()`, `substring()`, `map()`, `reclassify()`, `isEmpty()`

#### @platform-sec/sensitive-string-zod
- `zSensitiveString()` for parsing strings into `SensitiveString` instances
- `zSensitive()` and `zCredential()` convenience helpers
- `zSensitiveWithValidation()` for custom string validation
- `zSensitiveOptional()` for nullable sensitive fields
- `zSensitiveDeserialize()` for parsing serialized format

### Security
- All serialization methods redact by default
- Timing-safe comparison for credentials
- Private fields inaccessible via reflection or type coercion
- Comprehensive test suite with canary leak detection
