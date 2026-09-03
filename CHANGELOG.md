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
