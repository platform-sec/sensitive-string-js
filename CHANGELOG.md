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

### Security

- String transformations preserve sensitivity state and invoke reveal authorization and auditing.
- Partial queries are denied for credentials by default to prevent character-by-character oracle
  attacks.
- Replacement callbacks are rejected because they would receive raw matched content.
- Regex instances are snapshotted before raw access so overridden `exec` and symbol hooks cannot
  receive sensitive values; native match metadata containing the complete input is not returned.
- Regex queries follow `allowPartialQueries`, and credentials deny them by default to prevent
  caller-controlled pattern oracles.

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
