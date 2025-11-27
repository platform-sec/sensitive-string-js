# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-XX-XX

### Added

#### @anthropic-security/sensitive-core
- `SensitiveString` class with ES2022 `#private` fields for true encapsulation
- Automatic redaction in `toString()`, `toJSON()`, and `util.inspect()`
- Sensitivity classification system: `generic`, `secret`, `token`, `pii_email`, `pii_generic`
- Policy registry with customizable redaction and security behaviors
- Constant-time comparison for `secret` and `token` classes
- `RevealContext` for audit-ready reveal operations
- `withRevealContext()` for AsyncLocalStorage-based context propagation
- `redactInStructure()` and `safeLog()` for safe logging of nested structures
- `SensitiveEnvelope` for service-to-service transmission
- Utility methods: `concat()`, `substring()`, `map()`, `reclassify()`, `isEmpty()`

#### @anthropic-security/sensitive-zod
- `zSensitive()` for parsing strings into `SensitiveString` instances
- `zSensitiveEmail()` with email format validation
- Convenience functions: `zSensitivePII()`, `zSensitiveSecret()`, `zSensitiveToken()`
- `zSensitiveWithValidation()` for custom string validation
- `zSensitiveOptional()` for nullable sensitive fields
- `zSensitiveFromEnvelope()` for parsing envelope format

### Security
- All serialization methods redact by default
- Timing-safe comparison for secrets and tokens
- Private fields inaccessible via reflection or type coercion
- Comprehensive test suite with canary leak detection
