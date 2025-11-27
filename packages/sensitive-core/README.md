# @anthropic-security/sensitive-core

Core library for handling sensitive string data with automatic redaction, type-safe classification, and audit-ready reveal patterns.

## Installation

```bash
pnpm add @anthropic-security/sensitive-core
```

## Requirements

- Node.js 20+
- TypeScript 5.4+ (for best type inference)

## Quick Start

```typescript
import { 
  SensitiveString, 
  safeLog, 
  withRevealContext 
} from '@anthropic-security/sensitive-core';

// Create a sensitive value
const apiKey = new SensitiveString(process.env.API_KEY!, 'secret');

// Safe for logging - automatically redacted
console.log('Using API key:', apiKey);
// Output: Using API key: SensitiveString<secret> { [REDACTED:secret] }

// JSON serialization is safe
console.log(JSON.stringify({ key: apiKey }));
// Output: {"key":"[REDACTED:secret]"}

// Explicit reveal when needed
const raw = apiKey.reveal({ name: 'api-call', reason: 'authenticating' });
```

## Features

- **Automatic Redaction**: `toString()`, `toJSON()`, `util.inspect()` all return redacted values
- **True Private Fields**: Uses ES2022 `#private` for runtime encapsulation
- **Sensitivity Classification**: `generic`, `secret`, `token`, `pii_email`, `pii_generic`
- **Constant-Time Comparison**: Timing-safe equality for secrets and tokens
- **Audit Context**: AsyncLocalStorage-based context propagation
- **Zero External Dependencies**: Only uses Node.js built-ins

## API

See the [main README](../../README.md) for full API documentation.

## License

MIT
