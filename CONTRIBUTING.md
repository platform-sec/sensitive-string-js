# Contributing to SensitiveString

Thank you for considering contributing to SensitiveString! This document outlines the guidelines for contributing to this security-focused library.

## Development Setup

1. **Prerequisites**
   - Node.js 20+
   - pnpm 9+

2. **Clone and Install**
   ```bash
   git clone https://github.com/your-org/sensitive-string-lib.git
   cd sensitive-string-lib
   pnpm install
   ```

3. **Build**
   ```bash
   pnpm build
   ```

4. **Test**
   ```bash
   pnpm test
   ```

## Code Guidelines

### Security Requirements

This is a security-focused library. All contributions must:

1. **Maintain Redaction Guarantees**
   - Never expose raw values in `toString()`, `toJSON()`, or `inspect()`
   - Any new serialization paths must redact by default

2. **Include Canary Tests**
   - All tests involving sensitive values must use the `CANARY` constant
   - Tests must verify the canary does NOT appear in output

3. **Preserve Private Field Encapsulation**
   - Use ES2022 `#private` fields for sensitive data
   - Never expose private data through public APIs

### Code Style

- TypeScript with `strict` mode
- ESLint + Prettier for formatting
- Run `pnpm lint` before committing

### Testing

- Use vitest for all tests
- Aim for >90% code coverage
- Include both positive and adversarial tests

```typescript
// Example test structure
describe('Feature', () => {
  it('should work correctly', () => {
    // Happy path
  });
  
  it('should not leak sensitive values', () => {
    const s = new SensitiveString(CANARY, 'credential');
    const output = someOperation(s);
    expect(output).not.toContain(CANARY); // Canary check
  });
});
```

## Pull Request Process

1. **Fork and Branch**
   - Create a feature branch from `main`
   - Use descriptive branch names: `feature/add-winston-integration`, `fix/timing-safe-comparison`

2. **Commits**
   - Use clear, descriptive commit messages
   - Reference issues when applicable

3. **Testing**
   - All tests must pass
   - Add tests for new functionality
   - Include adversarial tests for security features

4. **Documentation**
   - Update README if adding new APIs
   - Add JSDoc comments for public APIs
   - Update CHANGELOG.md

5. **Review**
   - Security-impacting changes require review from a maintainer
   - Address all review comments before merge

## Security Considerations

### What Qualifies as Security-Impacting?

- Changes to `SensitiveString` class
- Changes to redaction logic
- New serialization or transmission methods
- Changes to policy enforcement
- Context propagation changes

### Reporting Security Issues

Do NOT open public issues for security vulnerabilities.

Email security@your-org.com with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Questions?

Open a discussion on GitHub or reach out to the maintainers.
