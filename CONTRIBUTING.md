# Contributing to SensitiveString

Thank you for considering contributing to SensitiveString! This document outlines the guidelines for contributing to this security-focused library.

## Development Setup

1. **Prerequisites**
   - Node.js 22.12+ to use the packages. To work on them, the version in `.nvmrc`, which is what
     CI runs on push. Volta picks it up from `package.json` on its own.
   - pnpm 9+

2. **Clone and Install**
   ```bash
   git clone https://github.com/your-org/sensitive-string-lib.git
   cd sensitive-string-lib
   pnpm install
   ```
   Installing also points `core.hooksPath` at `.githooks`, which adds a pre-push hook (step 5).

3. **Build**
   ```bash
   pnpm build
   ```

4. **Test**
   ```bash
   pnpm test
   ```

5. **Verify before pushing**
   ```bash
   pnpm verify
   ```
   Runs every check CI gates a push on, with `CI=true` set as CI sets it: the lockfile, formatting,
   release consistency, build, type-check, lint and tests. The pre-push hook runs it and refuses a
   push whose commit is not the checked-out, clean working tree, since that is what it checked.
   `git push --no-verify` skips it for one push. The audit and the latest-client and live-provider
   runs are left to CI's nightly run, which also takes the newest Node rather than the pin.

6. **Packaging check** (after a build)
   ```bash
   pnpm check:packaging
   ```
   Loads every built package by its own name through both `require` and
   `import`. The unit suite imports by relative path, so nothing else in the
   repository exercises a package manifest.

7. **Timing analysis** (optional, not part of `pnpm test`)
   ```bash
   pnpm test:timing
   ```
   Statistical measurements of the constant-time comparison path. Their verdict
   depends on how busy the machine is, so they inform rather than gate. Run them
   on an idle machine when changing `equals()`.

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
- Run `pnpm lint` before committing, and `pnpm verify` before pushing

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
   - Update the relevant package README when adding or changing an API
   - Add JSDoc comments for public APIs
   - Run `pnpm changeset` for every user-visible package change and commit the generated file
   - Do not manually edit generated package changelogs during normal release preparation

5. **Review**
   - Security-impacting changes require review from a maintainer
   - Address all review comments before merge

Packages version independently. In the Changesets prompt, select the packages whose own public
behavior changed; dependency-range propagation is handled during versioning. Documentation-only,
test-only, and CI-only changes do not need a changeset. See [RELEASING.md](RELEASING.md) for the
complete versioning and publication process.

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
