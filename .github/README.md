# GitHub Workflows and Security

This directory contains GitHub Actions workflows and security documentation for the SensitiveString project.

## Workflows

### Continuous Integration

**[`workflows/ci.yml`](workflows/ci.yml)**
- Runs on every push and pull request
- Jobs: lint, build, test (Node 22 & 24), coverage, security-audit
- Ensures code quality and security baseline
- [Local testing guide](TESTING_CI.md)

### Supply Chain Security

**[`workflows/dependency-review.yml`](workflows/dependency-review.yml)**
- Runs on pull requests only
- Blocks vulnerable and malicious dependencies
- Enforces license compliance (MIT, Apache-2.0, BSD, ISC)
- Checks OpenSSF Scorecard ratings

**[`workflows/codeql.yml`](workflows/codeql.yml)**
- Runs on push, PRs, and weekly schedule (Mondays)
- Static security analysis for vulnerabilities
- Detects: SQL injection, XSS, command injection, timing attacks, etc.
- Uses extended security query suite

**[`workflows/sbom.yml`](workflows/sbom.yml)**
- Runs on main branch pushes and releases
- Generates Software Bill of Materials (CycloneDX, SPDX)
- Creates dependency tree and checksums
- Attaches SBOMs to releases

## Documentation

- **[SUPPLY_CHAIN_SECURITY.md](SUPPLY_CHAIN_SECURITY.md)** - Comprehensive supply chain security guide
  - Workflow documentation
  - Vulnerability response procedures
  - SBOM usage guide
  - Security hardening checklist

- **[TESTING_CI.md](TESTING_CI.md)** - Local CI testing with `act`
  - How to run workflows locally
  - Troubleshooting guide
  - Known limitations

## Quick Reference

### For Contributors

**Before submitting a PR:**
```bash
# Run local checks
pnpm lint
pnpm test
pnpm build

# Test CI locally (optional)
act -j lint
act -j build
act -j test --matrix node-version:22
```

**Adding dependencies:**
1. Add with pnpm: `pnpm add <package>`
2. PR will automatically check for vulnerabilities and license compatibility
3. Review dependency-review bot comments

### For Maintainers

**Responding to security alerts:**
```bash
# Check current vulnerabilities
pnpm audit

# Update vulnerable package
pnpm update <package>@latest

# If no fix available, see SUPPLY_CHAIN_SECURITY.md
```

**Generating SBOMs manually:**
```bash
# Trigger SBOM workflow
gh workflow run sbom.yml

# Download latest SBOM
gh run download --name sbom-<commit-sha>
```

**Reviewing CodeQL findings:**
1. Go to **Security** → **Code scanning alerts**
2. Triage each alert
3. Fix or dismiss with justification

## Workflow Permissions

All workflows use least-privilege permissions:
- Read-only by default
- Write access only where required (security events, artifacts)
- No deployment or package publishing permissions

## Security

For security concerns, see [SUPPLY_CHAIN_SECURITY.md](SUPPLY_CHAIN_SECURITY.md) or file a security advisory.
