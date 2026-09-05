# GitHub Workflows and Security

This directory contains GitHub Actions workflows and security documentation for the SensitiveString project.

## Workflows

### Continuous Integration

**[`workflows/ci.yml`](workflows/ci.yml)**

- Runs on every push and pull request
- Jobs: lint, build, test (Node 22 & 24), coverage, security-audit
- Ensures code quality and security baseline
- [Local testing guide](TESTING_CI.md)

### Package Versioning and Release

**[`workflows/version-packages.yml`](workflows/version-packages.yml)**

- Maintains a Version Packages pull request from committed changesets
- Commits package manifests, package changelogs, internal ranges, and the lockfile together
- Uses independent package versions; dependent releases are added only when their ranges require it

**[`workflows/release.yml`](workflows/release.yml)**

- Manually dispatched after a Version Packages pull request is merged
- Defaults to a dry run
- Builds, signs, and verifies exact tarballs before publishing those same bytes
- Creates package-specific tags and one GitHub release per publication batch
- [Maintainer release guide](../RELEASING.md)

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

- **[RELEASING.md](../RELEASING.md)** - Independent versioning and publishing
  - Contributor changesets
  - Version Packages pull request review
  - Dry-run and real release process

## Quick Reference

### For Contributors

**Before submitting a PR:**

```bash
# Run local checks
pnpm lint
pnpm test
pnpm build

# Add release intent for a user-visible package change
pnpm changeset

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

**Preparing and checking a release:**

```bash
# Inspect pending release intent
pnpm release:status

# Reproduce the Version Packages update on a clean branch (writes release files)
pnpm release:version

# Validate committed manifests, ranges, changelogs, and lockfile
pnpm release:check
```

Merge the Version Packages pull request, then dispatch `release.yml` with `dry_run` enabled before a
real publication. The `npm-publish` environment should require maintainer approval and expose the
`NPM_TOKEN` secret only to the publish job. See [RELEASING.md](../RELEASING.md).

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
- The version workflow can write its release-preparation branch and pull request
- A non-dry release can publish only after approval in the `npm-publish` environment
- The publish job can write package tags; the release job can write GitHub releases

## Security

For security concerns, see [SUPPLY_CHAIN_SECURITY.md](SUPPLY_CHAIN_SECURITY.md) or file a security advisory.
