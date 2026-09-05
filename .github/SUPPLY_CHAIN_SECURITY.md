# Supply Chain Security

This document describes the supply chain security measures implemented in this project to protect against dependency vulnerabilities, malicious packages, and supply chain attacks.

## Overview

As a security-critical library handling sensitive data, this project implements defense-in-depth supply chain security:

1. **Dependency and License Review** - Automated review of pull-request dependency changes
2. **Vulnerability Scanning** - Continuous monitoring for known CVEs
3. **Static Analysis** - CodeQL security scanning for code vulnerabilities
4. **Cosign Signing** - Keyless signatures over exact publication tarballs
5. **SLSA Provenance** - SLSA Level 3 provenance for independently rebuilt artifacts
6. **Release Integrity** - Committed versions, validated ranges, and byte-preserving publication
7. **SBOM Generation** - Software Bills of Materials for transparency
8. **Lockfile Enforcement** - Reproducible installs with frozen dependencies

## Security Workflows

### 1. Dependency Review (Pull Requests)

**Workflow**: [`workflows/dependency-review.yml`](workflows/dependency-review.yml)
**Trigger**: Every pull request to `main`
**Purpose**: Block malicious or vulnerable dependencies before they enter the codebase

**What it checks**:
- ✅ Known vulnerabilities (CVEs) with moderate+ severity
- ✅ License compatibility (blocks GPL, LGPL, AGPL)
- ✅ OpenSSF Scorecard ratings (security posture)
- ✅ Deprecated or abandoned packages
- ✅ Packages with no license information

**Allowed licenses**: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD
**Blocked licenses**: GPL-2.0, GPL-3.0, LGPL-2.0, LGPL-2.1, LGPL-3.0, AGPL-3.0

**How to fix failures**:
```bash
# Review the dependency causing the issue
pnpm why <package-name>

# Remove problematic dependency
pnpm remove <package-name>

# Find alternative packages with better security/licensing
```

### 2. Security Audit (CI Pipeline)

**Workflow**: [`workflows/ci.yml`](workflows/ci.yml) (security-audit job)
**Trigger**: Every push and pull request
**Purpose**: Detect vulnerabilities in existing dependencies

**What it checks**:
- 🔍 **pnpm audit**: Known vulnerabilities in dependency tree
- 🔍 **Lockfile integrity**: Ensures `pnpm-lock.yaml` is in sync
- 🔍 **Malicious packages**: Pattern-based detection of suspicious package names
- 🔍 **Critical vulnerabilities**: Fails build if critical CVEs found
- ⚠️ **High vulnerabilities**: Warns but doesn't block (requires review)

**Severity thresholds**:
- **Critical**: ❌ Build fails immediately
- **High**: ⚠️ Warning logged, manual review required
- **Moderate/Low**: Logged for tracking

**Fixing audit failures**:
```bash
# View detailed audit report
pnpm audit

# Update specific package
pnpm update <package-name> --latest

# Update all dependencies (use with caution)
pnpm update --latest

# If no fix is available, check for patches or alternatives
pnpm audit --fix
```

### 3. CodeQL Security Scanning

**Workflow**: [`workflows/codeql.yml`](workflows/codeql.yml)
**Trigger**: Push to main, pull requests, weekly schedule (Mondays 00:00 UTC)
**Purpose**: Static analysis to detect security vulnerabilities in source code

**What it detects**:
- 🔐 SQL injection vulnerabilities
- 🔐 Cross-site scripting (XSS)
- 🔐 Command injection
- 🔐 Path traversal
- 🔐 Insecure randomness
- 🔐 Hardcoded credentials
- 🔐 Timing attacks
- 🔐 And 200+ other security issues

**Query suites**:
- `security-extended`: Comprehensive security checks
- `security-and-quality`: Security + code quality rules

**Reviewing findings**:
1. Go to **Security** → **Code scanning alerts** in GitHub
2. Review each alert's severity and remediation advice
3. Fix vulnerabilities before merging
4. Dismiss false positives with justification

### 4. Cosign Artifact Signing

**Workflows**: [`workflows/release.yml`](workflows/release.yml) (release artifacts) and
[`workflows/ci.yml`](workflows/ci.yml) (main-branch snapshots)
**Trigger**: Manual release dispatch, or a push to `main` for the CI snapshot
**Purpose**: Cryptographically sign npm package tarballs using Sigstore keyless signing

**What it does**:
- 📝 **Keyless signing**: Uses GitHub OIDC for identity, no key management required
- 📝 **Transparency log**: All signatures recorded in Rekor public transparency log
- 📝 **Certificate chain**: Fulcio-issued short-lived certificates tied to GitHub identity
- 📝 **Verification**: Automatic verification of signatures after signing

**Signing artifacts**:
- `*.tgz` - npm package tarballs
- `*.sig` - Detached cosign signatures
- `*.pem` - Signing certificates

The release workflow signs the tarballs produced from its validated publish plan, downloads that
same signed bundle in the publish job, verifies it again, and passes those tarball paths directly to
npm. The CI sign job is an additional snapshot of all packages; it is not a release source of truth.

**Verifying signatures locally**:
```bash
# Install cosign
brew install cosign  # macOS
# or: go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Download an exact release bundle from a dry or real release run
gh run download <run-id> --name signed-release-bundle-<commit-sha>
cd signed-release-bundle/packages

# Verify signature
cosign verify-blob \
  --signature package.tgz.sig \
  --certificate package.tgz.pem \
  --certificate-identity-regexp \
    '^https://github\.com/OWNER/REPO/\.github/workflows/release\.yml@refs/(heads|tags)/.+$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  package.tgz
```

**Security properties**:
- ✅ Tamper-evident: Any modification invalidates the signature
- ✅ Non-repudiable: Signature tied to GitHub Actions workflow identity
- ✅ Transparent: All signatures publicly logged in Rekor
- ✅ No secrets: Uses OIDC workload identity, no key to steal

### 5. SLSA Provenance (Level 3)

**Workflow**: [`workflows/slsa-provenance.yml`](workflows/slsa-provenance.yml)
**Trigger**: Push to `main`, legacy `v*` tags, releases, or manual dispatch
**Purpose**: Generate SLSA Level 3 provenance attestations for independently rebuilt artifacts

**SLSA Level 3 guarantees**:
- ✅ **Source integrity**: Build triggered from verified source
- ✅ **Build integrity**: Build ran on isolated, ephemeral infrastructure
- ✅ **Provenance authenticity**: Provenance signed and tamper-evident
- ✅ **Non-falsifiable**: Provenance generated by trusted builder, not user-controlled

**What it generates**:
- `multiple.intoto.jsonl` - SLSA provenance in in-toto format
- Contains: builder identity, source commit, build parameters, artifact hashes

This workflow rebuilds packages from the same source ref. Its provenance covers that rebuild, not
the byte-for-byte tarballs selected and published by `release.yml`; Cosign signatures and
`SHA256SUMS` are the authority for those exact release bytes.

**Verifying provenance locally**:
```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Download artifact and provenance
gh run download --name npm-packages-slsa
gh run download --name multiple.intoto.jsonl

# Verify provenance
slsa-verifier verify-artifact \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/OWNER/REPO \
  package.tgz
```

**Provenance contents**:
```json
{
  "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
  "builder": {
    "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
  },
  "invocation": {
    "configSource": {
      "uri": "git+https://github.com/OWNER/REPO@refs/heads/main",
      "digest": { "sha1": "<commit-sha>" }
    }
  },
  "materials": [...],
  "subject": [
    { "name": "package.tgz", "digest": { "sha256": "..." } }
  ]
}
```

**Why SLSA Level 3?**
- The slsa-github-generator runs on GitHub's isolated infrastructure
- Users cannot modify the build or provenance after initiation
- Provides highest assurance for GitHub Actions-based builds

### 6. Release Integrity and Independent Versioning

**Workflows**: [`workflows/version-packages.yml`](workflows/version-packages.yml) and
[`workflows/release.yml`](workflows/release.yml)

Release intent is committed as Changesets. The Version Packages pull request consumes those files
and commits package manifests, package changelogs, internal dependency and peer ranges, and the
lockfile together. Packages version independently; a dependent receives a release only when its
declared range must change.

The release workflow does not calculate versions. It checks npm for committed versions that have not
been published, validates their manifests and changelogs, packs them in dependency order, and
publishes the exact signed tarballs. Each package gets a standard `name@version` git tag. One batch
GitHub release named `release-<run-id>` carries the tarballs, signatures, certificates, and checksum
file and triggers the release-level SBOM and SLSA workflows once.

See [`../RELEASING.md`](../RELEASING.md) for contributor, review, dry-run, and publication steps.

### 7. SBOM Generation

**Workflow**: [`workflows/sbom.yml`](workflows/sbom.yml)
**Trigger**: Push to main, releases, manual dispatch
**Purpose**: Generate Software Bill of Materials for transparency and compliance

**Generated artifacts**:
- 📄 **CycloneDX SBOM** (JSON + XML) - Industry standard format
- 📄 **SPDX SBOM** (JSON) - Linux Foundation format
- 📄 **Dependency tree** - Human-readable hierarchy
- 📄 **Checksums** (SHA-256, SHA-512) - Integrity verification

**SBOM formats**:

**CycloneDX** (`sbom-*.json`, `sbom-*.xml`):
- Includes component list, licenses, hashes, and vulnerability data
- Used by security tools and compliance systems
- Per-package and monorepo-wide SBOMs

**SPDX** (`sbom-spdx-*.json`):
- Alternative standard for SBOM
- Focuses on licensing and provenance

**Accessing SBOMs**:
```bash
# Download from latest workflow run
gh run download --name sbom-<commit-sha>

# SBOMs are also attached to the publication batch release
gh release download release-<run-id> --pattern 'sbom-*'
```

**Using SBOMs**:
- **Vulnerability scanning**: Import into tools like Grype, Trivy, Dependency-Track
- **License compliance**: Audit all transitive dependencies
- **Procurement**: Share with security teams for approval
- **Incident response**: Quickly identify if vulnerable components are used

### 8. Lockfile Enforcement

**Mechanism**: `pnpm install --frozen-lockfile` in all CI jobs
**Purpose**: Ensure reproducible builds and prevent unexpected dependency updates

**Protection provided**:
- ✅ Prevents supply chain injection via version ranges
- ✅ Ensures builds are reproducible
- ✅ Pins exact versions including transitive dependencies
- ✅ Detects manual edits to `package.json` without lockfile update

**Best practices**:
```bash
# Always update lockfile when changing dependencies
pnpm install

# Commit both package.json and pnpm-lock.yaml together
git add package.json pnpm-lock.yaml
git commit -m "deps: update dependency X"

# Never manually edit pnpm-lock.yaml
```

## Responding to Security Issues

### Critical Vulnerability Discovered

1. **Assess impact**:
   ```bash
   pnpm audit --json | jq '.advisories | to_entries[] | select(.value.severity == "critical")'
   ```

2. **Check for fixes**:
   ```bash
   pnpm audit --fix
   ```

3. **If no fix available**:
   - Find alternative package
   - Apply patch using `pnpm patch`
   - Consider vendoring if necessary
   - Document risk acceptance if unavoidable

4. **Update and test**:
   ```bash
   pnpm update <package>@latest
   pnpm test
   pnpm build
   ```

5. **Create security advisory**:
   - If vulnerability affects published package users
   - Use GitHub Security Advisories

### Malicious Package Detected

1. **Immediately revert**:
   ```bash
   git revert <commit-with-malicious-package>
   pnpm install --frozen-lockfile
   ```

2. **Audit for damage**:
   - Check for exfiltrated secrets
   - Review git history for unauthorized commits
   - Rotate credentials if compromised

3. **Report**:
   - Report to npm: security@npmjs.com
   - File issue with package maintainer
   - Document in security advisory

### License Compliance Violation

1. **Identify problematic dependency**:
   ```bash
   pnpm licenses list
   ```

2. **Options**:
   - Replace with compatible alternative
   - Request license exception from legal team
   - Contribute to make package available under compatible license

## Security Hardening Checklist

When adding new dependencies:

- [ ] Check OpenSSF Scorecard: https://securityscorecards.dev/
- [ ] Review package reputation (downloads, maintainers, age)
- [ ] Audit package.json scripts for suspicious commands
- [ ] Check for typosquatting (similar names to popular packages)
- [ ] Verify maintainer identity (npm profile, GitHub)
- [ ] Review recent issues/PRs for security concerns
- [ ] Run local audit: `pnpm audit`
- [ ] Check bundle size impact
- [ ] Ensure license compatibility

## Tools and Resources

### Scanning Tools

- **GitHub Dependency Review**: Built into pull requests
- **pnpm audit**: Built into pnpm CLI
- **CodeQL**: GitHub's semantic code analysis
- **Snyk**: Alternative vulnerability scanner (commercial)
- **Socket.dev**: Supply chain attack detection (commercial)

### SBOM Tools

- **CycloneDX**: https://cyclonedx.org/
- **SPDX**: https://spdx.dev/
- **Grype**: SBOM vulnerability scanner
- **Dependency-Track**: Continuous SBOM analysis platform

### Standards and Frameworks

- **SLSA**: Supply-chain Levels for Software Artifacts
- **SSDF**: Secure Software Development Framework (NIST)
- **OpenSSF**: Open Source Security Foundation best practices
- **OWASP Dependency-Check**: Vulnerability detection

## Monitoring and Alerts

### Automated Alerts

GitHub sends alerts for:
- Dependabot security advisories
- CodeQL findings
- Secret scanning (if enabled)

Configure notifications:
1. Go to repository **Settings** → **Notifications**
2. Enable "Dependabot alerts"
3. Enable "Code scanning alerts"

### Manual Monitoring

Regular security reviews (recommended monthly):
```bash
# Check for outdated dependencies
pnpm outdated

# Audit for vulnerabilities
pnpm audit

# Review dependency licenses
pnpm licenses list

# Check for new advisories
gh api /repos/:owner/:repo/dependabot/alerts
```

## CI Configuration

### Required Secrets

- `CODECOV_TOKEN` - For coverage reporting (optional)
- `NPM_TOKEN` - For the publish job in `release.yml`; store it in the protected `npm-publish`
  environment

Cosign, SLSA, and GitHub attestations use short-lived GitHub OIDC identities rather than committed
signing keys.

### Required Permissions

Workflows use least-privilege permissions:
- `contents: read` - Clone repository
- `security-events: write` - Upload CodeQL results
- `pull-requests: write` - Maintain the Version Packages pull request
- `contents: write` - Update that pull-request branch, push package tags, and create releases
- `id-token: write` - Sign artifacts, create npm provenance, and produce attestations
- `attestations: write` - Publish GitHub-native build and SBOM attestations

Write permissions are scoped to the jobs that need them. Repository settings must also allow GitHub
Actions to create pull requests for the Version Packages workflow.

### Act (Local CI Testing)

Test security workflows locally:
```bash
# Test dependency scanning (requires GitHub token)
act pull_request -j dependency-review

# Test security audit
act push -j security-audit

# Validate the local parts of versioning and release automation
pnpm release:check
actionlint .github/workflows/version-packages.yml .github/workflows/release.yml
zizmor .github/workflows/version-packages.yml .github/workflows/release.yml
```

Artifact transfer, GitHub API writes, OIDC signing and attestations, npm registry publication, and
the Version Packages pull request require hosted services that `act` does not reproduce. Treat those
steps as locally untestable, not as package failures. Use a GitHub release dry run for the complete
pre-publication path. See [TESTING_CI.md](TESTING_CI.md) for the exact local boundaries.

## Incident Response

If a supply chain attack is detected:

1. **Isolate**: Stop deployments immediately
2. **Assess**: Determine scope of compromise
3. **Contain**: Remove malicious code, rotate credentials
4. **Notify**: Inform users if published package affected
5. **Remediate**: Fix vulnerability, update dependencies
6. **Review**: Conduct post-mortem, improve controls

## Additional Resources

- [npm Security Best Practices](https://docs.npmjs.com/security-best-practices)
- [OpenSSF Scorecards](https://github.com/ossf/scorecard)
- [SLSA Framework](https://slsa.dev/)
- [GitHub Supply Chain Security](https://docs.github.com/en/code-security/supply-chain-security)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)

## Verifying Releases

Each publication batch has a synthetic `release-<run-id>` GitHub release. The independently
versioned package tags are `@platform-sec/<package>@<version>`; use the batch tag when downloading
assets.

### Verify with Cosign

```bash
# Download the exact signed publication artifacts
gh release download release-<run-id> \
  --pattern '*.tgz' \
  --pattern '*.sig' \
  --pattern '*.pem'

# Verify each package
for pkg in *.tgz; do
  cosign verify-blob \
    --signature "${pkg}.sig" \
    --certificate "${pkg}.pem" \
    --certificate-identity-regexp \
      '^https://github\.com/OWNER/REPO/\.github/workflows/release\.yml@refs/(heads|tags)/.+$' \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$pkg"
done
```

### Verify SLSA Provenance for the Rebuild

The SLSA workflow produces and verifies its own rebuild from the batch release's source ref. Download
both artifacts from that workflow run so the provenance subjects and tarballs are from the same
build. This complements, but does not replace, Cosign verification of the published bytes.

```bash
# Download matching artifacts from the SLSA workflow run
gh run download <slsa-run-id> --name npm-packages-slsa --dir slsa-packages
gh run download <slsa-run-id> --name multiple.intoto.jsonl --dir slsa-provenance

# Verify each rebuilt package against provenance
for pkg in slsa-packages/*.tgz; do
  slsa-verifier verify-artifact \
    --provenance-path slsa-provenance/multiple.intoto.jsonl \
    --source-uri github.com/OWNER/REPO \
    --source-tag release-<run-id> \
    "$pkg"
done
```

### Verify GitHub Attestations

GitHub-native attestations are generated for the SLSA workflow's release-event rebuild.

```bash
# Verify using GitHub's attestation verification
gh attestation verify package.tgz --repo OWNER/REPO
```

### Verify Checksums

```bash
# Download exact release tarballs and their checksum manifest
gh release download release-<run-id> --pattern '*.tgz' --pattern 'SHA256SUMS'

# Verify
sha256sum -c SHA256SUMS
```

## Questions?

For security concerns, contact the maintainers or file a security advisory on GitHub.
