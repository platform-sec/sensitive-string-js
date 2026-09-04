# Testing CI Locally with Act

This project uses GitHub Actions for continuous integration. You can test the CI workflow locally using [act](https://github.com/nektos/act) before pushing to GitHub.

## Prerequisites

Install `act`:
```bash
# macOS
brew install act

# Linux
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Windows
choco install act-cli
```

## Running CI Locally

### List available jobs
```bash
act -l
```

### Run specific jobs
```bash
# Run lint checks
act -j lint

# Run build
act -j build

# Run tests for Node 22
act -j test --matrix node-version:22

# Run tests for Node 24
act -j test --matrix node-version:24

# Run coverage
act -j coverage

# Run the secrets-provider live tiers
act -j secrets-live --container-options '--volume /tmp/k3s:/tmp/k3s'

# Run the HTTP client suites against the latest client releases.
# Needs network access to the npm registry; it installs outside the lockfile
# on purpose, which is the whole point of the job.
act -j http-client-compat
```

### Run all jobs
```bash
act push --container-options '--volume /tmp/k3s:/tmp/k3s'
```

## Known Limitations with Act

### 1. Artifact Upload/Download
The artifact upload and download actions will fail in `act` because they require GitHub's runtime API. This is expected and the workflow is configured with `continue-on-error: true` for these steps.

**What fails:**
- `actions/upload-artifact@v4` - Build artifacts
- `codecov/codecov-action@v4` - Coverage reports

**Impact:** None for local testing. The actual build and test steps complete successfully.

### 2. Cache Actions
Cache save/restore operations may show warnings about connection failures. This doesn't affect the CI functionality.

**What you'll see:**
```
Failed to restore: getCacheEntry failed: connect EHOSTUNREACH
Failed to save: reserveCache failed: connect EHOSTUNREACH
```

**Impact:** Tests run slightly slower without caching, but functionality is unaffected.

### 3. Kubernetes Live Test Volume

The Kubernetes live tier starts k3s through the Docker socket inside the `act` job container. The
kubeconfig is therefore written to the Docker host's `/tmp/k3s`, which is not the job container's
`/tmp/k3s` unless it is mounted explicitly. Run any `act` command that includes `secrets-live` with:

```bash
--container-options '--volume /tmp/k3s:/tmp/k3s'
```

Without that option, only the Kubernetes matrix entry fails because it cannot see the kubeconfig.
This is a nested-Docker limitation of the local `act` harness, not a failure in
`@platform-sec/sensitive-string-k8s`; the GitHub-hosted job does not need the option.

## CI Workflow Jobs

The CI workflow includes these jobs:

1. **Workflow Security** - actionlint and zizmor over the workflows themselves
2. **Lint** - ESLint, Prettier formatting checks, and the root type-check
3. **Build** - Compiles TypeScript packages and checks the package manifests
4. **Test** - Runs Vitest test suite on Node 22 and 24
5. **Coverage** - Generates test coverage reports
6. **Security Audit** - Vulnerability scanning and dependency verification

Three jobs are informational and set `continue-on-error: true`. Each of them
tests this repository against something it does not control, so a release or an
image moving upstream reports rather than blocks:

7. **Vault compatibility** - the `sensitive-vault` live suite against Vault and
   OpenBao containers, because a fork diverges and a compatibility claim made
   once is a claim that rots.
8. **Secrets provider live tier** - the Kubernetes, SOPS and AWS live suites
   against k3s, the real `sops` binary and a LocalStack emulator. A fixture is
   only as good as the recording behind it.
9. **HTTP client compatibility** - the six HTTP client suites against the
   *latest* axios, got, ky and undici rather than the lockfile pins. Those
   suites assert the bare client's behaviour before the wrapper's, so they are
   regression tests against the clients as much as against this repository: a
   client release that changes a measured row (which property a rejection keeps
   a revealed credential in, whether a 200 keeps it too, which headers survive a
   cross-origin redirect) shows up here rather than in a bug report. The job
   writes the versions it resolved into the run summary.

## Security Workflows

Additional security workflows run automatically:

1. **Dependency Review** (PRs only) - Scans new dependencies for vulnerabilities and license issues
2. **CodeQL** - Static security analysis (push, PR, weekly schedule)
3. **SBOM Generation** - Creates Software Bill of Materials (main branch, releases)

See [SUPPLY_CHAIN_SECURITY.md](./SUPPLY_CHAIN_SECURITY.md) for detailed documentation.

## Expected Results

When all checks pass, you should see:
```
🏁  Job succeeded
```

If any checks fail, you'll see:
```
🏁  Job failed
Error: Job 'JobName' failed
```

## Quick Commands

```bash
# Before pushing, run the essential checks:
act -j lint
act -j build
act -j test --matrix node-version:22

# Or run everything (will take longer):
act push --container-options '--volume /tmp/k3s:/tmp/k3s'
```

## Troubleshooting

### "Error: image not found"
Configure act to use the medium-size Docker image:
```bash
echo "-P ubuntu-latest=catthehacker/ubuntu:act-latest" > ~/.config/act/actrc
```

### "Job failed"
Read the error output carefully - it will show which step failed and why. Common issues:
- Linting errors (fix with `pnpm lint:fix` and `pnpm format`)
- Test failures (fix failing tests)
- Build errors (TypeScript compilation issues)
