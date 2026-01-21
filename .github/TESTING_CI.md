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

# Run tests for Node 20
act -j test --matrix node-version:20

# Run tests for Node 22
act -j test --matrix node-version:22

# Run coverage
act -j coverage
```

### Run all jobs
```bash
act push
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

## CI Workflow Jobs

The CI workflow includes these jobs:

1. **Lint** - ESLint and Prettier formatting checks
2. **Build** - Compiles TypeScript packages
3. **Test** - Runs Vitest test suite on Node 20 and 22
4. **Coverage** - Generates test coverage reports

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
act -j test --matrix node-version:20

# Or run everything (will take longer):
act push
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
