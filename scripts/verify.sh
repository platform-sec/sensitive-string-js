#!/usr/bin/env bash
# Run the checks CI gates a push on, the way CI runs them.
#
#   pnpm verify
#
# The pre-push hook in .githooks runs this, and it is the command to run before
# saying a change is done. It covers the gating steps of the Lint, Build and
# Test jobs. It leaves out what CI runs but does not gate on (the timing
# analysis, the live provider tiers, the latest-client compatibility run) and
# the audit, whose verdict depends on advisories published after the code was
# written. Those belong to the nightly run.
#
# CI=true is set because CI sets it, and it changes behaviour: typescript-eslint
# switches to single-run programs under it, which once made a suite pass here
# and fail there.
set -euo pipefail

export CI=true

cd "$(dirname "$0")/.."

expected_node="v$(tr -d '[:space:]' < .nvmrc)"
if [ "$(node --version)" != "$expected_node" ]; then
  echo "warn  node $(node --version) is not the $expected_node CI pins in .nvmrc." \
    "A result here may not match CI." >&2
fi

step() {
  local name=$1
  shift
  local started=$SECONDS
  echo "==>   $name"
  if ! "$@"; then
    echo "FAIL  $name ($((SECONDS - started))s)" >&2
    exit 1
  fi
  echo "ok    $name ($((SECONDS - started))s)"
}

# Cheapest first, so a stale lockfile or an unformatted file fails in seconds.
step 'lockfile matches the manifests' pnpm install --frozen-lockfile --lockfile-only --silent
# --cache keys on file content, so a warm run checks only what changed.
step 'format' pnpm --silent format:check --cache
step 'release consistency' pnpm --silent release:check
step 'build' pnpm --silent build

# Type-check and lint read the build and not each other, so they run at once,
# each into its own log, and a failing one prints its log when both are done.
# The tests run after them, alone: run beside lint they failed one run in two
# here and passed on the next, which is a 10 second test timeout losing a race
# for the CPU, and a hook that fails at random teaches --no-verify.
#
# Lint runs without its cache. The config is type-aware, and ESLint's cache
# keys on the file being linted, so a change to one file that breaks the types
# another relies on would replay the other's clean result here while CI, which
# has no cache, fails it.
logs=$(mktemp -d)
trap 'rm -rf "$logs"' EXIT

declare -A pids=()
run_in_background() {
  local name=$1
  shift
  "$@" > "$logs/$name.log" 2>&1 &
  pids[$name]=$!
}

started=$SECONDS
echo "==>   type-check and lint, in parallel"
run_in_background type-check pnpm --silent typecheck
run_in_background lint pnpm --silent lint --no-cache

failed=()
for name in type-check lint; do
  if wait "${pids[$name]}"; then
    echo "ok    $name"
  else
    failed+=("$name")
  fi
done

for name in "${failed[@]}"; do
  echo "FAIL  $name" >&2
  cat "$logs/$name.log" >&2
done
if [ "${#failed[@]}" -gt 0 ]; then
  exit 1
fi
echo "ok    type-check and lint ($((SECONDS - started))s)"

step 'test' pnpm --silent test

echo "ok    every gating CI check passed in ${SECONDS}s"
