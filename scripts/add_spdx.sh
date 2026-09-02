#!/usr/bin/env bash
# bulk_spdx_headers.sh
#
# Bulk-add SPDX headers repo-wide using the REUSE tool (`reuse annotate`).
# - Operates on git-tracked files only.
# - Excludes common binary/build/dependency paths.
# - Batches to avoid argv length limits.
# - Safe-ish by default: refuses to run on a dirty working tree.
#
# Requirements: Python3 + pipx (preferred) or pip. Git.
#
# Usage:
#   ./bulk_spdx_headers.sh \
#     --license Apache-2.0 \
#     --holder "Acme, Inc" \
#     --year 2026 \
#     --mode replace
#
# Modes:
#   replace    -> replace existing license/copyright header blocks (standardize hard)
#   no-replace -> do not replace; only insert if missing (more conservative)
#
set -euo pipefail

########################################
# Defaults (override via CLI flags)
########################################
LICENSE_ID="MIT"
HOLDER="AppSec Science, LLC"
YEAR="$(date +%Y)"
MODE="replace"                 # replace | no-replace
FALLBACK_DOT_LICENSE="true"    # if true, writes <file>.license for unknown comment styles
BATCH_SIZE="200"

# Exclusions: tweak to your repo.
EXCLUDE_DIRS=(
  ".git" ".idea" ".vscode"
  "node_modules" "vendor"
  "dist" "build" "target" "out" "bin"
  ".venv" ".tox" "__pycache__"
  "coverage"
)
EXCLUDE_FILES=(
  "package-lock.json" "pnpm-lock.yaml" "yarn.lock"
)
EXCLUDE_EXTS=(
  # images/docs
  ".png" ".jpg" ".jpeg" ".gif" ".webp" ".ico" ".pdf"
  # archives
  ".zip" ".gz" ".tgz" ".bz2" ".xz" ".7z"
  # binaries/objs
  ".exe" ".dll" ".so" ".dylib" ".a" ".o" ".obj" ".class" ".jar"
  # fonts
  ".woff" ".woff2" ".ttf" ".eot"
  # minified
  ".min.js" ".min.css"
)

########################################
# CLI parsing
########################################
usage() {
  cat <<EOF
Usage:
  $0 [--license SPDX_ID] [--holder "Name/Org"] [--year YYYY] [--mode replace|no-replace]
     [--batch N] [--no-fallback-dot-license]

Examples:
  $0 --license Apache-2.0 --holder "Acme, Inc" --year 2026 --mode replace
  $0 --license MIT --holder "Jane Doe" --mode no-replace

Notes:
  - Requires a clean git working tree.
  - Only touches git-tracked files (git ls-files).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --license) LICENSE_ID="${2:-}"; shift 2 ;;
    --holder)  HOLDER="${2:-}"; shift 2 ;;
    --year)    YEAR="${2:-}"; shift 2 ;;
    --mode)    MODE="${2:-}"; shift 2 ;;
    --batch)   BATCH_SIZE="${2:-}"; shift 2 ;;
    --no-fallback-dot-license) FALLBACK_DOT_LICENSE="false"; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$LICENSE_ID" || -z "$HOLDER" || -z "$YEAR" ]]; then
  echo "ERROR: --license, --holder, and --year must be set." >&2
  exit 2
fi

if [[ "$MODE" != "replace" && "$MODE" != "no-replace" ]]; then
  echo "ERROR: --mode must be 'replace' or 'no-replace'." >&2
  exit 2
fi

########################################
# Preconditions
########################################
if ! command -v git >/dev/null 2>&1; then
  echo "ERROR: git not found in PATH." >&2
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: not inside a git repository." >&2
  exit 1
fi

# Refuse to run on a dirty tree (this is a mass rewrite; make it deterministic).
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "ERROR: working tree is not clean. Commit/stash first." >&2
  exit 1
fi

########################################
# Ensure `reuse` is available
########################################
ensure_reuse() {
  if command -v reuse >/dev/null 2>&1; then
    return 0
  fi

  echo "reuse not found; attempting install..."

  if command -v pipx >/dev/null 2>&1; then
    pipx install reuse || true
  fi

  if command -v reuse >/dev/null 2>&1; then
    return 0
  fi

  # Fallback: user install via pip (might require PATH update depending on environment)
  if command -v python3 >/dev/null 2>&1; then
    python3 -m pip install --user reuse || true
  fi

  if ! command -v reuse >/dev/null 2>&1; then
    echo "ERROR: Could not install/find 'reuse'. Install it, then re-run:" >&2
    echo "  pipx install reuse" >&2
    echo "or" >&2
    echo "  python3 -m pip install --user reuse" >&2
    exit 1
  fi
}
ensure_reuse

########################################
# Build candidate file list (git-tracked, excluded paths/exts)
########################################
tmp_list="$(mktemp)"
cleanup() { rm -f "$tmp_list"; }
trap cleanup EXIT

python3 - <<PY >"$tmp_list"
import os, sys, subprocess

exclude_dirs = set(${EXCLUDE_DIRS[@]/#/'"'}); exclude_dirs = {d.strip('"') for d in exclude_dirs}
exclude_files = set(${EXCLUDE_FILES[@]/#/'"'}); exclude_files = {f.strip('"') for f in exclude_files}

exclude_exts = set(${EXCLUDE_EXTS[@]/#/'"'}); exclude_exts = {e.strip('"') for e in exclude_exts}

# Get NUL-separated tracked files
p = subprocess.run(["git", "ls-files", "-z"], check=True, stdout=subprocess.PIPE)
paths = [x.decode("utf-8", "surrogateescape") for x in p.stdout.split(b"\x00") if x]

out = sys.stdout.buffer

def is_excluded(path: str) -> bool:
    base = os.path.basename(path)
    if base in exclude_files:
        return True

    parts = path.split("/")
    if any(part in exclude_dirs for part in parts):
        return True

    lower = path.lower()
    for ext in exclude_exts:
        if lower.endswith(ext):
            return True
    return False

for path in paths:
    if not path or is_excluded(path):
        continue
    out.write(path.encode("utf-8", "surrogateescape") + b"\x00")
PY

########################################
# Run reuse annotate in batches
########################################
echo "Bulk annotating SPDX headers..."
echo "  License: $LICENSE_ID"
echo "  Holder:  $HOLDER"
echo "  Year:    $YEAR"
echo "  Mode:    $MODE"
echo "  Batch:   $BATCH_SIZE"
echo

python3 - <<PY
import os, subprocess, sys

license_id = ${LICENSE_ID@Q}
holder = ${HOLDER@Q}
year = ${YEAR@Q}
mode = ${MODE@Q}
fallback = ${FALLBACK_DOT_LICENSE@Q}.lower() == "true"
batch_size = int(${BATCH_SIZE@Q})

data = open(${tmp_list@Q}, "rb").read()
paths = [p.decode("utf-8", "surrogateescape") for p in data.split(b"\x00") if p]

if not paths:
    print("No files matched after exclusions; nothing to do.")
    sys.exit(0)

common = ["reuse", "annotate", "--license", license_id, "--copyright", holder, "--year", year]

if mode == "no-replace":
    common.append("--no-replace")

if fallback:
    common.append("--fallback-dot-license")

# Batch to avoid argv limits
for i in range(0, len(paths), batch_size):
    batch = paths[i:i+batch_size]
    cmd = common + batch
    subprocess.run(cmd, check=True)

print(f"Done. Annotated {len(paths)} files.")
PY

echo
echo "Suggested next steps:"
echo "  1) Review the diff:     git status && git diff --stat"
echo "  2) Run REUSE lint:      reuse lint"
echo "  3) Optional grep:       rg -n \"SPDX-License-Identifier:\" ."
