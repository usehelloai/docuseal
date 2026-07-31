#!/usr/bin/env bash
# AI preflight validation. Thin wrapper around `make validate`.
#
# Agents MUST run this before any push (per
# workspace_shared/standards/ai_remediation_loop.md section 3 step 4 and
# section 8 local validation contract).
#
# Location-independent: resolves the repo root from its own path so it
# works regardless of caller's CWD. If `make validate` is missing, stop
# loudly. Do not invent verification commands.

set -euo pipefail

# Resolve repo root relative to this script (scripts/ai_preflight.sh ->
# repo root is the parent dir). Works whether called as
# `bash scripts/ai_preflight.sh`, `./scripts/ai_preflight.sh`, or with
# an absolute path from any other CWD.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"
cd "${REPO_ROOT}"

echo "Running AI preflight validation from ${REPO_ROOT}..."

if [[ ! -f "Makefile" ]]; then
  echo "ERROR: No Makefile found at ${REPO_ROOT}/Makefile." >&2
  echo "This repo does not yet satisfy the workspace standard." >&2
  echo "See workspace_shared/standards/ai_remediation_loop.md section 4." >&2
  exit 2
fi

if ! command -v make >/dev/null 2>&1; then
  echo "ERROR: 'make' not installed." >&2
  echo "Install with: brew install make  (macOS) or apt install build-essential (Linux)" >&2
  exit 3
fi

# Ensure the authoritative native gate is actually installed. core.hooksPath is
# stored in local git config (NOT tracked), so a fresh clone would not run
# .githooks/pre-push. Self-heal here, the local-gate entrypoint agents run.
if [[ "$(git -C "${REPO_ROOT}" config --get core.hooksPath 2>/dev/null || true)" != ".githooks" ]]; then
  git -C "${REPO_ROOT}" config core.hooksPath .githooks
  echo "Set core.hooksPath=.githooks so the native pre-push gate runs."
fi

# Capture working-tree cleanliness BEFORE validating. The stamp records HEAD, so
# HEAD must be exactly what gets validated: any uncommitted change (tracked OR a
# new untracked source/fixture/config that validation depends on) means validate
# ran on a tree different from HEAD, and an uncommitted fix could make it pass
# while the committed SHA was never validated. `git status --porcelain` excludes
# gitignored build output (.next/, caches), so it flags only real, pushable
# sources. Captured BEFORE `make validate` because validate's own frontend build
# regenerates artifacts.
HEAD_SHA="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true)"
PRE_DIRTY=""
[[ -n "${HEAD_SHA}" ]] && PRE_DIRTY="$(git -C "${REPO_ROOT}" status --porcelain --untracked-files=no 2>/dev/null || true)"

# Invalidate any prior stamp BEFORE validating. If `make validate` exits non-zero,
# `set -e` aborts the script before the post-validate cleanup below ever runs, so
# a stale `ai_preflight_ok` for this same HEAD would otherwise survive and let the
# push gate reuse a previous success even though THIS validation failed (CR
# mercury #98). The stamp is (re)written only after validate AND all post-checks
# pass.
STAMP_DIR="${REPO_ROOT}/.claude/cache"
STAMP_FILE="${STAMP_DIR}/ai_preflight_ok"
[[ -n "${HEAD_SHA}" ]] && rm -f "${STAMP_FILE}" 2>/dev/null || true

make validate

# Re-check HEAD and tracked cleanliness AFTER validate. If `make validate` itself
# moved HEAD (committed/amended/checked out another commit) or mutated a tracked
# file (a regenerated lockfile, codegen, auto-format), HEAD no longer matches the
# validated tree and the stamp would be unsound. HEAD_SHA_AFTER guards the
# move-HEAD case, which a clean worktree alone would not catch (CR identity #27).
# (The frontend build regenerates frontend/dashboard/next-env.d.ts
# deterministically; that file is committed in sync, so a clean run is a no-op.)
HEAD_SHA_AFTER=""
[[ -n "${HEAD_SHA}" ]] && HEAD_SHA_AFTER="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true)"
POST_DIRTY=""
[[ -n "${HEAD_SHA}" ]] && POST_DIRTY="$(git -C "${REPO_ROOT}" status --porcelain --untracked-files=no 2>/dev/null || true)"

# Local-gate stamp (ai_remediation_loop completion, handoff Section 5.1).
# Record the HEAD sha on success so .claude/hooks/require_preflight_before_push.sh
# and .githooks/pre-push can confirm `make validate` ran against the exact commit
# being pushed. The stamp lives under .claude/cache/ (gitignored). HEAD-pinned by
# design: validate AFTER your final commit, then push.
if [[ -z "${HEAD_SHA}" ]]; then
  echo "WARNING: not a git repo; local-gate stamp not written (push gate will block)." >&2
elif [[ -n "${PRE_DIRTY}" ]]; then
  rm -f "${STAMP_FILE}" 2>/dev/null || true
  echo "WARNING: tracked files were uncommitted before validation, so the validated" >&2
  echo "         tree did not match HEAD. NOT writing the local-gate stamp. Commit or" >&2
  echo "         stash your changes, then re-run so the stamp attests the exact commit." >&2
elif [[ -n "${HEAD_SHA_AFTER}" && "${HEAD_SHA_AFTER}" != "${HEAD_SHA}" ]]; then
  rm -f "${STAMP_FILE}" 2>/dev/null || true
  echo "WARNING: HEAD moved during validation (${HEAD_SHA} -> ${HEAD_SHA_AFTER}), so the" >&2
  echo "         stamp would attest the wrong commit. NOT writing the local-gate stamp." >&2
  echo "         Re-run ai_preflight on the final commit." >&2
elif [[ -n "${POST_DIRTY}" ]]; then
  rm -f "${STAMP_FILE}" 2>/dev/null || true
  echo "WARNING: make validate modified tracked files, so HEAD no longer matches the" >&2
  echo "         validated tree. NOT writing the local-gate stamp. Commit those changes" >&2
  echo "         and re-run so the stamp attests the final commit:" >&2
  printf '%s\n' "${POST_DIRTY}" | sed 's/^/           /' >&2
else
  mkdir -p "${STAMP_DIR}"
  printf '%s\n' "${HEAD_SHA}" > "${STAMP_FILE}"
  echo "Local-gate stamp written for ${HEAD_SHA} -> ${STAMP_DIR}/ai_preflight_ok"
  STAMP_WRITTEN=1
fi

echo ""
# Exit non-zero on ANY no-stamp path. `make validate` may have passed, but if no
# stamp was written the push gate WILL block the next push, so reporting success
# (exit 0) here misleads a caller -- a human or the autofix agent -- into
# committing/pushing only to be blocked with no clear cause (CR/Codex identity
# #27). A non-zero exit makes the "commit/stash and re-run on the final commit"
# requirement unmissable. The stamp-written path is the only success path.
if [[ "${STAMP_WRITTEN:-0}" -eq 1 ]]; then
  echo "AI preflight validation completed successfully."
else
  echo "AI preflight: make validate passed but NO local-gate stamp was written" >&2
  echo "(see the WARNING above). The push gate will block until you commit or stash" >&2
  echo "your changes and re-run ai_preflight on the exact commit you intend to push." >&2
  exit 1
fi
