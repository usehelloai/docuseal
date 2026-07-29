#!/usr/bin/env bash
# PreToolUse(Edit|MultiEdit|Write): scan proposed content for banned patterns
# before the write lands.
#   1. U+2014 em-dash (global engineering convention: no em dashes; use a
#      colon, comma, or parentheses instead).
#   2. Plaintext secrets (private keys, AWS keys, generic high-entropy
#      assignments) heading into a committed file. CI gitleaks is the
#      authoritative gate; this is the in-repo local gate so a secret never
#      reaches a commit in the first place.
#
# Deny schema: a match is reported via the CURRENT Claude Code PreToolUse hook
# contract: stdout JSON with `hookSpecificOutput.permissionDecision: "deny"` and
# `permissionDecisionReason`, exit 0. The legacy top-level `decision`/`message`
# shape is DEPRECATED for PreToolUse (Claude Code proceeds through the normal
# permission flow and the "block" is silently ignored), so it must not be used.
# Source: docs.claude.com/en/docs/claude-code/hooks (Hook output > PreToolUse).
#
# CI no-op: claude-code-action loads project hooks inside the autofix runner.
# A blocking PreToolUse hook there would break autofix, so this hook exits 0
# immediately under GITHUB_ACTIONS / CI. Local sessions get the full gate.
set -euo pipefail

# No-op in CI/autofix runners (claude-code-action). The CI gitleaks job and
# docs-lint cover these paths server-side; an in-runner block would wedge autofix.
if [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${CI:-}" = "true" ]; then
  exit 0
fi

# Shared detector library (SINGLE source of truth for every write vector). Both
# this hook and scan_bash_content.sh source it, so a detector added there applies
# uniformly to Edit/Write AND Bash by construction -- no hand-mirroring, no drift.
HOOK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# source= lets `shellcheck -x` follow the lib; disable=SC1091 keeps the
# diff-scoped CI check (which runs without -x and may not co-pass the lib) clean.
# shellcheck source=.claude/hooks/lib/content_scan.sh disable=SC1091
. "${HOOK_DIR}/lib/content_scan.sh"

input=$(cat)
tool_name=$(echo "$input" | jq -r '.tool_name // empty')
file_path=$(echo "$input" | jq -r '.tool_input.file_path // empty')

# Emit a PreToolUse deny decision in the CURRENT documented schema and exit.
# `permissionDecision: "deny"` cancels the tool call; `permissionDecisionReason`
# is fed back to Claude. jq -n builds the JSON so the reason is always escaped.
deny() {
  jq -n --arg reason "$1" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $reason
    }
  }'
  exit 0
}

# --- Scope: which files does the gate apply to? ---------------------------
# Strategy is INCLUDE-by-default for text-ish source/config/secret files, with
# an explicit skip-list for binary / lock / vendored paths. The prior allowlist
# approach silently skipped any extension it didn't enumerate, so new code/secret
# file types (and extensionless files) fell through to `exit 0` ungated. We now:
#   1. skip known-binary / lock / vendored extensions outright,
#   2. otherwise scan, which covers .env / .env.* / *.pem / *.key / *.p12 /
#      *.pfx / *.crt / *.cer (the secret-bearing files this hook exists for)
#      AND extensionless code/config files (Dockerfile, Makefile, Procfile, etc.)
#      by basename.
base=$(basename -- "$file_path")

case "$file_path" in
  # Binary / media / archives / fonts: never text-scan. (.svg is intentionally
  # NOT here: SVG is XML text and can carry visible copy / em dashes, so it is
  # scanned like other text assets.)
  *.png|*.jpg|*.jpeg|*.gif|*.webp|*.bmp|*.ico|*.pdf|*.zip|*.gz|*.tar|*.tgz|*.bz2|*.xz|*.7z|*.rar \
  |*.woff|*.woff2|*.ttf|*.otf|*.eot|*.mp3|*.mp4|*.mov|*.avi|*.wav|*.so|*.dylib|*.dll|*.o|*.a|*.bin|*.exe \
  |*.pyc|*.pyo|*.class|*.jar|*.wasm)
    exit 0
    ;;
  # Lock / generated dependency manifests: high-volume, no hand-authored secrets.
  # (*.lock already covers Cargo.lock/poetry.lock/uv.lock/yarn.lock; list only
  # the non-.lock manifest names.)
  *.lock|*.sum|package-lock.json|pnpm-lock.yaml)
    exit 0
    ;;
  # Vendored / build output trees.
  */node_modules/*|*/.venv/*|*/venv/*|*/dist/*|*/build/*|*/.git/*)
    exit 0
    ;;
esac

# Extensionless files: only scan recognised code/config basenames; anything
# else extensionless is treated as out of scope to avoid scanning data blobs.
case "$file_path" in
  *.*) ;;  # has an extension and survived the skip-list above -> in scope
  *)
    case "$base" in
      Dockerfile|Dockerfile.*|Containerfile|Makefile|GNUmakefile|Procfile|Justfile|justfile \
      |Rakefile|Gemfile|Brewfile|.env|.envrc|.bashrc|.zshrc|.profile)
        ;;  # in scope
      *)
        exit 0
        ;;
    esac
    ;;
esac

# --- Build the content to scan -------------------------------------------
# For Write the whole file is the new content. For Edit/MultiEdit the tool only
# supplies the changed fragment(s); to catch a value-only secret replacement
# (e.g. editing `PLACEHOLDER` -> a real token where the `API_KEY=` assignment
# key lives in the existing file, NOT in new_string) we reconstruct the
# post-edit file: read the current on-disk file and apply the replacement(s) in
# memory, then scan the result. If the file can't be read (new file), we fall
# back to the fragment(s) alone.
content=""

reconstruct_edit() {
  # $1 = old_string, $2 = new_string. Echoes the post-edit file text if the
  # current file is readable and old_string occurs in it; otherwise echoes
  # new_string alone (best effort). Uses awk for literal (non-regex) replace so
  # secret values with regex metacharacters are handled safely.
  #
  # ENVIRON instead of -v: awk's -v assignment runs backslash-escape processing
  # and rejects embedded newlines ("newline in string"), so multi-line old/new
  # strings crash awk. ENVIRON values are taken verbatim -- the same pattern
  # used by cs_unquoted_segments in lib/content_scan.sh.
  local old_s="$1" new_s="$2"
  if [ -n "$file_path" ] && [ -f "$file_path" ]; then
    local current
    current=$(cat -- "$file_path" 2>/dev/null || true)
    if [ -n "$current" ] && [ -n "$old_s" ] && [[ "$current" == *"$old_s"* ]]; then
      # Literal replace-all via awk (index/substr), preserving newlines.
      # Pass old/new through ENVIRON so embedded newlines survive intact.
      CS_OLD="$old_s" CS_NEW="$new_s" awk '
        BEGIN { RS="\0"; old=ENVIRON["CS_OLD"]; new=ENVIRON["CS_NEW"] }
        {
          out=""; rest=$0; ol=length(old)
          if (ol==0) { print rest; next }
          while ((p=index(rest,old))>0) {
            out=out substr(rest,1,p-1) new
            rest=substr(rest,p+ol)
          }
          out=out rest
          printf "%s", out
        }
      ' <<<"$current"
      return
    fi
  fi
  # Fall back to scanning the new fragment plus a small slice of old context so
  # an assignment key adjacent to the replaced value is still in view.
  printf '%s\n%s' "$old_s" "$new_s"
}

case "$tool_name" in
  Edit)
    old_string=$(echo "$input" | jq -r '.tool_input.old_string // ""')
    new_string=$(echo "$input" | jq -r '.tool_input.new_string // ""')
    content=$(reconstruct_edit "$old_string" "$new_string")
    ;;
  Write)
    content=$(echo "$input" | jq -r '.tool_input.content // ""')
    ;;
  MultiEdit)
    # Apply each edit in sequence against the reconstructed file so a value-only
    # replacement in any edit is caught with its assignment key in context.
    if [ -n "$file_path" ] && [ -f "$file_path" ]; then
      content=$(cat -- "$file_path" 2>/dev/null || true)
    fi
    n_edits=$(echo "$input" | jq -r '.tool_input.edits | length // 0')
    if [ "${n_edits:-0}" -gt 0 ]; then
      for i in $(seq 0 $((n_edits - 1))); do
        o=$(echo "$input" | jq -r ".tool_input.edits[$i].old_string // \"\"")
        nw=$(echo "$input" | jq -r ".tool_input.edits[$i].new_string // \"\"")
        if [ -n "$content" ] && [ -n "$o" ] && [[ "$content" == *"$o"* ]]; then
          content=$(CS_OLD="$o" CS_NEW="$nw" awk '
            BEGIN { RS="\0"; old=ENVIRON["CS_OLD"]; new=ENVIRON["CS_NEW"] }
            { out=""; rest=$0; ol=length(old)
              if (ol==0) { printf "%s", rest; next }
              while ((p=index(rest,old))>0) { out=out substr(rest,1,p-1) new; rest=substr(rest,p+ol) }
              printf "%s%s", out, rest
            }' <<<"$content")
        else
          # New file or fragment not present: append the fragment so it is scanned.
          content="${content}"$'\n'"${o}"$'\n'"${nw}"
        fi
      done
    fi
    ;;
  *) exit 0 ;;
esac

if [ -z "$content" ]; then exit 0; fi

# --- Scan via the shared detector library --------------------------------
# scan_content applies the em-dash + secret detectors with confidence tiering
# keyed off file_path (doc-only paths skip secret tiers; *.env.example/.sample
# skip only the low-confidence heuristic). HIGH-confidence shapes (PEM blocks,
# AWS AKIA/ASIA ids) run even on example files because a real credential copied
# into an example config is still a leak. On the first hit it prints a reason and
# returns 0; we turn that into a PreToolUse deny. CI gitleaks remains the
# authoritative server-side gate; this is the local pre-commit gate.
if reason=$(scan_content "$content" "$file_path"); then
  deny "$reason"
fi

exit 0
