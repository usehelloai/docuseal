#!/usr/bin/env bash
# PreToolUse(Bash): close the Bash write vector for the banned-content gate.
#
# scan_banned_content.sh only sees Edit|MultiEdit|Write, so a local agent can
# bypass it entirely by writing a file through Bash: a heredoc, `tee`, or a
# `>` / `>>` redirect into `.env` / a `.py` / a `Dockerfile`. Bash is allowed in
# this repo's settings, so without this hook a hardcoded secret or em dash can be
# written and committed without the local gate the project added. This hook
# scans the Bash COMMAND STRING for the same two banned patterns and denies the
# call when it finds one. It is intentionally conservative: it gates the whole
# command text, not just the redirected payload, so a secret echoed anywhere in
# the command is caught.
#
# Deny schema matches the current Claude Code PreToolUse contract:
# `hookSpecificOutput.permissionDecision: "deny"` + `permissionDecisionReason`,
# exit 0 (legacy top-level `decision`/`message` is deprecated and ignored).
# Source: docs.claude.com/en/docs/claude-code/hooks.
set -euo pipefail

# No-op in CI/autofix runners, same rationale as scan_banned_content.sh.
if [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${CI:-}" = "true" ]; then
  exit 0
fi

# Shared detector library (SINGLE source of truth). scan_banned_content.sh sources
# the SAME file, so every secret/em-dash detector applies identically to the Bash
# write vector and the Edit/Write vector -- the Dockerfile space-form gap and any
# future pattern can no longer reach one hook but not the other (Codex #30).
HOOK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# source= lets `shellcheck -x` follow the lib; disable=SC1091 keeps the
# diff-scoped CI check (which runs without -x and may not co-pass the lib) clean.
# shellcheck source=.claude/hooks/lib/content_scan.sh disable=SC1091
. "${HOOK_DIR}/lib/content_scan.sh"

input=$(cat)
tool_name=$(echo "$input" | jq -r '.tool_name // empty')
command=$(echo "$input" | jq -r '.tool_input.command // empty')

if [ "$tool_name" != "Bash" ] || [ -z "$command" ]; then exit 0; fi

# Normalize Bash line continuations (`\` + newline) to a space.
command=$(printf '%s' "$command" | awk '{ while (sub(/\\$/,"")) { if ((getline nxt) > 0) $0 = $0 " " nxt; else break } print }')

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

# Only gate commands that actually WRITE file content. A read-only command
# (grep, cat, ls) that merely mentions a token is not a commit vector, and
# gating it would be noisy. Heuristic: the command writes a file via
#   - a heredoc (<<),
#   - `tee`,
#   - an output redirect (> / >>) into a path, OR
#   - an interpreter invoked with inline code (python -c, node -e, perl -e,
#     ruby -e, php -r, etc.) that opens/writes a file. Interpreter writes do not
#     use shell redirection, so the redirect heuristic alone misses
#     `python3 -c 'open(".env","w").write("API_KEY=...")'`, a write vector that
#     .claude/settings.json's Bash(python3:*) / Bash(node:*) allowances expose.
writes_file=0
case "$command" in
  *'<<'*|*' tee '*|*$'\t''tee '*|*'|tee '*|*'|tee'*) writes_file=1 ;;
esac
# Output redirect to a FILE: `>` / `>>`, optionally prefixed by a single fd
# digit (`1>file`, `2>err.log`), followed by a path target. A `&` target is an
# fd DUP (`2>&1`, `>&2`), not a file write, so the target must not start with
# `&`. The redirect may LEAD the command (`> .env printf ...`); the char before
# the optional fd digit is start-of-string or a non-fd char.
if grep -qE '(^|[^0-9&])[0-9]?>>?[[:space:]]*[^&[:space:]]' <<<"$command"; then
  writes_file=1
fi
# Combined stdout+stderr redirect to a FILE: `&>file` / `&>>file` / `>&file`
# (Bash). The target after the operator must be a path, not a digit (`>&2` is an
# fd dup). `>|` (noclobber-override) writes a file too.
if grep -qE '(&>>?|>&|>\|)[[:space:]]*[^&0-9[:space:]]' <<<"$command"; then
  writes_file=1
fi
# In-place editors rewrite a file with NO redirect: sed -i / perl -i (the -i may
# carry a backup suffix, e.g. `sed -i.bak`). Without this, `sed -i 's/.../KEY=secret/' .env`
# bypasses the write-vector gate (Codex PR #20 / #15).
if grep -qE '(^|[[:space:]/;&|])(sed|perl)[[:space:]]+([^|;&]*[[:space:]])?(-[A-Za-z]*i|--in-?place)' <<<"$command"; then
  writes_file=1
fi
# dd writes to its `of=` target without a shell redirect, e.g.
# `printf 'API_KEY=...' | dd of=.env`. Gate the whole command when an `of=`
# operand is present.
if grep -qE '(^|[[:space:]])dd[[:space:]]+([^|;&]*[[:space:]])?of=' <<<"$command"; then
  writes_file=1
fi
# Interpreter inline-code invocation: gate the whole command when an interpreter
# is run with an inline-code flag (-c / -e / -r / -E / -p / -n / --eval /
# --exec). Inline interpreter code is the only realistic Bash file-write path
# that does not go through a redirect or tee, and these flags are the universal
# "run this code string" entrypoints across python/node/perl/ruby/php/bash. We
# gate on the FLAG (not on parsing the code) so any write call inside the inline
# program (open(...,"w"), fs.writeFileSync, File.write, ...) is covered. This is
# conservative by design: a read-only inline one-liner is rare and a denied
# false positive is cheap relative to a leaked secret.
if grep -qE -- \
  '(^|[[:space:]/;&|])(python[0-9.]*|node|nodejs|deno|bun|perl|ruby|php|tclsh|lua|Rscript|osascript|bash|sh|zsh|ksh)([[:space:]]+-[A-Za-z]*)*[[:space:]]+(-[A-Za-z]*[ceEprn]|--eval|--exec)([[:space:]]|=|$)' \
  <<<"$command"; then
  writes_file=1
fi

if [ "$writes_file" != "1" ]; then exit 0; fi

# --- Scan via the shared detector library --------------------------------
# scan_command runs the SAME detectors as the Edit/Write path (em dash, PEM
# blocks, AWS AKIA/ASIA, generic key=value secrets, Dockerfile space-form
# ENV/ARG). No confidence tiering is applied here: a Bash command can write any
# file type and no single target path is known, so the strictest reading runs --
# any secret literal in a file-writing command is denied. On the first hit it
# prints a reason and returns 0; we turn that into a PreToolUse deny.
if reason=$(scan_command "$command"); then
  deny "$reason"
fi

exit 0
