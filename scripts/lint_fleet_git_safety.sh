#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Fleet git-safety lint (incident 2026-07-26, recommendation R3).
#
# Statically rejects the working-tree/branch DESTROYERS in committed shell
# scripts under scripts/**, so a fleet-automation script can never again carry
# a `git checkout -f` / `checkout -B` / `reset --hard` / `clean -fd` / `git stash`
# that silently discards a live session's uncommitted work in a checkout it does
# not own. That exact class caused the 2026-07-26 fleet data-loss incident, where
# a propagation loop's `git checkout -f` force-discarded unstaged edits in three
# primary checkouts. Prose in a standard did not stop it; a mechanical gate does.
#
# This is the HARNESS-AGNOSTIC layer of the fix: it runs in CI and `make validate`
# regardless of which agent (Claude Code, Codex, OpenCode) or human wrote the
# script, complementing the Claude-Code PreToolUse hook (which only catches
# INTERACTIVE commands). The safe alternative is scripts/fleet_mutate.sh
# (worktree isolation); see standards/parallel_session_policy.md.
#
# SCOPE: tracked shell scripts under scripts/ (the incident script was bash).
# Python fleet automation must route mutations through fleet_mutate.sh or its
# own reviewed helper; extending this lint to the subprocess arg-list form is a
# documented follow-up (the list form `["git","checkout","-f"]` is not a shell
# command line and needs a different matcher).
#
# OPT-OUT: a genuinely-safe use (e.g. destroying a THROWAWAY worktree this script
# just created) may carry a same-line marker `# fleet-git-safe: <reason>`. The
# reason is mandatory; a bare marker is itself a violation, so the escape hatch
# cannot be used to silently wave a destroyer through.
#
# THREAT MODEL / LIMITATIONS: this is a regex denylist guarding a COOPERATIVE author
# (agent or human) against the mistake that caused the incident, which was a LITERAL
# `git checkout -f`. Like every regex guard (and the settings.json deny list it
# complements), it does not stop DELIBERATE obfuscation: dynamic construction such as
# `f=-f; git checkout "$f"` or `c=checkout; git "$c" -f` evades it, and a force flag
# after a `--` pathspec terminator (`git checkout -- -f`) may false-positive. Defeating
# obfuscation needs token/AST-aware parsing, out of scope here; the durable defense for
# committed fleet scripts is that fleet_mutate.sh is the sanctioned mutation path and
# human review is the backstop. The point is to make the accidental destroyer
# unmergeable, not to sandbox a hostile script.
#
# EXIT: 0 clean, 1 on any violation (a real gate; NO CI no-op, unlike the hooks).
# ---------------------------------------------------------------------------
set -euo pipefail

# Fail-closed abort with a diagnostic (used by the scan helpers below).
die() { printf 'lint_fleet_git_safety: %s\n' "$1" >&2; exit 1; }

root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "lint_fleet_git_safety: not a git repo; nothing to scan." >&2
  exit 0
}
cd "$root"

# One scratch file for the whole run, created up front with an explicit failure
# check, so matching greps a REAL file instead of a per-call here-string. A
# here-string silently creates a temp file whose creation failure (denied/full
# temp dir) surfaces as redirection exit 1, indistinguishable from grep's "no
# match" -> a fail-OPEN on exactly the constrained environments this gate must
# harden. Checking mktemp ONCE here fails CLOSED at the right place instead.
scan_tmp=$(mktemp) || { echo "lint_fleet_git_safety: cannot create temp file; failing closed." >&2; exit 1; }
trap 'rm -f "$scan_tmp"' EXIT

# Tracked shell scripts under scripts/ AT ANY DEPTH. Use a path-prefix pathspec and
# filter by extension, NOT a `**` glob: git pathspec does not expand `**` without
# `:(glob)` magic, so `scripts/**/*.sh` would silently miss nested scripts (a loophole).
# A read loop (not `mapfile`) keeps this runnable on macOS default Bash 3.2, which
# `make validate` uses; see tasks/lessons.md.
files=()
while IFS= read -r _f; do
  [ -n "$_f" ] && files+=("$_f")
done < <(git ls-files -- scripts 2>/dev/null | grep -E '\.sh$' | sort -u)
if [ "${#files[@]}" -eq 0 ]; then
  echo "lint_fleet_git_safety: no tracked scripts/*.sh; OK."
  exit 0
fi

# Destroyer command forms (bash). Each is scoped to a single command segment via
# [^|;&]* so it does not leak across ; | &&. `checkout -B` is matched
# case-SENSITIVELY (a separate grep without -i) so the safe `-b` (create) is never
# flagged; the rest are matched case-insensitively (flags/SQL casing vary).
# fleet-git-safe: these are detector definitions, not invocations.
ci_patterns=(  # fleet-git-safe: pattern table, scanned case-insensitively
  'git[[:space:]]+([^|;&]*[[:space:]])?checkout[[:space:]]+([^|;&]*[[:space:]])?(--force|-[a-zA-Z]*f[a-zA-Z]*)([[:space:]]|=|$)'  # fleet-git-safe: detector
  # Path-restore forms that DISCARD unstaged worktree edits: `git checkout -- <path>`
  # and `git checkout .`. `--force` is unaffected (it is `--f`, not `-- `).
  'git[[:space:]]+([^|;&]*[[:space:]])?checkout[[:space:]]+([^|;&]*[[:space:]])?(--[[:space:]]|\.([[:space:]]|$))'                # fleet-git-safe: detector
  'git[[:space:]]+([^|;&]*[[:space:]])?reset[[:space:]]+([^|;&]*[[:space:]])?--hard'                                             # fleet-git-safe: detector
  # clean -fd: combined (-fd/-df) AND split/long forms in either order (matching the hook).
  'git[[:space:]]+([^|;&]*[[:space:]])?clean[[:space:]]+[^|;&]*-[a-zA-Z]*(f[a-zA-Z]*d|d[a-zA-Z]*f)'                              # fleet-git-safe: detector
  'git[[:space:]]+([^|;&]*[[:space:]])?clean[[:space:]]+[^|;&]*(--force|-[a-zA-Z]*f[a-zA-Z]*)[[:space:]][^|;&]*-[a-zA-Z]*d'      # fleet-git-safe: detector
  'git[[:space:]]+([^|;&]*[[:space:]])?clean[[:space:]]+[^|;&]*-[a-zA-Z]*d[a-zA-Z]*[[:space:]][^|;&]*(--force|-[a-zA-Z]*f[a-zA-Z]*)'  # fleet-git-safe: detector
  'git[[:space:]]+([^|;&]*[[:space:]])?stash([[:space:]]|$)'                                                                     # fleet-git-safe: detector
  # MODERN `git switch` force/discard forms (git-switch: -f/--force/--discard-changes
  # throw away local modifications), same data-loss class as checkout -f.
  'git[[:space:]]+([^|;&]*[[:space:]])?switch[[:space:]]+([^|;&]*[[:space:]])?(--force|--discard-changes|-[a-zA-Z]*f[a-zA-Z]*)([[:space:]]|=|$)'  # fleet-git-safe: detector
)
# Case-SENSITIVE forms: `checkout -B` and `switch -C` force-reset a branch. Scanned
# without -i so lowercase `-b`/`-c` (safe create) never match; combined short flags
# (`-qB`, `-qC`) are covered like the hook. `--force-create` is the long `-C`.
cs_patterns=(  # fleet-git-safe: pattern table, case-sensitive
  'git[[:space:]]+([^|;&]*[[:space:]])?checkout[[:space:]]+([^|;&]*[[:space:]])?-[a-zA-Z]*B[a-zA-Z]*([[:space:]]|$)'                 # fleet-git-safe: detector
  'git[[:space:]]+([^|;&]*[[:space:]])?switch[[:space:]]+([^|;&]*[[:space:]])?(--force-create|-[a-zA-Z]*C[a-zA-Z]*)([[:space:]]|$)'  # fleet-git-safe: detector
)

# Waiver marker regex. Honors `# fleet-git-safe: <reason>` ONLY as a genuine
# trailing shell comment: the `#` must start at a word boundary (line start or after
# whitespace, so a `#` embedded in a pathname like `path/#x` is NOT a comment), a
# reason is required, and from there to END OF LINE there must be no quote, backtick,
# or command separator (so a marker hidden inside a quoted string ahead of a real
# destroyer does not waive it). EXCL is built via printf so the single quote,
# double quote, and backtick embed cleanly; the trailing `$` anchor is concatenated
# as a literal to avoid the shell's `$"..."` locale-string syntax.
_SQ=$(printf '\047'); _BT=$(printf '\140')
EXCL="${_SQ}\"${_BT};|&"
marker_re="(^|[[:space:]])#[[:space:]]*fleet-git-safe:[[:space:]]*[^[:space:]${EXCL}][^${EXCL}]*"

# Fail-CLOSED grep: exit 0 = match, 1 = no match, anything else = grep error, which
# must abort (never be silently treated as "no destroyer"). Sets `hit_rc`.
hit() {  # <mode: ci|cs> <pattern> <text>
  local mode="$1" pat="$2" text="$3"
  # Write the line to the pre-created scratch file (fail closed if that write
  # fails), then grep a real file -- no here-string, so a temp-dir failure cannot
  # masquerade as "no match", and no pipe, so pipefail/SIGPIPE cannot mask a hit.
  printf '%s\n' "$text" > "$scan_tmp" || die "scratch write failed; failing closed"
  # grep stays on the left of `||` so its exit 1 (no match) does not trip `set -e`.
  hit_rc=0
  if [ "$mode" = ci ]; then
    grep -qiE "$pat" "$scan_tmp" || hit_rc=$?
  else
    grep -qE "$pat" "$scan_tmp" || hit_rc=$?
  fi
  [ "$hit_rc" -le 1 ] || die "grep failed (exit $hit_rc) while scanning; failing closed"
}

violations=0
report() {  # <file> <lineno> <line>
  printf '  %s:%s: %s\n' "$1" "$2" "$(printf '%s' "$3" | sed 's/^[[:space:]]*//')" >&2
  violations=$((violations + 1))
}

# Scan ONE logical line (backslash-continuations already joined). A function so it
# can run both inside the read loop AND for a final pending line at EOF (a script
# ending in `git checkout -f \` with no trailing newline still executes, so it must
# be scanned). Uses the file-scoped `f`.
scan_logical() {  # <logical-line> <start-lineno>
  local line="$1" start="$2" trimmed matched pat has_wt has_staged
  # Skip full-comment logical lines (first non-whitespace char is '#').
  [ -z "$line" ] && return 0
  trimmed=${line#"${line%%[![:space:]]*}"}
  [ "${trimmed:0:1}" = "#" ] && return 0

  matched=""
  for pat in "${ci_patterns[@]}"; do
    hit ci "$pat" "$line"
    if [ "$hit_rc" -eq 0 ]; then matched="yes"; break; fi
  done
  if [ -z "$matched" ]; then
    for pat in "${cs_patterns[@]}"; do
      hit cs "$pat" "$line"
      if [ "$hit_rc" -eq 0 ]; then matched="yes"; break; fi
    done
  fi
  # `git restore` that touches the WORKTREE discards unstaged edits. Long-form modes
  # decide safety unambiguously (short -S/-W vs -s/--source differ only by case):
  # `--worktree` present -> destroyer; else `--staged` present -> safe (unstage only);
  # else (default or short-flag form) -> conservatively a destroyer.
  if [ -z "$matched" ]; then
    hit ci 'git[[:space:]]+([^|;&]*[[:space:]])?restore([[:space:]]|$)' "$line"
    if [ "$hit_rc" -eq 0 ]; then
      hit ci 'restore[^|;&]*--worktree' "$line"; has_wt=$hit_rc
      hit ci 'restore[^|;&]*--staged'   "$line"; has_staged=$hit_rc
      if [ "$has_wt" -eq 0 ]; then matched="yes"
      elif [ "$has_staged" -eq 0 ]; then :
      else matched="yes"; fi
    fi
  fi
  [ -n "$matched" ] || return 0

  # A `# fleet-git-safe: <reason>` marker waives the line, but only as a genuine
  # clean trailing shell comment (see marker_re). Fail-closed grep here too.
  hit cs "$marker_re"'$' "$line"
  [ "$hit_rc" -eq 0 ] && return 0
  report "$f" "$start" "$line"
}

# SC2094: the inner loop only READS "$f"; report writes to stderr and hit writes to
# the distinct "$scan_tmp", never to "$f", so the read/write-same-file warning is a
# false positive. The directive sits in front of the whole compound `for` command.
# shellcheck disable=SC2094
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  physno=0        # physical line number just read
  start=0         # starting physical line number of the current logical line
  logical=""      # accumulated logical line (backslash-continuations joined)
  pending="no"    # are we mid-continuation?
  while IFS= read -r line || [ -n "$line" ]; do
    physno=$((physno + 1))
    if [ "$pending" = "no" ]; then start=$physno; logical=""; fi
    # A trailing backslash continues the command onto the next physical line;
    # join them so a destroyer split as `git checkout \<NL>-f main` is caught.
    if [ "${line%\\}" != "$line" ]; then
      logical="$logical${line%\\} "
      pending="yes"
      continue
    fi
    logical="$logical$line"
    pending="no"
    scan_logical "$logical" "$start"
  done < "$f"
  # Flush a final line left mid-continuation at EOF (unterminated `... \`): the
  # shell still runs it, so it must be scanned rather than silently dropped.
  [ "$pending" = "yes" ] && scan_logical "$logical" "$start"
done

if [ "$violations" -gt 0 ]; then
  echo "" >&2
  echo "lint_fleet_git_safety: $violations destroyer(s) in committed scripts (see above)." >&2
  echo "Fleet automation must NOT run git checkout -f/-B/-- <path>, git switch -f/--discard-changes/-C, git restore <worktree>, reset --hard, clean -fd, or git stash" >&2  # fleet-git-safe: help text listing the banned verbs, not an invocation
  echo "against a checkout it does not own. Use scripts/fleet_mutate.sh (worktree isolation)." >&2
  echo "If a use is provably safe (e.g. a throwaway worktree you just created), annotate the" >&2
  echo "line with a justified marker:  # fleet-git-safe: <reason>" >&2
  exit 1
fi

echo "lint_fleet_git_safety: ${#files[@]} script(s) scanned, no destroyers. OK."
exit 0
