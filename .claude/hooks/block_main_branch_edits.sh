#!/usr/bin/env bash
# PreToolUse(Edit|MultiEdit|Write|Bash): block direct writes on protected
# branches (main/master/production/release[/*]).
#
# Two vectors are covered:
#   Edit|MultiEdit|Write -> tool_input.file_path. Worktree-aware: the branch is
#     derived from the working tree that contains the target file, not from
#     CLAUDE_PROJECT_DIR, so an edit in a feature worktree launched from a
#     main checkout is allowed.
#   Bash                 -> tool_input.command. A Bash file-write (redirect,
#     heredoc, tee, sed -i, or an inline-code interpreter) on a protected
#     branch is the same protected-branch mutation and is blocked. Read-only
#     Bash (no write vector) is always allowed. Bash branch resolution uses
#     CLAUDE_PROJECT_DIR / cwd (no single target path to locate a worktree).
#
# Deny schema: the CURRENT Claude Code PreToolUse contract -- stdout JSON with
# hookSpecificOutput.permissionDecision: "deny" + permissionDecisionReason,
# exit 0. The legacy top-level {"decision":"block"} shape is DEPRECATED for
# PreToolUse (Claude Code ignores it and runs the tool anyway), so it must not
# be used. Source: docs.claude.com/en/docs/claude-code/hooks.
#
# Bypasses:
#   HOOK_ALLOW_DETACHED=1 lets the tool through when the resolved tree has a
#   detached HEAD.
#
# CI no-op: the AI autofix workflow checks out the PR head by SHA, so the working
# tree is DETACHED. Without this exit, every autofix Edit/Write would be denied
# (detached-HEAD branch) and autofix could never repair the PR. The scan hooks
# already no-op under GITHUB_ACTIONS / CI for the same reason; this guard does
# too. The authoritative protected-branch boundary remains the PR's required CI
# checks, not a local hook that the runner must be free to bypass.
set -euo pipefail

if [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${CI:-}" = "true" ]; then
  exit 0
fi

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

input=$(cat)
tool_name=$(printf '%s' "$input" | jq -r '.tool_name // empty')
file_path=$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty')
command=$(printf '%s' "$input" | jq -r '.tool_input.command // empty')
# Normalize Bash line continuations (`\` + newline) to a space.
command=$(printf '%s' "$command" | awk '{ while (sub(/\\$/,"")) { if ((getline nxt) > 0) $0 = $0 " " nxt; else break } print }')

# For a Bash tool call, only writes are in scope. A read-only command (grep,
# cat, ls) does not mutate the branch, so it is always allowed regardless of
# branch. Detect the same write vectors scan_bash_content.sh gates, plus the
# in-place editors (sed -i / perl -i) that rewrite a file without a redirect.
if [ "$tool_name" = "Bash" ]; then
  if [ -z "$command" ]; then exit 0; fi
  writes_file=0
  case "$command" in
    *'<<'*|tee\ *|*' tee '*|*$'\t''tee '*|*'|tee '*|*'|tee'*) writes_file=1 ;;
  esac
  # Output redirect into a target: `>`/`>>` (optionally fd-prefixed `1>`), the
  # combined forms `&>`/`>&`/`&>>`, and `>|`. A leading redirect is allowed. A
  # `&`/digit target is an fd dup (`2>&1`), not a file write. A redirect to a
  # /dev sink (`2>/dev/null`, `>/dev/stderr`) discards output rather than
  # writing repo content, so strip those before the match; otherwise every
  # read-only command that silences stderr counts as a write and gets denied
  # whenever an absolute argument resolves to a protected checkout.
  strip_dev_sinks() {
    sed -E 's#([0-9]?|&)>>?[[:space:]]*/dev/(null|stdout|stderr|tty)##g'
  }
  # A '>' INSIDE quoted argument text is data, not a redirect (`some-cli
  # --prompt '<task>do x</task>'` writes nothing), so replace each quoted span
  # with the placeholder Q before the redirect match. Backslash-escaped quotes
  # are dropped first so they cannot mispair the spans, and newlines are joined
  # so a span survives a multi-line argument. A quoted redirect TARGET
  # (`> "file name"`) stays detected: its '>' sits outside the quotes and Q is
  # a valid target token. The write-target path checks and the in-quote
  # interpreter/awk scans below still read the ORIGINAL command.
  unquoted=$(printf '%s' "$command" | tr '\n' ' ' \
    | sed -E "s/\\\\.//g; s/'[^']*'|\"[^\"]*\"/Q/g")
  redirect_probe=$(printf '%s' "$unquoted" | strip_dev_sinks)
  if printf '%s' "$redirect_probe" | grep -qE '(^|[^0-9&])[0-9]?>>?[[:space:]]*[^&[:space:]]'; then
    writes_file=1
  fi
  if printf '%s' "$redirect_probe" | grep -qE '(&>>?|>&|>\|)[[:space:]]*[^&0-9[:space:]]'; then
    writes_file=1
  fi
  # awk redirects to a file from INSIDE its quoted program (`awk '{print >
  # "f"}'`), which the quote strip above hides, so an awk invocation is
  # scanned on the original text (same over-block direction as before).
  if printf '%s' "$command" | grep -qE '(^|[[:space:]/;&|])[gnm]?awk[[:space:]]' \
     && printf '%s' "$command" | strip_dev_sinks | grep -qE '(^|[^0-9&])[0-9]?>>?[[:space:]]*[^&[:space:]]'; then
    writes_file=1
  fi
  # Downloaders: curl writes only with an output flag; wget writes a file BY
  # DEFAULT (to cwd or -P/--directory-prefix), so any wget fetch of a URL is a
  # write. Covers curl -o/-O/--output/--output-dir (incl. attached -oFILE).
  if printf '%s' "$command" | grep -qE '(^|[[:space:]/;&|])curl[[:space:]]+[^|;&]*(-o|-O|--output|--output-dir|--remote-name)'; then
    writes_file=1
  fi
  if printf '%s' "$command" | grep -qE '(^|[[:space:]/;&|])wget[[:space:]]'; then
    writes_file=1
  fi
  # find ... -delete / -exec rm removes files; xargs runs a (possibly writing)
  # command over piped args (`printf f | xargs touch`).
  if printf '%s' "$command" | grep -qE '(^|[[:space:]/;&|])find[[:space:]]+[^|;&]*(-delete|-exec[[:space:]]+(rm|cp|mv|truncate|tee))'; then
    writes_file=1
  fi
  if printf '%s' "$command" | grep -qE '[|][[:space:]]*xargs[[:space:]]+([^|;&]*[[:space:]])?(cp|mv|touch|mkdir|install|ln|rm|truncate|tee|sed|chmod|chown|dd|rsync)([[:space:]]|$)'; then
    writes_file=1
  fi
  # In-place editors: sed -i / perl -i (short, incl. backup suffix) or the long
  # forms sed --in-place / perl -i with --inplace-equivalent spellings.
  if printf '%s' "$command" | grep -qE '(^|[[:space:]/;&|])(sed|perl)[[:space:]]+([^|;&]*[[:space:]])?(-[A-Za-z]*i|--in-?place)'; then
    writes_file=1
  fi
  # truncate resizes/creates a file (truncate -s 0 README.md).
  if printf '%s' "$command" | grep -qE '(^|[[:space:]/;&|])truncate[[:space:]]'; then
    writes_file=1
  fi
  # dd writes to its of= target without a shell redirect.
  if printf '%s' "$command" | grep -qE '(^|[[:space:]])dd[[:space:]]+([^|;&]*[[:space:]])?of='; then
    writes_file=1
  fi
  # File-creating/copying/moving/removing commands that mutate the worktree
  # without a redirect: cp, mv, touch, mkdir, install, ln, rm, rsync. On a
  # protected branch these create, overwrite, or delete tracked content.
  if printf '%s' "$command" | grep -qE '(^|[[:space:]/;&|])(cp|mv|touch|mkdir|install|ln|rm|rsync|chmod|chown)[[:space:]]'; then
    writes_file=1
  fi
  # Archive extraction writes files into the worktree: tar -x..., unzip.
  if printf '%s' "$command" | grep -qE '(^|[[:space:]/;&|])(tar[[:space:]]+[^|;&]*-[A-Za-z]*x|unzip[[:space:]])'; then
    writes_file=1
  fi
  # Patch application / Git operations that rewrite the worktree in place:
  # git apply / am, patch, git checkout -- / restore (revert worktree), git clone
  # (writes a new tree), and the change-applying ops merge / cherry-pick / revert
  # / stash pop|apply / rebase / pull. On a protected branch these are direct
  # mutations of tracked content.
  # EXCEPTION: non-force branch CREATION (git checkout -b, git switch -c /
  # --create) is the sanctioned exit from a protected branch (the deny message
  # itself recommends it) and rewrites no tracked content, so strip those
  # invocations (up to the next |;& separator) before the match; any other
  # write in the same command still trips the remaining patterns. The force
  # forms (-B / -C) can move an existing branch pointer and stay blocked.
  git_write_probe=$(printf '%s' "$command" | sed -E 's/(^|[[:space:];&|])git[[:space:]]+(checkout[[:space:]]+-b|switch[[:space:]]+(-c|--create))([[:space:]]+[^|;&]*)?/\1/g')
  if printf '%s' "$git_write_probe" | grep -qE '(^|[[:space:]/;&|])(patch[[:space:]]|git[[:space:]]+([^|;&]*[[:space:]])?(apply|am|clone|restore|merge|cherry-pick|revert|rebase|pull|commit|checkout|stash[[:space:]]+(pop|apply))([[:space:]]|$))'; then
    writes_file=1
  fi
  # Interpreter inline-code invocation that WRITES a file. An inline interpreter
  # is only treated as a write when its code also contains a write-like API, so a
  # read-only one-liner (`python -c 'print(1)'`) is NOT blocked. Write hints:
  # open(...,"w"/"a"/"x"), file write methods, fs.write*, File.write/open(...:w),
  # `> file` inside the code, shutil/os file mutators.
  if printf '%s' "$command" | grep -qE -- \
       '(^|[[:space:]/;&|])(python[0-9.]*|node|nodejs|deno|bun|perl|ruby|php|tclsh|lua|Rscript|osascript|bash|sh|zsh|ksh)([[:space:]]+-[A-Za-z]*)*[[:space:]]+(-[A-Za-z]*[ceEprn]|--eval|--exec)([[:space:]]|=|$)' \
     && printf '%s' "$command" | grep -qE -- \
       'open[^)]*,[[:space:]]*["'"'"'][waxr+]*[wax]|writeFileSync|appendFileSync|createWriteStream|\.write[[:space:]]*\(|File\.(write|open)|IO\.write|fs_write|os\.(remove|unlink|rmdir|replace|rename|mkdir|makedirs)|shutil\.(copy|move|rmtree)|[^&0-9]>>?[[:space:]]*[^&[:space:]]'; then
    writes_file=1
  fi
  if [ "$writes_file" != "1" ]; then exit 0; fi
  # Resolve the branch from the WRITE TARGET(S) when they are absolute paths: a
  # session launched from a feature worktree can still write into a protected
  # checkout by absolute path (`printf x > /repo-on-main/x`,
  # `cp /tmp/src /repo-on-main/x`). A command can carry several absolute tokens
  # (cp SOURCE DEST), so check EVERY absolute candidate: if ANY resolves to a
  # protected branch, deny. Quotes/separators are stripped per token. Always also
  # check the launch dir as a fallback candidate.
  check_dir() {
    local d="$1" t b
    while [ -n "$d" ] && [ "$d" != "/" ] && [ ! -d "$d" ]; do d=$(dirname "$d"); done
    t=$(git -C "$d" rev-parse --show-toplevel 2>/dev/null || true)
    [ -z "$t" ] && return 0
    b=$(git -C "$t" branch --show-current 2>/dev/null || true)
    if [ -z "$b" ]; then
      [ "${HOOK_ALLOW_DETACHED:-0}" = "1" ] && return 0
      deny "Detached HEAD detected for working tree '$t'. Check out a named branch before editing, or set HOOK_ALLOW_DETACHED=1 for legitimate detached-HEAD work."
    fi
    case "$b" in
      main|master|production|release|release/*)
        deny "Cannot write directly on protected branch '$b' (resolved from $t). Create a feature branch first: git checkout -b <branch-name>."
        ;;
    esac
  }
  # Check the launch dir (covers relative-path writes like `rm README.md` /
  # `cp /tmp/x README.md`, which land in the launch worktree) AND every absolute
  # write target in the command (covers a cross-worktree write by absolute path,
  # e.g. `cp /tmp/x /repo-on-main/README.md` from a feature launch dir). If ANY
  # resolves to a protected branch, deny. Checking both can over-block a
  # feat-target write made from a main launch dir, which is the safe direction
  # (a denied legit write is recoverable; a silent main mutation is not).
  launch="${CLAUDE_PROJECT_DIR:-$(pwd)}"
  # A leading `cd DIR && ...` / `cd DIR; ...` changes where RELATIVE writes land,
  # so relative writes resolve against DIR, not the launch dir. Use DIR as the
  # base for the relative-write check in that case; otherwise use the launch dir.
  # (Absolute and ../ traversal targets are checked explicitly below regardless.)
  reldir="$launch"
  cd_target=$(printf '%s' "$command" | sed -nE 's/^[[:space:]]*cd[[:space:]]+([^|;&]+)[[:space:]]*(&&|;|\|).*/\1/p' | sed -E 's/[[:space:]]+$//; s/^["'"'"']//; s/["'"'"']$//')
  if [ -n "$cd_target" ]; then
    case "$cd_target" in
      /*) reldir="$cd_target" ;;
      *)  reldir="$launch/$cd_target" ;;
    esac
  fi
  check_dir "$reldir"
  while IFS= read -r cand; do
    [ -z "$cand" ] && continue
    # Home-qualified case patterns below ("~/", '$HOME/', '${HOME}/') are MATCH
    # literals for the candidate text, not expansions, so SC2088 (tilde in
    # quotes) and SC2016 (no expansion in single quotes) are expected here.
    # shellcheck disable=SC2088,SC2016
    case "$cand" in
      # Absolute target: check the path itself (it may BE a directory, e.g.
      # `cp /tmp/x /repo-on-main/`) and its parent dir (for a file target).
      /*) check_dir "$cand"; check_dir "$(dirname "$cand")" ;;
      # Home-qualified targets (~/main/x, $HOME/main/x, ${HOME}/main/x) expand to
      # an absolute path under $HOME; resolve and check.
      "~/"*)        exp="$HOME/${cand#\~/}"; check_dir "$exp"; check_dir "$(dirname "$exp")" ;;
      '$HOME/'*)    exp="$HOME/${cand#\$HOME/}"; check_dir "$exp"; check_dir "$(dirname "$exp")" ;;
      '${HOME}/'*)  exp="$HOME/${cand#\$\{HOME\}/}"; check_dir "$exp"; check_dir "$(dirname "$exp")" ;;
      # Relative TRAVERSAL targets (containing ../) can escape the launch
      # worktree into a protected checkout (`cp /tmp/x ../main/README.md`).
      # Resolve them against the launch dir before checking.
      *../*) check_dir "$reldir/$cand"; check_dir "$(dirname "$reldir/$cand")" ;;
    esac
  done < <(
    {
      printf '%s' "$command" \
        | tr '[:blank:]' '\n' \
        | sed -E 's/^([0-9]?>>?|&>>?|>[&|]|of=|[\"'"'"'])//; s/[\"'"'"';|&]+$//' \
        | { grep -E '^(/|~/|\$\{?HOME\}?/|[^-].*\.\./|\.\./)' || true; }
      # Absolute paths embedded in quoted inline-interpreter literals
      # (`open("/repo-on-main/x")`): pull any quoted "/..."-style token.
      printf '%s\n' "$command" \
        | { grep -oE '["'"'"']/[^"'"'"']+["'"'"']' || true; } \
        | sed -E 's/^["'"'"']//; s/["'"'"']$//'
      # Directory-option values that carry an absolute path attached to the flag
      # (`--directory-prefix=/main`, `--output-dir=/main`, `--directory=/main`,
      # `-C/main`, `-P/main`, `--work-tree=/main`): the / is not a token start, so
      # pull it out explicitly.
      printf '%s\n' "$command" \
        | { grep -oE '(--directory-prefix=|--output-dir=|--directory=|--work-tree=|-C|-P|-o|-O)/[^[:space:]|;&]+' || true; } \
        | sed -E 's#^[^/]*/#/#'
    }
  )
  exit 0
elif [ -n "$file_path" ]; then
  dir=$(dirname "$file_path")
  # The file may not exist yet (new-file Write into a non-existent subdir).
  # Walk up to the first existing directory so git can resolve the worktree.
  # Without this, a Write to /repo-on-main/newdir/new.md would resolve to no
  # git tree and fall through to "allow", bypassing the protected-branch rule.
  while [ -n "$dir" ] && [ "$dir" != "/" ] && [ ! -d "$dir" ]; do
    dir=$(dirname "$dir")
  done
else
  dir="${CLAUDE_PROJECT_DIR:-$(pwd)}"
fi

top=$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null || true)

if [ -z "$top" ]; then
  exit 0
fi

branch=$(git -C "$top" branch --show-current 2>/dev/null || true)

if [ -z "$branch" ]; then
  if [ "${HOOK_ALLOW_DETACHED:-0}" = "1" ]; then
    exit 0
  fi
  deny "Detached HEAD detected for working tree '$top'. Check out a named branch before editing, or set HOOK_ALLOW_DETACHED=1 for legitimate detached-HEAD work."
fi

case "$branch" in
  main|master|production|release|release/*)
    deny "Cannot write directly on protected branch '$branch' (resolved from $top). Create a feature branch first: git checkout -b <branch-name>."
    ;;
esac

exit 0
