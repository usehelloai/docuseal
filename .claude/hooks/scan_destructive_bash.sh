#!/usr/bin/env bash
# PreToolUse(Bash): block dangerous shell commands that go beyond simple exact-match
# deny patterns. Catches common destructive operations (force-push, hard reset, db
# drops, mass deletes) before execution.
#
# Deny schema: matches the CURRENT Claude Code PreToolUse contract: stdout JSON
# with `hookSpecificOutput.permissionDecision: "deny"` + `permissionDecisionReason`,
# exit 0. The legacy top-level `decision`/`message` shape is DEPRECATED for
# PreToolUse (Claude Code ignores it and runs the command anyway), so it must not
# be used. Source: docs.claude.com/en/docs/claude-code/hooks.
#
# CI no-op: claude-code-action loads project hooks inside the autofix runner.
# A blocking PreToolUse hook there would block legitimate autofix Bash steps,
# so this hook exits 0 immediately under GITHUB_ACTIONS / CI, matching
# scan_banned_content.sh and scan_bash_content.sh. Local sessions get the gate.
set -euo pipefail

if [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${CI:-}" = "true" ]; then
  exit 0
fi

input=$(cat)
tool_name=$(echo "$input" | jq -r '.tool_name // empty')
command=$(echo "$input" | jq -r '.tool_input.command // empty')

if [ "$tool_name" != "Bash" ] || [ -z "$command" ]; then exit 0; fi

# Normalize Bash line continuations (`\` + newline) to a space so a command
# split across lines (`git \<NL>push --force ...`) is scanned as one command.
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

# Explicit operator override: allow destructive commands for this invocation.
# Checked BEFORE the scan so the block JSON is never emitted when the override
# is set. Previously the loop printed the {"decision":"block"} line FIRST and
# only then checked the override, so a set override still emitted the block on
# stdout and the command stayed blocked (the override was a no-op).
if [ "${HOOK_ALLOW_DESTRUCTIVE:-0}" = "1" ]; then exit 0; fi

# --- Working-tree / branch destroyers that need CASE-SENSITIVE matching, so they
# cannot live in the case-insensitive `dangerous_patterns` loop below. Incident
# 2026-07-26: a WSE fleet loop's `git checkout -f` force-discarded a live session's
# UNCOMMITTED edits in a primary checkout it did not own; git could not recover
# them (never staged). `git checkout -f/--force` overwrites the working tree;
# `git checkout -B` force-resets a branch. Both destroy uncommitted work.
#   WHY case-sensitive: `-B` (force-create/reset) must be distinguished from the
#   SAFE `-b` (create) -- and `-b` is the escape hatch the main-branch edit guard
#   relies on. Under `grep -i` the `-B` pattern would also match `-b` and wrongly
#   block every legitimate branch creation. So this block scans WITHOUT -i.
# The `([^|;&]*[[:space:]])?` before `checkout` also catches the `git -C <path>`
# form. Plain switches (`git checkout main`, `git checkout -b feat/x`) fall
# through untouched. `reset --hard` is already covered (case-insensitively) below.
checkout_destroyers=(
  # checkout `-f`/`--force`, including COMBINED short flags (`-qf`, `-fq`). The
  # combined `-[a-zA-Z]*f[a-zA-Z]*` alternative catches `-qf`; `--force` stays a
  # distinct alternative (the combined form's leading `-<alpha>` never matches `--force`).
  'git[[:space:]]+([^|;&]*[[:space:]])?checkout[[:space:]]+([^|;&]*[[:space:]])?(--force|-[a-zA-Z]*f[a-zA-Z]*)([[:space:]]|=|$)'
  # checkout `-B` force-reset, including COMBINED short flags (`-qB`, `-Bq`).
  'git[[:space:]]+([^|;&]*[[:space:]])?checkout[[:space:]]+([^|;&]*[[:space:]])?-[a-zA-Z]*B[a-zA-Z]*([[:space:]]|$)'
  # MODERN equivalents via `git switch`: `-f`/`--force`/`--discard-changes` throw
  # away local modifications (git-switch docs), and `-C`/`--force-create` reset a
  # branch. Same data-loss class as checkout -f/-B; safe `switch -c` (create) and a
  # plain `git switch <branch>` are NOT matched (case-sensitive `-C`, boundary `-f`).
  'git[[:space:]]+([^|;&]*[[:space:]])?switch[[:space:]]+([^|;&]*[[:space:]])?(--force|--discard-changes|-[a-zA-Z]*f[a-zA-Z]*)([[:space:]]|=|$)'
  'git[[:space:]]+([^|;&]*[[:space:]])?switch[[:space:]]+([^|;&]*[[:space:]])?(--force-create|-[a-zA-Z]*C[a-zA-Z]*)([[:space:]]|$)'
)
for pat in "${checkout_destroyers[@]}"; do
  # Case-SENSITIVE (no -i): lowercase `-b`/`-c` (safe create) must never match the
  # `-B`/`-C` force rules. Herestring, not `echo |`, for the pipefail/SIGPIPE reason.
  if grep -qE "$pat" <<<"$command"; then
    deny "Blocked: working-tree/branch destroyer (git checkout -f/--force/-B, or git switch -f/--force/--discard-changes/-C). These overwrite the working tree or force-reset a branch and CANNOT recover uncommitted work -- this class caused the 2026-07-26 fleet data-loss incident. Never run them against a checkout you do not own: mutate fleet repos in a throwaway detached worktree (see scripts/fleet_mutate.sh), commit before switching branches, and use 'git checkout -b' / 'git switch -c' (create), never '-B' / '-C' (force). Genuine human-authorized one-off: set HOOK_ALLOW_DESTRUCTIVE=1 for this invocation."
  fi
done

# --- Path-restore destroyers that discard UNSTAGED worktree edits: `git checkout
# -- <path>`, `git checkout .`, and worktree-restoring `git restore`. Same
# uncommitted-work-loss class as the policy already prohibits
# (parallel_session_policy.md). `git restore --staged <path>` (unstage only) stays
# allowed; `--worktree` or a default/short-form restore is denied. Case-insensitive
# is fine here (no -b/-B ambiguity); long-form modes decide restore safety.
path_restore=0
if grep -qiE 'git[[:space:]]+([^|;&]*[[:space:]])?checkout[[:space:]]+([^|;&]*[[:space:]])?(--[[:space:]]|\.([[:space:]]|$))' <<<"$command"; then
  path_restore=1
elif grep -qiE 'git[[:space:]]+([^|;&]*[[:space:]])?restore([[:space:]]|$)' <<<"$command"; then
  if grep -qiE 'restore[^|;&]*--worktree' <<<"$command"; then path_restore=1
  elif grep -qiE 'restore[^|;&]*--staged' <<<"$command"; then path_restore=0
  else path_restore=1; fi
fi
if [ "$path_restore" -eq 1 ]; then
  deny "Blocked: working-tree discard (git checkout -- <path>, git checkout ., or a worktree-restoring git restore). These throw away UNSTAGED edits and cannot recover them. Commit first, or operate in a throwaway worktree (scripts/fleet_mutate.sh). 'git restore --staged <path>' (unstage only) is allowed. Genuine human-authorized one-off: set HOOK_ALLOW_DESTRUCTIVE=1 for this invocation."
fi

dangerous_patterns=(
  # Force push: --force, --force-with-lease, short -f, or a leading-`+` refspec
  # (git-push docs: a refspec starting with `+` forces the update, equivalent to
  # --force for that ref). [^|;&]* bounds the match to a single command.
  'git[[:space:]]+([^|;&]*[[:space:]])?push[[:space:]]+([^|;&]*[[:space:]])?(--force(-with-lease)?|-[a-zA-Z]*f[a-zA-Z]*([[:space:]]|$))'
  # Leading-`+` refspec forces the update, equivalent to --force for that ref.
  # Match any `+<ref>` token: a bare name (`+main`), a `src:dst` pair, or a
  # slashed ref (`+refs/heads/main`). The `+` must start a whitespace-delimited
  # argument, so a legitimate `a+b` literal elsewhere does not trip it.
  'git[[:space:]]+([^|;&]*[[:space:]])?push[[:space:]]+[^|;&]*[[:space:]]["'"'"']?\+[A-Za-z0-9_./-]+([[:space:]]|$|:|["'"'"'])'
  # Mirror push: --mirror force-overwrites ALL refs on the remote (and deletes
  # remote refs absent locally). git-push docs: a destructive, history-rewriting
  # push mode.
  'git[[:space:]]+([^|;&]*[[:space:]])?push[[:space:]]+[^|;&]*--mirror'
  # Remote ref delete: `git push --delete` or a short `-d` (incl. combined like
  # `-vd`) removes a remote ref (git-push -h: `-d, --delete`).
  'git[[:space:]]+([^|;&]*[[:space:]])?push[[:space:]]+([^|;&]*[[:space:]])?(--delete([[:space:]]|=)|-[a-zA-Z]*d([[:space:]]|$))'
  # Empty-source delete refspec: `git push origin :main` (empty <src> deletes
  # <dst> on the remote, per git-push docs). Match a `:`-prefixed ref token that
  # starts a whitespace-delimited argument.
  'git[[:space:]]+([^|;&]*[[:space:]])?push[[:space:]]+[^|;&]*[[:space:]][\"'"'"']?:[A-Za-z0-9_./-]+([[:space:]]|$|[\"'"'"'])'
  # Prune push: `git push --prune ...` deletes remote refs with no local match.
  'git[[:space:]]+([^|;&]*[[:space:]])?push[[:space:]]+[^|;&]*--prune'
  # Any `git reset --hard` discards index + working-tree changes (git reset -h:
  # --hard resets HEAD, index, and worktree). Block all forms (--hard origin/...,
  # --hard HEAD~1, or a bare --hard), not just the origin/ rewind.
  'git[[:space:]]+([^|;&]*[[:space:]])?reset[[:space:]]+[^|;&]*--hard'
  # git clean that force-removes untracked DIRECTORIES needs both a force flag
  # (-f or --force) and -d, in any order, combined or split, adjacent or not
  # (CR #101: -fd/-df, plus split -f -d / -d -f / -d -x -f / --force -d). The
  # [^|;&]* bounds each match to a single command (no crossing ; | &&).
  'git[[:space:]]+([^|;&]*[[:space:]])?clean[[:space:]]+[^|;&]*-[a-zA-Z]*(f[a-zA-Z]*d|d[a-zA-Z]*f)'
  'git[[:space:]]+([^|;&]*[[:space:]])?clean[[:space:]]+[^|;&]*(--force|-[a-zA-Z]*f[a-zA-Z]*)[[:space:]][^|;&]*-[a-zA-Z]*d'
  'git[[:space:]]+([^|;&]*[[:space:]])?clean[[:space:]]+[^|;&]*-[a-zA-Z]*d[a-zA-Z]*[[:space:]][^|;&]*(--force|-[a-zA-Z]*f[a-zA-Z]*)'
  # Forced local branch delete of a protected branch. Covers the combined `-D`,
  # AND a split lowercase delete + force in either order/spelling: `-d -f`,
  # `-f -d`, `--delete -f`, `-d --force`, `--delete --force`, `--force --delete`.
  # Optional global options before `branch`; release and release/* included.
  # The protected branch may appear as ANY operand (`git branch -D feature main`),
  # so match it anywhere after the delete flags within the single command.
  'git[[:space:]]+([^|;&]*[[:space:]])?branch[[:space:]]+([^|;&]*[[:space:]])?-[a-zA-Z]*D[[:space:]][^|;&]*[[:space:]]["'"'"']?(main|master|production|release)([[:space:]]|/|$|["'"'"'])'
  'git[[:space:]]+([^|;&]*[[:space:]])?branch[[:space:]]+([^|;&]*[[:space:]])?-[a-zA-Z]*D[[:space:]]+["'"'"']?(main|master|production|release)([[:space:]]|/|$|["'"'"'])'
  'git[[:space:]]+([^|;&]*[[:space:]])?branch[[:space:]]+[^|;&]*(-[a-zA-Z]*d|--delete)[^|;&]*(-[a-zA-Z]*f|--force)[^|;&]*[[:space:]]["'"'"']?(main|master|production|release)([[:space:]]|/|$|["'"'"'])'
  'git[[:space:]]+([^|;&]*[[:space:]])?branch[[:space:]]+[^|;&]*(-[a-zA-Z]*f|--force)[^|;&]*(-[a-zA-Z]*d|--delete)[^|;&]*[[:space:]]["'"'"']?(main|master|production|release)([[:space:]]|/|$|["'"'"'])'
  # Combined short delete+force in ONE flag token: `git branch -df main` /
  # `-fd main` (and with other letters interspersed). Both d and f in one -... run.
  'git[[:space:]]+([^|;&]*[[:space:]])?branch[[:space:]]+([^|;&]*[[:space:]])?-[a-zA-Z]*(df|fd)[a-zA-Z]*[[:space:]][^|;&]*[[:space:]]?["'"'"']?(main|master|production|release)([[:space:]]|/|$|["'"'"'])'
  # Force-update / force-create of a protected local branch ref:
  # `git branch -f main HEAD~1` rewrites where the branch points (and -M/--move
  # renames over it). Distinct from -D (delete) above.
  'git[[:space:]]+([^|;&]*[[:space:]])?branch[[:space:]]+([^|;&]*[[:space:]])?(-[a-zA-Z]*[fM]|--force|--move)[[:space:]]+([^|;&]*[[:space:]])?["'"'"']?(main|master|production|release)([[:space:]]|/|$|["'"'"'])'
  'alembic[[:space:]]+downgrade'
  'dropdb[[:space:]]'
  # SQL drops/truncate are case-insensitive (psql -c 'drop table users'); the
  # final grep runs with -i so these match both DROP TABLE and drop table.
  'DROP[[:space:]]+(TABLE|DATABASE|SCHEMA)'
  # TRUNCATE TABLE <name> (explicit keyword, unambiguous), OR the keyword-less
  # SQL form `TRUNCATE <ident> ;` terminated by a semicolon. Requiring TABLE or a
  # trailing `;` keeps prose like `echo truncate the log` from tripping.
  'TRUNCATE[[:space:]]+TABLE[[:space:]]+[A-Za-z_]'
  'TRUNCATE[[:space:]]+[A-Za-z_][A-Za-z0-9_."]*[[:space:]]*;'
  # Recursive S3 object delete: the AWS CLI accepts --recursive before OR after
  # the URI, with optional global options before `s3`. ([^|;&]* stays in one cmd.)
  'aws[[:space:]]+([^|;&]*[[:space:]])?s3[[:space:]]+rm[[:space:]]+[^|;&]*--recursive'
  'aws[[:space:]]+([^|;&]*[[:space:]])?s3[[:space:]]+rm[[:space:]]+[^|;&]*s3://[^|;&]*--recursive'
  # Forced S3 bucket removal: `aws s3 rb --force s3://bucket` deletes the bucket
  # and all objects (flag before or after the URI).
  'aws[[:space:]]+([^|;&]*[[:space:]])?s3[[:space:]]+rb[[:space:]]+[^|;&]*--force'
  'aws[[:space:]]+([^|;&]*[[:space:]])?rds[[:space:]]+delete-db'
  # kubectl delete of a high-blast-radius resource. Flags may precede the
  # resource type (kubectl delete -n prod deployment x), so allow an optional
  # flag/arg run between `delete` and the type. Match the full names AND the
  # documented shortnames (ns=namespaces, pv, deploy/deployment, sts=statefulset).
  'kubectl[[:space:]]+([^|;&]*[[:space:]])?delete[[:space:]]+([^|;&]*[[:space:]])?(namespaces?|ns|pv|persistentvolumes?|deployments?|deploy|statefulsets?|sts)([[:space:]]|$|/)'
  # Terraform destroy in all documented forms: bare `terraform destroy`, a
  # global option before the subcommand (`terraform -chdir=infra destroy`), and
  # the apply-with-destroy plan (`terraform apply -destroy`).
  'terraform[[:space:]]+([^|;&]*[[:space:]])?destroy'
  'terraform[[:space:]]+([^|;&]*[[:space:]])?apply[[:space:]]+[^|;&]*-destroy'
  # Forced recursive rm: -f and -r are independent GNU short options, so any
  # combined/split ordering is destructive (-rf, -fr, -r -f, -f -r, -r -x -f).
  # Two patterns: a recursive-flag-group then a force-flag-group, or the reverse.
  # Each group matches the SHORT combined form (-rf, -fr, -r, -f) OR the GNU LONG
  # form (--recursive / --force), so mixed spellings (`rm -r --force /x`,
  # `rm --force -r /x`) are covered. An optional `--` terminator may precede the
  # target. Sensitive targets: an absolute / or ~/ or $HOME path, OR repo
  # metadata `.git` / `./.git` (a recursive delete of .git destroys history).
  '\brm[[:space:]]+([^|;&]*[[:space:]])?(--recursive|-[a-zA-Z]*r[a-zA-Z]*)[[:space:]]+([^|;&]*[[:space:]])?(--force|-[a-zA-Z]*f[a-zA-Z]*)[[:space:]]+([^|;&]*[[:space:]])?(--[[:space:]]+)?[\"'"'"']?(/|~([/[:space:]]|$|[\"'"'"'])|\$\{?HOME\}?|(\./)?\.git([/[:space:]]|$|[\"'"'"']))[^[:space:]]*'
  '\brm[[:space:]]+([^|;&]*[[:space:]])?(--force|-[a-zA-Z]*f[a-zA-Z]*)[[:space:]]+([^|;&]*[[:space:]])?(--recursive|-[a-zA-Z]*r[a-zA-Z]*)[[:space:]]+([^|;&]*[[:space:]])?(--[[:space:]]+)?[\"'"'"']?(/|~([/[:space:]]|$|[\"'"'"'])|\$\{?HOME\}?|(\./)?\.git([/[:space:]]|$|[\"'"'"']))[^[:space:]]*'
  # Short combined single-flag form (-rf / -fr) before a sensitive target.
  '\brm[[:space:]]+-[a-zA-Z]*(rf|fr)[a-zA-Z]*[[:space:]]+([^|;&]*[[:space:]])?(--[[:space:]]+)?[\"'"'"']?(/|~([/[:space:]]|$|[\"'"'"'])|\$\{?HOME\}?|(\./)?\.git([/[:space:]]|$|[\"'"'"']))[^[:space:]]*'
  # Force/recursive flag AFTER the sensitive target (GNU rm permits options after
  # operands): `rm -r /tmp/x -f`, `rm -f /tmp/x -r`. A recursive-or-force flag,
  # then a sensitive target operand, then the complementary flag later in the cmd.
  '\brm[[:space:]]+(--recursive|-[a-zA-Z]*r[a-zA-Z]*)[[:space:]]+[\"'"'"']?(/|~|\$\{?HOME\}?|(\./)?\.git([/[:space:]]|$))[^|;&]*[[:space:]](--force|-[a-zA-Z]*f[a-zA-Z]*)([[:space:]]|$)'
  '\brm[[:space:]]+(--force|-[a-zA-Z]*f[a-zA-Z]*)[[:space:]]+[\"'"'"']?(/|~|\$\{?HOME\}?|(\./)?\.git([/[:space:]]|$))[^|;&]*[[:space:]](--recursive|-[a-zA-Z]*r[a-zA-Z]*)([[:space:]]|$)'
  # curl|sh / wget|sh pipe-to-shell, with or without whitespace around the pipe
  # (`curl ... | bash`, `curl ...|sh`, `wget -qO- ... | sh` all run remote code).
  '\b(curl|wget)[[:space:]]+[^|;&]*\|[[:space:]]*(sudo([[:space:]]+-[^[:space:]]+([[:space:]]+[^-][^|;&[:space:]]*)?)*[[:space:]]+)?((/[^[:space:]]*/)?env([[:space:]]+[^[:space:]]+)*[[:space:]]+)?(/[^[:space:]]*/)?(bash|sh|zsh)\b'
  # Admin PR merge bypasses required reviews/checks (repo rule: no --admin merge
  # without per-PR owner approval). Allow gh/`pr` options anywhere before --admin
  # (`gh -R o/r pr merge 12 --admin`, `gh pr --repo o/r merge --admin`).
  'gh[[:space:]]+([^|;&]*[[:space:]])?pr[[:space:]]+([^|;&]*[[:space:]])?merge[[:space:]]+[^|;&]*--admin'
  # GitHub repo deletion is irreversible. Gate `gh repo delete ...` (with options
  # before the subcommand).
  'gh[[:space:]]+([^|;&]*[[:space:]])?repo[[:space:]]+([^|;&]*[[:space:]])?delete([[:space:]]|$)'
)

for pat in "${dangerous_patterns[@]}"; do
  # -i so lowercase SQL (drop table) and mixed-case flags match too. Command
  # names are lowercase, so case-insensitivity does not widen the command set.
  # Herestring (not `echo |`): under set -o pipefail a `grep -q` early-exit can
  # SIGPIPE the upstream `echo` and flip the pipeline status to failure, masking
  # a real match. Feeding grep from a herestring removes that hazard (Codex P2).
  if grep -qiE "$pat" <<<"$command"; then
    deny "Destructive command pattern matched: /$pat/. If this is intentional, ask the user to authorize explicitly (e.g., 'I authorize this destructive command') before re-running, or temporarily set HOOK_ALLOW_DESTRUCTIVE=1 in the environment."
  fi
done

exit 0
