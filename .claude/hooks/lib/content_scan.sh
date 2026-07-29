#!/usr/bin/env bash
# Shared banned-content / secret detection library for the local PreToolUse gate.
#
# SINGLE SOURCE OF TRUTH. Both entry hooks source this file and call its
# detectors, so every pattern applies uniformly to every write vector by
# construction:
#   .claude/hooks/scan_banned_content.sh  (Edit | MultiEdit | Write)
#   .claude/hooks/scan_bash_content.sh    (Bash redirect | tee | heredoc | interpreter)
#
# WHY THIS EXISTS: the two entry hooks previously maintained SEPARATE copies of
# the secret/em-dash regexes. Every pattern added to one had to be hand-mirrored
# to the other, and the copies drifted (e.g. the Dockerfile space-form ENV/ARG
# detector reached scan_banned_content.sh but not scan_bash_content.sh, so a
# `echo 'ENV API_KEY <value>' > Dockerfile` slipped the Bash vector -- Codex #30).
# Centralising the detectors here makes that class of divergence impossible.
#
# This file is SOURCED, never executed; it defines functions and sets no traps,
# `set` flags, or global side effects. The sourcing hook owns process options
# and the deny()/exit contract.
#
# CONTRACT: each detector is a predicate returning 0 (match / banned) or 1 (no
# match). Detectors read their single argument ($1 = text to scan) and print
# nothing. The two PUBLIC entrypoints map a detector hit to a human-readable
# reason string on stdout and return 0; callers turn that into a PreToolUse deny.
#
#   scan_content "<content>" "<file_path>"
#     For Edit|MultiEdit|Write: applies confidence tiering keyed off file_path
#     (doc-only paths skip secret tiers; *.env.example/.sample skip only the
#     low-confidence heuristic). Em dash + HIGH + (conditionally) LOW detectors.
#
#   scan_command "<command>"
#     For Bash: no single target path is known and the command text can write
#     ANY file type, so NO tiering is applied -- every detector runs. This is
#     deliberately the strictest reading: a long secret literal or Dockerfile
#     space-form assignment anywhere in a file-writing command is denied.
#
# Both print a reason and return 0 on the FIRST detector hit; return 1 (and
# print nothing) when the text is clean.

# --- Individual detectors (predicates: 0 = banned, 1 = clean) ----------------
# Every write vector runs the SAME functions below; add a new pattern here once.
#
# WHY HERESTRINGS, NOT `printf | grep`: the sourcing hooks run with `set -o
# pipefail`. With `printf '%s' "$1" | grep -q PAT`, when PAT matches near the
# START of a large input, `grep -q` exits immediately on the first hit; `printf`
# is then killed by SIGPIPE (exit 141) and, under pipefail, the PIPELINE status
# becomes 141 (failure) even though grep matched. The predicate would return
# nonzero ("clean") and a real secret would slip the gate (Codex P2: a 200KB
# proposed file with a secret on line 1 was allowed). Feeding grep from a
# herestring removes the upstream process entirely, so there is no SIGPIPE and
# the predicate reflects grep's true match status. `grep -q` still exits early
# (fast) without any pipeline-status hazard.

# U+2014 em dash (engineering convention bans em dashes).
cs_has_emdash() {
  grep -qF -- "$(printf '\xe2\x80\x94')" <<<"$1"
}

# PEM private key block (HIGH confidence: real-credential shape).
cs_has_pem_private_key() {
  grep -qE -- '-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----' <<<"$1"
}

# AWS access key id, long-lived (AKIA) or temporary (ASIA) (HIGH confidence).
cs_has_aws_access_key() {
  grep -qE -- '\b(AKIA|ASIA)[0-9A-Z]{16}\b' <<<"$1"
}

# Generic secret assignment with a long literal value via `:`/`=` (LOW
# confidence heuristic). The optional quote BEFORE the delimiter catches
# JSON/YAML quoted keys, e.g. `"api_key": "..."`.
cs_has_keyvalue_secret() {
  grep -qiE -- \
    '(secret|password|passwd|api[_-]?key|token|private[_-]?key)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9/+_-]{24,}' \
    <<<"$1"
}

# Dockerfile space-form ENV/ARG secret assignment: `ENV API_KEY <value>` /
# `ARG SECRET <value>` use whitespace (no `:`/`=`), so cs_has_keyvalue_secret
# never sees a delimiter and misses them. Match the instruction keyword, a
# secret-ish key, then a long literal value.
#
# The leading boundary `(^|[[:space:];&|'"\`])` lets the ENV/ARG keyword sit at
# the start of a physical Dockerfile line (the Edit|Write vector) OR be embedded
# in a Bash command that emits that line (the Bash vector), e.g.
# `echo 'ENV API_KEY <value>' > Dockerfile`, where the keyword is preceded by a
# quote/space. Without this, the space-form detector matched the direct write
# vector but NOT the Bash write vector -- the exact divergence Codex #30 flagged.
cs_has_dockerfile_spaceform_secret() {
  # Leading boundary class includes whitespace, shell operators (; & |), and
  # both quote chars + backtick, assembled via printf so the single/double quote
  # and backtick survive shell quoting cleanly. `_re` is a POSIX ERE.
  local boundary re
  boundary=$(printf '[[:space:];&|`%s%s]' "'" '"')   # [ \t;&|`'"]
  re="(^|${boundary})(ENV|ARG)[[:space:]]+[A-Za-z0-9_]*(secret|password|passwd|api[_-]?key|token|private[_-]?key)[A-Za-z0-9_]*[[:space:]]+[\"'\`]?[A-Za-z0-9/+_-]{24,}"
  grep -qiE -- "$re" <<<"$1"
}

# --- Public entrypoint: content (Edit | MultiEdit | Write) --------------------
# $1 = content to scan, $2 = file_path (used only for confidence tiering).
# Prints a reason and returns 0 on the first hit; returns 1 when clean.
scan_content() {
  local content="$1" file_path="$2"
  local doc_only=0 example_env=0

  # Em dash applies to every in-scope file regardless of tier.
  if cs_has_emdash "$content"; then
    printf '%s' "Em dash (U+2014) found in proposed content. Engineering convention bans em dashes; use a colon, comma, or parentheses instead."
    return 0
  fi

  # Confidence tiering keyed off the target path:
  #   doc_only  -> skip BOTH secret tiers (prose quotes secret formats as examples).
  #   example   -> run HIGH tier, skip LOW tier (placeholders allowed, real creds not).
  #   otherwise -> run BOTH tiers.
  case "$file_path" in
    *.md|*.mdx|*.txt) doc_only=1 ;;
    *.env.example|*.env.sample) example_env=1 ;;
  esac

  if [ "$doc_only" = "1" ]; then
    return 1
  fi

  # ---- HIGH-confidence detectors (run even on .env.example/.sample) ----
  if cs_has_pem_private_key "$content"; then
    printf '%s' "Plaintext PRIVATE KEY block found in proposed content. Never commit private keys (Identity RS256 signing keys live in env/KMS/Secrets Manager). Reference them via environment configuration."
    return 0
  fi
  if cs_has_aws_access_key "$content"; then
    printf '%s' "AWS access key id found in proposed content. Do not commit AWS credentials; use environment / IAM roles / Secrets Manager."
    return 0
  fi

  # ---- LOW-confidence heuristics (suppressed for example/sample env files) ----
  if [ "$example_env" != "1" ]; then
    if cs_has_keyvalue_secret "$content"; then
      printf '%s' "Possible hardcoded secret (long literal assigned to a secret/password/api_key/token field) found in proposed content. Move it to environment configuration. If this is a false positive (e.g. a placeholder or test fixture), make the value an obvious placeholder."
      return 0
    fi
    if cs_has_dockerfile_spaceform_secret "$content"; then
      printf '%s' "Dockerfile space-form secret assignment (ENV/ARG <KEY> <value>) found in proposed content. Do not bake secrets into image layers; pass them at runtime via env/secrets. If this is a placeholder, shorten it to an obvious placeholder."
      return 0
    fi
  fi

  return 1
}

# --- Public entrypoint: command (Bash) ---------------------------------------
# $1 = the Bash command string. No target path is known and the command can
# write any file type, so NO confidence tiering is applied: every detector runs.
# Prints a reason and returns 0 on the first hit; returns 1 when clean.
scan_command() {
  local command="$1"

  if cs_has_emdash "$command"; then
    printf '%s' "Em dash (U+2014) found in a Bash command that writes file content. Engineering convention bans em dashes; use a colon, comma, or parentheses instead."
    return 0
  fi
  if cs_has_pem_private_key "$command"; then
    printf '%s' "Plaintext PRIVATE KEY block found in a Bash command that writes file content. Never commit private keys; reference them via environment configuration (env/KMS/Secrets Manager)."
    return 0
  fi
  if cs_has_aws_access_key "$command"; then
    printf '%s' "AWS access key id found in a Bash command that writes file content. Do not commit AWS credentials; use environment / IAM roles / Secrets Manager."
    return 0
  fi
  if cs_has_keyvalue_secret "$command"; then
    printf '%s' "Possible hardcoded secret (long literal assigned to a secret/password/api_key/token field) found in a Bash command that writes file content. Move it to environment configuration; if it is a placeholder/test fixture, make the value an obvious placeholder."
    return 0
  fi
  if cs_has_dockerfile_spaceform_secret "$command"; then
    printf '%s' "Dockerfile space-form secret assignment (ENV/ARG <KEY> <value>) found in a Bash command that writes file content. Do not bake secrets into image layers; pass them at runtime via env/secrets. If this is a placeholder, shorten it to an obvious placeholder."
    return 0
  fi

  return 1
}
