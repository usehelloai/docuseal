# docuseal Makefile
#
# Provides the `validate` target the AI remediation loop local gate expects.
# scripts/ai_preflight.sh runs `make validate` before every push and stamps
# .claude/cache/ai_preflight_ok on success; .githooks/pre-push blocks a push
# whose commit was not stamped. These commands mirror this repo's required CI
# lint checks (.github/workflows/ci.yml: Rubocop, Erblint) so the local gate and
# CI agree. The authoritative gate is the PR's required checks; this target is
# the fast local pre-push convenience. It touches no runtime code and is inert
# until a developer opts in via `git config core.hooksPath .githooks`. Requires
# the Ruby toolchain (bundle install).
.PHONY: validate

validate:
	bundle exec rubocop
	bundle exec erb_lint ./app
