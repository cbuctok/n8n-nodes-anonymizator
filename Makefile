# Thin wrappers for agents and humans. The npm scripts in package.json stay the source of truth.

.DEFAULT_GOAL := help
QUIET_LOG ?= $(or $(TMPDIR),/tmp)/n8n-nodes-anonymizator-quiet.log

.PHONY: help test-quiet check-quiet
help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed -E 's/^([a-z-]+):.*## /  \1\t/'

test-quiet: ## npm test (build + unit tests), print only the summary; full log on failure
	@npm test >$(QUIET_LOG) 2>&1 \
		&& { grep -E '^# (tests|pass|fail|skipped|todo|cancelled)|^ℹ (tests|pass|fail|skipped|todo|cancelled)' $(QUIET_LOG) || echo "npm test: ok"; } \
		|| { tail -n 80 $(QUIET_LOG); echo "npm test FAILED (full log: $(QUIET_LOG))"; exit 1; }

# npm test already runs the build, so check-quiet does not build twice.
check-quiet: ## lint, build and unit tests, quiet unless something fails
	@npm run lint >$(QUIET_LOG) 2>&1 && echo "lint: ok" \
		|| { tail -n 60 $(QUIET_LOG); echo "lint FAILED (full log: $(QUIET_LOG))"; exit 1; }
	@$(MAKE) --no-print-directory test-quiet

# --- shared git helpers (infra/scripts/git) ---
GIT_SCRIPTS ?= $(shell cd "$$(git rev-parse --path-format=absolute --git-common-dir)/../.." && pwd)/infra/scripts/git
.PHONY: land prune-merged whereami
land: ## land BR=<branch> [DRY=1]: --no-ff into integration, promote, sync local, delete branch
	@test -n "$(BR)" || { echo "usage: make land BR=<branch> [DRY=1]"; exit 2; }
	@$(GIT_SCRIPTS)/land.sh $(BR) $(if $(DRY),--dry-run)
prune-merged: ## remove merged worktrees/branches [APPLY=1]
	@$(GIT_SCRIPTS)/prune-merged.sh $(if $(APPLY),--apply)
whereami: ## branch, worktree, status, recent commits
	@$(GIT_SCRIPTS)/whereami.sh
