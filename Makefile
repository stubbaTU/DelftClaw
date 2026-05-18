# DelftClaw operator targets.
#
# Edit VPS_HOST / VPS_USER below, then on your laptop:
#
#     make deploy                  # rsync repo to VPS + run setup_vps.sh
#     make scenario NAME=seek_cc   # launch a scenario on the VPS
#     make scenarios               # list scenarios + their agents on the VPS
#     make watch    NAME=seek_cc   # tail the full journal (every line)
#     make watch-ipv8 NAME=seek_cc # tail only IPv8 wire events + errors
#     make trace    NAME=seek_cc   # one-shot snapshot per agent
#     make stop     NAME=seek_cc   # stop a scenario
#     make ssh                     # interactive shell on the VPS
#     make test                    # run the local pytest suite
#
# Override any default from the command line:
#
#     make deploy VPS_HOST=other.example.com

VPS_HOST  ?= srv1665973.hstgr.cloud
VPS_USER  ?= root
VPS_ROOT  ?= /opt/delftclaw
MCP_PORT  ?= 8765
NAME      ?=

REPO_ROOT := $(shell pwd)
SSH       := ssh -o StrictHostKeyChecking=accept-new $(VPS_USER)@$(VPS_HOST)
RSYNC_EXC := --exclude=venv --exclude=.git --exclude=__pycache__ \
             --exclude=.pytest_cache --exclude='*.pyc' --exclude='*.pem' \
             --exclude='*.key' --exclude='ec*.pem' --exclude=.venv

.PHONY: help deploy push bootstrap scenario scenarios watch watch-ipv8 trace stop \
        community-demo community-demo-real community-demo-stop ssh test clean check-name

help:
	@awk 'BEGIN {FS=":.*?## "} /^[a-zA-Z_-]+:.*## / { printf "  %-14s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# Repo deployment
# ---------------------------------------------------------------------------

deploy: push bootstrap ## Push repo + run setup_vps.sh on the VPS (idempotent)

push: ## rsync the repo to the VPS, skipping venv/git/caches
	rsync -av --delete-after $(RSYNC_EXC) ./ $(VPS_USER)@$(VPS_HOST):$(VPS_ROOT)/

bootstrap: ## Run setup_vps.sh on the VPS as root
	$(SSH) "bash $(VPS_ROOT)/deploy/setup_vps.sh"

# ---------------------------------------------------------------------------
# Scenario orchestration
# ---------------------------------------------------------------------------

check-name:
	@if [ -z "$(NAME)" ]; then \
		echo "set NAME=<scenario>. example: make scenario NAME=seek_cc"; \
		exit 1; \
	fi

scenario: push check-name ## Start scenario NAME on the VPS
	$(SSH) "cd $(VPS_ROOT) && PYTHONPATH=$(VPS_ROOT) \
		$(VPS_ROOT)/venv/bin/python -m deploy.scenario_boot $(NAME)"

scenarios: ## List active scenarios + agents on the VPS
	$(SSH) "systemctl list-units 'delftclaw-mcp@*.service' --no-pager; \
		echo; \
		systemctl list-units 'delftclaw-watchdog@*.service' --no-pager"

watch: check-name ## Tail the full journal (every line — Ctrl-C to stop)
	$(SSH) "journalctl --no-pager -f \
		-u 'delftclaw-mcp@$(NAME)-*.service' \
		-u 'delftclaw-watchdog@$(NAME)-*.service'"

watch-ipv8: check-name ## Tail only IPv8 wire events + errors (filtered)
	$(SSH) "journalctl --no-pager -f \
		-u 'delftclaw-mcp@$(NAME)-*.service' \
		-u 'delftclaw-watchdog@$(NAME)-*.service' \
		| grep --line-buffered -E \
		  'IPv8|delftclaw\\.|TOOL |turn |openclaw|ERROR|WARN|FAIL|Traceback' \
		| grep --line-buffered -vE \
		  'GET /head|GET /entries|GET /entry/'"

trace: check-name ## Snapshot per-agent demo state (turns, tools, IPv8 events, community)
	$(SSH) "PYTHONPATH=$(VPS_ROOT) $(VPS_ROOT)/venv/bin/python -m deploy.trace $(NAME)"

stop: check-name ## Stop scenario NAME + teardown its env files
	$(SSH) "cd $(VPS_ROOT) && PYTHONPATH=$(VPS_ROOT) \
		$(VPS_ROOT)/venv/bin/python -m deploy.scenario_boot $(NAME) --teardown"

community-demo: push ## Run the direct community demo checklist on the VPS
	$(SSH) "cd $(VPS_ROOT) && PYTHONPATH=$(VPS_ROOT) \
		$(VPS_ROOT)/venv/bin/python -m deploy.community_demo \
		--provider mock --root /var/lib/delftclaw/community_demo --reset"

community-demo-real: push ## Start the real-agent community_demo scenario on the VPS
	$(SSH) "cd $(VPS_ROOT) && PYTHONPATH=$(VPS_ROOT) \
		$(VPS_ROOT)/venv/bin/python -m deploy.community_demo --real-agents"

community-demo-stop: ## Stop the real-agent community_demo scenario on the VPS
	$(SSH) "cd $(VPS_ROOT) && PYTHONPATH=$(VPS_ROOT) \
		$(VPS_ROOT)/venv/bin/python -m deploy.community_demo --stop-real-agents"

# ---------------------------------------------------------------------------
# Operator extras
# ---------------------------------------------------------------------------

ssh: ## Interactive shell on the VPS
	$(SSH)

test: ## Run the local pytest suite
	venv/bin/python -m pytest \
		tests/test_protocol_compiler.py tests/test_overlay_registry.py \
		tests/test_content_community.py tests/test_bittorrent.py \
		tests/test_agent_runtime.py tests/test_agent_mcp.py \
		tests/test_stop_predicates.py tests/test_scenario_manifest.py \
		tests/test_watchdog_turn_builder.py \
		test_signed_log.py test_signed_verify.py test_peer_log.py \
		-q

clean: ## Remove __pycache__ + .pytest_cache locally
	find . -type d -name '__pycache__' -not -path './venv/*' -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache
