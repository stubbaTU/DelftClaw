# DelftClaw operator targets.
#
# Edit VPS_HOST / VPS_USER below, then on your laptop:
#
#     make deploy                  # rsync repo to VPS + run setup_vps.sh
#     make scenario NAME=seek_cc   # launch a scenario on the VPS
#     make scenarios               # list scenarios + their agents on the VPS
#     make watch    NAME=seek_cc   # tail the full journal (every line)
#     make watch-ipv8 NAME=seek_cc # tail only IPv8 wire events + errors
#     make tools    NAME=seek_cc   # tail only TOOL audit lines (one per agent tool call)
#     make tail-turns NAME=seek_cc # turn-summary tail: lock acquire/release + TOOL + IPv8
#     make tools-summary NAME=seek_cc  # one-shot histogram: TOOL counts per agent + per name
#     make trace    NAME=seek_cc   # one-shot snapshot per agent
#     make stop     NAME=seek_cc   # stop a scenario
#     make demo     NAME=seek_cc   # one-shot: deploy + llm-up + stop + scenario
#     make llm-up                  # install/start LLM proxy on the VPS
#     make llm-down                # stop the LLM proxy
#     make llm-logs                # tail the LLM proxy journal
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

.PHONY: help deploy push bootstrap reinstall-units scenario scenarios watch watch-ipv8 \
        tools tail-turns tools-summary trace stop \
        demo llm-up llm-down llm-logs \
        ssh test clean check-name sq3-containment-official sq3-containment-preflight

help:
	@awk 'BEGIN {FS=":.*?## "} /^[a-zA-Z0-9_-]+:.*## / { printf "  %-15s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# Repo deployment
# ---------------------------------------------------------------------------

deploy: push bootstrap ## Push repo + run setup_vps.sh on the VPS (idempotent)

push: ## rsync the repo to the VPS, skipping venv/git/caches
	rsync -av --delete-after $(RSYNC_EXC) ./ $(VPS_USER)@$(VPS_HOST):$(VPS_ROOT)/

bootstrap: ## Run setup_vps.sh on the VPS as root
	$(SSH) "bash $(VPS_ROOT)/deploy/setup_vps.sh"

reinstall-units: push ## Reinstall the templated systemd units + daemon-reload (no apt / no ollama)
	# Lightweight subset of bootstrap that only refreshes the unit files
	# under /etc/systemd/system. Use whenever deploy/systemd/*.service
	# changes — ``make demo`` only rsyncs files into /opt/delftclaw and
	# would otherwise leave systemd reading the previous unit body.
	# Idempotent and fast (no apt, no ollama, no venv work).
	$(SSH) "set -e; \
	    for unit in delftclaw-mcp@.service delftclaw-watchdog@.service \
	                delftclaw-identity-mcp@.service delftclaw-security-mcp@.service; do \
	      if [ -f $(VPS_ROOT)/deploy/systemd/\$$unit ]; then \
	        install -m 0644 -o root -g root \
	          $(VPS_ROOT)/deploy/systemd/\$$unit /etc/systemd/system/\$$unit; \
	      fi; \
	    done; \
	    systemctl daemon-reload"

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

watch-ipv8: check-name ## Tail IPv8 + TOOL events; drops the pull-loop + uvicorn noise
	$(SSH) "journalctl --no-pager -f \
		-u 'delftclaw-mcp@$(NAME)-*.service' \
		-u 'delftclaw-watchdog@$(NAME)-*.service' \
		| grep --line-buffered -E \
		  'IPv8|delftclaw\\.|TOOL |turn |openclaw|ERROR|WARN|FAIL|Traceback' \
		| grep --line-buffered -vE \
		  'GET /head|GET /entries|GET /entry/|httpx INFO HTTP Request.*head|Processing request of type|streamable_http|Negotiated protocol|Received session ID|Created new transport|Terminating session'"

tools: check-name ## Live tail of TOOL audit lines (one entry per agent tool call)
	$(SSH) "journalctl --no-pager -f \
		-u 'delftclaw-mcp@$(NAME)-*.service' \
		-u 'delftclaw-watchdog@$(NAME)-*.service' \
		| grep --line-buffered -E 'delftclaw\\.agent\\.tools.*TOOL '"

tail-turns: check-name ## Turn-level tail: lock acquire/release + TOOL + IPv8 + errors
	$(SSH) "journalctl --no-pager -f \
		-u 'delftclaw-mcp@$(NAME)-*.service' \
		-u 'delftclaw-watchdog@$(NAME)-*.service' \
		| grep --line-buffered -E \
		  'llm turn lock|TOOL |IPv8 (send|recv)|ERROR|WARN|FAIL|Traceback|stop_predicate'"

tools-summary: check-name ## One-shot histogram of TOOL invocations per agent and per tool name
	$(SSH) "journalctl --no-pager --since '1 hour ago' \
		-u 'delftclaw-mcp@$(NAME)-*.service' \
		-u 'delftclaw-watchdog@$(NAME)-*.service' \
		| grep -E 'delftclaw\\.agent\\.tools.*TOOL (call|ok|fail|skip)' \
		| awk '{ \
		    for (i=1; i<=NF; i++) { \
		      if (\$\$i ~ /^name=/) { name=\$\$i; sub(/^name=/, \"\", name) } \
		      if (\$\$i ~ /^session=/) { sess=\$\$i; sub(/^session=/, \"\", sess) } \
		    } \
		    op=\$\$5; counts[op\" \"name]++ \
		  } \
		  END { \
		    for (k in counts) printf \"%6d  %s\\n\", counts[k], k \
		  }' \
		| sort -nr"

trace: check-name ## Snapshot per-agent demo state (turns, tools, IPv8 events, community)
	$(SSH) "PYTHONPATH=$(VPS_ROOT) $(VPS_ROOT)/venv/bin/python -m deploy.trace $(NAME)"

stop: check-name ## Stop scenario NAME + teardown its env files
	$(SSH) "cd $(VPS_ROOT) && PYTHONPATH=$(VPS_ROOT) \
		$(VPS_ROOT)/venv/bin/python -m deploy.scenario_boot $(NAME) --teardown"

sq3-containment-preflight: push ## Check VPS has Docker + gVisor/runsc + iptables for SQ3
	$(SSH) "cd $(VPS_ROOT) && PYTHONPATH=$(VPS_ROOT) \
		$(VPS_ROOT)/venv/bin/python -m security.containment_layer.official_runner \
		--out results/sq3_official_preflight \
		--timeout 10 \
		--preflight-only \
		--image python:3.12-slim"

sq3-containment-official: push ## Run official SQ3 containment battery on the VPS
	$(SSH) "cd $(VPS_ROOT) && PYTHONPATH=$(VPS_ROOT) \
		$(VPS_ROOT)/venv/bin/python -m security.containment_layer.official_runner \
		--out results/sq3_official_containment \
		--timeout 10 \
		--image python:3.12-slim"

# ---------------------------------------------------------------------------
# Gemini proxy + one-shot demo launcher
# ---------------------------------------------------------------------------

# Pull LLM_API_KEYS / LLM_PROXY_PORT / LLM_PROXY_UPSTREAM out of
# configs/host.env so the Makefile can pass them to the VPS without the
# user re-typing keys. host.env is gitignored.
LLM_KEYS := $(shell grep -E '^LLM_API_KEYS=' configs/host.env 2>/dev/null | sed 's/^LLM_API_KEYS=//')
LLM_PORT := $(shell grep -E '^LLM_PROXY_PORT=' configs/host.env 2>/dev/null | sed 's/^LLM_PROXY_PORT=//' | head -1)
LLM_UPSTREAM := $(shell grep -E '^LLM_PROXY_UPSTREAM=' configs/host.env 2>/dev/null | sed 's/^LLM_PROXY_UPSTREAM=//' | head -1)

llm-up: push ## Install + (re)start the LLM proxy on the VPS
	@if [ -z "$(LLM_KEYS)" ]; then \
	  echo "LLM_API_KEYS is empty in configs/host.env — populate it first."; \
	  echo "Get a key at https://console.anthropic.com, then edit configs/host.env."; \
	  exit 1; \
	fi
	$(SSH) "LLM_API_KEYS='$(LLM_KEYS)' \
	        LLM_PROXY_PORT='$(or $(LLM_PORT),11600)' \
	        LLM_PROXY_UPSTREAM='$(or $(LLM_UPSTREAM),https://api.anthropic.com/v1)' \
	        REPO_ROOT='$(VPS_ROOT)' \
	        bash $(VPS_ROOT)/deploy/install_llm_proxy.sh"

llm-down: ## Stop the LLM proxy on the VPS
	$(SSH) "systemctl stop delftclaw-llm-proxy || true; \
	        systemctl disable delftclaw-llm-proxy || true; \
	        systemctl status delftclaw-llm-proxy --no-pager || true"

llm-logs: ## Tail the LLM proxy journal (Ctrl-C to stop)
	$(SSH) "journalctl --no-pager -f -u delftclaw-llm-proxy"

demo: check-name push reinstall-units llm-up ## One-shot: push + refresh units + llm-up + stop + scenario
	# reinstall-units is part of the chain so a systemd unit change
	# (e.g. adding the --redteam-host/port flags) lands without a
	# separate ``make deploy``. Caught once: stale unit silently
	# disabled the redteam FastAPI sub-server on every MCP process,
	# which made pull_loop.error fire on every tick and prevented
	# bob/charlie/dave from ever seeing alice's donation entry.
	-$(SSH) "cd $(VPS_ROOT) && PYTHONPATH=$(VPS_ROOT) \
		$(VPS_ROOT)/venv/bin/python -m deploy.scenario_boot $(NAME) --teardown"
	$(SSH) "cd $(VPS_ROOT) && PYTHONPATH=$(VPS_ROOT) \
		$(VPS_ROOT)/venv/bin/python -m deploy.scenario_boot $(NAME)"
	@echo
	@echo "Demo running. Useful follow-ups:"
	@echo "  make tools         NAME=$(NAME)  # live: every tool call by every agent"
	@echo "  make tail-turns    NAME=$(NAME)  # live: lock acquire/release + tools + wire"
	@echo "  make watch-ipv8    NAME=$(NAME)  # live: IPv8 + TOOL events only"
	@echo "  make tools-summary NAME=$(NAME)  # one-shot: TOOL histogram (last hour)"
	@echo "  make trace         NAME=$(NAME)  # one-shot: per-agent snapshot"
	@echo "  make llm-logs                    # proxy traffic"

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
