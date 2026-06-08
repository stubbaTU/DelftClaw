"""CLI compatibility wrapper for the preventative-layer AgentDojo runner."""

from security.preventative_layer.agentdojo_runner import main


if __name__ == "__main__":
    raise SystemExit(main())
