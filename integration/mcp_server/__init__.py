"""MCP server exposing AgentChannel as 10 LLM-callable tools.

Wraps :class:`communication.channel.agent_channel.AgentChannel` and exposes
its public API as Model Context Protocol tools. Designed for OpenClaw and
any other MCP host. Streamable-HTTP transport on 127.0.0.1.
"""
