"""AgentChannel — the single class OpenClaw integrates against."""

from communication.channel.agent_channel import AgentChannel
from communication.channel.inbox import Inbox, IncomingMessage

__all__ = ["AgentChannel", "Inbox", "IncomingMessage"]
