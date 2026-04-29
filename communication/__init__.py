"""OpenClaw Communication: Layers 0–5 plus the AgentChannel adapter for OpenClaw."""

__version__ = "0.1.0"

from communication.channel.agent_channel import AgentChannel
from communication.channel.inbox import Inbox, IncomingMessage
from communication.trustroom.community import TrustroomCommunity

__all__ = [
    "AgentChannel",
    "Inbox",
    "IncomingMessage",
    "TrustroomCommunity",
]
