"""DelftClaw overlay-protocol compiler: `.md` descriptors -> runtime IPv8 communities."""

from protocol.compiler import (
    CompiledOverlay,
    ProtocolCompileError,
    canonicalize_md,
    community_id_from_md,
    compile_overlay,
    parse_md,
)
from protocol.llm import LLMClient, OpenAICompatibleClient
from protocol.registry import OverlayRegistry
from protocol.sandbox import SandboxError, safe_exec, validate_ast

__all__ = [
    "CompiledOverlay",
    "LLMClient",
    "OpenAICompatibleClient",
    "OverlayRegistry",
    "ProtocolCompileError",
    "SandboxError",
    "canonicalize_md",
    "community_id_from_md",
    "compile_overlay",
    "parse_md",
    "safe_exec",
    "validate_ast",
]
