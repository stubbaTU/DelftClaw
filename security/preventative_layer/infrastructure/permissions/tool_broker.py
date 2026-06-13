from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from security.preventative_layer.infrastructure.permissions.models import PermissionRequest, Subject
from security.preventative_layer.infrastructure.permissions.permission_engine import PermissionEngine


ToolFn = Callable[..., Any]
ResourceResolver = Callable[[dict[str, Any]], str | None]


@dataclass(frozen=True)
class RegisteredTool:
    fn: ToolFn
    action: str
    resource_resolver: ResourceResolver
    sink: str | None = None
    effect_class: str | None = None
    classification_source: str | None = None
    neutral_args: tuple[str, ...] = ()
    broadcast_sink: bool = False
    allow_content_after_untrusted: bool = False


class ToolBroker:
    """
    Provides a unified interface for registering and calling tools (most importantly, denied calls never touch the actual implementation).
    """
    def __init__(self, permission_engine: PermissionEngine) -> None:
        self.permission_engine = permission_engine
        self._tools: dict[str, RegisteredTool] = {}
        self._proxies: dict[str, ToolFn] = {}

    def register_tool(
        self,
        tool_name: str,
        fn: ToolFn,
        action: str,
        resource_resolver: ResourceResolver,
        sink: str | None = None,
        effect_class: str | None = None,
        classification_source: str | None = None,
        neutral_args: tuple[str, ...] = (),
        broadcast_sink: bool = False,
        allow_content_after_untrusted: bool = False,
    ) -> None:
        self._tools[tool_name] = RegisteredTool(
            fn,
            action,
            resource_resolver,
            sink,
            effect_class,
            classification_source,
            neutral_args,
            broadcast_sink,
            allow_content_after_untrusted,
        )

    def register_proxy(self, proxy_name: str, fn: ToolFn) -> None:
        self._proxies[proxy_name] = fn

    async def call_tool(
        self,
        subject: Subject,
        tool_name: str,
        args: dict[str, Any],
        task_id: str | None = None,
        current_round: int | None = None,
        input_taint: str | None = None,
    ) -> Any:
        registered = self._tools.get(tool_name)
        if registered is None:
            return {
                "ok": False,
                "blocked": True,
                "error": "permission_denied",
                "reason": "unknown tool",
                "reason_code": "unknown_tool",
                "denial_class": "security_enforcement",
            }

        try:
            resource_id = registered.resource_resolver(args)
        except Exception:
            resource_id = None
        request = PermissionRequest(
            request_id=str(uuid.uuid4()),
            subject=subject,
            tool_name=tool_name,
            action=registered.action,
            resource_id=resource_id,
            resource_label=None,
            args=dict(args),
            task_id=task_id,
            sink=registered.sink,
            input_taint=input_taint,
            effect_class=registered.effect_class,
            classification_source=registered.classification_source,
            neutral_args=registered.neutral_args,
            broadcast_sink=registered.broadcast_sink,
            allow_content_after_untrusted=registered.allow_content_after_untrusted,
        )
        decision = self.permission_engine.decide(request, current_round=current_round)
        if decision.decision == "deny":
            return {
                "ok": False,
                "blocked": True,
                "error": "permission_denied",
                "reason": decision.reason,
                "reason_code": decision.reason_code,
                "denial_class": decision.denial_class,
            }

        call_args = decision.sanitized_args if decision.sanitized_args is not None else args
        if decision.matched_capability_id is not None:
            if not self.permission_engine.capability_store.consume(decision.matched_capability_id):
                return {
                    "ok": False,
                    "blocked": True,
                    "error": "permission_denied",
                    "reason": "capability use limit exhausted",
                    "reason_code": "capability_use_limit_exhausted",
                    "denial_class": "security_enforcement",
                }
        try:
            if decision.decision == "allow_via_proxy":
                if not decision.proxy_name or decision.proxy_name not in self._proxies:
                    return {
                        "ok": False,
                        "blocked": True,
                        "error": "permission_denied",
                        "reason": "missing proxy",
                        "reason_code": "missing_proxy",
                        "denial_class": "security_enforcement",
                    }
                result = self._proxies[decision.proxy_name](subject=subject, **call_args)
            else:
                result = registered.fn(**call_args)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            return {"ok": False, "error": "tool_failed", "reason": f"{type(exc).__name__}: {exc}"}
        return result
