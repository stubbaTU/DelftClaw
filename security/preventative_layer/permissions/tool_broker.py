from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from security.preventative_layer.permissions.models import PermissionRequest, Subject
from security.preventative_layer.permissions.permission_engine import PermissionEngine


ToolFn = Callable[..., Any]
ResourceResolver = Callable[[dict[str, Any]], str | None]


@dataclass(frozen=True)
class RegisteredTool:
    fn: ToolFn
    action: str
    resource_resolver: ResourceResolver
    sink: str | None = None


class ToolBroker:
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
    ) -> None:
        self._tools[tool_name] = RegisteredTool(fn, action, resource_resolver, sink)

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
            return {"ok": False, "error": "permission_denied", "reason": "unknown tool"}

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
        )
        decision = self.permission_engine.decide(request, current_round=current_round)
        if decision.decision == "deny":
            return {"ok": False, "blocked": True, "error": "permission_denied", "reason": decision.reason}

        call_args = decision.sanitized_args if decision.sanitized_args is not None else args
        try:
            if decision.decision == "allow_via_proxy":
                if not decision.proxy_name or decision.proxy_name not in self._proxies:
                    return {
                        "ok": False,
                        "blocked": True,
                        "error": "permission_denied",
                        "reason": "missing proxy",
                    }
                result = self._proxies[decision.proxy_name](subject=subject, **call_args)
            else:
                result = registered.fn(**call_args)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            return {"ok": False, "error": "tool_failed", "reason": f"{type(exc).__name__}: {exc}"}
        return result
