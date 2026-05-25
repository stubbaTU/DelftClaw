from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from claw_community.service import ClawCommunityService


ACTION_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


class GoalRunner:
    def __init__(self, service: ClawCommunityService) -> None:
        self.service = service

    def run_goal_file(self, path: str | Path) -> list[dict[str, Any]]:
        text = Path(path).read_text(encoding="utf-8")
        results = []
        for block in ACTION_BLOCK_RE.findall(text):
            action = json.loads(block)
            results.append(self.run_action(action))
        return results

    def run_action(self, action: dict[str, Any]) -> dict[str, Any]:
        tool = action["tool"]
        args = dict(action.get("args", {}))
        if tool == "create_community":
            return self.service.create_community(**args)
        if tool == "buy_seedbox":
            return self.service.buy_seedbox(**args)
        if tool == "join_community":
            return self.service.join_community(**args)
        if tool == "import_file_catalog":
            return self.service.import_file_catalog(**args)
        if tool == "find_file":
            return self.service.find_file(**args)
        if tool == "retrieve_file":
            return self.service.retrieve_file(**args)
        if tool == "get_status":
            return self.service.get_status(**args)
        raise ValueError(f"unknown goal tool: {tool}")
