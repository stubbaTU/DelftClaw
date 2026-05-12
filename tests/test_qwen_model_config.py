from __future__ import annotations

import json
from pathlib import Path

import pytest

from security.integration.model_config import load_model_runtime_config


def test_prefers_environment_over_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg_path = tmp_path / "openclaw.json"
    cfg_path.write_text(
        json.dumps({"model": {"default": "from-file"}, "openai": {"base_url": "http://file-host:8000/v1"}}),
        encoding="utf-8",
    )

    monkeypatch.setenv("OPENAI_API_BASE", "http://env-host:8000/v1")
    monkeypatch.setenv("OPENAI_MODEL", "from-env")
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")

    cfg = load_model_runtime_config(cfg_path)

    assert cfg.base_url == "http://env-host:8000/v1"
    assert cfg.model == "from-env"
    assert cfg.api_key == "env-key"


def test_loads_from_openclaw_json_when_env_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_BASE", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    cfg_path = tmp_path / "openclaw.json"
    cfg_path.write_text(
        json.dumps(
            {
                "model": {"default": "Qwen/Qwen2.5-7B-Instruct"},
                "openai": {"base_url": "http://gpu-node:8000/v1"},
            }
        ),
        encoding="utf-8",
    )

    cfg = load_model_runtime_config(cfg_path)

    assert cfg.base_url == "http://gpu-node:8000/v1"
    assert cfg.model == "Qwen/Qwen2.5-7B-Instruct"
    assert cfg.api_key == "dummy"


def test_raises_when_no_model_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("OPENAI_API_BASE", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    cfg_path = tmp_path / "openclaw.json"
    cfg_path.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError):
        load_model_runtime_config(cfg_path)

