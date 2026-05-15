"""Tests for ``deploy.scenario_boot._load_host_env``.

The per-host override file ``configs/host.env`` is gitignored — every
dev sets their own. These tests pin the dotenv-light parser so the
behaviour stays predictable across machines:

  * KEY=VALUE pairs roundtrip.
  * blank lines + ``#`` comments are skipped.
  * KEY= (empty value) is treated as "unset" so the hard-coded fallback
    in scenario_boot.py wins.
  * missing file yields {} (no error).
  * env var on the process wins over host.env (resolution order matters).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deploy import scenario_boot


def test_load_host_env_returns_empty_when_missing(tmp_path):
    assert scenario_boot._load_host_env(tmp_path / "nope.env") == {}


def test_load_host_env_parses_basic_pairs(tmp_path):
    (tmp_path / "host.env").write_text("FOO=bar\nBAZ=qux\n", encoding="utf-8")
    assert scenario_boot._load_host_env(tmp_path / "host.env") == {
        "FOO": "bar",
        "BAZ": "qux",
    }


def test_load_host_env_ignores_comments_and_blank_lines(tmp_path):
    body = (
        "# comment line\n"
        "\n"
        "KEY1=val1\n"
        "   # indented comment\n"
        "KEY2=val2\n"
    )
    (tmp_path / "host.env").write_text(body, encoding="utf-8")
    assert scenario_boot._load_host_env(tmp_path / "host.env") == {
        "KEY1": "val1",
        "KEY2": "val2",
    }


def test_load_host_env_empty_value_is_dropped(tmp_path):
    """``KEY=`` with no value falls through to scenario_boot's hard-coded default."""
    (tmp_path / "host.env").write_text("KEY=\nOTHER=hello\n", encoding="utf-8")
    assert scenario_boot._load_host_env(tmp_path / "host.env") == {"OTHER": "hello"}


def test_load_host_env_handles_whitespace(tmp_path):
    (tmp_path / "host.env").write_text("  KEY  =  spaced value  \n", encoding="utf-8")
    assert scenario_boot._load_host_env(tmp_path / "host.env") == {
        "KEY": "spaced value",
    }


def test_qwen_resolution_env_var_wins_over_host_env(monkeypatch, tmp_path):
    """Process env > host.env > hard-coded default."""
    host_env = tmp_path / "host.env"
    host_env.write_text(
        "QWEN_BASE_URL=http://host-env-url:9999/v1\n"
        "QWEN_MODEL=host-env-model\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("QWEN_BASE_URL", "http://env-var-url:8000/v1")
    monkeypatch.setenv("QWEN_MODEL", "env-var-model")

    base, model, _api_key = scenario_boot._resolve_qwen(host_env)
    assert base == "http://env-var-url:8000/v1"
    assert model == "env-var-model"


def test_qwen_resolution_host_env_wins_over_default(monkeypatch, tmp_path):
    host_env = tmp_path / "host.env"
    host_env.write_text(
        "QWEN_BASE_URL=http://host-env-only/v1\n"
        "QWEN_MODEL=host-env-model\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("QWEN_BASE_URL", raising=False)
    monkeypatch.delenv("QWEN_MODEL", raising=False)

    base, model, _api_key = scenario_boot._resolve_qwen(host_env)
    assert base == "http://host-env-only/v1"
    assert model == "host-env-model"


def test_qwen_resolution_default_when_neither_set(monkeypatch, tmp_path):
    monkeypatch.delenv("QWEN_BASE_URL", raising=False)
    monkeypatch.delenv("QWEN_MODEL", raising=False)

    base, model, _api_key = scenario_boot._resolve_qwen(tmp_path / "no_such.env")
    assert base == scenario_boot.DEFAULT_QWEN_BASE_URL
    assert model == scenario_boot.DEFAULT_QWEN_MODEL


def test_ollama_api_key_resolution(monkeypatch, tmp_path):
    """OLLAMA_API_KEY follows the same env > host.env > default order."""
    host_env = tmp_path / "host.env"
    host_env.write_text("OLLAMA_API_KEY=from-host-env\n", encoding="utf-8")
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    _b, _m, key = scenario_boot._resolve_qwen(host_env)
    assert key == "from-host-env"

    monkeypatch.setenv("OLLAMA_API_KEY", "from-process-env")
    _b, _m, key = scenario_boot._resolve_qwen(host_env)
    assert key == "from-process-env"

    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    _b, _m, key = scenario_boot._resolve_qwen(tmp_path / "no_such.env")
    assert key == scenario_boot.DEFAULT_OLLAMA_API_KEY


def test_resolve_qwen_partial_override(monkeypatch, tmp_path):
    """host.env may override only one of BASE_URL / MODEL."""
    host_env = tmp_path / "host.env"
    host_env.write_text("QWEN_MODEL=host-env-model-only\n", encoding="utf-8")
    monkeypatch.delenv("QWEN_BASE_URL", raising=False)
    monkeypatch.delenv("QWEN_MODEL", raising=False)

    base, model, _api_key = scenario_boot._resolve_qwen(host_env)
    assert base == scenario_boot.DEFAULT_QWEN_BASE_URL
    assert model == "host-env-model-only"
