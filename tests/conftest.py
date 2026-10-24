"""Shared fixtures: throwaway git repositories and a scripted fake LLM."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from auditor.llm import LLMResponse, ToolCall  # noqa: E402

FAKE_KEY = "sk-proj-" + "Ab3" * 12  # looks like a real key; it is not one

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def git(repo: Path, *args: str) -> str:
    out = subprocess.run(["git", *args], cwd=repo, env=GIT_ENV, capture_output=True, check=True)
    return out.stdout.decode().strip()


def write_files(repo: Path, files: dict[str, str | bytes]) -> None:
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8", newline="\n")


def make_repo(path: Path, commits: list[tuple[str, dict[str, str | bytes], list[str]]]) -> Path:
    """Create a git repo. Each commit is (message, files to write, files to delete)."""
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "core.autocrlf", "false")
    for message, files, deletions in commits:
        write_files(path, files)
        for rel in deletions:
            git(path, "rm", "-q", rel)
        git(path, "add", "-A")
        git(path, "commit", "-q", "-m", message)
    return path


WORKFLOW = """\
name: CI
on:
  pull_request_target:
    branches: [main]
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: someone/setup-thing@main
      - run: pip install -r requirements.txt
      - run: pytest || true
"""

APP = """\
import os

DATA_DIR = "C:\\\\Users\\\\bob\\\\projects\\\\data"


def load(name):
    return open(os.path.join(DATA_DIR, name)).read()
"""

CONFIG = f"""\
import os

API_KEY = "{FAKE_KEY}"
DB_HOST = os.environ.get("DB_HOST", "localhost")
"""


@pytest.fixture
def defect_repo(tmp_path: Path) -> Path:
    """A small repository with several injected DevOps defects."""
    return make_repo(tmp_path / "defect", [
        ("initial", {
            "README.md": "# Demo\n\nA demo app.\n",
            ".gitignore": "*.log\n",
            "app.py": APP,
            "config.py": CONFIG,
            "requirements.txt": "requests\nflask\n",
            ".env": "DB_PASSWORD=Sup3rS3cretValue9\n",
            "tests/test_app.py": "def test_ok():\n    assert True\n",
            ".github/workflows/ci.yml": WORKFLOW,
            "__pycache__/app.cpython-311.pyc": b"\x00\x01binary\x00",
            "deploy_keys.txt": "TOKEN=ghp_" + "a1B2" * 9 + "\n",
        }, []),
        ("remove deploy keys", {}, ["deploy_keys.txt"]),
    ])


@pytest.fixture
def healthy_repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "healthy", [
        ("initial", {
            "README.md": "# Healthy\n",
            ".gitignore": "__pycache__/\n.env\n.venv/\n",
            "pyproject.toml": '[project]\nname = "healthy"\nversion = "0.1.0"\n\n[tool.ruff]\nline-length = 100\n',
            "src/healthy/__init__.py": "def add(a, b):\n    return a + b\n",
            "tests/test_add.py": "from healthy import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n",
        }, []),
    ])


# ---------------------------------------------------------------------------
# Scripted fake LLM
# ---------------------------------------------------------------------------

Turn = list[tuple[str, dict[str, Any]]] | str | Callable[[list[dict[str, Any]]], Any]


class FakeLLM:
    """Returns scripted turns. A turn is a list of (tool_name, args) calls, a plain text reply,
    or a callable taking the message history and returning either of those."""

    model = "fake-model"

    def __init__(self, turns: list[Turn], stop_reason_override: dict[int, str] | None = None):
        self.turns = list(turns)
        self.calls: list[dict[str, Any]] = []
        self.stop_reason_override = stop_reason_override or {}
        self._n = 0

    def complete(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse:
        self.calls.append({"system": system, "messages": [dict(m) for m in messages], "tools": [t["name"] for t in tools]})
        turn: Any = self.turns.pop(0) if self.turns else "nothing more to do"
        if callable(turn):
            turn = turn(messages)
        self._n += 1
        if isinstance(turn, str):
            return LLMResponse(raw_content={"fake_text": turn}, text=turn, tool_calls=[],
                               stop_reason=self.stop_reason_override.get(self._n, "end_turn"))
        calls = [ToolCall(id=f"toolu_{self._n}_{i}", name=n, input=a) for i, (n, a) in enumerate(turn)]
        raw = {"fake_calls": [(c.name, c.input) for c in calls]}
        return LLMResponse(raw_content=raw, text="", tool_calls=calls,
                           stop_reason=self.stop_reason_override.get(self._n, "tool_use"),
                           usage={"input_tokens": 10, "output_tokens": 5})


@pytest.fixture
def fake_llm_factory():
    return FakeLLM


def last_tool_results(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Tool results ({id, name, content, is_error}) from the most recent tool turn."""
    for m in reversed(messages):
        if m["role"] == "tool":
            return m["results"]
    return []
