"""Run tracing: a JSONL record of every LLM turn and tool call, plus stderr progress."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, TextIO

from auditor.redact import redact


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


class Tracer:
    def __init__(self, path: str | Path | None = None, verbose: bool = True, stream: TextIO | None = None):
        self.path = Path(path) if path else None
        self.verbose = verbose
        self.stream = stream or sys.stderr
        self._fh = None
        self._t0 = time.monotonic()
        self.events: list[dict[str, Any]] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.path, "w", encoding="utf-8")

    def event(self, kind: str, **data: Any) -> None:
        record = {"t": round(time.monotonic() - self._t0, 3), "event": kind, **_scrub(data)}
        self.events.append(record)
        if self._fh:
            self._fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            self._fh.flush()

    def say(self, message: str) -> None:
        if self.verbose:
            print(redact(message), file=self.stream, flush=True)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
