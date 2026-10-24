"""Final JSON report: build, validate against the output contract, and write atomically."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from auditor.findings import CATEGORIES, FIELDS, SEVERITIES, Finding
from auditor.redact import redact

_SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


class ReportError(Exception):
    pass


def build_report(repository: str, findings: Iterable[Finding]) -> dict[str, Any]:
    violations = []
    for f in findings:
        v = f.to_violation()
        for key in ("description", "evidence", "recommendation"):
            v[key] = redact(v[key])
        violations.append(v)
    violations.sort(key=lambda v: (_SEVERITY_ORDER[v["severity"]], v["category"], v["file"] or "", v["line"] or 0))
    report = {"repository": repository, "violations": violations}
    validate_report(report)
    return report


def validate_report(report: Any) -> None:
    """Raise ReportError unless ``report`` matches the assignment's output contract exactly."""
    if not isinstance(report, dict) or set(report) != {"repository", "violations"}:
        raise ReportError("report must be an object with exactly 'repository' and 'violations'")
    if not isinstance(report["repository"], str) or not report["repository"]:
        raise ReportError("'repository' must be a non-empty string")
    if not isinstance(report["violations"], list):
        raise ReportError("'violations' must be an array")
    for i, v in enumerate(report["violations"]):
        where = f"violations[{i}]"
        if not isinstance(v, dict) or set(v) != set(FIELDS):
            raise ReportError(f"{where} must have exactly the fields {', '.join(FIELDS)}")
        for key in ("rule_id", "category", "severity", "description", "evidence", "recommendation"):
            if not isinstance(v[key], str) or not v[key].strip():
                raise ReportError(f"{where}.{key} must be a non-empty string")
        if v["severity"] not in SEVERITIES:
            raise ReportError(f"{where}.severity must be one of {SEVERITIES}")
        if v["category"] not in CATEGORIES:
            raise ReportError(f"{where}.category must be one of {CATEGORIES}")
        if v["file"] is not None and (not isinstance(v["file"], str) or not v["file"]):
            raise ReportError(f"{where}.file must be a non-empty string or null")
        if v["line"] is not None and (isinstance(v["line"], bool) or not isinstance(v["line"], int) or v["line"] < 1):
            raise ReportError(f"{where}.line must be a positive integer or null")
        if v["file"] is None and v["line"] is not None:
            raise ReportError(f"{where}.line must be null when file is null")
        for key in ("description", "evidence", "recommendation"):
            if redact(v[key]) != v[key]:
                raise ReportError(f"{where}.{key} contains an unredacted secret-like value")


def write_report(report: dict[str, Any], output: str | Path) -> Path:
    """Write JSON atomically so a crash never leaves a half-written report behind."""
    validate_report(report)
    out = Path(output)
    if out.parent and not out.parent.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".report-", suffix=".json", dir=out.parent or Path("."))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, out)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return out
