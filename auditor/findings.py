"""Candidate violations recorded by the agent, with harness-side validation.

The LLM reports findings through the ``record_violation`` tool. Each call is
checked here (allowed category/severity, file exists, line in range, no
duplicate, no secret values) and rejected with an explanatory error the model can
act on. During verification, findings are kept, dropped, or re-graded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from auditor.redact import redact
from tools import RepoTools, ToolError, ToolResult

CATEGORIES = (
    "repository_hygiene", "dependency_management", "code_quality", "testing", "ci_cd",
    "security", "configuration", "collaboration", "build_release",
)
CATEGORY_ALIASES = {
    "hygiene": "repository_hygiene", "repo_hygiene": "repository_hygiene", "repository hygiene": "repository_hygiene",
    "dependencies": "dependency_management", "dependency": "dependency_management",
    "dependency management": "dependency_management",
    "quality": "code_quality", "code quality": "code_quality", "linting": "code_quality",
    "tests": "testing", "test": "testing",
    "ci": "ci_cd", "ci/cd": "ci_cd", "github_actions": "ci_cd", "github actions": "ci_cd", "github_actions_ci": "ci_cd",
    "secrets": "security", "config": "configuration",
    "build": "build_release", "release": "build_release", "build_and_release": "build_release",
    "build and release": "build_release", "deployment": "build_release",
}
SEVERITIES = ("critical", "high", "medium", "low")
RULE_ID = re.compile(r"^[A-Z]{2,4}-\d{3}$")
FIELDS = ("rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation")


@dataclass
class Finding:
    id: str
    rule_id: str
    category: str
    severity: str
    file: str | None
    line: int | None
    description: str
    evidence: str
    recommendation: str
    status: str = "candidate"          # candidate | kept | dropped | withdrawn
    notes: list[str] = field(default_factory=list)

    def to_violation(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in FIELDS}

    def label(self) -> str:
        loc = self.file or "(repo-level)"
        if self.line:
            loc += f":{self.line}"
        return f"{self.id} {self.rule_id} [{self.severity}] {loc} - {self.description}"


class FindingStore:
    def __init__(self, tools: RepoTools):
        self.tools = tools
        self.findings: list[Finding] = []

    # ---------------------------------------------------------------- queries

    def active(self) -> list[Finding]:
        return [f for f in self.findings if f.status in ("candidate", "kept")]

    def get(self, finding_id: str) -> Finding:
        for f in self.findings:
            if f.id == str(finding_id).strip().upper():
                return f
        raise ToolError(f"no finding with id '{finding_id}'; known ids: {', '.join(f.id for f in self.findings) or 'none'}")

    def summary(self) -> str:
        act = self.active()
        if not act:
            return "No findings recorded yet."
        return "Current findings:\n" + "\n".join("  " + f.label() for f in act)

    # ------------------------------------------------------------- validation

    def _check_file_line(self, file: Any, line: Any) -> tuple[str | None, int | None]:
        if file in (None, "", "null", "None"):
            return None, None  # repo-level finding (e.g. a missing file): line is meaningless
        try:
            rel = self.tools.normalize(str(file))
        except ToolError as exc:
            raise ToolError(f"invalid file: {exc}") from None
        if not (self.tools.root / rel).is_file():
            raise ToolError(
                f"file '{rel}' does not exist in the repository. If the finding is about a missing file, "
                "set file=null and line=null and say what is missing in the description."
            )
        if line in (None, "", 0, "null"):
            return rel, None
        try:
            line = int(line)
        except (TypeError, ValueError):
            raise ToolError("line must be an integer or null") from None
        total = self.tools.line_count(rel)
        if line < 1 or line > max(total, 1):
            raise ToolError(f"line {line} is outside {rel} (1-{total}); re-read the file and cite the exact line")
        return rel, line

    @staticmethod
    def _norm_category(value: str) -> str:
        cat = str(value).strip().lower()
        cat = CATEGORY_ALIASES.get(cat, cat).replace(" ", "_").replace("-", "_")
        if cat not in CATEGORIES:
            raise ToolError(f"category must be one of {', '.join(CATEGORIES)}")
        return cat

    @staticmethod
    def _norm_severity(value: str) -> str:
        sev = str(value).strip().lower()
        if sev not in SEVERITIES:
            raise ToolError(f"severity must be one of {', '.join(SEVERITIES)}")
        return sev

    def _check_evidence(self, rel: str, line: int | None, evidence: str) -> None:
        """Anti-hallucination check: a quoted snippet ("..." or `...`) must exist at the cited location.

        Passes if no snippet is quoted, or if at least one quoted snippet appears within
        +/-5 lines of ``line`` (or anywhere in the file when line is null).
        """
        quoted = [q.strip() for q in re.findall(r"[`\"]([^`\"\n]{6,160})[`\"]", evidence)]
        quoted = [q for q in quoted if q and "REDACTED" not in q]
        if not quoted:
            return

        def squash(s: str) -> str:
            return re.sub(r"\s+", " ", s).strip().lower()

        lines = redact((self.tools.root / rel).read_text("utf-8", "replace")).splitlines()
        window = lines[max(0, line - 6): line + 5] if line else lines
        hay = squash("\n".join(window))
        if any(squash(q) in hay for q in quoted):
            return
        for n, text in enumerate(lines, 1):
            if any(squash(q) in squash(text) for q in quoted):
                raise ToolError(f"the quoted evidence appears at {rel}:{n}, not near line {line}; cite line {n}")
        raise ToolError(
            f"none of the quoted snippets in 'evidence' were found in {rel}. Quote text exactly as it appears "
            "in the file (re-read it), or describe the observation without quotation marks."
        )

    # ------------------------------------------------------------------ tools

    def record(self, args: dict[str, Any]) -> ToolResult:
        missing = [k for k in FIELDS if k not in args]
        if missing:
            raise ToolError(f"missing field(s): {', '.join(missing)} (use null for file/line when not applicable)")
        rule_id = str(args["rule_id"]).strip().upper()
        if not RULE_ID.match(rule_id):
            raise ToolError("rule_id must look like 'SEC-001' (2-4 capital letters, dash, 3 digits)")
        category = self._norm_category(args["category"])
        severity = self._norm_severity(args["severity"])
        file, line = self._check_file_line(args["file"], args["line"])
        texts = {}
        for key in ("description", "evidence", "recommendation"):
            value = str(args[key] or "").strip()
            if len(value) < 8:
                raise ToolError(f"'{key}' is too short - be specific")
            texts[key] = redact(value)[:1200]

        if file:
            self._check_evidence(file, line, texts["evidence"])
        for f in self.active():
            if f.rule_id == rule_id and f.file == file and (f.line == line or line is None or f.line is None):
                raise ToolError(f"duplicate of {f.id} ({f.rule_id} at {f.file or 'repo level'}); not recorded")

        finding = Finding(f"V{len(self.findings) + 1}", rule_id, category, severity, file, line, **texts)
        overlap = [f for f in self.active() if file and f.file == file and f.line == line]
        self.findings.append(finding)
        msg = f"Recorded {finding.id}."
        if overlap:
            msg += (f" Note: {', '.join(o.id for o in overlap)} cite the same location - make sure this is a "
                    "distinct problem, otherwise withdraw one.")
        return ToolResult(msg + "\n" + self.summary())

    def withdraw(self, args: dict[str, Any]) -> ToolResult:
        f = self.get(args["finding_id"])
        f.status = "withdrawn"
        f.notes.append(f"withdrawn: {args.get('reason', '')}")
        return ToolResult(f"Withdrew {f.id}.\n" + self.summary())

    def verdict(self, args: dict[str, Any]) -> ToolResult:
        f = self.get(args["finding_id"])
        if f.status not in ("candidate", "kept"):
            raise ToolError(f"{f.id} is already {f.status}")
        decision = str(args["decision"]).lower()
        reason = str(args.get("reason") or "")
        if decision == "drop":
            f.status = "dropped"
            f.notes.append(f"dropped in verification: {reason}")
            return ToolResult(f"{f.id} dropped.")
        if decision != "keep":
            raise ToolError("decision must be 'keep' or 'drop'")
        if args.get("severity"):
            new = self._norm_severity(args["severity"])
            if new != f.severity:
                f.notes.append(f"severity {f.severity} -> {new}: {reason}")
                f.severity = new
        if args.get("line") is not None:
            _, f.line = self._check_file_line(f.file, args["line"]) if f.file else (None, None)
        f.status = "kept"
        f.notes.append(f"kept: {reason}")
        return ToolResult(f"{f.id} kept ({f.severity}).")


# ---------------------------------------------------------------------------
# Control-tool schemas
# ---------------------------------------------------------------------------

RECORD_VIOLATION_SCHEMA = {
    "name": "record_violation",
    "description": (
        "Record one confirmed DevOps violation. Only call this after you have observed concrete evidence "
        "with a tool (normally read_file on the exact lines). One call per distinct problem. The harness "
        "rejects calls whose file does not exist, whose line is out of range, or that duplicate an "
        "existing finding. Never include secret values - refer to them as <REDACTED> or describe them."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "rule_id": {"type": "string", "description": "Rule id from the catalog, e.g. SEC-001."},
            "category": {"type": "string", "enum": list(CATEGORIES)},
            "severity": {"type": "string", "enum": list(SEVERITIES)},
            "file": {"type": ["string", "null"], "description": "Repo-relative path, or null for repo-level/missing-file findings."},
            "line": {"type": ["integer", "null"], "description": "1-based line of the evidence, or null."},
            "description": {"type": "string", "description": "One sentence: what is wrong."},
            "evidence": {"type": "string", "description": "What you observed and where (quote short non-secret snippets)."},
            "recommendation": {"type": "string", "description": "Concrete, actionable remediation."},
        },
        "required": list(FIELDS),
    },
}

WITHDRAW_SCHEMA = {
    "name": "withdraw_violation",
    "description": "Withdraw a previously recorded finding (e.g. you found an acceptable alternative or it duplicates another).",
    "input_schema": {
        "type": "object",
        "properties": {"finding_id": {"type": "string"}, "reason": {"type": "string"}},
        "required": ["finding_id", "reason"],
    },
}

FINISH_SCHEMA = {
    "name": "finish",
    "description": "End the current phase after all required work for that phase is complete.",
    "input_schema": {
        "type": "object",
        "properties": {"summary": {"type": "string", "description": "Short summary of what was inspected and concluded."}},
        "required": ["summary"],
    },
}

INVESTIGATION_FINISH_SCHEMA = {
    "name": "finish",
    "description": (
        "End the investigation only after every DevOps inspection area has been considered and all findings are "
        "recorded. List every area you reviewed; the harness rejects incomplete coverage."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "Short summary of what was inspected and concluded."},
            "areas_reviewed": {
                "type": "array",
                "items": {"type": "string", "enum": list(CATEGORIES)},
                "description": "Every DevOps category considered during this investigation.",
            },
        },
        "required": ["summary", "areas_reviewed"],
    },
}

VERDICT_SCHEMA = {
    "name": "submit_verdict",
    "description": "Decide one candidate finding: keep it (optionally re-grading severity or correcting the line) or drop it.",
    "input_schema": {
        "type": "object",
        "properties": {
            "finding_id": {"type": "string"},
            "decision": {"type": "string", "enum": ["keep", "drop"]},
            "reason": {"type": "string"},
            "severity": {"type": "string", "enum": list(SEVERITIES)},
            "line": {"type": "integer"},
        },
        "required": ["finding_id", "decision", "reason"],
    },
}
