"""Audit orchestration: investigation loop, then a verification loop, then the report."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from auditor.findings import (
    CATEGORIES,
    FINISH_SCHEMA,
    INVESTIGATION_FINISH_SCHEMA,
    OBSERVATION_VERDICT_SCHEMA,
    RECORD_VIOLATION_SCHEMA,
    RESOLVE_OBSERVATION_SCHEMA,
    VERDICT_SCHEMA,
    WITHDRAW_SCHEMA,
    Finding,
    FindingStore,
)
from auditor.llm import LLMClient
from auditor.loop import AgentLoop, LoopOutcome
from auditor.prompts import INVESTIGATION_SYSTEM, VERIFICATION_SYSTEM
from auditor.redact import redact
from auditor.repo import Checkout
from auditor.report import build_report
from auditor.trace import Tracer
from tools import INSPECTION_TOOL_SCHEMAS, RepoTools, ToolError, ToolResult, make_inspection_handlers, validate_args


@dataclass
class AuditConfig:
    max_steps: int = 45
    verify_steps: int = 20
    verify: bool = True
    timeout_s: float = 1800.0


@dataclass
class AuditResult:
    report: dict[str, Any]
    findings: list[Finding]
    phases: dict[str, LoopOutcome] = field(default_factory=dict)


class AuditIncompleteError(Exception):
    """The agent stopped before it explicitly completed every required phase."""


# Control tools receive the validated argument dict itself; inspection tools get **kwargs.
_CONTROL_TOOLS = {
    "record_violation", "withdraw_violation", "finish", "submit_verdict",
    "resolve_observation", "submit_observation_verdict",
}


def _dispatcher(schemas: list[dict[str, Any]], handlers: dict[str, Callable[..., Any]]) -> Callable[[str, dict[str, Any]], ToolResult]:
    by_name = {s["name"]: s for s in schemas}

    def dispatch(name: str, args: dict[str, Any]) -> ToolResult:
        if name not in by_name:
            return ToolResult(f"Unknown tool '{name}'. Available: {', '.join(by_name)}", is_error=True)
        try:
            clean = validate_args(by_name[name]["input_schema"], args)
            out = handlers[name](**clean) if name not in _CONTROL_TOOLS else handlers[name](clean)
        except ToolError as exc:
            return ToolResult(f"Error: {exc}", is_error=True)
        return out if isinstance(out, ToolResult) else ToolResult(str(out))

    return dispatch



def _overview(tools: RepoTools, checkout: Checkout, repo_url: str) -> str:
    files = tools.tracked_files()
    top = Counter(PurePosixPath(f).parts[0] + ("/" if len(PurePosixPath(f).parts) > 1 else "") for f in files)
    entries = ", ".join(sorted(top))
    return (
        f"Audit this repository: {repo_url}\n"
        f"Checked out default branch '{checkout.default_branch}' at commit {checkout.head_commit[:12]}; "
        f"{checkout.commit_count} commit(s) available{' (shallow clone)' if checkout.shallow else ''}; "
        f"{len(files)} tracked file(s).\n"
        f"Top-level entries: {entries or '(none)'}\n\n"
        "Investigate with the tools, record each confirmed violation with record_violation, and call finish "
        "when all inspection areas have been considered."
    )


def _context_snippet(tools: RepoTools, f: Finding, radius: int = 4) -> str:
    if not f.file:
        return "(repository-level finding; no file)"
    try:
        lines = redact((tools.root / f.file).read_text("utf-8", "replace")).splitlines()
    except OSError:
        return "(file unreadable)"
    if not f.line:
        head = lines[:12]
        return "\n".join(f"{n:>5}| {t[:200]}" for n, t in enumerate(head, 1)) + ("\n  ..." if len(lines) > 12 else "")
    lo, hi = max(1, f.line - radius), min(len(lines), f.line + radius)
    return "\n".join(f"{'>' if n == f.line else ' '}{n:>4}| {lines[n - 1][:200]}" for n in range(lo, hi + 1))


def run_audit(repo_url: str, checkout: Checkout, llm: LLMClient, tracer: Tracer, config: AuditConfig) -> AuditResult:
    started = time.monotonic()
    tools = RepoTools(checkout.path)
    store = FindingStore(tools)
    raw_inspect_handlers = make_inspection_handlers(tools)
    inspection_tools_used: set[str] = set()

    def tracked_handler(name: str, handler: Callable[..., Any]) -> Callable[..., Any]:
        def call(**kwargs: Any) -> Any:
            result = handler(**kwargs)
            inspection_tools_used.add(name)
            return result
        return call

    inspect_handlers = {name: tracked_handler(name, handler) for name, handler in raw_inspect_handlers.items()}
    phases: dict[str, LoopOutcome] = {}
    observation_resolutions: dict[str, dict[str, str | None]] = {}
    observation_verdicts: dict[str, dict[str, str | None]] = {}

    tracer.event("audit_start", repository=repo_url, model=getattr(llm, "model", "?"),
                 default_branch=checkout.default_branch, head=checkout.head_commit,
                 tracked_files=len(tools.tracked_files()))

    # ---------------------------------------------------------- investigation
    investigate_deadline = started + config.timeout_s * (0.75 if config.verify else 1.0)

    def resolve_observation(args: dict[str, Any]) -> ToolResult:
        observation_id = str(args["observation_id"]).strip().upper()
        observations = {o.id: o for o in tools.workflow_observations}
        if observation_id not in observations:
            raise ToolError(
                f"unknown workflow observation '{observation_id}'; call inspect_workflows and use an emitted ID"
            )
        observation = observations[observation_id]
        decision = str(args["decision"]).lower()
        reason = str(args.get("reason") or "").strip()
        if len(reason) < 8:
            raise ToolError("reason is too short; cite the concrete workflow evidence behind the decision")
        finding_id = args.get("finding_id")
        if decision == "reported":
            if not finding_id:
                raise ToolError("reported requires finding_id for the finding that covers this observation")
            finding = store.get(str(finding_id))
            if finding.status not in ("candidate", "kept"):
                raise ToolError(f"{finding.id} is {finding.status}, so it cannot cover an observation")
            if finding.file != observation.file:
                raise ToolError(
                    f"{finding.id} cites {finding.file or 'the repository'}, but {observation_id} is in "
                    f"{observation.file}"
                )
            if observation.report_required and finding.rule_id != observation.suggested_rule:
                raise ToolError(
                    f"{observation_id} requires {observation.suggested_rule}, but {finding.id} uses "
                    f"{finding.rule_id}; record or link the correctly classified finding"
                )
            finding_id = finding.id
        elif decision == "dismissed":
            if finding_id:
                raise ToolError("dismissed observations must not provide finding_id")
            if observation.report_required:
                raise ToolError(
                    f"{observation_id} is a confirmed tracked workflow anti-pattern ({observation.kind}) and "
                    "cannot be dismissed because it is deliberate, educational, a detector fixture, or guarded. "
                    "Record a finding, mention any guard in the evidence, adjust severity if appropriate, then "
                    "resolve it as reported with finding_id."
                )
            finding_id = None
        else:
            raise ToolError("decision must be 'reported' or 'dismissed'")
        observation_resolutions[observation_id] = {
            "decision": decision, "reason": reason, "finding_id": finding_id,
        }
        return ToolResult(f"Resolved {observation_id} as {decision}.")

    def finish_investigation(args: dict[str, Any]) -> ToolResult:
        reviewed = {str(area).strip() for area in args.get("areas_reviewed", [])}
        unknown = sorted(reviewed - set(CATEGORIES))
        if unknown:
            return ToolResult(f"Not finished: unknown inspection area(s): {', '.join(unknown)}.", is_error=True)
        missing = [area for area in CATEGORIES if area not in reviewed]
        if missing:
            return ToolResult(f"Not finished: inspection areas not yet confirmed: {', '.join(missing)}.", is_error=True)
        if "list_files" not in inspection_tools_used:
            return ToolResult("Not finished: call list_files first to map the repository.", is_error=True)
        if len(inspection_tools_used) < 2:
            return ToolResult(
                "Not finished: use at least one follow-up inspection tool after mapping the repository.",
                is_error=True,
            )
        has_github_workflows = any(
            file.startswith(".github/workflows/") and file.endswith((".yml", ".yaml"))
            for file in tools.tracked_files()
        )
        if has_github_workflows and "inspect_workflows" not in inspection_tools_used:
            return ToolResult(
                "Not finished: GitHub Actions workflows exist; call inspect_workflows before completing the audit.",
                is_error=True,
            )
        pending_observations = [
            observation.id for observation in tools.workflow_observations
            if observation.id not in observation_resolutions
        ]
        if pending_observations:
            return ToolResult(
                "Not finished: high-risk workflow observations still need resolve_observation: "
                + ", ".join(pending_observations) + ".",
                is_error=True,
            )
        invalid_links = []
        for observation_id, resolution in observation_resolutions.items():
            if resolution["decision"] != "reported" or not resolution["finding_id"]:
                continue
            finding = store.get(str(resolution["finding_id"]))
            if finding.status not in ("candidate", "kept"):
                invalid_links.append(f"{observation_id}->{finding.id} ({finding.status})")
        if invalid_links:
            return ToolResult(
                "Not finished: reported workflow observations no longer have active findings: "
                + ", ".join(invalid_links) + ".",
                is_error=True,
            )
        return ToolResult("Investigation finished.", terminal=True)

    inv_schemas = INSPECTION_TOOL_SCHEMAS + [
        RECORD_VIOLATION_SCHEMA, WITHDRAW_SCHEMA, RESOLVE_OBSERVATION_SCHEMA, INVESTIGATION_FINISH_SCHEMA,
    ]
    inv_handlers = {
        **inspect_handlers,
        "record_violation": store.record,
        "withdraw_violation": store.withdraw,
        "resolve_observation": resolve_observation,
        "finish": finish_investigation,
    }
    tracer.say(f"[investigate] model={getattr(llm, 'model', '?')} max_steps={config.max_steps}")
    inv = AgentLoop(llm, INVESTIGATION_SYSTEM, inv_schemas, _dispatcher(inv_schemas, inv_handlers), tracer,
                    phase="investigate", max_steps=config.max_steps, deadline=investigate_deadline)
    phases["investigate"] = inv.run(_overview(tools, checkout, repo_url))
    tracer.say(f"[investigate] ended: {phases['investigate'].stop_reason}; "
               f"{len(store.active())} candidate finding(s)")
    if not phases["investigate"].finished:
        raise AuditIncompleteError(
            f"investigation stopped before finish ({phases['investigate'].stop_reason}); no report was written"
        )

    # ----------------------------------------------------------- verification
    candidates = store.active()
    dismissed_observations = [
        observation for observation in tools.workflow_observations
        if observation_resolutions.get(observation.id, {}).get("decision") == "dismissed"
    ]
    if config.verify and (candidates or dismissed_observations):
        def submit_finding_verdict(args: dict[str, Any]) -> ToolResult:
            finding = store.get(str(args["finding_id"]))
            if str(args["decision"]).lower() == "drop":
                observations = {o.id: o for o in tools.workflow_observations}
                required_links = [
                    observation_id
                    for observation_id, resolution in observation_resolutions.items()
                    if resolution.get("finding_id") == finding.id
                    and observations[observation_id].report_required
                ]
                if required_links:
                    raise ToolError(
                        f"{finding.id} is required by tracked workflow anti-pattern(s) "
                        f"{', '.join(required_links)} and cannot be dropped for being deliberate, educational, "
                        "a detector fixture, or guarded. Keep it and adjust severity if needed."
                    )
            return store.verdict(args)

        def submit_observation_verdict(args: dict[str, Any]) -> ToolResult:
            observation_id = str(args["observation_id"]).strip().upper()
            dismissed = {o.id: o for o in dismissed_observations}
            if observation_id not in dismissed:
                raise ToolError(f"'{observation_id}' is not a dismissed observation awaiting review")
            if observation_id in observation_verdicts:
                raise ToolError(f"{observation_id} already has a verification verdict")
            decision = str(args["decision"]).lower()
            reason = str(args.get("reason") or "").strip()
            if len(reason) < 8:
                raise ToolError("reason is too short; cite the concrete workflow evidence")
            finding_id = args.get("finding_id")
            if decision == "overturn":
                if not finding_id:
                    raise ToolError("overturn requires finding_id; record the missed violation first")
                finding = store.get(str(finding_id))
                if finding.status not in ("candidate", "kept"):
                    raise ToolError(f"{finding.id} is {finding.status}, so it cannot support an overturn")
                if finding.file != dismissed[observation_id].file:
                    raise ToolError(
                        f"{finding.id} cites {finding.file or 'the repository'}, but {observation_id} is in "
                        f"{dismissed[observation_id].file}"
                    )
                finding_id = finding.id
            elif decision == "uphold":
                if finding_id:
                    raise ToolError("uphold must not provide finding_id")
                finding_id = None
            else:
                raise ToolError("decision must be 'uphold' or 'overturn'")
            observation_verdicts[observation_id] = {
                "decision": decision, "reason": reason, "finding_id": finding_id,
            }
            return ToolResult(f"Verification {decision} recorded for {observation_id}.")

        def finish_verification(_args: dict[str, Any]) -> ToolResult:
            pending = [f.id for f in store.findings if f.status == "candidate"]
            if pending:
                return ToolResult(f"Not finished: no verdict yet for {', '.join(pending)}. Submit them, then finish.",
                                  is_error=True)
            pending_observations = [o.id for o in dismissed_observations if o.id not in observation_verdicts]
            if pending_observations:
                return ToolResult(
                    "Not finished: dismissed workflow observations still need independent verdicts: "
                    + ", ".join(pending_observations) + ".",
                    is_error=True,
                )
            return ToolResult("Verification finished.", terminal=True)

        ver_schemas = INSPECTION_TOOL_SCHEMAS + [
            RECORD_VIOLATION_SCHEMA, VERDICT_SCHEMA, OBSERVATION_VERDICT_SCHEMA, FINISH_SCHEMA,
        ]
        ver_handlers = {
            **inspect_handlers,
            "record_violation": store.record,
            "submit_verdict": submit_finding_verdict,
            "submit_observation_verdict": submit_observation_verdict,
            "finish": finish_verification,
        }
        blocks = []
        for f in candidates:
            blocks.append(
                f"### {f.id}\nrule_id={f.rule_id} category={f.category} severity={f.severity} "
                f"file={f.file} line={f.line}\ndescription: {f.description}\nevidence: {f.evidence}\n"
                f"recommendation: {f.recommendation}\ncontext:\n{_context_snippet(tools, f)}"
            )
        observation_blocks = []
        for observation in dismissed_observations:
            observation_blocks.append(
                f"### {observation.id}\nkind={observation.kind} suggested_rule={observation.suggested_rule} "
                f"file={observation.file} line={observation.line}\nsummary: {observation.summary}\n"
                f"facts: {'; '.join(observation.evidence)}\nguard check: {observation.mitigation}\n"
                "Review this from the raw facts independently. The investigator's rationale is intentionally "
                "withheld to avoid anchoring."
            )
        task = (
            f"Repository: {repo_url} (default branch '{checkout.default_branch}').\n"
            f"Review {len(candidates)} candidate finding(s) and {len(dismissed_observations)} dismissed "
            "high-risk workflow observation(s). Submit a verdict for every item.\n\n"
            + "\n\n".join(blocks + observation_blocks)
        )
        verify_steps = config.verify_steps
        tracer.say(
            f"[verify] reviewing {len(candidates)} candidate(s) and "
            f"{len(dismissed_observations)} dismissal(s), max_steps={verify_steps}"
        )
        ver = AgentLoop(llm, VERIFICATION_SYSTEM, ver_schemas, _dispatcher(ver_schemas, ver_handlers), tracer,
                        phase="verify", max_steps=verify_steps, deadline=started + config.timeout_s)
        phases["verify"] = ver.run(task)
        if not phases["verify"].finished:
            raise AuditIncompleteError(
                f"verification stopped before finish ({phases['verify'].stop_reason}); no report was written"
            )
        undecided = [f for f in store.findings if f.status == "candidate"]
        if undecided:
            raise AuditIncompleteError(
                f"verification finished with undecided findings: {', '.join(f.id for f in undecided)}; "
                "no report was written"
            )
        tracer.say(f"[verify] ended: {phases['verify'].stop_reason}; kept {len(store.active())}, "
                   f"dropped {sum(f.status == 'dropped' for f in store.findings)}"
                   + (f", {len(undecided)} undecided (kept)" if undecided else ""))

    final = store.active()
    report = build_report(repo_url, final)
    usage: dict[str, int] = {}
    for outcome in phases.values():
        for k, v in (outcome.usage or {}).items():
            usage[k] = usage.get(k, 0) + v
    tracer.event(
        "audit_end", duration_s=round(time.monotonic() - started, 1), usage=usage,
        phases={k: {"steps": v.steps, "stop_reason": v.stop_reason} for k, v in phases.items()},
        findings=[{"id": f.id, "rule_id": f.rule_id, "status": f.status, "severity": f.severity,
                   "file": f.file, "line": f.line, "notes": f.notes} for f in store.findings],
        workflow_observations=[
            {
                "id": o.id, "kind": o.kind, "file": o.file, "line": o.line,
                "report_required": o.report_required,
                "investigation": observation_resolutions.get(o.id),
                "verification": observation_verdicts.get(o.id),
            }
            for o in tools.workflow_observations
        ],
    )
    return AuditResult(report=report, findings=final, phases=phases)
