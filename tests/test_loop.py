"""Agent-loop behaviour with a scripted LLM: dispatch, error feedback, budgets, termination."""

import re
import time

import pytest

from auditor.auditor import AuditConfig, AuditIncompleteError, run_audit
from auditor.findings import CATEGORIES
from auditor.llm import LLMError
from auditor.loop import AgentLoop
from auditor.repo import Checkout
from auditor.trace import Tracer
from conftest import FakeLLM, last_tool_results, make_repo
from tools import ToolResult


def _audit_finish(summary="done"):
    return {"summary": summary, "areas_reviewed": list(CATEGORIES)}


def _loop(llm, handler, max_steps=10, deadline=None):
    tools = [{"name": n, "description": n, "input_schema": {"type": "object"}} for n in ("echo", "finish")]
    return AgentLoop(llm, "system", tools, handler, Tracer(None, verbose=False), "test", max_steps, deadline)


def _handler(log):
    def handle(name, args):
        log.append((name, args))
        if name == "finish":
            return ToolResult("done", terminal=True)
        if name == "boom":
            raise RuntimeError("tool crashed")
        return ToolResult(f"echo {args}")
    return handle


def test_loop_runs_tools_and_finishes():
    log = []
    llm = FakeLLM([[("echo", {"x": 1}), ("echo", {"x": 2})], [("finish", {})]])
    out = _loop(llm, _handler(log)).run("go")
    assert out.finished and out.stop_reason == "finished" and out.steps == 2
    assert log == [("echo", {"x": 1}), ("echo", {"x": 2}), ("finish", {})]
    # both results returned in ONE tool turn, matched to their call ids/names, budget note attached
    second_request = llm.calls[1]["messages"]
    results = last_tool_results(second_request)
    assert [(r["id"], r["name"]) for r in results] == [("toolu_1_0", "echo"), ("toolu_1_1", "echo")]
    assert second_request[-1]["note"].startswith("[test: turn 1/10")
    assert second_request[1]["role"] == "assistant" and "raw" in second_request[1]


def test_tool_exception_becomes_error_result_not_crash():
    llm = FakeLLM([[("boom", {})], [("finish", {})]])
    out = _loop(llm, _handler([])).run("go")
    assert out.finished
    err = last_tool_results(llm.calls[1]["messages"])[0]
    assert err["is_error"] is True and "tool crashed" in err["content"]


def test_text_reply_is_nudged_then_gives_up():
    llm = FakeLLM(["thinking...", "still thinking", "no tools", "never"])
    out = _loop(llm, _handler([])).run("go")
    assert out.stop_reason == "no_tool_calls" and not out.finished
    assert "Continue the investigation" in llm.calls[1]["messages"][-1]["content"]


def test_max_steps_enforced():
    llm = FakeLLM([[("echo", {})]] * 10)
    out = _loop(llm, _handler([]), max_steps=3).run("go")
    assert out.stop_reason == "max_steps" and len(llm.calls) == 3
    assert "Budget almost exhausted" in llm.calls[-1]["messages"][-1]["note"]


def test_deadline_enforced():
    llm = FakeLLM([[("echo", {})]] * 5)
    out = _loop(llm, _handler([]), deadline=time.monotonic() - 1).run("go")
    assert out.stop_reason == "deadline" and llm.calls == []


def test_truncated_turn_does_not_execute_tools():
    log = []
    llm = FakeLLM([[("echo", {"x": 1})], [("finish", {})]], stop_reason_override={1: "max_tokens"})
    _loop(llm, _handler(log)).run("go")
    assert log == [("finish", {})]
    assert last_tool_results(llm.calls[1]["messages"])[0]["is_error"] is True


def test_malformed_call_gets_specific_retry_hint():
    llm = FakeLLM(["", [("finish", {})]], stop_reason_override={1: "malformed_tool_call"})
    out = _loop(llm, _handler([])).run("go")
    assert out.finished
    assert "malformed" in llm.calls[1]["messages"][-1]["content"]


def test_refusal_raises():
    llm = FakeLLM(["no"], stop_reason_override={1: "refusal"})
    with pytest.raises(LLMError):
        _loop(llm, _handler([])).run("go")


def _checkout(path):
    return Checkout(path=path, default_branch="main", head_commit="0" * 40, commit_count=2, shallow=False)


def test_full_audit_llm_driven_tool_selection(defect_repo):
    """The model's *follow-up* calls depend on what earlier tools returned."""

    def investigate_secret(messages):
        listing = last_tool_results(messages)[0]["content"]
        assert "config.py" in listing  # decision based on the observation
        return [("search_code", {"pattern": r"API_KEY\s*="})]

    def record_from_search(messages):
        hit = last_tool_results(messages)[0]["content"]
        line = int(hit.split("config.py:")[1].split(":")[0])
        return [("read_file", {"path": "config.py", "start_line": line, "end_line": line}),
                ("record_violation", {
                    "rule_id": "SEC-001", "category": "security", "severity": "critical", "file": "config.py",
                    "line": line, "description": "Hardcoded API key in config.py",
                    "evidence": "API_KEY is assigned a literal sk- style key (value redacted)",
                    "recommendation": "Read the key from an environment variable and rotate the exposed key."}),
                ("record_violation", {
                    "rule_id": "HYG-001", "category": "repository_hygiene", "severity": "low", "file": None,
                    "line": None, "description": "README is missing",
                    "evidence": "Claimed README absence", "recommendation": "Add a README.md"})]

    llm = FakeLLM([
        [("list_files", {}), ("inspect_workflows", {})],
        investigate_secret,
        record_from_search,
        [("finish", _audit_finish())],
        # verification phase
        [("submit_verdict", {"finding_id": "V1", "decision": "keep", "reason": "literal key"}),
         ("submit_verdict", {"finding_id": "V2", "decision": "drop", "reason": "README.md exists"})],
        [("finish", {"summary": "verified"})],
    ])
    result = run_audit("https://github.com/o/r", _checkout(defect_repo), llm, Tracer(None, verbose=False),
                       AuditConfig(max_steps=10, verify_steps=5))
    assert [v["rule_id"] for v in result.report["violations"]] == ["SEC-001"]
    assert result.report["violations"][0]["line"] == 3
    assert result.phases["investigate"].finished and result.phases["verify"].finished
    # verification phase received the candidates with context
    verify_prompt = llm.calls[4]["messages"][0]["content"]
    assert "### V1" in verify_prompt and "### V2" in verify_prompt and ">   3|" in verify_prompt
    assert "submit_verdict" in llm.calls[4]["tools"] and "record_violation" in llm.calls[4]["tools"]


def test_rejected_finding_is_reported_back_to_model(defect_repo):
    llm = FakeLLM([
        [("list_files", {}), ("inspect_workflows", {})],
        [("record_violation", {"rule_id": "SEC-001", "category": "security", "severity": "critical",
                               "file": "secrets.py", "line": 1, "description": "Hardcoded secret here",
                               "evidence": "a secret", "recommendation": "remove it now"})],
        [("finish", _audit_finish())],
    ])
    result = run_audit("u", _checkout(defect_repo), llm, Tracer(None, verbose=False), AuditConfig(verify=False))
    err = last_tool_results(llm.calls[2]["messages"])[0]
    assert err["is_error"] and "does not exist" in err["content"]
    assert result.report["violations"] == []


def test_verification_finish_requires_all_verdicts(defect_repo):
    rec = ("record_violation", {"rule_id": "CFG-002", "category": "configuration", "severity": "medium",
                                "file": ".env", "line": 1, "description": "Local .env file is tracked",
                                "evidence": ".env is committed and not ignored", "recommendation": "Untrack it"})
    llm = FakeLLM([[('list_files', {}), ('inspect_workflows', {})],
                   [rec], [("finish", _audit_finish("x"))],
                   [("finish", {"summary": "lazy"})],
                   [("finish", {"summary": "still lazy"})],
                   [("submit_verdict", {"finding_id": "V1", "decision": "keep", "reason": "ok"})],
                   [("finish", {"summary": "ok"})]])
    result = run_audit("u", _checkout(defect_repo), llm, Tracer(None, verbose=False), AuditConfig())
    first_finish = last_tool_results(llm.calls[4]["messages"])[0]
    second_finish = last_tool_results(llm.calls[5]["messages"])[0]
    assert first_finish["is_error"] and "V1" in first_finish["content"]
    assert second_finish["is_error"] and "V1" in second_finish["content"]
    assert len(result.report["violations"]) == 1


def test_investigation_finish_requires_mapping_followup_and_all_areas(defect_repo):
    llm = FakeLLM([
        [("finish", _audit_finish("too early"))],
        [("list_files", {})],
        [("finish", _audit_finish("still early"))],
        [("inspect_workflows", {})],
        [("finish", {"summary": "missing areas", "areas_reviewed": ["security"]})],
        [("finish", _audit_finish("complete"))],
    ])
    result = run_audit(
        "u", _checkout(defect_repo), llm, Tracer(None, verbose=False),
        AuditConfig(max_steps=6, verify=False),
    )
    assert result.phases["investigate"].finished
    assert "list_files" in last_tool_results(llm.calls[1]["messages"])[0]["content"]
    assert "follow-up" in last_tool_results(llm.calls[3]["messages"])[0]["content"]
    assert "not yet confirmed" in last_tool_results(llm.calls[5]["messages"])[0]["content"]


def test_workflow_repository_must_run_workflow_inspection(defect_repo):
    llm = FakeLLM([
        [("list_files", {}), ("search_code", {"pattern": "API_KEY"})],
        [("finish", _audit_finish())],
        [("inspect_workflows", {})],
        [("finish", _audit_finish())],
    ])
    result = run_audit(
        "u", _checkout(defect_repo), llm, Tracer(None, verbose=False),
        AuditConfig(max_steps=4, verify=False),
    )
    rejected_finish = last_tool_results(llm.calls[2]["messages"])[0]
    assert rejected_finish["is_error"] and "call inspect_workflows" in rejected_finish["content"]
    assert result.phases["investigate"].finished


def test_incomplete_investigation_raises_instead_of_building_partial_report(defect_repo):
    llm = FakeLLM([[("list_files", {}), ("inspect_workflows", {})]])
    with pytest.raises(AuditIncompleteError, match="investigation stopped before finish"):
        run_audit(
            "u", _checkout(defect_repo), llm, Tracer(None, verbose=False),
            AuditConfig(max_steps=1, verify=False),
        )


def test_incomplete_verification_raises_instead_of_keeping_undecided(defect_repo):
    rec = ("record_violation", {"rule_id": "CFG-002", "category": "configuration", "severity": "medium",
                                "file": ".env", "line": 1, "description": "Local .env file is tracked",
                                "evidence": ".env is committed and not ignored", "recommendation": "Untrack it"})
    llm = FakeLLM([
        [("list_files", {}), ("inspect_workflows", {})], [rec], [("finish", _audit_finish())],
        [("submit_verdict", {"finding_id": "V1", "decision": "keep", "reason": "confirmed"})],
    ])
    with pytest.raises(AuditIncompleteError, match="verification stopped before finish"):
        run_audit(
            "u", _checkout(defect_repo), llm, Tracer(None, verbose=False),
            AuditConfig(max_steps=5, verify_steps=1),
        )


def test_active_workflow_antipattern_cannot_be_dismissed_as_educational(tmp_path):
    repo = make_repo(tmp_path / "active-injection", [("initial", {
        "README.md": "# Educational example\nThis is intentionally safe.\n",
        ".github/workflows/injection.yml": """\
name: Injection demo
on: issues
jobs:
  unsafe:
    runs-on: ubuntu-latest
    steps:
      - name: Print issue
        run: echo \"${{ github.event.issue.title }}\"
""",
    }, [])])
    seen: dict[str, str] = {}

    def dismiss_observation(messages):
        output = "\n".join(result["content"] for result in last_tool_results(messages))
        seen["id"] = re.search(r"WF-[0-9A-F]{8}", output).group(0)
        return [
            ("read_file", {"path": ".github/workflows/injection.yml"}),
            ("resolve_observation", {
                "observation_id": seen["id"], "decision": "dismissed",
                "reason": "The README describes this as an educational example.",
            }),
        ]

    def report_after_rejected_dismissal(messages):
        results = last_tool_results(messages)
        dismissal = next(result for result in results if result["name"] == "resolve_observation")
        assert dismissal["is_error"] and "cannot be dismissed" in dismissal["content"]
        return [
            ("record_violation", {
                "rule_id": "SEC-005", "category": "security", "severity": "high",
                "file": ".github/workflows/injection.yml", "line": 8,
                "description": "Issue title is interpolated directly into a shell command.",
                "evidence": "The run step directly expands github.event.issue.title.",
                "recommendation": "Pass the title through an environment variable and quote it in the shell.",
            }),
            ("resolve_observation", {
                "observation_id": seen["id"], "decision": "reported", "finding_id": "V1",
                "reason": "The tracked direct event-to-shell interpolation is covered by V1.",
            }),
        ]

    llm = FakeLLM([
        [("list_files", {}), ("inspect_workflows", {})],
        dismiss_observation,
        report_after_rejected_dismissal,
        [("finish", _audit_finish())],
        [("submit_verdict", {
            "finding_id": "V1", "decision": "drop",
            "reason": "The README says this was deliberately inserted for education.",
        })],
        [("submit_verdict", {"finding_id": "V1", "decision": "keep", "reason": "Active injection confirmed"})],
        [("finish", {"summary": "recall review complete"})],
    ])
    result = run_audit(
        "u", _checkout(repo), llm, Tracer(None, verbose=False),
        AuditConfig(max_steps=6, verify_steps=5),
    )
    assert [v["rule_id"] for v in result.report["violations"]] == ["SEC-005"]
    rejected_drop = last_tool_results(llm.calls[5]["messages"])[0]
    assert rejected_drop["is_error"] and "cannot be dropped" in rejected_drop["content"]
    assert result.phases["verify"].finished and len(llm.calls) == 7


def test_fake_placeholder_dismissal_gets_blind_zero_finding_review(tmp_path):
    repo = make_repo(tmp_path / "fake-placeholder", [("initial", {
        "README.md": "# Demo\n",
        ".github/workflows/demo.yml": """\
name: Placeholder demo
on: workflow_dispatch
jobs:
  demo:
    runs-on: ubuntu-latest
    env:
      DEMO_SECRET: NOT_A_REAL_SECRET
    steps:
      - run: echo "$DEMO_SECRET"
""",
    }, [])])
    seen: dict[str, str] = {}

    def dismiss_placeholder(messages):
        output = "\n".join(result["content"] for result in last_tool_results(messages))
        seen["id"] = re.search(r"WF-[0-9A-F]{8}", output).group(0)
        return [("resolve_observation", {
            "observation_id": seen["id"], "decision": "dismissed",
            "reason": "DEMO_SECRET is explicitly assigned the NOT_A_REAL_SECRET placeholder.",
        })]

    def uphold_independently(messages):
        prompt = messages[0]["content"]
        assert seen["id"] in prompt
        assert "NOT_A_REAL_SECRET placeholder" not in prompt
        assert "rationale is intentionally withheld" in prompt
        return [("submit_observation_verdict", {
            "observation_id": seen["id"], "decision": "uphold",
            "reason": "The variable is an explicit fake placeholder rather than a credential.",
        })]

    llm = FakeLLM([
        [("list_files", {}), ("inspect_workflows", {})],
        dismiss_placeholder,
        [("finish", _audit_finish())],
        uphold_independently,
        [("finish", {"summary": "placeholder dismissal verified"})],
    ])
    result = run_audit(
        "u", _checkout(repo), llm, Tracer(None, verbose=False),
        AuditConfig(max_steps=5, verify_steps=3),
    )
    assert result.report["violations"] == [] and result.phases["verify"].finished


def test_investigation_cannot_finish_with_unresolved_workflow_observation(tmp_path):
    repo = make_repo(tmp_path / "unresolved", [("initial", {
        "README.md": "# Demo\n",
        ".github/workflows/injection.yml": """\
name: Demo
on: issues
jobs:
  unsafe:
    runs-on: ubuntu-latest
    steps:
      - run: echo \"${{ github.event.issue.title }}\"
""",
    }, [])])
    observed: dict[str, str] = {}

    def resolve_after_rejection(messages):
        results = last_tool_results(messages)
        assert results[0]["is_error"] and "resolve_observation" in results[0]["content"]
        all_text = "\n".join(
            result["content"]
            for call in llm.calls
            for message in call["messages"]
            if message.get("role") == "tool"
            for result in message["results"]
        )
        observed["id"] = re.search(r"WF-[0-9A-F]{8}", all_text).group(0)
        return [
            ("record_violation", {
                "rule_id": "SEC-005", "category": "security", "severity": "high",
                "file": ".github/workflows/injection.yml", "line": 7,
                "description": "Issue title is interpolated directly into a shell command.",
                "evidence": "The run step directly expands github.event.issue.title.",
                "recommendation": "Pass the title through a quoted environment variable.",
            }),
            ("resolve_observation", {
                "observation_id": observed["id"], "decision": "reported", "finding_id": "V1",
                "reason": "The workflow anti-pattern is recorded as V1.",
            }),
        ]

    llm = FakeLLM([
        [("list_files", {}), ("inspect_workflows", {})],
        [("finish", _audit_finish())],
        resolve_after_rejection,
        [("finish", _audit_finish())],
    ])
    result = run_audit(
        "u", _checkout(repo), llm, Tracer(None, verbose=False),
        AuditConfig(max_steps=5, verify=False),
    )
    assert result.phases["investigate"].finished
    assert [finding["rule_id"] for finding in result.report["violations"]] == ["SEC-005"]
