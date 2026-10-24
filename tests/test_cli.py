"""End-to-end CLI tests with the LLM replaced by a scripted fake."""

import json

import pytest

import agent
from auditor.findings import CATEGORIES
from auditor.repo import RepoError, parse_repo
from conftest import FakeLLM, git


def _audit_finish(summary="done"):
    return {"summary": summary, "areas_reviewed": list(CATEGORIES)}


@pytest.mark.parametrize("url, expected", [
    ("https://github.com/owner/repo", "https://github.com/owner/repo"),
    ("https://github.com/owner/repo.git", "https://github.com/owner/repo"),
    ("github.com/owner/my.repo/", "https://github.com/owner/my.repo"),
    ("https://github.com/owner/repo/tree/main/src", "https://github.com/owner/repo"),
    ("https://GitHub.com/owner/repo", "https://github.com/owner/repo"),
    ("HTTPS://WWW.GITHUB.COM/owner/repo", "https://github.com/owner/repo"),
    ("https://github.com/owner/repo?tab=readme-ov-file", "https://github.com/owner/repo"),
    ("https://github.com/owner/repo#readme", "https://github.com/owner/repo"),
    ("https://github.com/owner/repo/blob/main/a.py?plain=1#L10", "https://github.com/owner/repo"),
])
def test_parse_repo_accepts_github_urls(url, expected):
    assert parse_repo(url).display_url == expected


@pytest.mark.parametrize("url, message", [
    ("", "is empty"),
    ("not a url", "not a GitHub repository URL"),
    ("https://gitlab.com/o/r", "not a GitHub repository URL"),
    ("https://github.com/onlyowner", "not a GitHub repository URL"),
    ("https://github.com/onlyowner?tab=repositories", "not a GitHub repository URL"),
    ("https://github.com/o/r/issues", "not a GitHub repository URL"),
    ("https://github.com/o/r; rm -rf /", "not a GitHub repository URL"),
    ("file:///etc", "not a GitHub repository URL"),
    ("https://github.com/o/..", "invalid repository name"),
    ("./does-not-exist", "does not exist"),
    ("../nope/repo", "does not exist"),
    ("C:\\no\\such\\folder", "does not exist"),
    ("/no/such/folder", "does not exist"),
])
def test_parse_repo_rejects_invalid(url, message):
    with pytest.raises(RepoError, match=message):
        parse_repo(url)


def test_parse_repo_local_paths(tmp_path, healthy_repo):
    assert parse_repo(str(healthy_repo)).display_url == str(healthy_repo.resolve())
    with pytest.raises(RepoError, match="is not a git repository"):
        parse_repo(str(tmp_path))
    f = tmp_path / "file.txt"
    f.write_text("x")
    with pytest.raises(RepoError, match="is a file"):
        parse_repo(str(f))


def test_git_messages_forced_to_english():
    from auditor.repo import _git_env
    env = _git_env()
    assert env["LC_ALL"] == env["LANGUAGE"] == "C"
    assert env["GIT_TERMINAL_PROMPT"] == "0"


@pytest.mark.parametrize("git_message", [
    "git clone failed: remote: Repository not found.\nfatal: repository 'https://github.com/o/r.git/' not found",
    "git clone failed: fatal: could not read Username for 'https://github.com': terminal prompts disabled",
    "git clone failed: fatal: Authentication failed for 'https://github.com/o/r.git/'",
])
def test_clone_not_found_messages_are_friendly(git_message):
    from auditor.repo import _clone_error
    assert str(_clone_error(RepoError(git_message), "https://github.com/o/r")) == \
        "repository https://github.com/o/r not found or not public"


def test_clone_other_errors_pass_through():
    from auditor.repo import _clone_error
    exc = RepoError("git clone failed: fatal: unable to access ...: Could not resolve host: github.com")
    assert _clone_error(exc, "https://github.com/o/r") is exc


def test_invalid_url_exits_2(tmp_path, capsys):
    assert agent.main(["--repo", "https://example.com/x", "--output", str(tmp_path / "r.json")]) == 2
    assert "not a GitHub repository URL" in capsys.readouterr().err
    assert not (tmp_path / "r.json").exists()


def test_missing_credentials_exit_4(tmp_path, monkeypatch, capsys, defect_repo):
    for var in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(agent, "_load_env", lambda: None)
    assert agent.main(["--repo", str(defect_repo), "--output", str(tmp_path / "r.json")]) == 4
    assert "GEMINI_API_KEY" in capsys.readouterr().err


def test_end_to_end_writes_valid_report_and_leaves_repo_unchanged(tmp_path, monkeypatch, defect_repo):
    head = git(defect_repo, "rev-parse", "HEAD")
    llm = FakeLLM([
        [("list_files", {}), ("inspect_workflows", {})],
        [("record_violation", {
            "rule_id": "SEC-004", "category": "security", "severity": "critical",
            "file": ".github/workflows/ci.yml", "line": 3,
            "description": "pull_request_target workflow checks out and runs PR code",
            "evidence": 'Trigger "pull_request_target:" plus checkout of the PR head sha and pytest run',
            "recommendation": "Use pull_request, or never check out untrusted code under pull_request_target."})],
        [("finish", _audit_finish())],
        [("submit_verdict", {"finding_id": "V1", "decision": "keep", "reason": "confirmed"})],
        [("finish", {"summary": "ok"})],
    ])
    monkeypatch.setattr(agent, "make_llm", lambda model: llm)
    out = tmp_path / "report.json"
    code = agent.main(["--repo", str(defect_repo), "--output", str(out), "-q"])
    assert code == 0
    report = json.loads(out.read_text())
    assert report["repository"] == str(defect_repo.resolve())
    assert report["violations"][0]["rule_id"] == "SEC-004"
    trace = [json.loads(line) for line in (tmp_path / "report.trace.jsonl").read_text().splitlines()]
    assert {"audit_start", "llm_turn", "tool_call", "audit_end"} <= {e["event"] for e in trace}
    assert git(defect_repo, "status", "--porcelain") == "" and git(defect_repo, "rev-parse", "HEAD") == head


def test_no_findings_still_writes_empty_report(tmp_path, monkeypatch, healthy_repo):
    llm = FakeLLM([
        [("list_files", {}), ("inspect_workflows", {})],
        [("finish", _audit_finish("healthy"))],
    ])
    monkeypatch.setattr(agent, "make_llm", lambda model: llm)
    out = tmp_path / "r.json"
    assert agent.main(["--repo", str(healthy_repo), "--output", str(out), "--trace", "none", "-q"]) == 0
    assert json.loads(out.read_text())["violations"] == []


def test_llm_failure_exits_5_without_report(tmp_path, monkeypatch, healthy_repo):
    from auditor.llm import LLMError

    class Broken(FakeLLM):
        def complete(self, *a, **k):
            raise LLMError("server exploded")

    monkeypatch.setattr(agent, "make_llm", lambda model: Broken([]))
    out = tmp_path / "r.json"
    assert agent.main(["--repo", str(healthy_repo), "--output", str(out), "-q"]) == 5
    assert not out.exists()


def test_incomplete_audit_exits_7_without_report(tmp_path, monkeypatch, healthy_repo):
    llm = FakeLLM([[("list_files", {}), ("inspect_workflows", {})]])
    monkeypatch.setattr(agent, "make_llm", lambda model: llm)
    out = tmp_path / "r.json"
    code = agent.main([
        "--repo", str(healthy_repo), "--output", str(out), "--trace", "none",
        "--max-steps", "1", "-q",
    ])
    assert code == 7
    assert not out.exists()


def test_missing_local_repo_exits_2(tmp_path):
    assert agent.main(["--repo", str(tmp_path / "nope"), "--output", str(tmp_path / "r.json")]) == 2


def test_unwritable_report_exits_6(tmp_path, monkeypatch, capsys, healthy_repo):
    llm = FakeLLM([
        [("list_files", {}), ("inspect_workflows", {})],
        [("finish", _audit_finish())],
    ])
    monkeypatch.setattr(agent, "make_llm", lambda model: llm)
    out_dir = tmp_path / "report.json"
    out_dir.mkdir()  # the output path is a directory, so the report cannot be written there
    code = agent.main(["--repo", str(healthy_repo), "--output", str(out_dir), "--trace", "none", "-q"])
    assert code == 6
    assert "report could not be written" in capsys.readouterr().err


def test_ctrl_c_exits_130(tmp_path, monkeypatch, capsys, healthy_repo):
    class Interrupted(FakeLLM):
        def complete(self, *a, **k):
            raise KeyboardInterrupt

    monkeypatch.setattr(agent, "make_llm", lambda model: Interrupted([]))
    out = tmp_path / "r.json"
    assert agent.main(["--repo", str(healthy_repo), "--output", str(out), "-q"]) == 130
    assert "error: interrupted" in capsys.readouterr().err
    assert not out.exists()


def test_bad_trace_path_gives_error_line(tmp_path, monkeypatch, capsys, healthy_repo):
    monkeypatch.setattr(agent, "make_llm", lambda model: FakeLLM([]))
    blocker = tmp_path / "file"
    blocker.write_text("x")
    code = agent.main(["--repo", str(healthy_repo), "--output", str(tmp_path / "r.json"),
                       "--trace", str(blocker / "trace.jsonl")])
    assert code == 2
    assert "cannot create trace file" in capsys.readouterr().err


def test_missing_dependency_gives_error_line(tmp_path, monkeypatch, capsys, healthy_repo):
    import sys
    monkeypatch.setitem(sys.modules, "auditor.report", None)  # makes `from auditor.report import ...` fail
    code = agent.main(["--repo", str(healthy_repo), "--output", str(tmp_path / "r.json")])
    err = capsys.readouterr().err
    assert code == 1
    assert "missing dependency" in err and "Traceback" not in err
