import pytest

from auditor.findings import FindingStore
from conftest import FAKE_KEY
from tools import RepoTools, ToolError


def _finding(**over):
    base = {
        "rule_id": "SEC-001", "category": "security", "severity": "critical", "file": "config.py", "line": 3,
        "description": "Hardcoded API credential in config.py",
        "evidence": 'config.py line 3 assigns a literal key: "API_KEY = "',
        "recommendation": "Load the key from an environment variable or a secrets manager and rotate it.",
    }
    base.update(over)
    return base


@pytest.fixture
def store(defect_repo):
    return FindingStore(RepoTools(defect_repo))


def test_record_valid_finding(store):
    res = store.record(_finding())
    assert "Recorded V1" in res.content
    assert store.active()[0].file == "config.py"


def test_category_alias_and_case_normalised(store):
    store.record(_finding(category="Security", severity="CRITICAL", rule_id="sec-001"))
    f = store.active()[0]
    assert (f.category, f.severity, f.rule_id) == ("security", "critical", "SEC-001")


@pytest.mark.parametrize("override, message", [
    ({"severity": "urgent"}, "severity must be one of"),
    ({"category": "misc"}, "category must be one of"),
    ({"rule_id": "secret-1"}, "rule_id must look like"),
    ({"file": "nope.py"}, "does not exist"),
    ({"file": "../etc/passwd"}, "invalid file"),
    ({"line": 999}, "outside config.py"),
    ({"description": "bad"}, "too short"),
    ({"evidence": 'it says "this text is not in the file at all"'}, "quoted snippets"),
])
def test_invalid_findings_rejected(store, override, message):
    with pytest.raises(ToolError, match=message):
        store.record(_finding(**override))
    assert store.active() == []


def test_evidence_found_elsewhere_points_to_right_line(tmp_path):
    from conftest import make_repo
    lines = [f"x{i} = {i}" for i in range(1, 30)]
    lines[19] = "VERIFY_SSL = False"
    repo = make_repo(tmp_path / "r", [("init", {"settings.py": "\n".join(lines) + "\n"}, [])])
    store = FindingStore(RepoTools(repo))
    with pytest.raises(ToolError, match="settings.py:20"):
        store.record(_finding(rule_id="SEC-008", file="settings.py", line=2,
                              evidence='TLS verification disabled: "VERIFY_SSL = False"'))
    store.record(_finding(rule_id="SEC-008", file="settings.py", line=20,
                          evidence='TLS verification disabled: "VERIFY_SSL = False"'))
    assert store.active()[0].line == 20


def test_missing_file_finding_uses_null(store):
    store.record(_finding(rule_id="DEP-004", category="dependency_management", severity="medium",
                          file=None, line=12, evidence="No lockfile next to requirements.txt"))
    f = store.active()[0]
    assert f.file is None and f.line is None


def test_duplicates_rejected(store):
    store.record(_finding())
    with pytest.raises(ToolError, match="duplicate of V1"):
        store.record(_finding())


def test_secret_values_are_redacted_from_fields(store):
    store.record(_finding(evidence=f"The key {FAKE_KEY} is hardcoded on line 3"))
    assert FAKE_KEY not in store.active()[0].evidence


def test_withdraw_and_verdicts(store):
    store.record(_finding())
    store.record(_finding(rule_id="CFG-001", category="configuration", severity="medium", file="app.py", line=3,
                          evidence="DATA_DIR points to a Windows user directory",
                          description="Machine-specific absolute path"))
    store.verdict({"finding_id": "V1", "decision": "keep", "reason": "real", "severity": "high"})
    store.verdict({"finding_id": "v2", "decision": "drop", "reason": "dup"})
    assert [f.id for f in store.active()] == ["V1"]
    assert store.active()[0].severity == "high"
    store.withdraw({"finding_id": "V1", "reason": "test"})
    assert store.active() == []
    with pytest.raises(ToolError, match="no finding"):
        store.verdict({"finding_id": "V9", "decision": "keep", "reason": "x"})
