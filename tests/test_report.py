import json

import pytest

from auditor.findings import Finding
from auditor.report import ReportError, build_report, validate_report, write_report


def _f(id_, severity, file="a.py", line=1, **kw):
    return Finding(id_, kw.get("rule_id", "SEC-001"), kw.get("category", "security"), severity, file, line,
                   "Hardcoded credential", kw.get("evidence", "literal key assigned"), "Use env vars")


def test_empty_report_is_valid(tmp_path):
    report = build_report("https://github.com/o/r", [])
    assert report == {"repository": "https://github.com/o/r", "violations": []}
    out = write_report(report, tmp_path / "sub" / "report.json")
    assert json.loads(out.read_text()) == report


def test_report_fields_order_and_sorting():
    report = build_report("https://github.com/o/r", [_f("V1", "low"), _f("V2", "critical", file=None, line=None)])
    assert [v["severity"] for v in report["violations"]] == ["critical", "low"]
    assert list(report["violations"][0]) == ["rule_id", "category", "severity", "file", "line",
                                            "description", "evidence", "recommendation"]
    assert report["violations"][0]["file"] is None and report["violations"][0]["line"] is None


def test_report_redacts_evidence():
    report = build_report("u", [_f("V1", "high", evidence='token = "abcdef1234567890xyz"')])
    assert "abcdef1234567890xyz" not in json.dumps(report)


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(extra=1),
    lambda r: r["violations"][0].update(severity="urgent"),
    lambda r: r["violations"][0].pop("evidence"),
    lambda r: r["violations"][0].update(line=0),
    lambda r: r["violations"][0].update(file=None),
    lambda r: r["violations"][0].update(category="misc"),
    lambda r: r["violations"][0].update(evidence='password = "hunter2xyz"'),
])
def test_validate_rejects_contract_violations(mutate):
    report = build_report("u", [_f("V1", "high")])
    mutate(report)
    with pytest.raises(ReportError):
        validate_report(report)
