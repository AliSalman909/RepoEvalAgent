import shutil

import pytest

from conftest import FAKE_KEY, git, make_repo
from tools import INSPECTION_TOOL_SCHEMAS, RepoTools, ToolError, validate_args


def test_list_files_shows_tracked_files_and_summary(defect_repo):
    out = RepoTools(defect_repo).list_files()
    assert "tracked file(s)" in out
    assert "config.py" in out and ".github/workflows/ci.yml" in out
    assert "deploy_keys.txt" not in out  # deleted in the second commit
    assert ".git/" not in out


def test_list_files_path_and_depth(defect_repo):
    tools = RepoTools(defect_repo)
    assert "tests/test_app.py" in tools.list_files(path="tests")
    collapsed = tools.list_files(max_depth=1)
    assert ".github/" in collapsed and "more file(s)" in collapsed
    assert "No tracked files" in tools.list_files(path="nope")


def test_read_file_numbers_lines_and_ranges(defect_repo):
    out = RepoTools(defect_repo).read_file("config.py", start_line=3, end_line=3)
    assert "lines 3-3 of 4" in out
    assert "    3| API_KEY" in out


def test_read_file_redacts_secrets(defect_repo):
    tools = RepoTools(defect_repo)
    out = tools.read_file("config.py") + tools.read_file(".env")
    assert FAKE_KEY not in out and "Sup3rS3cretValue9" not in out
    assert "<REDACTED:" in out


@pytest.mark.parametrize("bad", ["../outside.txt", "/../../etc/passwd", ".git/config", "missing.py", "tests"])
def test_read_file_rejects_bad_paths(defect_repo, bad):
    with pytest.raises(ToolError):
        RepoTools(defect_repo).read_file(bad)


def test_read_file_binary(defect_repo):
    assert "binary file" in RepoTools(defect_repo).read_file("__pycache__/app.cpython-311.pyc")


def test_search_code_finds_matches_with_line_numbers(defect_repo):
    out = RepoTools(defect_repo).search_code(r"API_KEY\s*=")
    assert "config.py:3:" in out
    assert FAKE_KEY not in out


def test_search_code_glob_no_match_and_bad_regex(defect_repo):
    tools = RepoTools(defect_repo)
    assert "No matches" in tools.search_code("API_KEY", path_glob="*.md")
    assert "ci.yml" in tools.search_code("pull_request_target", path_glob=".github/**")
    with pytest.raises(ToolError):
        tools.search_code("(unclosed")


def test_git_log_history_and_secret_removal(defect_repo):
    tools = RepoTools(defect_repo)
    log = tools.git_log()
    assert "2 commit(s)" in log and "remove deploy keys" in log
    hits = tools.git_log(grep_diff="ghp_", show_patch=True)
    assert "remove deploy keys" in hits and "initial" in hits
    assert "ghp_a1B2" not in hits  # the patch is redacted
    assert "deploy_keys.txt" in tools.git_log(show_files=True)


def test_inspect_workflows_reports_risky_settings(defect_repo):
    out = RepoTools(defect_repo).inspect_workflows()
    assert "pull_request_target" in out
    assert "write-all" in out
    assert "someone/setup-thing@main [mutable ref 'main'" in out
    assert "actions/checkout@v4 [version tag v4]" in out
    assert "failure suppressed" in out
    assert "checks out pull-request head code" in out


def test_inspect_workflows_none(healthy_repo):
    assert "GitHub Actions workflows: 0" in RepoTools(healthy_repo).inspect_workflows()


def test_inspect_workflows_emits_structured_active_and_mitigated_risks(tmp_path):
    repo = make_repo(tmp_path / "workflow-risks", [("initial", {
        "README.md": "# Workflow fixtures\n",
        ".github/workflows/active.yml": """\
name: Active injection
on: issues
jobs:
  unsafe:
    runs-on: ubuntu-latest
    steps:
      - run: echo \"${{ github.event.issue.title }}\"
""",
        ".github/workflows/inert.yml": """\
name: Inert examples
on: workflow_dispatch
jobs:
  inert:
    if: ${{ false }}
    runs-on: ${{ github.event.issue.title }}
    steps:
      - run: echo \"::set-output name=x::y\"
""",
        ".github/workflows/leaks.yml": """\
name: Leakage patterns
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: |
          set -ex
          echo \"${{ secrets.NPM_TOKEN }}\"
          npm publish --token \"${{ secrets.NPM_TOKEN }}\"
      - uses: actions/upload-artifact@v4
        with:
          path: |
            .env
            credentials.json
""",
        ".github/workflows/safe.yml": """\
name: Safe indirection
on: issues
jobs:
  safe:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: printf '%s\\n' \"$TITLE\"
""",
    }, [])])
    tools = RepoTools(repo)
    out = tools.inspect_workflows()
    observations = tools.workflow_observations
    kinds_by_file = {(o.file, o.kind) for o in observations}
    assert (".github/workflows/active.yml", "script_injection") in kinds_by_file
    assert (".github/workflows/inert.yml", "runner_injection") in kinds_by_file
    assert (".github/workflows/inert.yml", "deprecated_command") in kinds_by_file
    assert (".github/workflows/leaks.yml", "shell_trace") in kinds_by_file
    assert (".github/workflows/leaks.yml", "secret_log") in kinds_by_file
    assert (".github/workflows/leaks.yml", "secret_cli") in kinds_by_file
    assert (".github/workflows/leaks.yml", "sensitive_artifact") in kinds_by_file
    assert not any(o.file.endswith("safe.yml") and o.kind == "script_injection" for o in observations)
    assert "HIGH-RISK OBSERVATIONS" in out and "must be resolved before finish" in out
    inert = [o for o in observations if o.file.endswith("inert.yml")]
    assert inert and all("if: false guard" in o.mitigation for o in inert)


def test_check_gitignore(defect_repo, healthy_repo):
    out = RepoTools(defect_repo).check_gitignore([".env", "debug.log"])
    assert ".env: NOT ignored; TRACKED in git" in out
    assert "debug.log: ignored by .gitignore" in out
    assert ".env: ignored by .gitignore" in RepoTools(healthy_repo).check_gitignore([".env"])


@pytest.mark.skipif(shutil.which("ruff") is None, reason="ruff not installed")
def test_run_ruff_reports_issues_without_writing_cache(defect_repo):
    tools = RepoTools(defect_repo)
    out = tools.run_ruff()
    assert "ruff" in out
    assert not (defect_repo / ".ruff_cache").exists()
    assert git(defect_repo, "status", "--porcelain") == ""


def test_tools_never_modify_repo(defect_repo):
    tools = RepoTools(defect_repo)
    head = git(defect_repo, "rev-parse", "HEAD")
    tools.list_files()
    tools.read_file("app.py")
    tools.search_code("import")
    tools.git_log(show_patch=True)
    tools.inspect_workflows()
    tools.check_gitignore([".env"])
    assert git(defect_repo, "status", "--porcelain") == ""
    assert git(defect_repo, "rev-parse", "HEAD") == head


def test_validate_args():
    schema = next(s for s in INSPECTION_TOOL_SCHEMAS if s["name"] == "read_file")["input_schema"]
    assert validate_args(schema, {"path": "a.py", "start_line": "5"}) == {"path": "a.py", "start_line": 5}
    assert validate_args(schema, {"path": "a.py", "end_line": None}) == {"path": "a.py"}
    with pytest.raises(ToolError, match="missing required"):
        validate_args(schema, {})
    with pytest.raises(ToolError, match="unknown argument"):
        validate_args(schema, {"path": "a", "mode": "x"})
    with pytest.raises(ToolError, match="must be of type"):
        validate_args(schema, {"path": 3})
