"""Read-only repository inspection tools.

Every tool takes plain JSON-compatible arguments, returns a ``ToolResult`` whose
content is text for the LLM, and never modifies the repository or executes code
from it. Output is size-capped and passed through secret redaction.

Tools exposed to the agent:
  list_files, read_file, search_code, git_log          (required by the assignment)
  inspect_workflows, check_gitignore, run_ruff        (optional extras)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from auditor.redact import redact

MAX_OUTPUT_CHARS = 9000
MAX_LINE_CHARS = 300
DEFAULT_READ_LINES = 250
GIT_TIMEOUT = 60
RUFF_TIMEOUT = 120
LARGE_FILE_BYTES = 1_000_000
# Real-defect rules only: syntax errors, undefined names, unused imports/variables, bare except.
RUFF_RULES = "E4,E7,E9,F"

OTHER_CI_FILES = (
    ".gitlab-ci.yml", ".circleci/config.yml", "Jenkinsfile", "azure-pipelines.yml",
    ".travis.yml", "bitbucket-pipelines.yml", ".drone.yml", "buildkite.yml",
)


@dataclass
class ToolResult:
    content: str
    is_error: bool = False
    terminal: bool = False  # set by control tools (finish) to end a loop


class ToolError(Exception):
    """A user-facing tool failure: reported to the LLM as an error result."""


@dataclass(frozen=True)
class WorkflowObservation:
    """A high-risk workflow fact that the agent must explicitly resolve."""

    id: str
    file: str
    line: int
    kind: str
    suggested_rule: str
    summary: str
    evidence: tuple[str, ...]
    mitigation: str
    report_required: bool


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [output truncated: {len(text) - limit} more characters; narrow the query]"


def _clip_line(line: str) -> str:
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + " ...[line truncated]"


class RepoTools:
    """Inspection tools bound to one checked-out repository."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ValueError(f"repository root does not exist: {self.root}")
        self._tracked: list[str] | None = None
        self._pcre: bool | None = None
        self._workflow_observations: dict[str, WorkflowObservation] = {}

    # ------------------------------------------------------------------ helpers

    def _git(self, *args: str, timeout: int = GIT_TIMEOUT, check: bool = True) -> subprocess.CompletedProcess:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat", "LC_ALL": "C.UTF-8"}
        try:
            proc = subprocess.run(
                ["git", "-c", "core.quotepath=off", "-c", "core.fsmonitor=false", *args],
                cwd=self.root, capture_output=True, timeout=timeout, env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"git {args[0]} timed out after {timeout}s") from exc
        except FileNotFoundError as exc:
            raise ToolError("git executable not found") from exc
        if check and proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            raise ToolError(f"git {args[0]} failed: {err[:500]}")
        return proc

    def tracked_files(self) -> list[str]:
        if self._tracked is None:
            try:
                out = self._git("ls-files", "-z").stdout.decode("utf-8", "replace")
                self._tracked = sorted(p for p in out.split("\0") if p)
            except ToolError:
                files = []
                for dirpath, dirnames, filenames in os.walk(self.root):
                    dirnames[:] = [d for d in dirnames if d != ".git"]
                    for name in filenames:
                        files.append(Path(dirpath, name).relative_to(self.root).as_posix())
                self._tracked = sorted(files)
        return self._tracked

    def resolve(self, path: str) -> Path:
        """Map a repo-relative path to an absolute one, refusing anything outside the repo."""
        if path is None:
            raise ToolError("path is required")
        rel = str(path).strip().replace("\\", "/").lstrip("/")
        if rel.startswith("./"):
            rel = rel[2:]
        target = (self.root / rel).resolve()
        if target != self.root and self.root not in target.parents:
            raise ToolError(f"path '{path}' is outside the repository")
        if ".git" in PurePosixPath(target.relative_to(self.root).as_posix()).parts:
            raise ToolError("reading inside .git is not allowed; use git_log instead")
        return target

    def normalize(self, path: str) -> str:
        return self.resolve(path).relative_to(self.root).as_posix()

    def line_count(self, path: str) -> int:
        target = self.resolve(path)
        with open(target, "rb") as fh:
            data = fh.read()
        return data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)

    # -------------------------------------------------------------- list_files

    def list_files(self, path: str = "", max_depth: int | None = None, limit: int = 400) -> str:
        files = self.tracked_files()
        prefix = path.strip().replace("\\", "/").strip("/") if path else ""
        if prefix:
            self.resolve(prefix)  # validates the path stays inside the repo
            files = [f for f in files if f == prefix or f.startswith(prefix + "/")]
            if not files:
                return f"No tracked files under '{prefix}'."
        limit = max(20, min(int(limit or 400), 2000))

        def size(rel: str) -> int:
            try:
                return (self.root / rel).stat().st_size
            except OSError:
                return -1

        ext_counts = Counter((PurePosixPath(f).suffix or PurePosixPath(f).name) for f in files)
        lines = [
            f"{len(files)} tracked file(s){' under ' + prefix if prefix else ''}.",
            "By extension: " + ", ".join(f"{e}={c}" for e, c in ext_counts.most_common(15)),
        ]

        base_depth = len(PurePosixPath(prefix).parts) if prefix else 0
        if max_depth is None and len(files) > limit:
            max_depth = 2
        if max_depth is not None:
            max_depth = max(1, int(max_depth))
            shown: dict[str, int] = {}
            collapsed: dict[str, int] = defaultdict(int)
            for f in files:
                parts = PurePosixPath(f).parts
                if len(parts) - base_depth <= max_depth:
                    shown[f] = size(f)
                else:
                    collapsed["/".join(parts[: base_depth + max_depth]) + "/"] += 1
            entries = [(k, f"{v} bytes{' [LARGE]' if v > LARGE_FILE_BYTES else ''}") for k, v in shown.items()]
            entries += [(k, f"{v} more file(s) - list with path='{k.rstrip('/')}'") for k, v in collapsed.items()]
            lines.append(f"(depth limited to {max_depth}; deeper directories collapsed)")
        else:
            entries = []
            for f in files:
                s = size(f)
                entries.append((f, f"{s} bytes{' [LARGE]' if s > LARGE_FILE_BYTES else ''}"))
        entries.sort()
        for name, info in entries[:limit]:
            lines.append(f"{name}  ({info})")
        if len(entries) > limit:
            lines.append(f"... {len(entries) - limit} more entries; pass path= to narrow")
        return "\n".join(lines)

    # --------------------------------------------------------------- read_file

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        target = self.resolve(path)
        rel = target.relative_to(self.root).as_posix()
        if not target.exists():
            raise ToolError(f"file not found: {rel}")
        if target.is_dir():
            raise ToolError(f"'{rel}' is a directory; use list_files(path='{rel}')")
        data = target.read_bytes()
        if b"\0" in data[:8192]:
            return f"{rel}: binary file ({len(data)} bytes); content not shown."
        text = redact(data.decode("utf-8", "replace"))
        all_lines = text.splitlines()
        total = len(all_lines)
        start = max(1, int(start_line or 1))
        end = int(end_line) if end_line else start + DEFAULT_READ_LINES - 1
        end = min(max(end, start), total)
        if total == 0:
            return f"{rel}: empty file."
        if start > total:
            raise ToolError(f"start_line {start} is past the end of {rel} ({total} lines)")
        header = f"{rel} (lines {start}-{end} of {total})"
        body = [f"{n:>5}| {_clip_line(all_lines[n - 1])}" for n in range(start, end + 1)]
        out = header + "\n" + "\n".join(body)
        if end < total:
            out += f"\n... {total - end} more lines; call read_file with start_line={end + 1}"
        return _truncate(out)

    # ------------------------------------------------------------- search_code

    def _pcre_available(self) -> bool:
        if self._pcre is None:
            proc = self._git("grep", "-P", "-q", "-e", "a", "--", "x-nonexistent-path", check=False)
            self._pcre = "support for -P" not in proc.stderr.decode("utf-8", "replace")
        return self._pcre

    def search_code(
        self,
        pattern: str,
        path_glob: str = "",
        ignore_case: bool = False,
        fixed_string: bool = False,
        max_results: int = 60,
    ) -> str:
        if not pattern:
            raise ToolError("pattern must not be empty")
        max_results = max(1, min(int(max_results or 60), 200))
        args = ["grep", "-n", "-I", "--no-color", "--full-name"]
        if ignore_case:
            args.append("-i")
        if fixed_string:
            args.append("-F")
        elif self._pcre_available():
            args.append("-P")
        else:
            args.append("-E")
        args += ["-e", pattern, "--"]
        if path_glob:
            args += [g.strip() for g in str(path_glob).split(",") if g.strip()]
        proc = self._git(*args, check=False, timeout=GIT_TIMEOUT)
        if proc.returncode == 1:
            return f"No matches for {pattern!r}{' in ' + path_glob if path_glob else ''}."
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            raise ToolError(f"search failed (check the regex syntax): {err[:300]}")
        hits = proc.stdout.decode("utf-8", "replace").splitlines()
        per_file = Counter(h.split(":", 1)[0] for h in hits)
        lines = [f"{len(hits)} match(es) in {len(per_file)} file(s) for {pattern!r}."]
        if len(per_file) > 1:
            lines.append("Per file: " + ", ".join(f"{f}={c}" for f, c in per_file.most_common(20)))
        lines += [_clip_line(redact(h)) for h in hits[:max_results]]
        if len(hits) > max_results:
            lines.append(f"... {len(hits) - max_results} more matches; refine the pattern or path_glob")
        return _truncate("\n".join(lines))

    # ----------------------------------------------------------------- git_log

    def git_log(
        self,
        max_count: int = 30,
        path: str = "",
        grep_diff: str = "",
        show_files: bool = False,
        show_patch: bool = False,
    ) -> str:
        max_count = max(1, min(int(max_count or 30), 200))
        args = ["log", f"--max-count={max_count}", "--date=short", "--no-color",
                "--pretty=format:%h %ad %an | %s"]
        if show_patch:
            args += ["-p", "--unified=1"]
        elif show_files:
            args.append("--name-status")
        if grep_diff:
            args.append(f"-G{grep_diff}")
        if path:
            args += ["--", self.normalize(path)]
        proc = self._git(*args, check=False)
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            if "does not have any commits" in err:
                return "Repository has no commits."
            raise ToolError(f"git log failed: {err[:300]}")
        out = proc.stdout.decode("utf-8", "replace").strip()
        shallow = (self.root / ".git" / "shallow").exists()
        total = self._git("rev-list", "--count", "HEAD", check=False).stdout.decode().strip() or "?"
        header = f"{total} commit(s) reachable in this clone{' (shallow clone: older history not fetched)' if shallow else ''}."
        if not out:
            return header + "\nNo commits match the given filters."
        return _truncate(header + "\n" + redact(out))

    # ------------------------------------------------------- inspect_workflows

    _NOTABLE = [
        (r"pull_request_target", "pull_request_target trigger (runs with base-repo secrets/permissions)"),
        (r"workflow_run", "workflow_run trigger"),
        (r"write-all|:\s*write\b", "write permission"),
        (r"continue-on-error:\s*true", "continue-on-error: true"),
        (r"\|\|\s*(true|exit 0|:)\b", "failure suppressed with '|| true' or similar"),
        (r"\bset \+e\b", "set +e (errors ignored)"),
        (r"\bset\s+-[^\n]*x", "shell xtrace enabled (commands and expanded values are logged)"),
        (r"if:\s*(false|\$\{\{\s*false\s*\}\})", "step/job disabled with if: false"),
        (r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|head_commit|commits|pages)|head_ref)", "untrusted github context expression"),
        (r"github\.event\.pull_request\.head\.(sha|ref)|refs/pull/", "checks out pull-request head code"),
        (r"\$\{\{\s*secrets\.", "secret referenced"),
        (r"curl[^\n|]*\|\s*(ba|z)?sh", "pipes a downloaded script into a shell"),
        (r"--no-verify|--force\b|-f\s+origin", "forced/unverified git operation"),
        (r"^\s*#\s*-?\s*(run|uses|name):", "commented-out step"),
        (r"(npm|yarn|pnpm) (test|run test).*--if-present|pytest[^\n]*(--exitfirst|-x)?[^\n]*\|\|", "test command that may not fail the build"),
    ]

    @staticmethod
    def _classify_ref(uses: str) -> str:
        if uses.startswith("./"):
            return "local action"
        if uses.startswith("docker://"):
            return "docker image" + (" (pinned digest)" if "@sha256:" in uses else " (tag, not digest-pinned)")
        if "@" not in uses:
            return "NO REF (unpinned)"
        ref = uses.rsplit("@", 1)[1]
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            return "pinned to commit SHA"
        if re.fullmatch(r"v?\d+(\.\d+){0,2}", ref):
            return f"version tag {ref}"
        return f"mutable ref '{ref}' (branch or non-version tag)"

    @property
    def workflow_observations(self) -> list[WorkflowObservation]:
        return sorted(self._workflow_observations.values(), key=lambda o: (o.file, o.line, o.kind))

    @staticmethod
    def _workflow_guard(lines: list[str], line_number: int) -> str:
        """Describe concrete disabling guards around a workflow line, without assuming intent."""
        index = max(0, line_number - 1)
        job_start = 0
        for i in range(index, -1, -1):
            if re.match(r"^  [A-Za-z0-9_.-]+:\s*(?:#.*)?$", lines[i]):
                job_start = i
                break
        job_end = len(lines)
        for i in range(job_start + 1, len(lines)):
            if re.match(r"^  [A-Za-z0-9_.-]+:\s*(?:#.*)?$", lines[i]):
                job_end = i
                break
        job_header = lines[job_start:index + 1]
        steps_at = next((i for i, text in enumerate(job_header) if re.match(r"^    steps:\s*$", text)), len(job_header))
        if any(re.search(r"^    if:\s*(?:\$\{\{\s*)?false(?:\s*\}\})?\s*(?:#.*)?$", text, re.I)
               for text in job_header[:steps_at]):
            return "job has an explicit if: false guard"

        step_start = None
        for i in range(index, job_start, -1):
            if re.match(r"^      -\s+", lines[i]):
                step_start = i
                break
        if step_start is not None:
            step_end = min(job_end, next(
                (i for i in range(step_start + 1, job_end) if re.match(r"^      -\s+", lines[i])),
                job_end,
            ))
            if any(re.search(r"^        if:\s*(?:\$\{\{\s*)?false(?:\s*\}\})?\s*(?:#.*)?$", text, re.I)
                   for text in lines[step_start:step_end]):
                return "step has an explicit if: false guard"
        return "no explicit if: false guard was found around this line"

    def _scan_workflow_observations(self, file: str, raw: str) -> list[WorkflowObservation]:
        """Extract high-signal facts. These are review leads, never automatic violations."""
        lines = raw.splitlines()
        grouped: dict[str, list[tuple[int, str]]] = defaultdict(list)
        required_kinds: set[str] = set()

        run_block_indent: int | None = None
        for n, line in enumerate(lines, 1):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if run_block_indent is not None and stripped and indent <= run_block_indent:
                run_block_indent = None
            in_run = bool(re.match(r"^\s*-?\s*run:\s*", line)) or run_block_indent is not None
            if re.match(r"^\s*-?\s*run:\s*[>|]\s*(?:#.*)?$", line):
                run_block_indent = indent
                in_run = True

            untrusted = re.search(
                r"\$\{\{\s*(?:github\.(?:event\.(?:issue|pull_request|comment|review|head_commit|commits|pages)|head_ref)|inputs\.)",
                line,
            )
            if in_run and untrusted:
                grouped["script_injection"].append((n, "untrusted event/input expression is interpolated directly into a shell script"))
                required_kinds.add("script_injection")
            if re.search(r"^\s*runs-on:\s*.*\$\{\{.*(?:github\.event\.|inputs\.)", line):
                grouped["runner_injection"].append((n, "event input controls the runner label"))
                required_kinds.add("runner_injection")
            if in_run and re.search(r"(?:^|[;&|]\s*)set\s+-[A-Za-z]*x[A-Za-z]*\b", stripped):
                grouped["shell_trace"].append((n, "shell xtrace is enabled and can log expanded secret values"))
                required_kinds.add("shell_trace")
            if in_run and re.search(r"\b(?:echo|printf|printenv)\b", line, re.I) and re.search(
                r"(?:\$\{\{\s*secrets\.|\$(?:\{)?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*(?:\})?)",
                line,
                re.I,
            ):
                grouped["secret_log"].append((n, "a secret expression or secret-named variable is printed to the job log"))
                placeholder_variable = re.search(r"\$(?:\{)?(?:DEMO|FAKE|DUMMY)_[A-Z0-9_]*(?:\})?", line, re.I)
                if "${{ secrets." in line.lower() or not placeholder_variable:
                    required_kinds.add("secret_log")
            if in_run and re.search(r"\bcurl\b[^\n]*(?:\s-v\b|--verbose\b)", line) and re.search(
                r"authorization|bearer|token|secret|password", "\n".join(lines[max(0, n - 3):min(len(lines), n + 2)]), re.I
            ):
                grouped["secret_log"].append((n, "verbose curl is used near an authorization credential"))
                required_kinds.add("secret_log")
            if in_run and (
                re.search(r"\bnpm\s+publish\b[^\n]*(?:--token|--_authToken)\b", line, re.I)
                or re.search(r"\bdocker\s+login\b[^\n]*(?:-p\b|--password\b)", line, re.I)
                or re.search(r"\btwine\s+upload\b[^\n]*--password\b", line, re.I)
            ):
                grouped["secret_cli"].append((n, "a credential is supplied through a command-line argument"))
                required_kinds.add("secret_cli")
            if "::set-output" in line:
                grouped["deprecated_command"].append((n, "deprecated ::set-output workflow command is emitted"))
                required_kinds.add("deprecated_command")
            if re.search(r"contains\s*\([^\n]*github\.actor", line, re.I):
                grouped["actor_allowlist"].append((n, "substring matching is used as an actor authorization gate"))
                required_kinds.add("actor_allowlist")

        # Inspect upload-artifact step bodies for sensitive paths.
        for i, line in enumerate(lines):
            if not re.search(r"uses:\s*actions/upload-artifact@", line, re.I):
                continue
            indent = len(line) - len(line.lstrip())
            end = next((j for j in range(i + 1, len(lines))
                        if lines[j].strip() and len(lines[j]) - len(lines[j].lstrip()) < indent), len(lines))
            block = "\n".join(lines[i:end])
            if re.search(r"(?:^|[/\\])\.env(?:\.|$)|credentials?(?:\.json)?|\.ssh|id_rsa|private[_-]?key|\.pem\b", block, re.I | re.M):
                grouped["sensitive_artifact"].append((i + 1, "upload-artifact includes credential, environment, SSH, or private-key paths"))
                required_kinds.add("sensitive_artifact")

        # Multiple downloads writing the same basename can silently overwrite one another.
        destinations: dict[str, list[int]] = defaultdict(list)
        for n, line in enumerate(lines, 1):
            match = re.search(r"\b(?:curl\b[^\n]*\s-o|wget\b[^\n]*(?:\s-O)?)\s+['\"]?([^\s'\"]+)", line)
            if match:
                destinations[PurePosixPath(match.group(1)).name].append(n)
        for name, positions in destinations.items():
            if name and len(positions) > 1:
                grouped["download_collision"].append((positions[0], f"multiple downloads write the same filename {name!r}"))
                required_kinds.add("download_collision")

        meta = {
            "script_injection": ("SEC-005", "Possible shell-script injection"),
            "runner_injection": ("SEC-012", "Possible attacker-controlled runner selection"),
            "shell_trace": ("SEC-009", "Shell tracing near credential use"),
            "secret_log": ("SEC-006", "Possible credential exposure in CI logs"),
            "secret_cli": ("SEC-010", "Credential passed through process arguments"),
            "sensitive_artifact": ("SEC-011", "Sensitive files included in a workflow artifact"),
            "deprecated_command": ("CI-006", "Deprecated workflow command"),
            "actor_allowlist": ("COL-003", "Potentially bypassable actor allowlist"),
            "download_collision": ("CI-007", "Workflow download filename collision"),
        }
        observations: list[WorkflowObservation] = []
        for kind, facts in grouped.items():
            rule, summary = meta[kind]
            facts = sorted(set(facts))
            first_line = facts[0][0]
            digest = hashlib.sha1(f"{file}\0{kind}".encode()).hexdigest()[:8].upper()
            guards = {self._workflow_guard(lines, line_no) for line_no, _ in facts}
            observations.append(WorkflowObservation(
                id=f"WF-{digest}", file=file, line=first_line, kind=kind, suggested_rule=rule,
                summary=summary,
                evidence=tuple(f"line {line_no}: {detail}" for line_no, detail in facts),
                mitigation="; ".join(sorted(guards)),
                report_required=kind in required_kinds,
            ))
        return observations

    def inspect_workflows(self, path: str = "") -> str:
        files = self.tracked_files()
        wf = [f for f in files if re.match(r"\.github/workflows/[^/]+\.ya?ml$", f)]
        if path:
            norm = self.normalize(path)
            wf = [f for f in wf if f == norm]
            if not wf:
                raise ToolError(f"no workflow file '{norm}'")
        other = [f for f in files if f in OTHER_CI_FILES or f.endswith("/Jenkinsfile")]
        extras = [f for f in (".github/dependabot.yml", ".github/dependabot.yaml", ".github/CODEOWNERS",
                              "CODEOWNERS", ".pre-commit-config.yaml", ".github/renovate.json", "renovate.json")
                  if f in files]
        out = [f"GitHub Actions workflows: {len(wf)}" + (f" ({', '.join(wf)})" if wf else "")]
        out.append("Other CI configs: " + (", ".join(other) if other else "none"))
        out.append("Related automation/config files: " + (", ".join(extras) if extras else "none"))

        for f in wf:
            raw = (self.root / f).read_text("utf-8", "replace")
            for observation in self._scan_workflow_observations(f, raw):
                self._workflow_observations[observation.id] = observation
            out.append(f"\n=== {f} ===")
            try:
                doc = yaml.safe_load(raw)
            except yaml.YAMLError as exc:
                out.append(f"YAML PARSE ERROR: {str(exc)[:300]}")
                continue
            if not isinstance(doc, dict):
                out.append("Not a mapping - invalid workflow.")
                continue
            triggers = doc.get("on", doc.get(True))  # PyYAML parses bare `on` as True
            out.append(f"name: {doc.get('name')!r}")
            out.append(f"triggers: {json.dumps(triggers, default=str)[:600]}")
            out.append(f"top-level permissions: {json.dumps(doc.get('permissions', 'NOT SET (repository default token permissions)'), default=str)}")
            if "concurrency" in doc:
                out.append(f"concurrency: {json.dumps(doc['concurrency'], default=str)[:200]}")
            jobs = doc.get("jobs") or {}
            if not isinstance(jobs, dict):
                out.append("jobs: invalid")
                continue
            for job_id, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                attrs = []
                for key in ("runs-on", "needs", "if", "permissions", "environment", "continue-on-error", "uses", "timeout-minutes"):
                    if key in job:
                        attrs.append(f"{key}={json.dumps(job[key], default=str)[:150]}")
                out.append(f"- job '{job_id}': " + "; ".join(attrs))
                for i, step in enumerate(job.get("steps") or [], 1):
                    if not isinstance(step, dict):
                        continue
                    desc = step.get("name") or ""
                    parts = [f"  step {i}" + (f" '{desc}'" if desc else "")]
                    if "uses" in step:
                        parts.append(f"uses {step['uses']} [{self._classify_ref(str(step['uses']))}]")
                    if "run" in step:
                        run = " ; ".join(str(step["run"]).strip().splitlines())
                        parts.append(f"run: {run[:220]}")
                    for key in ("if", "continue-on-error", "with"):
                        if key in step:
                            parts.append(f"{key}={json.dumps(step[key], default=str)[:160]}")
                    out.append(" | ".join(parts))
            notable = []
            for n, line in enumerate(raw.splitlines(), 1):
                for pattern, label in self._NOTABLE:
                    if re.search(pattern, line):
                        notable.append(f"  line {n}: {label}: {_clip_line(line.strip())}")
            if notable:
                out.append("notable lines (facts to verify, not conclusions):")
                out.extend(notable[:40])
        selected = [o for o in self.workflow_observations if not path or o.file == norm]
        if selected:
            out.append("\nHIGH-RISK OBSERVATIONS (each ID must be resolved before finish):")
            for observation in selected:
                out.append(
                    f"- {observation.id} [{observation.kind}; suggested {observation.suggested_rule}] "
                    f"{observation.file}:{observation.line} - {observation.summary}. "
                    f"Facts: {'; '.join(observation.evidence)}. Guard check: {observation.mitigation}. "
                    + (
                        "Disposition: tracked anti-pattern; record a finding (guards may lower severity)."
                        if observation.report_required
                        else "Disposition: contextual review allowed (possible explicit placeholder)."
                    )
                )
            out.append(
                "Read the cited lines, then call resolve_observation for every ID. Documentation claiming a "
                "workflow is safe or intentional does not resolve an executable anti-pattern."
            )
        return _truncate(redact("\n".join(out)))

    # --------------------------------------------------------- check_gitignore

    def check_gitignore(self, paths: list[str]) -> str:
        if not paths:
            raise ToolError("paths must be a non-empty list")
        tracked = set(self.tracked_files())
        has_gitignore = (self.root / ".gitignore").exists()
        out = [f".gitignore present at root: {'yes' if has_gitignore else 'NO'}"]
        for p in paths[:50]:
            rel = str(p).strip().replace("\\", "/").lstrip("/")
            if not rel:
                continue
            self.resolve(rel)
            proc = self._git("check-ignore", "--no-index", "-v", rel, check=False)
            rule = proc.stdout.decode("utf-8", "replace").strip()
            ignored = f"ignored by {rule.split(chr(9))[0]}" if proc.returncode == 0 else "NOT ignored"
            is_tracked = rel in tracked or any(t.startswith(rel.rstrip("/") + "/") for t in tracked)
            out.append(f"{rel}: {ignored}; {'TRACKED in git' if is_tracked else 'not tracked'}")
        return "\n".join(out)

    # ---------------------------------------------------------------- run_ruff

    def run_ruff(self, path: str = "") -> str:
        ruff = shutil.which("ruff")
        if not ruff:
            return "run_ruff unavailable: ruff is not installed in this environment. Do not infer lint results."
        py_files = [f for f in self.tracked_files() if f.endswith(".py")]
        if not py_files:
            return "No tracked Python files; ruff not applicable."
        target = self.normalize(path) if path else "."
        # --isolated + --select give a consistent baseline regardless of the repo's ruff config.
        # Ruff is a static analyser: it parses files but never imports or executes them.
        cmd = [ruff, "check", "--isolated", "--no-cache", "--select", RUFF_RULES,
               "--output-format", "json", "--exit-zero", target]
        try:
            proc = subprocess.run(cmd, cwd=self.root, capture_output=True, timeout=RUFF_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise ToolError(f"ruff timed out after {RUFF_TIMEOUT}s") from None
        try:
            issues = json.loads(proc.stdout.decode("utf-8", "replace") or "[]")
        except json.JSONDecodeError:
            raise ToolError(f"ruff output unreadable: {proc.stderr.decode('utf-8', 'replace')[:300]}") from None
        if not issues:
            return f"ruff (rules {RUFF_RULES}) found no issues in {len(py_files)} Python file(s)."
        by_code: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for issue in issues:
            by_code[issue.get("code") or "syntax-error"].append(issue)
        out = [f"ruff (rules {RUFF_RULES}: syntax errors, undefined names, unused code, bare except; repo config ignored): {len(issues)} issue(s) in {len(py_files)} Python file(s)."]
        for code, items in sorted(by_code.items(), key=lambda kv: -len(kv[1])):
            first = items[0]
            out.append(f"{code} x{len(items)}: {first.get('message')}")
            for it in items[:3]:
                rel = Path(it.get("filename", "")).resolve()
                try:
                    rel_s = rel.relative_to(self.root).as_posix()
                except ValueError:
                    rel_s = str(it.get("filename"))
                out.append(f"    {rel_s}:{(it.get('location') or {}).get('row')}")
        return _truncate("\n".join(out))


# ---------------------------------------------------------------------------
# Tool schemas (name / description / JSON-schema input) and dispatch
# ---------------------------------------------------------------------------

INSPECTION_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_files",
        "description": (
            "List files tracked in the repository with sizes and an extension summary. "
            "Use path= to list one directory and max_depth= to collapse deep trees. "
            "Start an audit with this to map the repository."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repo-relative directory to list; empty for the whole repo."},
                "max_depth": {"type": "integer", "description": "Collapse entries deeper than this many levels below path."},
                "limit": {"type": "integer", "description": "Maximum entries to show (default 400)."},
            },
        },
    },
    {
        "name": "read_file",
        "description": (
            "Read a text file with line numbers (default: first 250 lines). Use start_line/end_line for "
            "other ranges. Credential values are shown as <REDACTED:...> markers; a marker means a "
            "literal credential-like value is present at that location."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repo-relative file path."},
                "start_line": {"type": "integer", "description": "First line to show (1-based)."},
                "end_line": {"type": "integer", "description": "Last line to show (inclusive)."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "search_code",
        "description": (
            "Search tracked text files for a regular expression (Perl-compatible when available) and return "
            "file:line:text matches. Use path_glob (comma-separated git pathspecs such as '*.py' or "
            "'.github/**') to narrow. Good for hardcoded credentials, absolute machine paths, debug flags, "
            "disabled TLS verification, TODO hacks, etc."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regular expression (or literal text with fixed_string=true)."},
                "path_glob": {"type": "string", "description": "Optional comma-separated pathspecs to restrict the search."},
                "ignore_case": {"type": "boolean"},
                "fixed_string": {"type": "boolean", "description": "Treat pattern as literal text."},
                "max_results": {"type": "integer", "description": "Maximum matches to return (default 60)."},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "git_log",
        "description": (
            "Inspect commit history: hash, date, author, subject. Options: path= (history of one file), "
            "grep_diff= (regex; only commits whose diff adds/removes matching lines - finds secrets "
            "committed then deleted), show_files= (files changed per commit), show_patch= (diff hunks, redacted)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "max_count": {"type": "integer", "description": "Number of commits (default 30, max 200)."},
                "path": {"type": "string"},
                "grep_diff": {"type": "string"},
                "show_files": {"type": "boolean"},
                "show_patch": {"type": "boolean"},
            },
        },
    },
    {
        "name": "inspect_workflows",
        "description": (
            "Parse GitHub Actions workflows: triggers, permissions, jobs, steps, action ref pinning, and "
            "line-numbered notable lines. Emits stable HIGH-RISK OBSERVATION IDs for event-to-shell injection, "
            "input-controlled runners, shell tracing, credential logging/CLI arguments, sensitive artifacts, "
            "deprecated commands, actor gates, and download collisions. Each observation is a fact to inspect and "
            "must be resolved explicitly. Tracked anti-pattern observations require a finding even when deliberately "
            "planted or guarded; explicit placeholder signals allow contextual review. Also reports other CI systems, "
            "Dependabot/Renovate, CODEOWNERS and pre-commit configs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Optional single workflow file to inspect."}},
        },
    },
    {
        "name": "check_gitignore",
        "description": (
            "For each path, report whether .gitignore rules would ignore it and whether it is tracked in "
            "git. Use to confirm committed local/generated files (e.g. .env, venv/, __pycache__/, *.log)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"paths": {"type": "array", "items": {"type": "string"}}},
            "required": ["paths"],
        },
    },
    {
        "name": "run_ruff",
        "description": (
            "Run the ruff linter statically (no code execution) with its default rule set (syntax errors, "
            "undefined names, unused imports/variables, bare except) and summarize issues. Python only."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Optional sub-path to lint."}},
        },
    },
]

def _type_ok(value: Any, json_type: str | None) -> bool:
    if json_type is None:
        return True
    if json_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if json_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return {
        "string": str, "boolean": bool, "array": list, "object": dict, "null": type(None),
    }.get(json_type, object) in type(value).__mro__


def validate_args(schema: dict[str, Any], args: Any) -> dict[str, Any]:
    """Light JSON-schema check: object shape, required keys, primitive types, enums.

    Lenient coercions ("12" -> 12, "true" -> True) absorb common LLM slips; anything
    else becomes a ToolError the model sees and can correct on its next turn.
    """
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ToolError("arguments must be a JSON object")
    props: dict[str, Any] = schema.get("properties", {})
    required = set(schema.get("required", []))
    for key in required:
        if key not in args:
            raise ToolError(f"missing required argument '{key}'")
    clean: dict[str, Any] = {}
    for key, value in args.items():
        if key not in props:
            raise ToolError(f"unknown argument '{key}'; allowed: {', '.join(props) or 'none'}")
        spec = props[key]
        types = spec.get("type")
        allowed = types if isinstance(types, list) else [types]
        if value is None and "null" not in allowed:
            if key in required:
                raise ToolError(f"argument '{key}' must not be null")
            continue  # treat an explicit null for an optional argument as "not given"
        if not any(_type_ok(value, t) for t in allowed):
            if "integer" in allowed and isinstance(value, str) and value.strip().lstrip("-").isdigit():
                value = int(value)
            elif "boolean" in allowed and isinstance(value, str) and value.lower() in ("true", "false"):
                value = value.lower() == "true"
            else:
                raise ToolError(f"argument '{key}' must be of type {'/'.join(str(a) for a in allowed)}")
        if "enum" in spec and value not in spec["enum"]:
            raise ToolError(f"argument '{key}' must be one of {spec['enum']}")
        clean[key] = value
    return clean


def make_inspection_handlers(tools: RepoTools) -> dict[str, Callable[..., str]]:
    return {
        "list_files": tools.list_files,
        "read_file": tools.read_file,
        "search_code": tools.search_code,
        "git_log": tools.git_log,
        "inspect_workflows": tools.inspect_workflows,
        "check_gitignore": tools.check_gitignore,
        "run_ruff": tools.run_ruff,
    }
