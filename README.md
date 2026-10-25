# DevOps Repository Auditing Agent

An autonomous LLM agent that inspects a public GitHub repository, finds DevOps best-practice violations, and
writes an evidence-based JSON report with actionable recommendations.

The agent loop, tool dispatch, and control flow are written from scratch in Python. The only LLM dependency is
Google's official Gen AI SDK (`google-genai`), used for plain `models.generate_content` calls with the SDK's
automatic function calling turned off. No LangChain, LangGraph, n8n or other agent framework is used. The Gemini
model defaults to `gemini-flash-lite-latest` and can be changed with `GEMINI_MODEL` in `.env` (or `--model`).

The only executable entry point is **`agent.py`**. After one-time setup, an evaluator runs the complete agent with:

```bash
python agent.py --repo https://github.com/owner/repository --output report.json
```

The other Python files are imported automatically by `agent.py`; they are not run separately.

---

## 1. Quick setup

Requirements: Python 3.10+ and `git` on `PATH`.

### Windows PowerShell

Activation is not required—the commands call the virtual environment's Python directly.

```powershell
git clone <this repository>
cd <this repository>
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Open `.env`, put the Gemini API key after `GEMINI_API_KEY=`, and run:

```powershell
.\.venv\Scripts\python.exe agent.py --repo https://github.com/owner/repository --output report.json
```

### Linux or macOS

```bash
git clone <this repository>
cd <this repository>
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
```

Open `.env`, put the Gemini API key after `GEMINI_API_KEY=`, and run:

```bash
.venv/bin/python agent.py --repo https://github.com/owner/repository --output report.json
```

If the virtual environment is activated, the shorter assignment command works on every platform:

```bash
python agent.py --repo https://github.com/owner/repository --output report.json
```

## 2. Environment configuration

### Why `.env.example` exists

`.env.example` is a safe, committed template showing every supported environment variable and its recommended
default. It deliberately contains no real credential. Copy it to `.env`, then add the API key to the copy:

```dotenv
GEMINI_API_KEY=replace-with-your-key
GEMINI_MODEL=gemini-flash-lite-latest
GEMINI_REQUESTS_PER_MINUTE=10
```

The agent loads `.env` automatically through `python-dotenv`; there is no need to export or source it manually.
`.env` is excluded by `.gitignore` because it contains the private API key. Never put a real key in `.env.example`,
commit `.env`, or include a key in screenshots, reports, or trace files. A Gemini API key can be created in
[Google AI Studio](https://aistudio.google.com/apikey).

If `.env` already exists, edit it directly instead of copying `.env.example` over it.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GEMINI_API_KEY` | yes | - | Private Gemini API key. `GOOGLE_API_KEY` is also accepted |
| `GEMINI_MODEL` | no | `gemini-flash-lite-latest` | Gemini model used for the audit; `--model` overrides it for one run |
| `GEMINI_REQUESTS_PER_MINUTE` | no | `10` | Maximum top-level Gemini calls per minute; calls are evenly spaced to avoid bursts |
| `GEMINI_THINKING_LEVEL` | no | unset | `minimal` / `low` / `medium` / `high`; only sent when set. Supported levels differ per model (e.g. `gemini-3.8-flash` rejects `minimal`) |
| `AGENT_MAX_STEPS` | no | `45` | Investigation turn budget |
| `AGENT_TIMEOUT` | no | `1800` | Overall wall-clock budget (seconds) |

Shell environment variables are also supported and take precedence over values loaded from `.env`.

## 3. Running

```bash
python agent.py --repo https://github.com/owner/repository --output report.json
```

`--repo` must be a public GitHub repository URL. The run is fully unattended: after the command starts, the agent
clones the target, investigates it, verifies candidate findings, writes its outputs, and removes the temporary clone.
Progress (including each selected tool) is printed to stderr.

Outputs:

- `report.json` is the report (format below). It is always written on a completed inspection, with an empty
  `violations` array if nothing was found.
- `report.trace.jsonl` is a full trace of every LLM turn, tool call (name, arguments, result preview, duration),
  finding and verdict, so you can check the agent's behaviour. Secrets are redacted.

### Optional command-line settings

These are advanced command-line options, not `.env` entries. They are not needed for a normal audit; most users only
need `--repo` and `--output` as shown above.

| Option | Meaning |
|---|---|
| `--trace PATH` / `--trace none` | Trace location / disable tracing |
| `--model ID` | Model id for this run (overrides `GEMINI_MODEL`) |
| `--max-steps N` | Investigation turn budget (default 45) |
| `--verify-steps N` | Verification turn budget (default 20) |
| `--no-verify` | Skip the false-positive review phase |
| `--timeout SECONDS` | Overall wall-clock budget (default 1800) |
| `--keep-clone` | Keep the temporary clone for debugging |
| `-q` | Quiet: only errors and the final summary |

For offline testing, `--repo` may also be the path to a local Git repository. The agent audits a temporary clone, so
the original repository is not modified.

### Generate a report

After adding the API key to `.env`, replace the URL below with the public GitHub repository you want to audit:

```powershell
python agent.py --repo https://github.com/pypa/sampleproject --output sampleproject-report.json
```

The command creates:

- `sampleproject-report.json` — the final audit report.
- `sampleproject-report.trace.jsonl` — a detailed execution trace useful for debugging.

You can choose any output filename. The committed `sample_report.json` in this project is an authentic example output
included for the assignment submission; users do not need to regenerate it.

### Common setup problems

- `error: no Gemini API key found`: add the key to `.env` after `GEMINI_API_KEY=`.
- Exit code 3: confirm the repository URL is correct and publicly accessible.
- Exit code 4: check the API key, model name, and that `GEMINI_REQUESTS_PER_MINUTE` is a positive number.
- A run may take several minutes because the default request limiter permits 10 Gemini calls per minute. Increase the
  value only if the API account's quota supports it.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Inspection completed, report written |
| 1 | Unexpected internal error (including a missing dependency) |
| 2 | Invalid arguments, repository URL or trace path |
| 3 | Repository could not be fetched (not found / not public / network / timeout) |
| 4 | LLM configuration error (missing or invalid API key, invalid request limit, or unknown model) |
| 5 | LLM API failure during the run (after retries, e.g. quota exhausted) or a safety block; no report is written |
| 6 | Inspection completed but the report could not be written (e.g. unwritable `--output` path) |
| 7 | Investigation or verification stopped before explicit completion; no report is written |
| 130 | Interrupted with Ctrl+C |

Every failure prints a one-line `error: ...` message to stderr (never a raw traceback). The temporary clone is
deleted on both success and failure; if operating-system permissions prevent cleanup, a warning identifies the
remaining temporary path instead of replacing the audit result with a traceback.

### Output contract

```json
{
  "repository": "https://github.com/example/demo-project",
  "violations": [
    {
      "rule_id": "SEC-001",
      "category": "security",
      "severity": "critical",
      "file": "config.py",
      "line": 17,
      "description": "Hardcoded API credential",
      "evidence": "Credential assigned directly in source code",
      "recommendation": "Use a secrets manager or environment variable"
    }
  ]
}
```

- `severity` is one of `critical`, `high`, `medium`, `low`.
- `category` is one of `repository_hygiene`, `dependency_management`, `code_quality`, `testing`, `ci_cd`,
  `security`, `configuration`, `collaboration`, `build_release`.
- `file`/`line` are `null` for repository-level findings, such as a missing file.
- The report is validated against this contract before it is written atomically. Secret values never appear.

`sample_report.json`, when included for submission, must be an authentic output generated with the command above.

---

## 4. Architecture

```
agent.py (CLI)
  │  validate URL ─► clone into a temp dir (auditor/repo.py) ─► run_audit ─► write report ─► delete clone
  ▼
auditor/auditor.py  ── orchestrates two agent phases over the same tools
  │
  ├─ Phase 1: INVESTIGATION  (AgentLoop, up to 45 turns)
  │     LLM ⇄ list_files / read_file / search_code / git_log / inspect_workflows /
  │           check_gitignore / run_ruff / record_violation / resolve_observation / finish
  │
  ├─ Phase 2: VERIFICATION   (AgentLoop, up to 20 turns)
  │     LLM reviews every candidate and each dismissed high-risk workflow observation,
  │     may add a missed finding, and must submit an explicit verdict for every item
  │
  └─ auditor/report.py ── contract validation, sorting, final redaction, atomic write
```

### The agent loop (`auditor/loop.py`)

The loop runs the assignment's Observe → Reason → Select tool → Execute tool → Interpret results → Report cycle:

1. Gemini receives the system instruction, the conversation so far and the tool schemas (as function declarations).
2. It chooses which tool(s) to call and with what arguments. Several independent calls per turn are allowed.
3. The loop validates the arguments against each tool's schema, executes the tool, and returns every result as a
   function response carrying the call's `id` and `name`, all in one turn. Errors come back as `{"error": ...}`
   responses, so the model can correct itself on the next turn.
4. The model interprets the results and decides on follow-up calls. For example, it can read a file it found in a
   listing, search the history after spotting a "remove secrets" commit, or open a workflow flagged by
   `inspect_workflows`.
5. This repeats until the model calls `finish`, or a budget ends the phase.

An investigation `finish` is accepted only after `list_files`, at least one follow-up inspection tool, explicit
consideration of all nine DevOps categories, and resolution of every high-risk observation emitted by
`inspect_workflows`. Repositories containing GitHub Actions cannot finish until that tool has run. Verification
cannot finish while a candidate lacks a keep/drop verdict or an investigator's
workflow-risk dismissal lacks an independent verdict. If either phase reaches a deadline, turn limit, or repeated
no-tool response before finishing, the command exits nonzero and does not publish a partial report.

Python enforces the budgets: a turn cap per phase, a wall-clock deadline, and a stop after repeated text-only
replies. A countdown is appended after each turn's tool results so the model can pace itself, and it is told to
wrap up when three turns remain. The conversation is append-only, and Gemini's own turns are re-sent unchanged so its
thought signatures stay valid. Turns cut off by the token limit are not executed. A malformed function call gets a
"retry with valid arguments" hint. A safety block is surfaced as an error.

There is no fixed checklist in code. The system prompt describes the inspection areas, a rule-id catalog for
consistent naming, a severity guide, and the evidence rules. What to inspect and in which order is decided by the LLM
from what it observes.

### Tools (`tools.py`)

| Tool | Purpose |
|---|---|
| `list_files(path?, max_depth?, limit?)` | Tracked files with sizes, extension summary, large-file markers; collapses big trees |
| `read_file(path, start_line?, end_line?)` | Line-numbered file content (250-line windows), binary detection |
| `search_code(pattern, path_glob?, ignore_case?, fixed_string?, max_results?)` | Regex search over tracked text files via `git grep` (PCRE when available) |
| `git_log(max_count?, path?, grep_diff?, show_files?, show_patch?)` | Commit history; `grep_diff` finds commits that added or removed matching lines, such as secrets deleted later |
| `inspect_workflows(path?)` | Parses workflows and emits tracked risk observations for event-to-shell interpolation, input-controlled runners, shell tracing, credential logging/CLI arguments, sensitive artifacts, deprecated commands, bypassable actor gates, and download collisions; also reports concrete guards and related CI config |
| `check_gitignore(paths)` | Whether paths are ignored (and by which rule) and whether they are tracked |
| `run_ruff(path?)` | Static lint (rules E4,E7,E9,F: syntax errors, undefined names, unused code, bare except) |
| `record_violation(...)` | Records a finding; the harness validates it (see below) |
| `withdraw_violation(id, reason)` | Retracts a finding when later evidence shows an acceptable alternative |
| `resolve_observation(id, reported/dismissed, reason, finding_id?)` | Requires every workflow observation to be resolved; tracked anti-patterns must link a finding, while only explicit context-review signals (such as fake placeholders) may be dismissed |
| `submit_verdict(id, keep/drop, reason, severity?, line?)` | Verification-phase decision |
| `submit_observation_verdict(id, uphold/overturn, reason, finding_id?)` | Independently reviews dismissed workflow risks; an overturn links a newly recorded finding |
| `finish(summary, areas_reviewed)` | Ends investigation after explicit nine-area coverage; verification uses `summary` only and rejects pending verdicts |

All tool outputs are size-capped and returned to the LLM for interpretation.

### Precision safeguards

The hidden-repository evaluation scores precision as well as recall, so several layers guard against false positives.

- **Harness validation of every finding.** The category and severity must be allowed values. The cited file must
  exist. The line must be inside the file. Exact duplicates are rejected, while repeated occurrences of the same
  rule in one file are grouped into one root-cause finding. A snippet quoted in the
  evidence must appear at or near the cited line; if it appears elsewhere, the error tells the model the right line.
  Rejections go back to the model as tool errors, so it re-checks instead of guessing.
- **Evidence rules in the prompt.** Equivalent alternatives are not violations. Examples: `pyproject.toml` instead
  of `requirements.txt`, linters configured in `setup.cfg`, GitLab CI instead of GitHub Actions, `actions/checkout@v4`
  major-version tags. Remote settings such as branch protection are never inferred. Placeholders and test fixtures
  are not leaked credentials. A healthy repository may have zero findings.
- **A separate verification phase.** A skeptical reviewer prompt re-examines each candidate with the cited lines
  attached. It drops unsupported, duplicate or out-of-scope findings and re-grades severity. It also runs when the
  initial report has zero findings but context-review workflow observations were dismissed, and can add a missed
  finding. Dismissal rationales are withheld from this phase so it reviews raw facts without anchoring.
- **Tracked workflow-risk coverage.** High-signal workflow facts are classified as required anti-patterns or
  contextual-review signals. The LLM retains judgment about evidence, severity, remediation, and follow-up checks,
  but cannot silently ignore required observations. Recognized tracked anti-patterns must be reported even when
  deliberate, educational, or guarded; guards affect severity.
  Only explicit contextual signals such as fake placeholders may be dismissed. Both decisions are recorded in the
  JSONL trace. README claims and repository intent never override executable YAML.
- **Fail-closed completion.** A partial investigation or verification never becomes a successful report. Every
  candidate needs an explicit verdict, and repository content is treated as untrusted evidence rather than as
  instructions to the agent.

---

## 5. Safety

- **The target is never modified.** The repository is cloned into a fresh temporary directory, which is deleted
  afterwards. The clone runs with no credential prompts, no LFS download, no submodules, symlinks disabled and hooks
  disabled. All tools are read-only, and `run_ruff` uses `--no-cache` so it writes nothing.
- **No untrusted code is executed.** The agent never imports, builds, installs or runs the target's code or tests.
  `run_pytest` was deliberately not implemented, because running a stranger's tests without a sandbox would violate
  this rule. Ruff only parses files.
- **Path containment.** Every path is resolved and must stay inside the clone. `.git` internals are off-limits, and
  symlinks are not materialised.
- **Secrets never leave redacted.** `auditor/redact.py` masks credential-like values in every tool output, trace
  record and report field, for example `<REDACTED:aws-access-key len=20>`. The model can still see that a credential
  is present. The final report is re-checked and rejected if anything secret-like survives.
- **Bounded execution.** Timeouts apply to clone (300 s), git commands (60 s), ruff (120 s), LLM requests (300 s, with
  SDK retries on 408/429/5xx) and the whole run (`--timeout`). Top-level LLM calls are evenly rate-limited to 10 per
  minute by default. Tool exceptions become error results instead of crashes.
- **No hardcoded answers.** Nothing in the code or prompts refers to specific repositories.

## 6. Tests

```bash
pytest
```

The tests build throwaway git repositories with injected defects. Examples include a hardcoded key, a tracked `.env`,
workflow injection and secret-leak patterns, explicitly inert workflow examples, a committed-then-deleted token, a
machine-specific path and a tracked `.pyc`. The agent loop is driven by a scripted fake LLM, so no API key is needed.
Coverage:

- **Tools** (`tests/test_tools.py`): outputs, path traversal rejection, binary handling, regex errors, history
  search, active/mitigated workflow-risk extraction, gitignore checks, and that no tool modifies the repo.
- **Redaction** (`tests/test_redact.py`): secrets are masked; env references and placeholders are preserved.
- **Finding validation** (`tests/test_findings.py`): bad severity, category, file or line, fabricated evidence,
  duplicates, withdraw and verdicts.
- **Report** (`tests/test_report.py`): contract validation, empty report, sorting, no secrets.
- **Gemini client** (`tests/test_llm.py`, offline): default/environment configuration, request limiting, tool-schema
  conversion, function-call parsing, thought-signature preservation, function responses with `id`/`name`,
  finish-reason mapping (safety, malformed call, max tokens), and API-error mapping.
- **Agent loop** (`tests/test_loop.py`): parallel dispatch and call-id matching, error feedback, nudging, step
  and deadline budgets, truncated turns, refusal, required observation resolution, zero-finding recall review,
  follow-up calls that depend on earlier observations, and verification semantics.
- **CLI** (`tests/test_cli.py`): URL validation, failure exit codes, end-to-end report and trace, empty report, and
  that the repository is unchanged.

CI (`.github/workflows/ci.yml`) runs `ruff check` and `pytest` on Python 3.10, 3.12 and 3.13.

## 7. Project layout

```
agent.py              CLI entry point
tools.py              inspection tool implementations + schemas + argument validation
auditor/
  auditor.py          two-phase orchestration (investigation, verification)
  loop.py             the agent/tool loop
  llm.py              Gemini client (google-genai, generate_content only) + transcript conversion
  prompts.py          system prompts, rule catalog, evidence rules, severity guide
  findings.py         finding store + record/withdraw/verdict validation
  report.py           output contract validation and atomic writing
  repo.py             URL validation, hardened clone, cleanup
  redact.py           secret redaction
  trace.py            JSONL tracing + progress output
tests/                pytest suite (fixture repos + scripted fake LLM)
sample_report.json    authentic example output
```

## 8. Limitations

- Only public GitHub repositories (or local git repositories) are supported. History is cloned to a depth of 300
  commits.
- Test failures are not detected by running tests, deliberately, for safety. The agent reasons about tests statically:
  whether they exist, whether CI runs them, and whether failures are suppressed.
- As with any LLM-based reviewer, results can vary between runs. The verification phase and harness validation are
  there to keep reported findings defensible.

---

Made by **Ali Bin Salman**.
