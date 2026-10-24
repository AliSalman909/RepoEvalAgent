#!/usr/bin/env python3
"""DevOps repository auditing agent - CLI entry point.

    python agent.py --repo https://github.com/owner/repo --output report.json

Exit codes:
  0  inspection completed, report written (an empty violations array is a valid result)
  2  invalid arguments / repository URL
  3  repository could not be fetched (not found, not public, network, timeout)
  4  LLM configuration error (missing/invalid GEMINI_API_KEY, GEMINI_MODEL not set or unknown)
  5  LLM API failure during the run (after retries)
  6  inspection completed but the report could not be written (e.g. unwritable --output path)
  7  agent stopped before completing investigation or verification (no report written)
  130 interrupted (Ctrl+C)
  1  unexpected internal error (including a missing dependency)
Every failure prints a single "error: ..." line to stderr.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2
EXIT_REPO = 3
EXIT_LLM_CONFIG = 4
EXIT_LLM = 5
EXIT_REPORT = 6
EXIT_INCOMPLETE = 7
EXIT_INTERRUPTED = 130  # shell convention: 128 + SIGINT(2)


def _load_env() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(ROOT / ".env")
    load_dotenv()  # also a .env in the current working directory, without overriding


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent.py",
        description="Autonomous LLM agent that audits a GitHub repository for DevOps best-practice violations.",
    )
    p.add_argument("--repo", required=True, help="Public GitHub repository URL (https://github.com/owner/repo)")
    p.add_argument("--output", default="report.json", help="Path of the JSON report to write (default: report.json)")
    p.add_argument("--trace", default=None,
                   help="JSONL trace of every LLM turn and tool call (default: <output stem>.trace.jsonl; 'none' disables)")
    p.add_argument("--model", default=None, help="Gemini model id; overrides $GEMINI_MODEL (one of the two is required)")
    p.add_argument("--max-steps", type=int, default=int(os.environ.get("AGENT_MAX_STEPS", 45)),
                   help="Maximum LLM turns in the investigation phase (default: 45)")
    p.add_argument("--verify-steps", type=int, default=20, help="Maximum LLM turns in the verification phase (default: 20)")
    p.add_argument("--no-verify", action="store_true", help="Skip the verification (false-positive review) phase")
    p.add_argument("--timeout", type=float, default=float(os.environ.get("AGENT_TIMEOUT", 1800)),
                   help="Overall wall-clock budget in seconds (default: 1800)")
    p.add_argument("--keep-clone", action="store_true", help="Do not delete the temporary clone (debugging)")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print errors and the final summary")
    return p


def make_llm(model: str | None):
    """Factory kept separate so tests can substitute a scripted client."""
    from auditor.llm import GeminiClient
    return GeminiClient(model=model)


def _fail(code: int, message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return code


def main(argv: list[str] | None = None) -> int:
    # argparse errors (missing --repo, non-numeric --max-steps) print usage and exit 2 on their own;
    # SystemExit is not an Exception, so it passes through the handlers below untouched.
    args = None
    tracer = None
    checkout = None
    try:
        _load_env()
        args = build_parser().parse_args(argv)

        # Imported here (inside the try) so a missing dependency gives an error line, not a traceback.
        from auditor.auditor import AuditConfig, AuditIncompleteError, run_audit
        from auditor.llm import LLMConfigError, LLMError
        from auditor.repo import RepoError, clone, parse_repo
        from auditor.report import ReportError, write_report
        from auditor.trace import Tracer

        if args.max_steps < 1 or args.verify_steps < 1 or args.timeout <= 0:
            return _fail(EXIT_USAGE, "--max-steps, --verify-steps and --timeout must be positive")
        try:
            source = parse_repo(args.repo)
        except RepoError as exc:
            return _fail(EXIT_USAGE, str(exc))

        output = Path(args.output)
        trace_path = None
        if (args.trace or "").lower() != "none":
            trace_path = Path(args.trace) if args.trace else output.with_name(output.stem + ".trace.jsonl")

        try:
            llm = make_llm(args.model)
        except LLMConfigError as exc:
            return _fail(EXIT_LLM_CONFIG, f"{exc}. Configure GEMINI_API_KEY and GEMINI_MODEL in .env (see .env.example).")

        try:
            tracer = Tracer(trace_path, verbose=not args.quiet)
        except OSError as exc:
            return _fail(EXIT_USAGE, f"cannot create trace file '{trace_path}': {exc} (use --trace PATH or --trace none)")

        started = time.monotonic()
        tracer.say(f"Cloning {source.display_url} ...")
        try:
            checkout = clone(source)
        except RepoError as exc:
            return _fail(EXIT_REPO, str(exc))
        config = AuditConfig(max_steps=args.max_steps, verify_steps=args.verify_steps,
                             verify=not args.no_verify, timeout_s=args.timeout)
        try:
            result = run_audit(source.display_url, checkout, llm, tracer, config)
        except AuditIncompleteError as exc:
            return _fail(EXIT_INCOMPLETE, str(exc))
        except LLMConfigError as exc:
            return _fail(EXIT_LLM_CONFIG, f"{exc}. Check GEMINI_API_KEY / GEMINI_MODEL.")
        except LLMError as exc:
            return _fail(EXIT_LLM, f"LLM failure, inspection incomplete, no report written: {exc}")
        try:
            write_report(result.report, output)
        except (OSError, ReportError) as exc:
            tracer.event("fatal", error=f"report write failed: {type(exc).__name__}: {exc}")
            return _fail(EXIT_REPORT, f"inspection completed but the report could not be written to '{output}': {exc}")
        counts: dict[str, int] = {}
        for v in result.report["violations"]:
            counts[v["severity"]] = counts.get(v["severity"], 0) + 1
        breakdown = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if s in counts)
        print(f"Audit complete in {time.monotonic() - started:.0f}s: {len(result.report['violations'])} violation(s)"
              f"{' (' + breakdown + ')' if breakdown else ''}. Report: {output}"
              + (f" Trace: {trace_path}" if trace_path else ""), file=sys.stderr)
        return EXIT_OK
    except KeyboardInterrupt:
        if tracer is not None:
            tracer.event("fatal", error="interrupted by user")
        return _fail(EXIT_INTERRUPTED, "interrupted")
    except ImportError as exc:
        return _fail(EXIT_INTERNAL, f"missing dependency ({exc}); run: pip install -r requirements.txt")
    except Exception as exc:  # last-resort guard: never die with a bare traceback
        if tracer is not None:
            tracer.event("fatal", error=f"{type(exc).__name__}: {exc}")
        return _fail(EXIT_INTERNAL, f"unexpected {type(exc).__name__}: {exc}")
    finally:
        if tracer is not None:
            tracer.close()
        if checkout is not None:
            if args is not None and args.keep_clone:
                print(f"clone kept at {checkout.path}", file=sys.stderr)
            else:
                from auditor.repo import cleanup
                try:
                    cleanup(checkout.path)
                except OSError as exc:
                    print(f"warning: could not remove temporary clone '{checkout.path}': {exc}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
