"""The agent loop: Observe -> Reason -> Select tool -> Execute -> Interpret, repeated.

The LLM decides which tool to call next based on everything it has observed so
far; this module only executes the calls it asks for, feeds the results back,
and enforces budgets (steps, wall-clock deadline). The conversation is
append-only: earlier turns are never edited.

Transcript format (provider-neutral; auditor/llm.py converts it for Gemini):
    {"role": "user", "content": "text"}
    {"role": "assistant", "raw": <model content, re-sent unchanged>}
    {"role": "tool", "results": [{"id", "name", "content", "is_error"}], "note": "text or None"}
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from auditor.llm import LLMClient, LLMError, LLMResponse
from auditor.trace import Tracer
from tools import ToolResult

ToolHandler = Callable[[str, dict[str, Any]], ToolResult]

NUDGE = (
    "You replied without calling a tool. Continue the investigation by calling tools, "
    "or call `finish` if you are done."
)
MALFORMED = (
    "Your last function call was malformed and was not executed. Call the tool again with valid "
    "arguments that match its schema."
)
MAX_NUDGES = 2


@dataclass
class LoopOutcome:
    steps: int
    finished: bool          # the model called its terminal tool
    stop_reason: str        # finished | max_steps | deadline | no_tool_calls | refusal
    final_text: str = ""
    usage: dict[str, int] | None = None


def _fmt_args(args: dict[str, Any], limit: int = 120) -> str:
    s = ", ".join(f"{k}={json.dumps(v, ensure_ascii=False)}" for k, v in args.items())
    return s if len(s) <= limit else s[:limit] + "..."


class AgentLoop:
    def __init__(
        self,
        llm: LLMClient,
        system: str,
        tools: list[dict[str, Any]],
        handler: ToolHandler,
        tracer: Tracer,
        phase: str,
        max_steps: int,
        deadline: float | None = None,
        terminal_tool: str = "finish",
    ):
        self.llm = llm
        self.system = system
        self.tools = tools
        self.handler = handler
        self.tracer = tracer
        self.phase = phase
        self.max_steps = max_steps
        self.deadline = deadline
        self.terminal_tool = terminal_tool
        self.messages: list[dict[str, Any]] = []
        self.usage: dict[str, int] = {}

    def _budget_note(self, step: int) -> str:
        left = self.max_steps - step
        note = f"[{self.phase}: turn {step}/{self.max_steps}, {left} left]"
        if self.deadline is not None:
            secs = int(self.deadline - time.monotonic())
            note += f" [{max(secs, 0)}s of wall-clock budget left]"
        if left <= 3:
            note += (f" Budget almost exhausted: record any remaining well-evidenced findings now, "
                     f"then call `{self.terminal_tool}`.")
        return note

    def _execute(self, step: int, resp: LLMResponse) -> tuple[list[dict[str, Any]], bool]:
        """Run every tool call in this turn; return neutral tool results and whether to stop."""
        results: list[dict[str, Any]] = []
        terminal = False
        truncated = resp.stop_reason == "max_tokens"
        for call in resp.tool_calls:
            started = time.monotonic()
            if truncated:
                result = ToolResult("Your response hit the output token limit, so this call was not run "
                                    "(its arguments may be incomplete). Re-issue it with shorter arguments.",
                                    is_error=True)
            else:
                self.tracer.say(f"  [{self.phase} {step}/{self.max_steps}] {call.name}({_fmt_args(call.input)})")
                try:
                    result = self.handler(call.name, call.input)
                except Exception as exc:  # a tool bug must not kill the run; the model sees the error
                    result = ToolResult(f"Tool '{call.name}' failed unexpectedly: {type(exc).__name__}: {exc}",
                                        is_error=True)
            terminal = terminal or result.terminal
            self.tracer.event(
                "tool_call", phase=self.phase, step=step, tool=call.name, args=call.input,
                is_error=result.is_error, duration_s=round(time.monotonic() - started, 3),
                result_chars=len(result.content), result_preview=result.content[:400],
            )
            results.append({"id": call.id, "name": call.name, "content": result.content,
                            "is_error": result.is_error})
        return results, terminal

    def run(self, task: str) -> LoopOutcome:
        self.messages = [{"role": "user", "content": task}]
        nudges = 0
        final_text = ""
        for step in range(1, self.max_steps + 1):
            if self.deadline is not None and time.monotonic() > self.deadline:
                self.tracer.event("loop_end", phase=self.phase, reason="deadline", steps=step - 1)
                return LoopOutcome(step - 1, False, "deadline", final_text, self.usage)

            resp = self.llm.complete(self.system, self.messages, self.tools)
            for k, v in resp.usage.items():
                self.usage[k] = self.usage.get(k, 0) + v
            if resp.text:
                final_text = resp.text
            self.tracer.event(
                "llm_turn", phase=self.phase, step=step, stop_reason=resp.stop_reason,
                text=resp.text[:2000], tool_calls=[{"name": c.name, "args": c.input} for c in resp.tool_calls],
                usage=resp.usage,
            )

            if resp.stop_reason == "refusal":
                self.tracer.event("loop_end", phase=self.phase, reason="refusal", steps=step)
                raise LLMError(f"the model declined to continue (safety block) {resp.text}".strip())
            self.messages.append({"role": "assistant", "raw": resp.raw_content})

            if not resp.tool_calls:
                # Answer with a user turn so the transcript alternates and the model gets guidance.
                nudges += 1
                if nudges > MAX_NUDGES:
                    self.tracer.event("loop_end", phase=self.phase, reason="no_tool_calls", steps=step)
                    return LoopOutcome(step, False, "no_tool_calls", final_text, self.usage)
                hint = MALFORMED if resp.stop_reason == "malformed_tool_call" else NUDGE
                self.messages.append({"role": "user", "content": hint + " " + self._budget_note(step)})
                continue

            results, terminal = self._execute(step, resp)
            if terminal:
                # Close the turn so the transcript stays well-formed, then stop.
                self.messages.append({"role": "tool", "results": results, "note": None})
                self.tracer.event("loop_end", phase=self.phase, reason="finished", steps=step)
                return LoopOutcome(step, True, "finished", final_text, self.usage)
            # All results of this turn go back together, followed by the budget note.
            self.messages.append({"role": "tool", "results": results, "note": self._budget_note(step)})

        self.tracer.event("loop_end", phase=self.phase, reason="max_steps", steps=self.max_steps)
        return LoopOutcome(self.max_steps, False, "max_steps", final_text, self.usage)
