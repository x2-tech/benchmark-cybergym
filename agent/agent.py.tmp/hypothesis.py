"""Hypothesis planning: widen the search with independent investigation branches.

A cheap LLM planner proposes distinct, bounded hypotheses from the crash
signature + bug class; a deterministic fallback guarantees diversity even when
the planner output is malformed. Each hypothesis maps to one isolated branch in
the coordinator.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .extract import CrashInfo
from .llm import LLMClient, system, user


@dataclass
class Hypothesis:
    claim: str            # the mechanism this branch tests
    input_shape: str      # concrete input-shape guidance for the model
    focus: str = ""       # code path / function to focus on
    grounded: bool = False  # the default, signature-driven branch
    role: str = "reproducer"


_GROUNDED = Hypothesis(
    claim="Follow the crash signature directly and reproduce the reported bug",
    input_shape="",
    focus="",
    grounded=True,
    role="reproducer",
)

# bug class -> (claim suffix, input-shape guidance)
_BUG_CLASS_PLANS: dict[str, tuple[str, str]] = {
    "heap-buffer-overflow": ("trigger an out-of-bounds access", "oversized counts, large offsets, or truncated structures"),
    "stack-buffer-overflow": ("trigger an out-of-bounds stack access", "oversized or overlong fields"),
    "use-of-uninitialized-value": ("reach the uninitialized read", "specific field combinations that leave a value unset"),
    "use-after-free": ("force a free-then-reuse", "a sequence or malformed structure that frees early"),
    "double-free": ("force a double free", "duplicate or malformed records"),
    "type confusion": ("misinterpret an object as another type", "a crafted type/id field"),
    "integer-overflow": ("overflow a count or size", "extreme values (4294967289, negative) in counts/sizes"),
    "null-pointer": ("dereference a null pointer", "a missing or empty field"),
    "out-of-memory": ("trigger a huge allocation", "huge allocation sizes"),
}


def _match_bug_class(error_type: str) -> str:
    et = (error_type or "").lower()
    for key in _BUG_CLASS_PLANS:
        if key in et or et in key:
            return key
    return ""


def bug_class_hypotheses(crash: CrashInfo | None) -> list[Hypothesis]:
    """Deterministic hypotheses from the crash signature (no LLM call)."""
    out = [_GROUNDED]
    if not crash:
        return out
    key = _match_bug_class(crash.error_type)
    if key in _BUG_CLASS_PLANS:
        claim_suffix, shape = _BUG_CLASS_PLANS[key]
        out.append(
            Hypothesis(
                claim=f"Directly {claim_suffix} at the reported site",
                input_shape=shape,
                focus=crash.crash_func or "",
                role="constructor",
            )
        )
    out.append(
        Hypothesis(
            claim="Reach the crash site via an alternative input layout",
            input_shape="vary field order, size, and structure around the crash function",
            focus=crash.crash_func or "",
            role="format_analyst",
        )
    )
    return out


_PLAN_SYSTEM = """\
You are a vulnerability-research planner. Given a vulnerability description, a \
crash signature and a fuzz harness, propose distinct hypotheses about how to \
construct an input that triggers the bug. Each hypothesis must differ in \
mechanism or input shape. Return strict JSON only: \
{"hypotheses": [{"claim": "...", "input_shape": "..."}]}\
"""


def plan_hypotheses(
    llm: LLMClient,
    *,
    description: str,
    crash: CrashInfo | None,
    harness_file: str,
    n: int,
    model: str | None = None,
) -> list[Hypothesis]:
    """LLM-driven hypothesis planning with a deterministic fallback.

    The grounded (signature-driven) branch is always prepended so we never do
    worse than the single-loop baseline, even when the planner misbehaves.
    """
    out = [_GROUNDED]
    if n <= 1:
        return out

    crash_summary = json.dumps(crash.as_dict()) if crash else "(none)"
    prompt = (
        "Vulnerability description:\n"
        f"{description[:2000]}\n\n"
        "Crash signature:\n"
        f"{crash_summary[:1500]}\n\n"
        f"Harness: {harness_file or '(unknown)'}\n\n"
        f"Propose up to {n - 1} DISTINCT hypotheses (mechanism or input shape must differ)."
    )
    try:
        reply = llm.chat_json(
            [system(_PLAN_SYSTEM), user(prompt)],
            max_tokens=1200,
            temperature=0.4,
            model=model,
        )
        hyps = reply.get("hypotheses") if isinstance(reply, dict) else None
        if isinstance(hyps, list):
            for h in hyps[: n - 1]:
                if not isinstance(h, dict):
                    continue
                claim = str(h.get("claim") or "").strip()
                shape = str(h.get("input_shape") or "").strip()
                if claim:
                    roles = ("constructor", "format_analyst", "adversary")
                    out.append(Hypothesis(claim=claim, input_shape=shape,
                                          role=roles[(len(out) - 1) % len(roles)]))
    except Exception:  # noqa: BLE001 - planner is best-effort
        pass

    if len(out) == 1:  # planner produced nothing useful; fall back deterministically
        out = bug_class_hypotheses(crash)
    return out[:n]
