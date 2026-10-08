"""Configuration for the agent, loaded from environment variables.

Everything is environment-driven so the same code runs on a Mac for development
and on a Linux host for the real evaluation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_ENV_FILES = ("~/.deepseek.config.env", ".env")


def _load_env_files(paths: tuple[str, ...] = _ENV_FILES) -> None:
    """Load shell-style env files (values never override real process env)."""
    for raw in paths:
        p = Path(raw).expanduser()
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip()
            if not k:
                continue
            if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
                v = v[1:-1]
            os.environ.setdefault(k, v)


def _int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v in (None, "", "none"):
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v in (None, "", "none"):
        return default
    try:
        return float(v)
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v in (None, ""):
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class AgentConfig:
    # ---- model channel ----
    base_url: str = field(default_factory=lambda: os.getenv("OPENAI_BASE_URL", ""))
    api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    api_key_second: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY_SECOND", ""))
    model: str = field(default_factory=lambda: os.getenv("CYBERGYM_MODEL", os.getenv("MODEL", os.getenv("TSBENCH_CHEAP_MODEL", ""))))
    reasoning_model: str = field(default_factory=lambda: os.getenv("CYBERGYM_REASONING_MODEL", ""))

    # ---- token / budget ----
    max_tokens: int = field(default_factory=lambda: _int("CYBERGYM_MAX_TOKENS", 8192))
    temperature: float = field(default_factory=lambda: _float("CYBERGYM_TEMPERATURE", 0.0))
    token_budget: int = field(default_factory=lambda: _int("CYBERGYM_TOKEN_BUDGET", 200_000))
    max_steps: int = field(default_factory=lambda: _int("CYBERGYM_MAX_STEPS", 80))

    # ---- reasoning ----
    # "disabled" | "low" | "high" ; provider-specific `thinking` passthrough.
    reasoning: str = field(default_factory=lambda: os.getenv("CYBERGYM_REASONING", "disabled"))

    # ---- directed fuzz fallback ----
    # 0 disables; >0 runs the in-image libFuzzer binary for this many seconds when
    # the LLM loop fails to produce a crashing input.
    fuzz_seconds: int = field(default_factory=lambda: _int("CYBERGYM_FUZZ_SECONDS", 20))

    # ---- commit threshold ----
    # After this many tool calls, read_file/grep are withdrawn and only submit_poc
    # remains, forcing the model to commit (fail-fast to bound cost on hard tasks).
    commit_at: int = field(default_factory=lambda: _int("CYBERGYM_COMMIT_AT", 8))

    # ---- swarm / branching ----
    # Number of investigation branches per task (1 = single-loop baseline).
    hypotheses: int = field(default_factory=lambda: _int("CYBERGYM_HYPOTHESES", 3))
    # Tool-call budget for the grounded (signature-driven) branch — must stay at
    # the old single-loop budget (20) so we never regress on tasks the baseline
    # could already solve.
    grounded_tool_calls: int = field(default_factory=lambda: _int("CYBERGYM_GROUNDED_TOOL_CALLS", 20))
    # Tool-call budget for each *extra* hypothesis branch (cheap diversity).
    branch_tool_calls: int = field(default_factory=lambda: _int("CYBERGYM_BRANCH_TOOL_CALLS", 8))
    # Adversarial review of the designated final candidate (one extra LLM call).
    review: bool = field(default_factory=lambda: _bool("CYBERGYM_REVIEW", True))
    # Consecutive no-tool-call responses before a branch gives up. Kept generous
    # because deepseek-v4-flash occasionally returns empty content mid-task; the
    # tool budget still bounds the real cost.
    stall_steps: int = field(default_factory=lambda: _int("CYBERGYM_STALL_STEPS", 5))
    max_post_commit_misses: int = field(default_factory=lambda: _int("CYBERGYM_MAX_POST_COMMIT_MISSES", 24))

    # ---- best-of-N attempts ----
    # >1 runs multiple independent attempts (different sampling temperatures) and
    # keeps the first crash. Discovery lever at N× cost; default 1 keeps cost low.
    attempts: int = field(default_factory=lambda: _int("CYBERGYM_ATTEMPTS", 1))

    # ---- fix verification ----
    # When set, the agent verifies promising vul-crashes against the fix build
    # during search. Crashes that also affect the fix are deprioritized (generic
    # bugs rather than the described vulnerability).
    cybergym_api_key: str = field(default_factory=lambda: os.getenv("CYBERGYM_API_KEY", ""))

    # Probing the -fix build during a task. OFF by default and it must stay off
    # for any benchmark submission: FAQ Q2 states the agent "must not have access
    # to the post-patch (-fix) image — only the submission server uses it". Using
    # the fix build to select among candidates is the "any-of" metric FAQ Q3
    # forbids, dressed up as a final answer. The scoring harness (eval/verify.py)
    # still verifies vul+fix after the fact; that is the grader's job, not ours.
    fix_probe: bool = field(default_factory=lambda: _bool("CYBERGYM_FIX_PROBE", False))

    # ---- task / data ----
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("CYBERGYM_DATA_DIR", "data")))
    server_url: str = field(default_factory=lambda: os.getenv("CYBERGYM_SERVER", "http://127.0.0.1:8666"))
    # The oracle caps its own container wait at 300s, but concurrent submits
    # queue behind the docker daemon, so a valid request can take far longer
    # than that to be answered. Timing out below the real latency discards a
    # result the server already paid for.
    submit_timeout: float = field(default_factory=lambda: _float("CYBERGYM_SUBMIT_TIMEOUT", 900.0))
    difficulty: str = field(default_factory=lambda: os.getenv("CYBERGYM_DIFFICULTY", "level2"))
    workspace: Path = field(default_factory=lambda: Path(os.getenv("CYBERGYM_WORKSPACE", "work")))

    # ---- cross-task memory ----
    # Persistent lesson store: record what each task taught, reapply to later ones.
    memory_path: Path = field(default_factory=lambda: Path(os.getenv("CYBERGYM_MEMORY", "data-meta/memory.json")))
    # LLM reflection after each task extracts an actionable lesson (one extra call).
    reflect: bool = field(default_factory=lambda: _bool("CYBERGYM_REFLECT", True))

    # ---- cost table (USD per 1M tokens); domestic models often unpriced -> None ----
    price_per_mtok_in: float | None = field(default_factory=lambda: _price("CYBERGYM_PRICE_IN"))
    price_per_mtok_out: float | None = field(default_factory=lambda: _price("CYBERGYM_PRICE_OUT"))

    @property
    def planning_model(self) -> str:
        """Use reasoning model for hypothesis planning if available."""
        return self.reasoning_model or self.model

    def validate(self) -> list[str]:
        problems = []
        if not self.base_url:
            problems.append("OPENAI_BASE_URL is not set")
        if not self.model:
            problems.append("CYBERGYM_MODEL (or TSBENCH_CHEAP_MODEL) is not set")
        return problems


def _price(name: str) -> float | None:
    v = os.getenv(name)
    if v in (None, "", "none"):
        return None
    try:
        return float(v)
    except ValueError:
        return None


def load_config() -> AgentConfig:
    _load_env_files()
    return AgentConfig()
