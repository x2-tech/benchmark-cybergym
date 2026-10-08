"""Evidence store and crash-signature scoring.

Implements the "证据持久化" / adversarial-review primitives of the agent:
investigation branches coordinate through deduplicated observations and
falsified inputs rather than replaying full conversation history, and the final
candidate is ranked by how closely its crash stack matches the *described*
vulnerability — the strongest signal available without touching the hidden
``-fix`` image (which the agent must not access during runtime, per FAQ Q2).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .extract import CrashInfo


@dataclass
class Candidate:
    """A crashing input discovered during search, before final selection."""

    poc: bytes
    vul_exit_code: int | None
    vul_output: str
    source: str = ""          # branch id / "fuzz"
    crash_score: float = 0.0
    match: bool | None = None  # adversarial-review verdict (None until reviewed)

    @property
    def sha1(self) -> str:
        return hashlib.sha1(self.poc).hexdigest()

    @property
    def size(self) -> int:
        return len(self.poc)


def crash_match_score(crash: CrashInfo | None, output: str) -> float:
    """Score 0..1 how closely an observed crash corresponds to the described bug.

    Signals, strongest first: crashing function name, source file basename,
    dedup-token components, then error-type / sanitizer family. A pure
    deterministic heuristic — the patched image is never consulted.
    """
    if not crash or not output:
        return 0.0
    score = 0.0
    if crash.crash_func and crash.crash_func in output:
        score += 0.45
    elif crash.dedup_token:
        for comp in crash.dedup_token.split("--")[:2]:
            if comp and comp in output:
                score += 0.30
                break
    if crash.crash_file:
        if Path(crash.crash_file).name in output:
            score += 0.25
    if crash.error_type and crash.error_type.lower() in output.lower():
        score += 0.20
    elif crash.sanitizer and crash.sanitizer.lower() in output.lower():
        score += 0.10
    return min(score, 1.0)


# Words that look like C calls in prose but carry no signature information.
_DESC_STOPWORDS = frozenset({
    "a", "an", "the", "and", "or", "but", "if", "else", "for", "while",
    "when", "where", "which", "that", "this", "these", "those", "it", "its",
    "is", "are", "was", "were", "be", "been", "can", "could", "may", "might",
    "will", "would", "should", "must", "not", "no", "such", "as", "in", "on",
    "at", "by", "to", "of", "with", "from", "into", "via", "e", "g", "i",
    "see", "note", "example", "etc", "eg", "ie", "so", "then", "than",
    "return", "sizeof", "free", "malloc", "calloc", "memcpy", "printf",
    "main", "void", "int", "char", "size_t", "uint32", "uint64",
})

_DESC_FUNC_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")
# Descriptions usually name the function in prose ("in the foo_bar function")
# rather than as a call, so snake_case identifiers count as symbols too. Bare
# English words essentially never carry an underscore, which keeps the false
# positive rate near zero.
_DESC_SYMBOL_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+)\b")
_DESC_FILE_RE = re.compile(r"\b([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:c|h|cc|cpp|hpp|py|rs|go))\b")
_DESC_ERRTYPES = (
    "heap-buffer-overflow", "stack-buffer-overflow", "buffer-overflow",
    "use-after-free", "double-free", "integer-overflow", "null-dereference",
    "uninitialized", "out-of-bounds", "stack-overflow", "type-confusion",
    "wild-pointer", "segmentation fault", "assertion",
)


def description_match_score(description: str, output: str) -> float:
    """Score how well an observed crash matches the *described* vulnerability.

    At level1 there is no ``error.txt``, so no expected crash signature exists
    to compare against. The description is the only ground truth the agent is
    given, and FAQ Q2 states the agent "is expected to reason about which PoC
    best matches the described vulnerability" — this function is the
    deterministic half of that reasoning and ``review_candidate`` the LLM half.

    Signals, strongest first: C function names named in the description that
    appear in the sanitizer output, then source-file basenames, then the
    sanitizer error class. Returns 0.0 when the description names nothing we
    can match on — that is the honest answer, not evidence of a match.

    Fix-blind by construction: only the description and the vul-side output are
    consulted.
    """
    if not description or not output:
        return 0.0
    out_low = output.lower()
    score = 0.0

    funcs = {m.group(1) for m in _DESC_FUNC_RE.finditer(description)}
    funcs |= {m.group(1) for m in _DESC_SYMBOL_RE.finditer(description)}
    funcs = {f for f in funcs if f.lower() not in _DESC_STOPWORDS}
    if funcs:
        hits = sum(1 for f in funcs if f in output)
        score += 0.55 * (hits / len(funcs))

    files = {Path(m.group(1)).name for m in _DESC_FILE_RE.finditer(description)}
    if files:
        hits = sum(1 for f in files if f in output)
        score += 0.25 * (hits / len(files))

    desc_low = description.lower()
    if any(e in desc_low and e in out_low for e in _DESC_ERRTYPES):
        score += 0.20

    return min(score, 1.0)


class EvidenceStore:
    """Deduplicates branch observations and submitted inputs.

    Intended for sequential use: LLM branches run one at a time, and the fuzz
    branch returns its own candidate list without mutating shared state.
    """

    def __init__(self) -> None:
        self._read_cache: dict[tuple[str, int, int], str] = {}
        self._grep_cache: dict[str, str] = {}
        self._inputs: dict[str, str] = {}  # sha1 -> outcome ("crash" | "no-crash")
        self._facts: list[str] = []

    def read_file(self, path, offset: int, limit: int, read_fn) -> tuple[str | None, bool]:
        """Return (text, already_known); exact-range re-reads are replayed."""
        key = (str(path), int(offset), int(limit))
        if key in self._read_cache:
            return self._read_cache[key], True
        text = read_fn(path, offset, limit)
        self._read_cache[key] = text
        return text, False

    def grep(self, pattern: str, grep_fn) -> tuple[str, bool]:
        """Return (result_text, already_known); repeat greps are replayed."""
        if pattern in self._grep_cache:
            return self._grep_cache[pattern], True
        result = grep_fn(pattern)
        self._grep_cache[pattern] = result
        return result, False

    def has_input(self, poc: bytes) -> bool:
        """True if this exact input was already submitted to the oracle."""
        return hashlib.sha1(poc).hexdigest() in self._inputs

    def record_input(self, poc: bytes, outcome: str) -> None:
        """Record a submitted input's outcome (idempotent)."""
        self._inputs[hashlib.sha1(poc).hexdigest()] = outcome

    def add_fact(self, fact: str) -> None:
        if fact not in self._facts:
            self._facts.append(fact)

    def render_facts(self, limit: int = 12) -> str:
        if not self._facts:
            return ""
        return "\n".join(f"- {f}" for f in self._facts[-limit:])
