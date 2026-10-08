"""LLM-assisted fuzz planning: dictionary tokens and seed selection.

A fuzzer's reach on a structured format is bounded by its corpus: random
mutation of a file that fails header validation never reaches the deep parser
branches where the bug lives. Two cheap LLM judgements widen that reach.

Where the LLM actually helps
-----------------------------
Not by writing seed bytes — it is no better at emitting a valid CFF table than
at hand-writing the whole PoC, which is the very failure this is meant to fix.
What it is good at is *reading code and naming constants*: the magic bytes, chunk
tags, record kinds and sentinel values that a parser branches on, plus picking
which of a hundred candidate files is most likely to exercise the crash site.

Both outputs are small text, which is the shape of work the model is reliable
at. Everything byte-level is still produced by the fuzzer.

If the planner call fails for any reason the caller keeps its deterministic
behaviour, so this can only add reach, never remove it.
"""

from __future__ import annotations

import re
from pathlib import Path

from .extract import CrashInfo
from .fuzz import _SEED_EXTS
from .llm import LLMClient, system, user

# libFuzzer dictionaries are `token="literal"`; AFL++ and honggfuzz accept the
# same file via their -x/--dict flags, so one format serves all three engines.
_MAX_TOKENS = 60
_MAX_TOKEN_LEN = 24
_MAX_SEED_PICKS = 12
# Repo test data goes up to hundreds of MB; that is a corpus entry, not a
# fuzzing seed, and reading it into memory to hand to docker is pure cost.
_MAX_SEED_BYTES = 512 * 1024

# Reuse the harvester's extension set so both stages agree on what counts as a
# candidate; the wider list below adds formats the fuzzer-side set omits, and
# the config formats are dropped because a YAML file is never a fuzzing seed.
_CONFIG_EXTS = {".yaml", ".yml", ".toml", ".ini", ".cfg", ".txt", ".md", ".rst", ".am", ".ac", ".cmake"}

_SEED_EXTS = (_SEED_EXTS | {
    ".tiff", ".tif", ".jp2", ".webp", ".heif", ".avif", ".zip", ".tar", ".gz",
}) - _CONFIG_EXTS


_SYSTEM = """\
You are helping configure a coverage-guided fuzzer for a C/C++ parser.

You will be shown the fuzzer harness entry point and the crash signature. Infer \
the INPUT FORMAT and reply with JSON only.

"tokens": format-level constants the parser compares input against — magic \
numbers, file signatures, chunk/tag identifiers, keyword strings, record type \
bytes. These become dictionary entries and dramatically improve the fuzzer's \
reach past header validation. Use short literals (<= 24 bytes). Include the \
file signature first if the format has one. Give at most 40 tokens.

"seeds": indices into the provided candidate file list, most promising first. \
Prefer files whose name or extension matches the input format, and files that \
look like small valid samples rather than large real-world blobs or build \
artifacts. At most 12 indices. If no candidates were provided, use [].

"reason": AT MOST 10 WORDS.

Reply with exactly one JSON object and nothing else — no prose before or after:
{"tokens": ["..."], "seeds": [0], "reason": "short"}

Tokens must be literal bytes that appear in valid input files, not descriptive \
words. Never invent a token you cannot justify from the harness or the format's \
public specification."""


def _salvage_seeds(text: str, n_candidates: int) -> list[int]:
    """Recover seed indices from a truncated reply.

    The reply is emitted in key order, so a model that lists 60 tokens before
    its picks can be cut off right where the useful part starts. Parsing the
    ``seeds`` array by regex keeps those picks instead of discarding them.
    """
    start = text.find('"seeds"')
    if start == -1:
        return []
    end = text.find("]", start)
    body = text[start:end] if end != -1 else text[start:]
    idx = [int(m) for m in re.findall(r"-?\d+", body.split(":", 1)[-1])]
    return _seed_indices({"seeds": idx}, n_candidates)


def _salvage_tokens(text: str) -> list[str]:
    """Recover tokens from a truncated reply.

    A reply cut off mid-array is common and, without this, costs the whole
    dictionary. Scanning for quoted literals before the truncation point still
    yields the magic bytes, which are emitted first.
    """
    start = text.find('"tokens"')
    if start != -1:
        end = text.find('"seeds"', start)
        text = text[start:end] if end != -1 else text[start:]
    # Only unescaped, short literals: a half-written escape sequence at the cut
    # point would otherwise produce a garbage token.
    found = re.findall(r'"([^"\\\n\r]{1,24})"', text)
    # The key names are quoted too; they are not format constants.
    return [t for t in found if t not in ("tokens", "seeds", "reason", "index", "why")]


def _tokens_from_reply(reply: dict) -> list[str]:
    """Validate and normalise planner tokens into printable dictionary literals."""
    raw = reply.get("tokens")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            continue
        tok = item
        if not tok or len(tok.encode("utf-8", errors="ignore")) > _MAX_TOKEN_LEN:
            continue
        # A dictionary literal cannot carry a raw newline, quote or backslash.
        if any(ch in tok for ch in ('\n', '\r', '"', '\\')):
            continue
        if any(ord(ch) < 0x20 for ch in tok):
            continue
        if tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
        if len(out) >= _MAX_TOKENS:
            break
    return out


def _seed_indices(reply: dict, n_candidates: int) -> list[int]:
    raw = reply.get("seeds")
    if not isinstance(raw, list):
        return []
    out: list[int] = []
    for item in raw:
        idx = item if isinstance(item, int) else None
        if idx is None:
            continue
        if 0 <= idx < n_candidates and idx not in out:
            out.append(idx)
        if len(out) >= _MAX_SEED_PICKS:
            break
    return out


def _render_dictionary(tokens: list[str], *, title: str) -> str:
    lines = [f"# {title}"]
    for tok in tokens:
        escaped = tok.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'dict_{len(lines)}="{escaped}"')
    return "\n".join(lines) + "\n"


def plan_fuzz(
    llm: LLMClient,
    *,
    crash: CrashInfo | None,
    harness_snippet: str,
    candidate_names: list[str],
    model: str | None = None,
) -> tuple[str, list[int], str]:
    """Ask the planner for dictionary tokens and seed preferences.

    Returns ``(dict_text, seed_indices, reason)``. Any failure yields an empty
    dictionary and no seed preference, leaving the caller's defaults intact.
    """
    listing = "\n".join(f"[{i}] {n}" for i, n in enumerate(candidate_names[:120]))
    parts = []
    if crash is not None:
        parts.append(
            f"Crash signature:\n"
            f"- project: {crash.project or 'unknown'}\n"
            f"- function: {crash.crash_func or 'unknown'}\n"
            f"- error type: {crash.error_type or 'unknown'}\n"
            f"- fuzz target: {crash.fuzzer_target or 'unknown'}"
        )
    if harness_snippet.strip():
        parts.append("Fuzzer harness / entry point:\n```c\n" + harness_snippet[:6000] + "\n```")
    if listing:
        parts.append("Candidate seed files:\n" + listing)
    else:
        parts.append("Candidate seed files: (none available)")

    try:
        reply = llm.chat_json(
            [system(_SYSTEM), user("\n\n".join(parts))],
            max_tokens=2000, temperature=0.2, model=model,
        )
    except Exception:  # noqa: BLE001 - planning is best-effort
        # chat_json raises when the reply is cut off mid-object, which is
        # exactly what a long token list invites. Re-ask once as free text and
        # keep whatever literals came through rather than losing the whole run.
        try:
            raw = llm.chat_text(
                [system(_SYSTEM), user("\n\n".join(parts))],
                max_tokens=2000, temperature=0.2, model=model,
            )
        except Exception:  # noqa: BLE001
            return "", [], ""
        tokens = _tokens_from_reply({"tokens": _salvage_tokens(raw)})
        dict_text = _render_dictionary(tokens, title="LLM-derived format tokens") if tokens else ""
        return dict_text, _salvage_seeds(raw, len(candidate_names)), "salvaged from truncated reply"

    tokens = _tokens_from_reply(reply)
    indices = _seed_indices(reply, len(candidate_names))
    reason = str(reply.get("reason") or "")[:200]
    dict_text = _render_dictionary(tokens, title="LLM-derived format tokens") if tokens else ""
    return dict_text, indices, reason


def harvest_harness_snippet(repo_root: Path, *, max_chars: int = 6000) -> str:
    """Locate the fuzz entry point and return its source (best effort).

    Reads the fuzzer's own harness rather than task text: the harness shows
    which bytes the parser is handed, which is what the token inference needs.
    """
    patterns = ("*fuzzer*.cc", "*fuzzer*.cpp", "*fuzzer*.c",
                "*Fuzzer*.cc", "*Fuzzer*.cpp",
                "*fuzz*.cc", "*fuzz*.cpp", "*fuzz*.c")
    best: Path | None = None
    for pat in patterns:
        for p in sorted(repo_root.rglob(pat)):
            if not p.is_file():
                continue
            if ".git" in p.parts:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size == 0 or size > 512 * 1024:
                continue
            if best is None or p.name.lower().startswith(("llvmfuzzertestoneinput", "fuzz", "fuzzer")):
                best = p
        if best is not None:
            break
    if best is None:
        return ""
    try:
        return best.read_text(errors="replace")[:max_chars]
    except OSError:
        return ""


def _seed_priority(p: Path) -> int:
    """Lower is better: real binary test data, then other data, then configs.

    The planner's judgement is only as good as what it is shown, and a repo
    holds far more YAML than it does fonts. Sorting here means the 120 slots go
    to plausible samples instead of CI configuration.
    """
    low = p.as_posix().lower()
    if any(k in low for k in (".circleci", ".travis", ".github", "appveyor")):
        return 5
    if p.suffix.lower() in _CONFIG_EXTS:
        return 4
    in_data = any(k in low for k in ("test", "data", "fixture", "example", "corpus", "sample"))
    if p.suffix.lower() in _SEED_EXTS and in_data:
        return 0
    if p.suffix.lower() in _SEED_EXTS:
        return 1
    return 3


def name_candidates(repo_root: Path, *, limit: int = 120) -> tuple[list[str], list[Path]]:
    """Choose candidate seed FILES to describe to the planner.

    Returns parallel lists of display names and paths, ordered so the most
    plausible samples are listed first and therefore numbered lowest — the
    planner picks by index, so ordering is part of the interface.
    """
    picked: list[tuple[int, str, Path]] = []
    for p in sorted(repo_root.rglob("*")):
        if not p.is_file() or ".git" in p.parts:
            continue
        if p.suffix.lower() not in _SEED_EXTS:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size == 0 or size > _MAX_SEED_BYTES:
            continue
        picked.append((_seed_priority(p), p.as_posix(), p))
    picked.sort(key=lambda t: (t[0], t[1]))
    chosen = picked[:limit]
    return [str(p.relative_to(repo_root)) for _, _, p in chosen], [p for _, _, p in chosen]
