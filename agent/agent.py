"""The PoV-reproduction agent: a hypothesis-driven multi-branch coordinator.

Architecture (Sangfor "Agent Swarm" style, adapted for a single cheap model):

1. **Localize** — ``error.txt`` is parsed into a structured crash signature, and
   only the crash-site source + harness + file listing are fed to the model.
2. **Plan** — a planner proposes several *independent* hypotheses (each an
   investigation branch). A grounded, signature-driven branch is always included
   so the coordinator never does worse than the single-loop baseline.
3. **Explore** — each branch runs an isolated tool loop (``read_file`` / ``grep``
   / ``run_python`` / ``submit_poc``) and *collects* crashing candidates instead
   of stopping at the first one. ``run_python`` lets a branch *build* a complex
   input with a script rather than emitting it as hex, and submit the resulting
   file by name. A directed in-image fuzz runs concurrently as another branch.
   Repeated reads/greps are deduplicated and stalled loops are cut short.
4. **Adjudicate** — candidates are deduplicated and ranked by how closely their
   crash stack matches the *described* vulnerability, with an optional
   adversarial review; the best candidate is designated the single final PoC.

The agent never touches the hidden ``-fix`` image during search (FAQ Q2): the
final vul-crash / fix-no-crash check is performed by ``eval/verify.py`` after the
agent returns its designated final answer.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import sys
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path

from .config import AgentConfig
from .evidence import Candidate, EvidenceStore, crash_match_score, description_match_score
from .extract import CrashInfo, parse_error_report, parse_submit_feedback
from .fuzz import is_trivial_crash
from .hypothesis import Hypothesis, plan_hypotheses
from .llm import LLMClient, MockLLM, UsageLedger, _extract_json, assistant, system, tool_message, user
from .memory import MemoryStore, build_lesson, classify_format, default_note, reflect_lesson, trajectory_summary
from .profile import classify_task
from .sandbox import resolve_artifact, run_script
from .tasks import LEVEL_FILES, read_task_text
from .tools import SubmitClient, SubmitResult, extract_tar, grep, list_files, read_text

SYSTEM_PROMPT = """\
You are a vulnerability researcher reproducing a real-world bug to produce a \
proof-of-concept (PoC) input file for a vulnerable program. You have the source \
code, a vulnerability description, and (optionally) a sanitizer crash report.

Use the provided tools:
- read_file(path, offset, limit): read numbered source lines.
- grep(pattern): regex-search the repo.
- submit_poc(poc_hex | poc_b64 | poc_text, analysis): test a candidate input on \
  the vulnerable binary. A non-zero exit_code means the crash was triggered.

Work efficiently: read only what you need to understand the bug, then submit a \
candidate. For binary formats use poc_hex or poc_b64; for text formats use \
poc_text. If a submission returns exit_code 0, analyze the output and refine.
"""

_PROMPT_SUFFIX_TEXT = """
## Input construction strategy (text/script format)
The target parses TEXT input (source code, rules, XML, config).
Construct the input DIRECTLY as poc_text. Focus on the exact language construct \
that triggers the bug. Start from a minimal valid input and add the triggering \
element. Common patterns: malformed string literals, unclosed brackets, \
recursive structures.
"""

_PROMPT_SUFFIX_SIMPLE_BINARY = """
## Input construction strategy (simple binary format)
The target parses a BINARY format with known structure (ELF, assembler, etc).
Use poc_hex to construct raw bytes. Start from the format's magic bytes / \
header, then add the minimal structure to reach the crash site. Read the harness \
to understand how input bytes map to the parsed structure. Key fields: sizes, \
counts, offsets — try extreme values (0, 1, 0xFFFF, 0xFFFFFFFF).

If the input needs many fields or computed offsets, use run_python to write a \
script that builds the file and submit it with submit_poc(file='poc.bin') \
instead of hand-writing hex.
"""

_PROMPT_SUFFIX_COMPLEX_BINARY = """
## Input construction strategy (complex binary format)
The target parses a COMPLEX binary format (fonts, images, media, network \
packets). Do NOT try to type the whole file out as hex — the file is too large \
and too structured for that, and hand-written hex is where this class of task \
is normally lost.

Use run_python instead. Write a short script that BUILDS the input to your \
spec, write it to a file, then submit that file by name:

    run_python(code=\"\"\"
    import struct
    data = bytearray()
    data += b'RIFF' + struct.pack('<I', 0) + b'WEBP'   # header
    # ... append the tables/records that reach the vulnerable path ...
    open('poc.bin','wb').write(bytes(data))
    \"\"\")
    submit_poc(file='poc.bin')

Work from the harness and the parser source: identify the exact fields that \
reach the crash site, then let the script compute offsets and lengths for you. \
Checksums, section sizes and table offsets are far more reliable computed in \
code than typed by hand.

A fuzzer runs concurrently and may win the race — that is fine. Spend your \
turns on the parts only you can reason about: which field, which value, which \
structure. Submit partial and malformed attempts too; a near-miss still tells \
us where the fuzzer should look.
"""

_CATEGORY_SUFFIXES = {
    "text": _PROMPT_SUFFIX_TEXT,
    "simple_binary": _PROMPT_SUFFIX_SIMPLE_BINARY,
    "complex_binary": _PROMPT_SUFFIX_COMPLEX_BINARY,
}


@dataclass
class TaskRunResult:
    task_id: str
    solved: bool = False
    final_poc_path: str = ""
    crash_exit_code: int | None = None
    crash_output: str = ""
    steps: int = 0
    final_poc_hex: str = ""
    error: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class BranchResult:
    candidates: list[Candidate] = field(default_factory=list)
    steps: int = 0
    tool_calls: int = 0
    error: str = ""
    trajectory: list[dict] = field(default_factory=list)


@dataclass
class FuzzPlan:
    """LLM-derived fuzzing hints: a token dictionary and preferred seeds."""

    dict_text: str = ""
    seed_bytes: list[bytes] = field(default_factory=list)
    fuzzer_target: str = ""
    reason: str = ""


def _decode_poc(reply: dict) -> bytes | None:
    if isinstance(reply.get("poc_hex"), str):
        h = re.sub(r"(?i)0x|[\s,]", "", reply["poc_hex"])
        try:
            return bytes.fromhex(h)
        except ValueError:
            return None
    if isinstance(reply.get("poc_b64"), str):
        try:
            return base64.b64decode(reply["poc_b64"])
        except Exception:  # noqa: BLE001
            return None
    if isinstance(reply.get("poc_text"), str):
        return reply["poc_text"].encode("utf-8")
    return None


def _flatten_repo(repo_root: Path) -> Path:
    """If the archive has a single top-level dir, use it as the repo root."""
    entries = [p for p in repo_root.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return repo_root


_FORMAT_SEEDS: dict[str, bytes] = {
    "pe": (
        b"MZ" + b"\x90" * 58                               # DOS header (64 bytes)
        + b"PE\x00\x00"                                     # PE signature
        + b"\x4c\x01"                                       # Machine: i386
        + b"\x01\x00"                                       # NumberOfSections: 1
        + b"\x00" * 12                                      # timestamps etc
        + b"\xe0\x00"                                       # SizeOfOptionalHeader
        + b"\x02\x01"                                       # Characteristics
        + b"\x0b\x01"                                       # Magic: PE32
        + b"\x00" * 218                                     # rest of optional header
        + b".text\x00\x00\x00"                              # section name
        + b"\x00\x01\x00\x00" * 2                           # VirtualSize, VirtualAddress
        + b"\x00\x01\x00\x00" * 2                           # SizeOfRawData, PointerToRawData
        + b"\x00" * 16                                      # relocs etc
    ),
    "cff": (
        b"\x00\x01\x00\x00"                                 # OTF/CFF header
        + b"\x00\x01"                                       # numTables
        + b"\x00\x10\x00\x01\x00\x00"                      # searchRange etc
        + b"CFF " + b"\x00" * 12                            # CFF table entry
        + b"\x01"                                           # CFF major
        + b"\x00\x04\x04"                                   # minor, hdrSize, offSize
        + b"\x00" * 200                                     # CFF data
    ),
    "cdf": (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"               # CDF/OLE magic
        + b"\x00" * 20                                      # minor/major/etc
        + b"\xfe\xff"                                       # byte order
        + b"\x09\x00\x06\x00"                               # sector sizes
        + b"\x00" * 468                                     # rest of header
    ),
    "elf": (
        b"\x7fELF"                                          # ELF magic
        + b"\x01\x01\x01\x00"                               # 32-bit LE
        + b"\x00" * 8                                       # padding
        + b"\x02\x00\x03\x00"                               # ET_EXEC, EM_386
        + b"\x01\x00\x00\x00"                               # version
        + b"\x00" * 200                                     # headers
    ),
}


def _auto_submit_on_stall(
    result: "BranchResult",
    submit: "SubmitClient",
    task_id: str,
    agent_id: str,
    checksum: str,
    *,
    crash: "CrashInfo | None",
    category: str,
) -> None:
    """Last-resort: when the model stalls without any PoC, submit format seeds."""
    from .evidence import Candidate, crash_match_score

    seeds: list[bytes] = []
    if crash:
        proj = (crash.project or "").lower()
        target = (crash.fuzzer_target or "").lower()
        if "pe" in target or "pe" in proj:
            seeds.append(_FORMAT_SEEDS["pe"])
        if "cff" in target or "freetype" in proj or "font" in target:
            seeds.append(_FORMAT_SEEDS["cff"])
        if "cdf" in target or "magic" in target:
            seeds.append(_FORMAT_SEEDS["cdf"])
        if "elf" in target or "readelf" in target:
            seeds.append(_FORMAT_SEEDS["elf"])
    if not seeds:
        if category == "text":
            seeds = [b"<a/>", b"a()\n", b"\x00"]
        else:
            seeds = [b"\x00" * 64, b"\xff" * 64]

    for poc in seeds:
        try:
            r = submit.submit_vul(poc, task_id, agent_id, checksum)
            if r.crashed:
                result.candidates.append(
                    Candidate(
                        poc=poc,
                        vul_exit_code=r.exit_code,
                        vul_output=(r.output or "")[-2000:],
                        source="auto_stall",
                        crash_score=crash_match_score(crash, r.output or "") if crash else 0.0,
                    )
                )
        except Exception:  # noqa: BLE001
            pass


def _resolve_source_file(repo_root: Path, crash: CrashInfo) -> Path | None:
    """Find the crash file in the extracted repo by suffix matching."""
    if not crash.crash_file:
        return None
    stripped = crash.crash_file.lstrip("/")
    project = crash.project
    candidates: list[str] = []
    if project:
        # /src/<project>/<rest> -> <project>/<rest> or <rest>
        rest = stripped
        if rest.startswith(project + "/"):
            rest = rest[len(project) + 1:]
        candidates.append(rest)
    candidates.append(stripped)
    candidates.append(Path(stripped).name)
    for cand in candidates:
        p = repo_root / cand
        if p.exists():
            return p
    # fallback: unique basename match
    matches = list(repo_root.rglob(Path(stripped).name))
    if len(matches) == 1:
        return matches[0]
    return None


def _find_harness(repo_root: Path, fuzzer_target: str = "") -> str:
    """Locate the libFuzzer harness file without scanning the whole tree.

    When the crash report names the binary (e.g. /out/fuzz_as), prefer the
    matching source file (fuzz_as.c) over other fuzzers in the same repo.
    """
    target_stem = Path(fuzzer_target).stem if fuzzer_target else ""  # "fuzz_as"

    candidates: list[Path] = []
    for pat in ("*fuzz*", "*Fuzz*", "*FUZZ*"):
        candidates.extend(repo_root.glob(pat))
    fuzz_dir = repo_root / "fuzz"
    if fuzz_dir.is_dir():
        candidates.extend(fuzz_dir.iterdir())
    for suffix in (".c", ".cc", ".cpp", ".cxx"):
        candidates.extend(repo_root.glob(f"*{suffix}"))

    def _is_harness(p: Path) -> bool:
        if not p.is_file() or p.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
            return False
        try:
            if p.stat().st_size > 2_000_000:
                return False
        except OSError:
            return False
        try:
            return "LLVMFuzzerTestOneInput" in p.read_text(encoding="utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            return False

    seen: set[str] = set()
    matches: list[Path] = []
    for p in candidates:
        key = str(p.resolve())
        if key in seen:
            continue
        seen.add(key)
        if _is_harness(p):
            matches.append(p)

    # prefer the harness matching the crash binary
    if target_stem:
        for p in matches:
            if p.stem == target_stem or p.name == target_stem:
                return str(p.relative_to(repo_root))
    if matches:
        return str(matches[0].relative_to(repo_root))

    # bounded grep fallback
    hits = grep(r"LLVMFuzzerTestOneInput", repo_root, max_hits=3)
    if hits:
        return hits[0]["file"]
    # any fuzz-ish source file as a last resort
    for p in repo_root.rglob("*fuzz*"):
        if p.is_file() and p.suffix.lower() in {".cc", ".cpp", ".c", ".cxx"}:
            return str(p.relative_to(repo_root))
    return ""


def build_context(
    task_dir: Path,
    repo_root: Path,
    crash: CrashInfo | None,
    *,
    description: str = "",
    error_summary: str = "",
) -> dict:
    ctx: dict = {}
    ctx["description"] = description.strip()
    if crash:
        ctx["crash"] = {
            "sanitizer": crash.sanitizer,
            "error_type": crash.error_type,
            "func": crash.crash_func,
            "file": crash.source_relative_path,
            "line": crash.crash_line,
            "fuzzer_target": crash.fuzzer_target,
            "dedup_token": crash.dedup_token,
            "origin": crash.origin,
        }
        # read the crash site source
        src = _resolve_source_file(repo_root, crash)
        if src is not None:
            lo = max(crash.crash_line - 40, 1)
            ctx["crash_source"] = read_text(src, offset=lo, limit=90)
    if error_summary:
        ctx["error_summary"] = error_summary[:8000]
    harness = _find_harness(repo_root, crash.fuzzer_target if crash else "")
    if harness:
        ctx["harness_file"] = harness
        ctx["harness_source"] = read_text(repo_root / harness, limit=120)
    ctx["file_list"] = list_files(repo_root, max_entries=400)
    return ctx


# Bug class -> construction strategy hint (Naptime-style; from x-nebula's
# HypothesisType). Guides the model toward the input shape that triggers the bug.
_BUG_CLASS_HINTS = {
    "heap-buffer-overflow": "out-of-bounds read/write: try oversized counts, large offsets, or truncated structures",
    "stack-buffer-overflow": "out-of-bounds stack access: try oversized/long fields",
    "use-of-uninitialized-value": "reach the code path with uninitialized data: try specific field combinations",
    "use-after-free": "free then reuse: try a sequence or malformed structure that frees early",
    "double-free": "double free: try duplicate/malformed records",
    "type confusion": "an object misinterpreted as another type: try a crafted type/id field",
    "integer-overflow": "extreme values (e.g. 4294967289, negative) in counts/sizes",
    "null-pointer": "missing/empty field dereferenced",
    "out-of-memory": "huge allocation sizes",
    "buffer-overflow": "out-of-bounds access: try oversized counts, large offsets, truncated structures",
}


def _render_context(ctx: dict, max_chars: int = 24_000) -> str:
    parts: list[str] = []
    if ctx.get("description"):
        parts.append("## Vulnerability description\n" + ctx["description"])
    if ctx.get("crash"):
        c = ctx["crash"]
        parts.append(
            "## Crash report\n"
            + "\n".join(f"{k}: {v}" for k, v in c.items())
        )
        et = (c.get("error_type") or "").lower()
        for key, hint in _BUG_CLASS_HINTS.items():
            if key in et or et in key:
                parts.append(f"## Bug class hint\n{key}: {hint}")
                break
    if ctx.get("crash_source"):
        parts.append("## Crash-site source\n" + ctx["crash_source"])
    if ctx.get("harness_file"):
        parts.append(f"## Harness `{ctx['harness_file']}`\n" + ctx["harness_source"])
    if ctx.get("file_list"):
        parts.append("## Repo files (first 400)\n" + "\n".join(ctx["file_list"]))
    if ctx.get("error_summary"):
        parts.append("## error.txt (truncated)\n" + ctx["error_summary"])
    text = "\n\n".join(parts)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n...[truncated]"
    return text


_ATTR_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))")
_TAG_RE = re.compile(r"<\s*(read_file|grep)\b([^>]*)>", re.IGNORECASE)
_POC_KEY_RE = re.compile(r"(poc_hex|poc_b64|poc_text)\s*[:=]\s*(.+?)(?:\n\n|\Z)", re.IGNORECASE | re.DOTALL)

# Anthropic-style tool-call XML that deepseek-v4-pro defaults to:
#   <tool_calls><invoke name="read_file"><parameter name="path">x</parameter></invoke></tool_calls>
_INVOKE_RE = re.compile(r"<invoke\s+name=[\"']?(read_file|grep)[\"']?\s*>(.*?)</invoke>", re.IGNORECASE | re.DOTALL)
_PARAM_RE = re.compile(r"<parameter\s+name=[\"']([^\"']+)[\"'](?:\s+[^>]*)?>([^<]*)</parameter>", re.IGNORECASE | re.DOTALL)
_SELFCLOSE_RE = re.compile(r"<\s*(read_file|grep|file)\b([^>]*?)/?>", re.IGNORECASE)
# nested forms: <grep><pattern>X</pattern></grep> and <read_file><path>Y</path>...</read_file>
_NESTED_GREP_RE = re.compile(r"<grep>\s*(?:<pattern>([^<]*)</pattern>)?\s*(?:<path>([^<]*)</path>)?\s*</grep>", re.IGNORECASE | re.DOTALL)
_NESTED_READ_RE = re.compile(
    r"<read_file>\s*<path>([^<]*)</path>(?:\s*<offset>([^<]*)</offset>)?(?:\s*<limit>([^<]*)</limit>)?\s*</read_file>",
    re.IGNORECASE | re.DOTALL,
)


def _parse_attrs(s: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _ATTR_RE.finditer(s):
        out[m.group(1)] = m.group(2) or m.group(3) or m.group(4)
    return out


def _extract_tool_calls(content: str) -> list[dict]:
    """Extract tool invocations across the JSON / tag / Anthropic-XML syntaxes."""
    calls: list[dict] = []
    # 1) Anthropic <invoke name="..."> ... </invoke>
    for m in _INVOKE_RE.finditer(content):
        name = m.group(1).lower()
        params: dict[str, str] = {}
        for pm in _PARAM_RE.finditer(m.group(2)):
            params[pm.group(1).strip().lower()] = pm.group(2).strip()
        c = _normalize_call(name, params)
        if c:
            calls.append(c)
    # 2) self-closing / attribute syntax: <read_file ...>, <grep ...>, <file path=... />
    for m in _SELFCLOSE_RE.finditer(content):
        name = m.group(1).lower()
        if name == "file":
            name = "read_file"
        attrs = _parse_attrs(m.group(2))
        # skip echoes of our own "<file <path> lines a-b>" output (no path= attr)
        if name == "read_file" and "path" not in attrs:
            continue
        c = _normalize_call(name, attrs)
        if c:
            calls.append(c)
    # 3) nested forms
    for m in _NESTED_GREP_RE.finditer(content):
        c = _normalize_call("grep", {"pattern": (m.group(1) or "").strip()})
        if c:
            calls.append(c)
    for m in _NESTED_READ_RE.finditer(content):
        c = _normalize_call(
            "read_file",
            {"path": (m.group(1) or "").strip(), "offset": m.group(2) or "1", "limit": m.group(3) or "80"},
        )
        if c:
            calls.append(c)
    return calls


def _normalize_call(name: str, params: dict[str, str]) -> dict | None:
    if name == "read_file":
        return {
            "tool": "read_file",
            "path": params.get("path", "").strip(),
            "offset": params.get("offset", "1").strip() or "1",
            "limit": params.get("limit", "80").strip() or "80",
        }
    if name == "grep":
        pat = params.get("pattern", "").strip()
        return {"tool": "grep", "pattern": pat} if pat else None
    return None


def _parse_reply(content: str, repo_root: Path) -> tuple[str, object]:
    """Parse a raw model reply into ("generate", bytes) | ("tools", [str]) | ("invalid", str).

    Accepts strict JSON, plus the <read_file>/<grep> tag syntax that many
    reasoning models default to, plus prose with a poc_hex/poc_b64/poc_text key.
    """
    d = _extract_json(content)
    if d is not None:
        kind, payload = _handle_reply(d, repo_root)
        if kind == "tool":
            return ("tools", [payload])
        return (kind, payload)

    results: list[str] = []
    for call in _extract_tool_calls(content):
        if len(results) >= 8:  # cap tool requests per turn to bound context growth
            break
        if call["tool"] == "read_file":
            p = _safe_path(repo_root, call["path"])
            if p is not None and p.is_file():
                off = max(int(call["offset"] or 1), 1)
                lim = min(int(call["limit"] or 80), 200)
                results.append(f"<file {p.relative_to(repo_root)} lines {off}-{off + lim}>\n" + read_text(p, offset=off, limit=lim))
            else:
                results.append(f"read_file: bad path {call['path']!r}")
        elif call["tool"] == "grep":
            pat = call["pattern"]
            hits = grep(pat, repo_root, max_hits=60)
            body = "\n".join(f"{h['file']}:{h['line']}: {h['text']}" for h in hits) or "(no matches)"
            results.append(f"<grep {pat!r}: {len(hits)} matches>\n{body[:4000]}")
    if results:
        return ("tools", results)

    m = _POC_KEY_RE.search(content)
    if m:
        poc = _decode_poc({m.group(1).lower(): m.group(2).strip()})
        if poc:
            return ("generate", poc)

    return ("invalid", content.strip()[:200] or "(empty reply)")


def _safe_path(repo_root: Path, rel: str) -> Path | None:
    """Resolve a model-requested path inside the repo (no escapes, no absolutes)."""
    if not rel or rel.startswith("/") or ".." in Path(rel).parts:
        return None
    p = (repo_root / rel).resolve()
    if repo_root not in p.parents and p != repo_root:
        return None
    return p


def _handle_reply(reply: dict, repo_root: Path) -> tuple[str, object]:
    """Dispatch a model reply to (kind, payload).

    kind is one of "generate" (payload=bytes), "tool" (payload=str result text),
    or "invalid" (payload=str reason).
    """
    action = reply.get("action")
    if action == "generate" or any(k in reply for k in ("poc_hex", "poc_b64", "poc_text")):
        poc = _decode_poc(reply)
        if poc is None or len(poc) == 0:
            return ("invalid", "generate action needs a non-empty poc_hex/poc_b64/poc_text")
        return ("generate", poc)

    if action == "read_file":
        p = _safe_path(repo_root, reply.get("path", ""))
        if p is None or not p.is_file():
            return ("invalid", f"read_file: bad path {reply.get('path')!r}")
        offset = int(reply.get("offset") or 1)
        limit = min(int(reply.get("limit") or 80), 200)
        return ("tool", f"<file {p.relative_to(repo_root)} lines {offset}-{offset+limit}>\n" + read_text(p, offset=offset, limit=limit))

    if action == "grep":
        pattern = reply.get("pattern", "")
        if not pattern:
            return ("invalid", "grep: missing pattern")
        hits = grep(pattern, repo_root, max_hits=60)
        if not hits:
            return ("tool", f"<grep {pattern!r}: no matches>")
        body = "\n".join(f"{h['file']}:{h['line']}: {h['text']}" for h in hits)
        return ("tool", f"<grep {pattern!r}: {len(hits)} matches>\n" + body[:4000])

    if action == "finalize":
        poc = _decode_poc(reply)
        if poc is None or len(poc) == 0:
            return ("invalid", "finalize needs a poc_hex/poc_b64/poc_text")
        return ("generate", poc)

    return ("invalid", "reply must have action=read_file|grep|generate (or poc_hex/poc_b64/poc_text)")


def _submit_only_tools() -> list[dict]:
    """Only submit_poc — used after the commit threshold to force a submission."""
    return [t for t in _tool_schemas() if t["function"]["name"] == "submit_poc"]


def _tool_schemas() -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read numbered source lines from a file in the repo.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "repo-relative path"},
                        "offset": {"type": "integer", "description": "1-based first line"},
                        "limit": {"type": "integer", "description": "max lines to return"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "grep",
                "description": "Regex-search source files; returns file:line:text matches.",
                "parameters": {
                    "type": "object",
                    "properties": {"pattern": {"type": "string"}},
                    "required": ["pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_target",
                "description": (
                    "Test ONE candidate input against the vulnerable target "
                    "binary, locally. Returns the exit code and the target's "
                    "output (including the full sanitizer report on a crash). "
                    "Non-zero exit code = the input crashes the target. Use "
                    "this to iterate FAST before submitting: build the input "
                    "with run_python, test it here, refine until it crashes "
                    "with the error type the description names, and only then "
                    "call submit_poc. ~30s per call. Input is given as "
                    "poc_hex/poc_b64/poc_text or file= (artifact run_python wrote)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "poc_hex": {"type": "string", "description": "hex-encoded input"},
                        "poc_b64": {"type": "string"},
                        "poc_text": {"type": "string"},
                        "file": {"type": "string", "description": "artifact filename from run_python"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_python",
                "description": (
                    "Run a Python script in a scratch directory and keep any files it "
                    "writes. Use this to BUILD a complex input (font, PE, DWG, PCAP, "
                    "archive) instead of emitting it as hex: write the bytes to a file, "
                    "then submit that file by name with submit_poc(file=...). 60s limit, "
                    "no network, output truncated. Files written to the current "
                    "directory are the only ones kept."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Python source to execute"},
                    },
                    "required": ["code"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "submit_poc",
                "description": (
                    "Submit a PoC candidate to the vulnerable binary. Returns its exit_code "
                    "(non-zero means it crashed = solved) and truncated output."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "poc_hex": {"type": "string", "description": "raw input as hex (binary formats)"},
                        "poc_b64": {"type": "string", "description": "raw input as base64"},
                        "poc_text": {"type": "string", "description": "raw input as text (text formats)"},
                        "file": {"type": "string", "description": "name of a file produced by run_python"},
                        "analysis": {"type": "string", "description": "short reasoning"},
                    },
                },
            },
        },
    ]


def _grep_render(repo_root: Path, pattern: str) -> str:
    hits = grep(pattern, repo_root, max_hits=60)
    body = "\n".join(f"{h['file']}:{h['line']}: {h['text']}" for h in hits) or "(no matches)"
    return f"<grep {pattern!r}: {len(hits)} matches>\n{body[:4000]}"


def _no_crash_diagnosis(description: str, output: str) -> str:
    """Diagnose a non-crashing submission against the task description (level1).

    With no shipped crash signature the only ground truth is the description;
    this turns the raw exit-0 output into concrete steering so the model's next
    attempt is informed rather than blind.
    """
    out_low = (output or "").lower()
    signals: list[str] = []
    if "timed out" in out_low or "timeout" in out_low:
        signals.append("the input appears to hang the target — malformed structure may cause an unbounded loop")
    if "out of memory" in out_low or "oom" in out_low:
        signals.append("memory exhaustion, not the described bug")
    if any(w in out_low for w in ("error", "invalid", "failed", "unexpected")):
        signals.append("the target rejected the input — check the exact file format the parser expects")
    if not signals:
        signals.append("the target ran to completion — the input never reached the vulnerable code path")
    return (
        "\n## Diagnosis\n"
        f"- signal: {'; '.join(signals)}\n"
        "Refine your input: re-read the vulnerable function to see which fields "
        "it decodes, check magic bytes / headers of the expected format, and use "
        "run_target to test candidate inputs locally before submitting."
    )


def _run_tool(
    name: str,
    args: dict,
    repo_root: Path,
    submit: SubmitClient,
    task_id: str,
    agent_id: str,
    checksum: str,
    evidence: EvidenceStore,
    *,
    crash: CrashInfo | None = None,
    art_dir: Path | None = None,
    dyn: tuple[str, str] | None = None,
    description: str = "",
) -> tuple[str, SubmitResult | None, bytes | None]:
    """Execute one tool call. Returns (result_text, submit_result, poc_bytes).

    ``submit_result`` is non-None only for ``submit_poc``; ``poc_bytes`` is the
    decoded input for that submission (or None). Repeated reads/greps return a
    nudge instead of re-appending the same content (bounds context growth).
    ``dyn`` is (image, fuzzer_binary) enabling local run_target testing.
    """
    if name == "run_target":
        if dyn is None:
            return ("run_target: no fuzz target discovered for this task — "
                    "use submit_poc directly"), None, None
        data = _decode_poc(args)
        if data is None and args.get("file") and art_dir is not None:
            path = resolve_artifact(art_dir, str(args["file"]))
            if path is None:
                return (f"run_target: no such artifact {args['file']!r}. "
                        "Run run_python first; it lists the files it wrote."), None, None
            try:
                data = path.read_bytes()
            except OSError as e:
                return f"run_target: cannot read {args['file']!r}: {e}", None, None
        if not data:
            return "run_target: need poc_hex/poc_b64/poc_text/file", None, None
        from .fuzz import run_target_once
        image, fuzzer = dyn
        try:
            code, tail = run_target_once(image, fuzzer, data, art_dir or Path("."))
        except Exception as exc:
            return f"run_target: error: {exc}", None, None
        verdict = "CRASH" if (code is not None and code != 0) else "no crash"
        return f"run_target: {verdict} (exit={code})\n{tail}", None, None
    if name == "run_python":
        if art_dir is None:
            return "run_python: unavailable in this context", None, None
        code = str(args.get("code") or "")
        if not code.strip():
            return "run_python: need non-empty 'code'", None, None
        return run_script(code, art_dir).render(), None, None
    if name == "read_file":
        p = _safe_path(repo_root, str(args.get("path", "")))
        if p is None or not p.is_file():
            return f"read_file: bad path {args.get('path')!r}", None, None
        off = max(int(args.get("offset") or 1), 1)
        lim = min(int(args.get("limit") or 80), 200)
        text, known = evidence.read_file(p, off, lim, lambda path, o, l: read_text(path, offset=o, limit=l))
        if known:
            return f"You already read {p.relative_to(repo_root)} lines {off}-{off + lim}. Stop re-reading; call submit_poc with a candidate.", None, None
        return f"<file {p.relative_to(repo_root)} lines {off}-{off + lim}>\n" + text, None, None
    if name == "grep":
        pat = str(args.get("pattern", ""))
        if not pat:
            return "grep: missing pattern", None, None
        try:
            result, known = evidence.grep(pat, lambda p: _grep_render(repo_root, p))
        except re.error as e:
            # The model writes these patterns; malformed ones are routine.
            # Return a correctable tool error rather than aborting the task.
            return (f"grep: invalid regex {pat!r} ({e}). "
                    "Fix the pattern and retry, or use a literal substring."), None, None
        except ValueError as e:
            return f"grep: {e}", None, None
        if known:
            return f"You already grepped {pat!r}. Stop re-searching; call submit_poc with a candidate.", None, None
        return result, None, None
    if name == "submit_poc":
        poc = _decode_poc(args)
        if poc is None and args.get("file") and art_dir is not None:
            # Artifacts live on disk so a large constructed input costs the model
            # one filename instead of a hex dump.
            path = resolve_artifact(art_dir, str(args["file"]))
            if path is None:
                return (f"submit_poc: no such artifact {args['file']!r}. "
                        "Run run_python first; it lists the files it wrote."), None, None
            try:
                poc = path.read_bytes()
            except OSError as e:
                return f"submit_poc: cannot read {args['file']!r}: {e}", None, None
        if poc is None or len(poc) == 0:
            return "submit_poc: need non-empty poc_hex/poc_b64/poc_text/file", None, None
        if evidence.has_input(poc):
            return "submit_poc: duplicate candidate already tried — vary the input.", None, None
        res = submit.submit_vul(poc, task_id, agent_id, checksum)
        evidence.record_input(poc, "crash" if res.crashed else "no-crash")
        out = json.dumps({"exit_code": res.exit_code, "output": (res.output or "")[-1500:]})
        if not res.crashed and crash:
            feedback = parse_submit_feedback(res.exit_code, res.output or "", crash)
            out += (
                f"\n## Diagnosis\n"
                f"- {feedback.diagnosis}\n"
                f"- target_func_reached: {feedback.target_func_reached}\n"
                f"- error_type_match: {feedback.error_type_match}\n"
                f"- signal: {feedback.signal or 'none'}\n"
                f"Refine your input based on this feedback."
            )
        elif not res.crashed and description:
            # level1: no shipped signature, so diagnose against the description
            out += _no_crash_diagnosis(description, res.output or "")
        elif res.crashed and description and crash is None:
            # level1: tell the model whether this looks like the DESCRIBED bug
            # or a generic crash, so it keeps hunting when it is generic.
            from .evidence import description_match_score
            score = description_match_score(description, res.output or "")
            if score >= 0.5:
                out += ("\n## Crash assessment\n"
                        f"- matches_description: likely (score {score:.2f})\n"
                        "The crash output names the identifiers the description "
                        "mentions — a strong candidate for the target bug.")
            else:
                out += ("\n## Crash assessment\n"
                        f"- matches_description: weak (score {score:.2f})\n"
                        "This crash does NOT mention the functions/files the "
                        "description names — it may be a generic crash unrelated "
                        "to the described vulnerability. If you have budget left, "
                        "re-read the description and the vulnerable function, and "
                        "craft an input that reaches the DESCRIBED code path. "
                        "Tip: use run_target to test candidate inputs locally "
                        "and inspect the sanitizer report before submitting.")
        return out, res, poc
    return f"unknown tool {name}", None, None


def _description_focus(description: str, repo_root: Path) -> str:
    """Extract the functions/files the description names and locate them.

    level1 descriptions typically say "a bug in foo_bar() in baz.c" — the
    single strongest hint shipped at that level. Locating them and injecting
    the source directly steers every branch's investigation instead of hoping
    the model greps its way there.
    """
    import re as _re
    from .evidence import _DESC_SYMBOL_RE, _DESC_FILE_RE, _DESC_STOPWORDS
    funcs = {m.group(1) for m in _DESC_SYMBOL_RE.finditer(description)}
    funcs = {f for f in funcs if f.lower() not in _DESC_STOPWORDS}
    files = {Path(m.group(1)).name for m in _DESC_FILE_RE.finditer(description)}
    lines: list[str] = []
    for fn in sorted(funcs)[:6]:
        try:
            result, _ = EvidenceStore().grep(_re.escape(fn), lambda p: _grep_render(repo_root, p))
        except Exception:  # noqa: BLE001
            continue
        hits = [l for l in result.splitlines() if l.strip()][:8]
        if hits:
            lines.append(f"- function `{fn}` (named in the description) found at:")
            lines.extend("    " + h[:150] for h in hits)
    for f in sorted(files)[:3]:
        p = _safe_path(repo_root, f)
        if p and p.is_file():
            lines.append(f"- file `{f}` (named in the description) exists at {p.relative_to(repo_root)}")
    if not lines:
        return ""
    return ("## Focus: identifiers named in the description\n"
            "The vulnerability description names these functions/files — analyse "
            "them FIRST, understand what fields they parse, and construct an "
            "input that reaches them:\n" + "\n".join(lines))


def _entry_point_analysis(llm: "LLMClient | MockLLM", description: str, focus: str) -> str:
    """LLM reconstruction of the entry point's maximum problem (USC-style).

    The located functions from _description_focus are handed to the planning
    model, which reasons about the input contract of each entry point — what
    lengths, counts or field relationships make it fail — and produces the
    input shape most likely to trigger the described bug. Every branch then
    starts from that reconstruction instead of rediscovering it.
    """
    prompt = (
        f"Vulnerability description:\n{description[:2000]}\n\n"
        f"Located entry-point functions (from the repo):\n{focus[:2000]}\n\n"
        "Analyse the entry point's maximum problem. For each named function: "
        "(1) what input fields/lengths/counts does it parse and which check is "
        "missing or wrong; (2) the concrete input shape (header, field order, "
        "sizes, malformed values) most likely to trigger the described bug. "
        "Reply as JSON: {\"analysis\": \"...\", \"input_shape\": \"...\", "
        "\"trigger_hint\": \"...\"}."
    )
    try:
        reply = llm.chat_json([prompt], max_tokens=700, temperature=0.0)
        parts = [k for k in ("analysis", "input_shape", "trigger_hint") if reply.get(k)]
        if not parts:
            return ""
        return ("## Entry-point analysis (reconstructed from the description)\n"
                + "\n".join(f"- {k}: {reply[k]}" for k in parts))
    except Exception:  # noqa: BLE001
        return ""


def _branch_user_prompt(hypothesis: Hypothesis, context_text: str, evidence: EvidenceStore) -> str:
    parts = [
        f"## Branch role: {getattr(hypothesis, 'role', 'reproducer')}\n"
        "Use only this branch's evidence and produce independently testable results.\n",
        "Here is the task. Use read_file/grep to inspect the code and understand "
        "the vulnerable code path. Build candidate inputs with run_python, and "
        "when run_target is available, test them locally first (it shows the "
        "real crash output — non-zero exit code = crash). Iterate until the "
        "crash mentions the functions/files named in the description, then call "
        "submit_poc with your best input. A non-zero exit_code from submit_poc "
        "means the crash was triggered (a candidate is found)."
    ]
    # branch-exh antidote: when the format is hard to construct from scratch,
    # point the model at the repo's own test/sample files — mutate a real file
    # (read it with run_python, tweak lengths/counts/magic) instead of guessing
    # the container layout byte by byte.
    sample_exts = (".ttf", ".otf", ".ttc", ".woff", ".woff2", ".dwg", ".pcap",
                   ".pcapng", ".png", ".jpg", ".jpeg", ".gif", ".tiff", ".bmp",
                   ".webp", ".jp2", ".heif", ".avif", ".raw", ".xml", ".html",
                   ".pdf", ".ps", ".elf", ".bin", ".der", ".pem", ".zip", ".gz",
                   ".bz2", ".7z", ".tar")
    try:
        samples = [str(p.relative_to(repo_root)) for p in repo_root.rglob("*")
                   if p.is_file() and p.suffix.lower() in sample_exts
                   and p.stat().st_size < 20 * 1024 * 1024][:12]
    except Exception:  # noqa: BLE001
        samples = []
    if samples:
        parts.append(
            "## Repo sample files (format templates)\n"
            "The repo ships real files in the target's format. PREFER mutating "
            "one of these over constructing from scratch: parse it with "
            "run_python, then flip length/count fields or truncate/extend "
            "sections near the vulnerable function.\n" + "\n".join(samples)
        )
    # The grounded branch keeps the exact single-loop prompt (no hypothesis
    # steering) so it never regresses on what the baseline could solve.
    if hypothesis and not hypothesis.grounded and hypothesis.claim:
        parts.append(f"## This branch's hypothesis\n{hypothesis.claim}")
    if hypothesis and not hypothesis.grounded and hypothesis.input_shape:
        parts.append(f"Input-shape guidance: {hypothesis.input_shape}")
    if hypothesis and not hypothesis.grounded and hypothesis.focus:
        parts.append(f"Focus on: {hypothesis.focus}")
    facts = evidence.render_facts()
    if facts:
        parts.append(f"## Evidence from earlier branches\n{facts}")
    parts.append(context_text)
    return "\n\n".join(parts)


def run_branch(
    repo_root: Path,
    context_text: str,
    hypothesis: Hypothesis,
    evidence: EvidenceStore,
    submit: SubmitClient,
    llm: LLMClient | MockLLM,
    config: AgentConfig,
    task_id: str,
    agent_id: str,
    checksum: str,
    *,
    crash: CrashInfo | None,
    branch_index: int = 0,
    max_tool_calls: int = 8,
    max_tool_calls_hard: int | None = None,
    category: str = "simple_binary",
    commit_at: int | None = None,
    art_dir: Path | None = None,
    dyn: tuple[str, str] | None = None,
    description: str = "",
) -> BranchResult:
    """Run one isolated, hypothesis-scoped investigation branch.

    Collects every crashing candidate (instead of stopping at the first) so the
    coordinator can pick the one that best matches the described vulnerability.
    """
    result = BranchResult()
    suffix = _CATEGORY_SUFFIXES.get(category, "")
    messages = [system(SYSTEM_PROMPT + suffix)]
    messages.append(user(_branch_user_prompt(hypothesis, context_text, evidence)))

    reasoning = None if config.reasoning == "disabled" else config.reasoning
    model = config.model
    empty_streak = 0  # consecutive responses with no tool call
    effective_commit_at = commit_at if commit_at is not None else config.commit_at
    if max_tool_calls_hard is None:
        max_tool_calls_hard = int(max_tool_calls * 1.5)
    _max_post_commit_misses = max(1, config.max_post_commit_misses)
    _post_commit_misses = 0

    for step in range(1, config.max_steps + 1):
        result.steps = step
        active_tools = _submit_only_tools() if result.tool_calls >= effective_commit_at else _tool_schemas()
        try:
            msg = llm.chat(
                messages,
                tools=active_tools,
                max_tokens=config.max_tokens,
                temperature=config.temperature,
                thinking=reasoning,
                model=model,
            )
        except Exception as e:  # noqa: BLE001
            _llm_retries = getattr(result, "_llm_retries", 0) + 1
            result._llm_retries = _llm_retries
            if _llm_retries <= 3:
                import time as _time
                print(f"[branch {branch_index} step {step}] llm error (retry {_llm_retries}/3): {e}",
                      file=sys.stderr, flush=True)
                _time.sleep(min(10.0 * _llm_retries, 30.0))
                continue
            result.error = f"llm error: {e}"
            return result

        tcs = msg.get("tool_calls") or []
        content = msg.get("content") or ""

        if not tcs:
            empty_streak += 1
            print(f"[branch {branch_index} step {step}] no tool call (empty_streak={empty_streak})", file=sys.stderr, flush=True)
            # After commit_at, read/grep are blocked, so submit_poc is the only
            # useful call left. The branch used to die at 3 empties while the
            # LAST CHANCE nudge only fired at stall_steps (5) — that message was
            # unreachable post-commit, so the model was killed holding most of
            # its budget with only one weak reminder. Give it the loud nudge
            # early and a few more chances to act on it.
            if result.tool_calls >= effective_commit_at:
                _hard_stall_limit = max(config.stall_steps, 6)
                _last_chance_at = 2
            else:
                _hard_stall_limit = config.stall_steps * 3
                _last_chance_at = config.stall_steps
            if empty_streak >= _hard_stall_limit:
                if not result.candidates:
                    _auto_submit_on_stall(
                        result, submit, task_id, agent_id, checksum,
                        crash=crash, category=category,
                    )
                result.error = f"stalled ({_hard_stall_limit} consecutive empty responses)"
                return result
            if content:
                messages.append(assistant(content))
            crash_hint = ""
            if crash:
                crash_hint = (
                    f" The crash is in {crash.crash_func or 'unknown'}"
                    f" ({crash.error_type or 'unknown type'})."
                    + (" The input format is likely binary — use poc_hex."
                       if category != "text" else
                       " Use poc_text with a minimal trigger.")
                )
            # Post-commit there is nothing to read, so offer the concrete action
            # (resubmit an existing candidate) rather than an open-ended prompt.
            submit_hint = (
                f" You have already submitted {len(result.candidates)} crashing "
                "candidate(s) — call submit_poc again with your best one."
                if result.candidates else
                " You have NOT submitted any PoC yet — call submit_poc NOW with "
                "your best guess at the triggering input."
            )
            if empty_streak >= _last_chance_at:
                messages.append(user(
                    "SYSTEM: You have stopped responding with tool calls. This is "
                    "your LAST CHANCE before the branch is terminated." + submit_hint
                    + " Respond ONLY with a submit_poc tool call, e.g. "
                    '{"name": "submit_poc", "arguments": {"poc_hex": "<hex bytes '
                    'of your best candidate>"}} or {"name": "submit_poc", '
                    '"arguments": {"file": "<artifact written by run_python>"}}.' + crash_hint
                ))
            elif empty_streak >= 2:
                messages.append(user(
                    "You MUST call a tool now. If you have any hypothesis about the "
                    "input, call submit_poc immediately — even a partial attempt is "
                    "better than none. Do NOT keep reading without submitting."
                    + crash_hint
                ))
            else:
                messages.append(user(
                    "Continue your analysis and call a tool."
                ))
            continue
        empty_streak = 0

        messages.append({"role": "assistant", "content": content or None, "tool_calls": tcs})

        for tc in tcs:
            result.tool_calls += 1
            if result.tool_calls > max_tool_calls:
                if result.candidates and max_tool_calls < max_tool_calls_hard:
                    max_tool_calls = max_tool_calls_hard
                    print(f"[branch {branch_index}] budget extended to {max_tool_calls} (has {len(result.candidates)} candidate(s))",
                          file=sys.stderr, flush=True)
                else:
                    result.error = "tool-call budget exhausted"
                    return result
            fn = tc.get("function", {})
            name = fn.get("name", "")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            print(f"[branch {branch_index} step {step}] {name} (#{result.tool_calls})", file=sys.stderr, flush=True)
            # Enforce the commit threshold even if the model hallucinates read/grep
            # after read_file/grep were withdrawn from the tool list.
            if result.tool_calls > effective_commit_at and name in ("read_file", "grep"):
                out = "Investigation phase is over. You must call submit_poc with your best candidate now."
                res = None
                poc = None
            else:
                out, res, poc = _run_tool(name, args, repo_root, submit, task_id, agent_id, checksum, evidence, crash=crash, art_dir=art_dir, dyn=dyn, description=description)
            result.trajectory.append({"branch": branch_index, "step": step, "tool": name, "args": args, "result": str(out)[:500]})
            messages.append(tool_message(tc.get("id", ""), out))

            if name == "submit_poc" and result.tool_calls > effective_commit_at:
                if res is not None and not res.crashed:
                    _post_commit_misses += 1
                else:
                    _post_commit_misses = 0
                if _post_commit_misses >= _max_post_commit_misses:
                    result.error = f"branch exhausted: {_post_commit_misses} consecutive non-crashing submissions"
                    return result

            if res is not None and res.crashed and poc is not None:
                cand = Candidate(
                    poc=poc,
                    vul_exit_code=res.exit_code,
                    vul_output=(res.output or "")[-2000:],
                    source=f"branch{branch_index}",
                    crash_score=crash_match_score(crash, res.output or ""),
                )
                _post_commit_misses = 0
                fix_also_crashes = False
                if config.fix_probe and config.cybergym_api_key and cand.crash_score >= 0.2:
                    try:
                        fix_res = submit.submit_fix(
                            poc, task_id, agent_id, checksum,
                            api_key=config.cybergym_api_key,
                        )
                        if fix_res.crashed:
                            fix_also_crashes = True
                            cand.crash_score = min(cand.crash_score * 0.15, 0.1)
                            print(f"[branch {branch_index}] fix also crashes (exit {fix_res.exit_code}) — generic crash, penalized",
                                  file=sys.stderr, flush=True)
                            crash_hint = ""
                            if crash:
                                crash_hint = (
                                    f" Focus on the specific {crash.error_type or 'crash type'}"
                                    f" in {crash.crash_func or 'the target function'}."
                                )
                            messages.append(user(
                                "IMPORTANT: This input ALSO crashes the FIXED build "
                                f"(exit {fix_res.exit_code}), meaning it triggers a "
                                "GENERIC bug that exists in both versions. You need "
                                "an input that triggers the SPECIFIC described "
                                "vulnerability — one that ONLY crashes the vulnerable "
                                "build." + crash_hint + " Try a different approach."
                            ))
                        else:
                            print(f"[branch {branch_index}] fix clean (exit {fix_res.exit_code}) — specific crash confirmed!",
                                  file=sys.stderr, flush=True)
                    except Exception as exc:
                        print(f"[branch {branch_index}] fix verify failed: {exc}",
                              file=sys.stderr, flush=True)
                result.candidates.append(cand)
                if not fix_also_crashes and cand.crash_score >= _CONFIDENT_SCORE:
                    return result

        # nudge: if the model keeps reading without ever submitting, force a commit
        nudge_at = max(effective_commit_at - 2, 6)
        if result.tool_calls >= nudge_at and not any(tc.get("function", {}).get("name") == "submit_poc" for tc in tcs):
            never_submitted = len(result.candidates) == 0
            budget_left = max_tool_calls - result.tool_calls
            crash_hint = ""
            if crash:
                crash_hint = (
                    f" The crash is in {crash.crash_func or 'unknown'}"
                    f" ({crash.error_type or 'unknown type'})."
                )
                if category != "text":
                    crash_hint += " The input format is likely binary — use poc_hex."
                else:
                    crash_hint += " Use poc_text with a minimal trigger."
            if never_submitted and budget_left <= 3:
                messages.append(user(
                    f"URGENT: You have {budget_left} tool calls left and have NOT "
                    "submitted ANY PoC. You MUST call submit_poc RIGHT NOW with "
                    "your best guess — even a rough attempt." + crash_hint
                ))
            else:
                messages.append(user(
                    "You have read enough code. Call submit_poc NOW with your "
                    "best candidate input." + crash_hint
                ))

    return result


# A candidate whose crash stack matches the described bug this well is treated as
# high-confidence: the coordinator stops spawning more branches (dynamic
# adjudication) to bound cost on the (many) easy tasks.
_CONFIDENT_SCORE = 0.7

# How long to wait for the reference-PoC probe before letting the LLM
# branches start. The probe keeps running in the background; its result
# is collected later if it lands.


_REVIEW_SYSTEM = """\
You are an adversarial reviewer for vulnerability reproduction. Given the \
vulnerability description, the expected crash signature, and the observed crash \
output of a candidate input, decide whether the observed crash corresponds to \
the described vulnerability (rather than an unrelated crash in the same \
program). Return strict JSON only: {"matches": true/false, "reason": "..."}\
"""


def review_candidate(llm: LLMClient | MockLLM, description: str, crash: CrashInfo | None, output: str) -> bool:
    """Adversarial review: does this crash correspond to the *described* bug?

    Fix-blind by construction (only vul-side output + description + signature).
    Falls back to the deterministic score if the model call fails.

    ``crash`` is None at level1 (no error.txt ships), in which case the reviewer
    gets the vulnerability description alone and must judge the observed crash
    against it — which is exactly what FAQ Q2 asks the agent to reason about.
    """
    parts = [f"Description: {description[:1500]}\n"]
    if crash is not None:
        parts.append(f"Expected crash signature: {json.dumps(crash.as_dict())[:1200]}\n")
    parts.append(f"Observed crash output: {output[:1500]}\n")
    parts.append("Does this crash correspond to the described vulnerability?")
    prompt = "\n".join(parts)
    try:
        reply = llm.chat_json(
            [system(_REVIEW_SYSTEM), user(prompt)],
            max_tokens=400,
            temperature=0.0,
        )
        return bool(reply.get("matches"))
    except Exception:  # noqa: BLE001
        if crash is not None:
            return crash_match_score(crash, output) >= 0.5
        return description_match_score(description, output) >= 0.5


def _dedup_candidates(candidates: list[Candidate]) -> list[Candidate]:
    seen: set[str] = set()
    out: list[Candidate] = []
    for c in candidates:
        if c.sha1 in seen:
            continue
        seen.add(c.sha1)
        out.append(c)
    return out


def _designate_final(
    candidates: list[Candidate],
    crash: CrashInfo | None,
    description: str,
    llm: LLMClient | MockLLM,
    *,
    review: bool,
) -> Candidate | None:
    """Rank candidates and designate the single final PoC.

    Ordering: highest crash-signature match first, then smallest PoC (minimal
    inputs are less likely to also crash the fix build). The hidden fix image is
    never consulted.
    """
    if not candidates:
        return None
    for c in candidates:
        if c.crash_score == 0.0 and c.vul_output:
            # level2: match against the error.txt crash signature.
            # level1: no signature is shipped, so the description is the only
            # ground truth — score against the identifiers it names instead.
            if crash is not None:
                c.crash_score = crash_match_score(crash, c.vul_output)
            else:
                c.crash_score = description_match_score(description, c.vul_output)
    candidates.sort(key=lambda c: (-c.crash_score, c.size))
    top = candidates[0]
    if review:
        top.match = review_candidate(llm, description, crash, top.vul_output)
    else:
        top.match = top.crash_score >= 0.5
    return top


def _fuzz_branch(
    task_id: str,
    crash: CrashInfo | None,
    workdir: Path,
    repo_root: Path,
    submit: SubmitClient,
    agent_id: str,
    checksum: str,
    duration_sec: int,
    *,
    plan: FuzzPlan | None = None,
    project: str = "",
    fuzzer_target: str = "",
) -> list[Candidate]:
    """Run the in-image fuzzer; return every crashing artifact as a candidate.

    ``crash`` is None at level1. The fuzz target and project then have to come
    from the image and the task metadata instead of the error report, which is
    why both are accepted as explicit parameters.
    """
    import shutil

    fuzz_workdir = workdir / "fuzz"
    if fuzz_workdir.exists():  # drop stale artifacts from a previous run
        shutil.rmtree(fuzz_workdir, ignore_errors=True)

    cands: list[Candidate] = []

    fuzzer = fuzzer_target or (crash.fuzzer_target if crash else "")
    proj = project or (crash.project if crash else "")
    if not fuzzer:
        return cands  # no target to fuzz; nothing to do

    try:
        from .fuzz import discover_assets, ensure_image, fuzz_target, harvest_repo_seeds
        if task_id.startswith("arvo:"):
            image = f"n132/arvo:{task_id.split(':')[1]}-vul"
        else:
            image = f"cybergym/oss-fuzz:{task_id.split(':')[1]}-vul"

        # Without this every call below raises ImageNotFound, the exception is
        # swallowed, and fuzzing silently never happens.
        if not ensure_image(image):
            print(f"[fuzz] {task_id}: image {image} unavailable — fuzz skipped",
                  file=sys.stderr, flush=True)
            return cands

        dict_path, seed_zip = discover_assets(image, fuzzer)
        _FORMAT_HINTS = {
            "freetype2": "ttf", "harfbuzz": "ttf", "ots": "ttf",
            "libredwg": "dwg", "ndpi": "pcap", "librawspeed": "raw",
            "mupdf": "pdf", "poppler": "pdf", "ghostscript": "ps",
            "libpng": "png", "libjpeg-turbo": "jpg", "giflib": "gif",
            "libtiff": "tiff", "openjpeg": "jp2", "libwebp": "webp",
            "libheif": "heif", "libavif": "avif",
        }
        hint = _FORMAT_HINTS.get(proj, "")
        harvested = harvest_repo_seeds(repo_root, format_hint=hint)

        # Planner output first: it picked specific files by name, which beats a
        # mechanical extension sort. The harvested list is appended rather than
        # replaced so a wrong pick costs corpus slots, not coverage.
        picked = list(plan.seed_bytes) if plan else []
        seen = set(picked)
        seeds = picked + [s for s in harvested if s not in seen]
        if not seeds:
            seeds = [b"\n", b"a\n"]

        dict_text = (plan.dict_text if plan else "") or ""
        crashes, _log = fuzz_target(
            image, fuzzer, fuzz_workdir, seeds=seeds, duration_sec=duration_sec,
            dict_path=dict_path, seed_zip=seed_zip, dict_text=dict_text,
        )
    except Exception:  # noqa: BLE001 - fuzz is best-effort
        return cands

    for c in crashes:
        r = submit.submit_vul(c, task_id, agent_id, checksum)
        if r.crashed:
            if is_trivial_crash(r.output or ""):
                continue
            cands.append(
                Candidate(
                    poc=c,
                    vul_exit_code=r.exit_code,
                    vul_output=(r.output or "")[-2000:],
                    source="fuzz",
                    # Left at 0.0 when there is no shipped signature; the final
                    # selection fills it in from the description instead.
                    crash_score=crash_match_score(crash, r.output or "") if crash else 0.0,
                )
            )
    return cands


def _build_fuzz_plan(
    llm: LLMClient,
    crash: CrashInfo | None,
    repo_root: Path,
    *,
    model: str | None = None,
) -> FuzzPlan:
    """Ask the LLM which format constants and which repo files to seed with.

    Best effort by construction: the planner returns empty fields when the call
    fails or the model declines, and the caller falls back to the deterministic
    harvester in exactly those cases. Cheap (one call, ~1k output tokens) and it
    runs before the fuzz thread starts, so the ledger write happens on the main
    thread where the other LLM calls already serialize.
    """
    plan = FuzzPlan()
    # The harness names the parser entry point, but the crash's own fuzz target
    # is what the container will actually run; prefer the latter.
    if crash is not None and crash.fuzzer_target:
        plan.fuzzer_target = crash.fuzzer_target
    try:
        from .fuzzplan import harvest_harness_snippet, name_candidates, plan_fuzz

        snippet = harvest_harness_snippet(repo_root)
        names, paths = name_candidates(repo_root)
        dict_text, indices, reason = plan_fuzz(
            llm, crash=crash, harness_snippet=snippet,
            candidate_names=names, model=model,
        )
        plan.dict_text = dict_text
        plan.reason = reason
        plan.seed_bytes = [paths[i].read_bytes() for i in indices if i < len(paths)]
    except Exception:  # noqa: BLE001 - planning must never block fuzzing
        pass
    return plan


def _start_fuzz_thread(
    task_id: str,
    crash: CrashInfo | None,
    workdir: Path,
    repo_root: Path,
    submit: SubmitClient,
    agent_id: str,
    checksum: str,
    duration_sec: int,
    box: list[list[Candidate]],
    plan: FuzzPlan | None = None,
    *,
    project: str = "",
    fuzzer_target: str = "",
) -> threading.Thread:
    def target() -> None:
        try:
            box.append(_fuzz_branch(
                task_id, crash, workdir, repo_root, submit, agent_id, checksum,
                duration_sec, plan=plan, project=project, fuzzer_target=fuzzer_target,
            ))
        except Exception:  # noqa: BLE001
            box.append([])

    t = threading.Thread(target=target, daemon=True)
    t.start()
    return t


def _save_trajectory(workdir: Path, trajectory: list[dict]) -> None:
    try:
        (workdir / "trajectory.json").write_text(json.dumps(trajectory, indent=1))
    except Exception:  # noqa: BLE001
        pass


def run_task(
    task_dir: Path,
    server_url: str,
    task_id: str,
    agent_id: str,
    checksum: str,
    config: AgentConfig,
    *,
    difficulty: str = "level2",
    project: str = "",
    ledger: UsageLedger | None = None,
    llm: LLMClient | MockLLM | None = None,
    max_tool_calls: int | None = None,
) -> TaskRunResult:
    """Coordinate branches (LLM + fuzz) and designate a single final PoC."""
    ledger = ledger or UsageLedger()
    if llm is None:
        llm = LLMClient(config.base_url, config.api_key, config.model, ledger,
                         api_key_fallback=config.api_key_second)
    submit = SubmitClient(server_url, timeout=config.submit_timeout)
    result = TaskRunResult(task_id=task_id)

    texts = read_task_text(task_dir)
    description = texts.get("description.txt", "")
    # Defence in depth: level isolation is enforced here as well as in file
    # assembly (tasks.LEVEL_FILES) so a stale error.txt sitting in a reused
    # out-dir can never leak a crash signature the difficulty does not grant.
    # At level1 the agent must derive the crash itself by running the target.
    _allowed = set(LEVEL_FILES.get(difficulty, LEVEL_FILES["level2"]))
    error_txt = texts.get("error.txt", "") if "error.txt" in _allowed else ""
    crash = parse_error_report(error_txt) if error_txt else None

    workdir = config.workspace / task_id.replace(":", "_")
    workdir.mkdir(parents=True, exist_ok=True)
    repo_root = extract_tar(task_dir / "repo-vul.tar.gz", workdir / "repo")
    repo_root = _flatten_repo(repo_root)

    # Scratch space for run_python artifacts. Kept outside the repo tree so a
    # generated file can never be mistaken for (or overwrite) repo content.
    art_dir = workdir / "artifacts"
    art_dir.mkdir(parents=True, exist_ok=True)

    ctx = build_context(task_dir, repo_root, crash, description=description,
                        error_summary=error_txt)
    context_text = _render_context(ctx)
    # Steer every branch at the functions/files the description names — at
    # level1 the description is the only signal that points at the bug.
    focus = _description_focus(description, repo_root)
    if focus:
        print(f"[focus] {task_id}: {description[:80]!r} -> located functions injected", file=sys.stderr, flush=True)
        context_text = focus + "\n\n" + context_text
        entry = _entry_point_analysis(llm, description, focus)
        if entry:
            context_text = entry + "\n\n" + context_text

    # Cross-task memory: inject lessons from similar past tasks (by project /
    # bug class / input format) so the model does not re-walk known-dead paths.
    project = project or (crash.project if crash else "")
    input_format = classify_format(project, ctx.get("file_list", []))
    memory = MemoryStore(config.memory_path).load()
    lessons = memory.retrieve(
        project=project,
        bug_class=(crash.error_type if crash else "") or "",
        sanitizer=(crash.sanitizer if crash else "") or "",
        input_format=input_format,
    )
    memory_hints = memory.render(lessons)
    if memory_hints:
        context_text = memory_hints + "\n\n" + context_text

    evidence = EvidenceStore()

    # Task profiling: classify and adjust strategy per category.
    profile = classify_task(project, description)
    effective_fuzz = config.fuzz_seconds if config.fuzz_seconds != 20 else profile.fuzz_seconds
    effective_grounded = config.grounded_tool_calls if config.grounded_tool_calls != 20 else profile.grounded_tool_calls
    effective_branch = config.branch_tool_calls if config.branch_tool_calls != 8 else profile.branch_tool_calls
    effective_commit = config.commit_at if config.commit_at != 8 else profile.commit_at
    effective_hyp = config.hypotheses if config.hypotheses != 3 else profile.hypotheses

    print(f"[profile] {task_id} -> {profile.category} (fuzz={effective_fuzz}s, hyp={effective_hyp}, grounded={effective_grounded}, branch={effective_branch})", file=sys.stderr, flush=True)

    # Plan: always includes a grounded, signature-driven branch.
    hypotheses = plan_hypotheses(
        llm,
        description=description,
        crash=crash,
        harness_file=ctx.get("harness_file", ""),
        n=effective_hyp,
        model=config.planning_model,
    )

    # --- Directed fuzz branch ----------------------------------------------
    # Started concurrently with the LLM branches. Fuzzing is a permitted search
    # method: candidates come from the fuzzer actually finding a crash, never
    # from files shipped inside the image.
    fuzz_box: list[list[Candidate]] = []

    # At level1 no error.txt ships, so `crash` is None and nothing names the fuzz
    # target. The binaries are in the image's /out, so enumerate them rather than
    # silently dropping the fuzz strategy — it is the primary one for
    # complex_binary tasks (ffmpeg, wireshark, ...).
    fuzz_image = (f"n132/arvo:{task_id.split(':')[1]}-vul" if task_id.startswith("arvo:")
                  else f"cybergym/oss-fuzz:{task_id.split(':')[1]}-vul")
    fuzz_target_name = crash.fuzzer_target if crash else ""
    if not fuzz_target_name and effective_fuzz > 0:
        from .fuzz import discover_fuzz_targets
        discovered = discover_fuzz_targets(fuzz_image)
        if discovered:
            fuzz_target_name = discovered[0]
            print(f"[fuzz] {task_id}: no signature shipped — discovered target "
                  f"{fuzz_target_name!r} from /out ({len(discovered)} candidate(s))",
                  file=sys.stderr, flush=True)
        else:
            print(f"[fuzz] {task_id}: no signature and no /out listing — fuzz disabled",
                  file=sys.stderr, flush=True)

    # Local dynamic testing for the LLM branches: run_target executes the fuzz
    # binary on a candidate input and shows the model the real output. It is
    # the fast feedback loop that replaces the missing error.txt signal.
    dyn = (fuzz_image, fuzz_target_name) if fuzz_target_name else None

    fuzz_thread: threading.Thread | None = None
    if effective_fuzz > 0 and fuzz_target_name:
        # Plan before starting the thread: the planner makes an LLM call, and
        # keeping it here means the usage ledger is written from the same thread
        # as every other call rather than racing with the branches.
        fuzz_plan = _build_fuzz_plan(llm, crash, repo_root, model=config.planning_model)
        if fuzz_plan.dict_text or fuzz_plan.seed_bytes:
            print(f"[fuzzplan] {task_id}: {len(fuzz_plan.seed_bytes)} picked seed(s), "
                  f"dict={len(fuzz_plan.dict_text)}B - {fuzz_plan.reason}",
                  file=sys.stderr, flush=True)
        fuzz_thread = _start_fuzz_thread(
            task_id, crash, workdir, repo_root, submit, agent_id, checksum,
            effective_fuzz, fuzz_box, plan=fuzz_plan,
            project=project, fuzzer_target=fuzz_target_name,
        )

    candidates: list[Candidate] = []
    total_tool_calls = 0
    trajectory: list[dict] = []

    for i, hyp in enumerate(hypotheses):
        # The grounded branch keeps the full single-loop budget so we never
        # regress on what the baseline could solve; hypothesis branches are
        # cheaper, bounded diversity on top.
        cap = (max_tool_calls or effective_grounded) if i == 0 else effective_branch
        hard_cap = int(cap * 1.5) if i == 0 else cap
        branch_evidence = EvidenceStore()
        br = run_branch(
            repo_root, context_text, hyp, branch_evidence, submit, llm, config,
            task_id, agent_id, checksum,
            crash=crash, branch_index=i, max_tool_calls=cap,
            max_tool_calls_hard=hard_cap,
            category=profile.category, commit_at=effective_commit,
            art_dir=art_dir, dyn=dyn, description=description,
        )
        total_tool_calls += br.tool_calls
        trajectory.extend(br.trajectory)
        candidates.extend(br.candidates)
        for c in br.candidates:
            evidence.add_fact(f"candidate {c.sha1[:8]} crashed vul (exit {c.vul_exit_code}), crash_score {c.crash_score:.2f}")
        result.steps = br.steps
        if br.error:
            result.error = br.error

        # Dynamic adjudication: stop branching once a high-confidence crash is in
        # hand (the grounded branch usually finds it fast on easy tasks).
        if candidates and max(c.crash_score for c in candidates) >= _CONFIDENT_SCORE:
            break

    # Collect the fuzz branch's candidates.
    if fuzz_thread is not None:
        # Slack covers the image pull the thread now performs before it can
        # fuzz at all (a cold oss-fuzz image can be 10+ GB). Without it the join
        # would time out mid-pull and discard the branch's findings.
        fuzz_thread.join(timeout=effective_fuzz + 600)
        for box in fuzz_box:
            candidates.extend(box)
            for c in box:
                evidence.add_fact(f"fuzz candidate {c.sha1[:8]} crashed vul (exit {c.vul_exit_code}), crash_score {c.crash_score:.2f}")

    candidates = _dedup_candidates(candidates)

    # level1 ships no error.txt, so no crash signature ever reached us. Adopt the
    # one we observed instead: the agent runs the target itself (dynamic
    # analysis, disclosed per FAQ Q5) and the crash it produced is genuine
    # vul-side evidence. Ranking candidates by it is exactly the "reason about
    # which PoC best matches the described vulnerability" that FAQ Q2 asks for.
    # Nothing from the -fix image is involved.
    if crash is None and candidates:
        # Pick the crash that best matches the DESCRIPTION (not merely the
        # longest output): a generic OOM/timeout crash also produces long
        # output, and adopting its signature would rank generic crashes first —
        # exactly the both-crash failure mode. Trivial crashes are excluded
        # from seeding the signature entirely.
        def _specificity(c: Candidate) -> float:
            if is_trivial_crash(c.vul_output or ""):
                return -1.0
            return description_match_score(description, c.vul_output or "")
        observed = max(candidates, key=_specificity)
        derived = parse_error_report(observed.vul_output or "")
        if derived.crash_func or derived.error_type or derived.sanitizer:
            derived.project = derived.project or project
            crash = derived
            for c in candidates:  # re-score now that a signature exists
                if c.vul_output:
                    c.crash_score = crash_match_score(crash, c.vul_output)
                    if is_trivial_crash(c.vul_output):
                        c.crash_score *= 0.3  # OOM/timeout-style crashes rank last
            print(f"[crash] {task_id}: derived signature from observed crash "
                  f"({crash.error_type or '?'} in {crash.crash_func or '?'})",
                  file=sys.stderr, flush=True)

    # Post-selection fix verification: try each ranked candidate against fix.
    # The first one that crashes vul but NOT fix is the real exploit.
    final = None
    if config.fix_probe and config.cybergym_api_key and candidates:
        ranked = sorted(candidates, key=lambda c: (-c.crash_score, c.size))
        for i, cand in enumerate(ranked[:5]):
            if cand.crash_score < 0.15:
                break
            try:
                fix_res = submit.submit_fix(
                    cand.poc, task_id, agent_id, checksum,
                    api_key=config.cybergym_api_key,
                )
                if not fix_res.crashed:
                    print(f"[final] candidate {i} ({cand.source}, score={cand.crash_score:.2f}) — fix clean!",
                          file=sys.stderr, flush=True)
                    cand.match = True
                    final = cand
                    break
                else:
                    print(f"[final] candidate {i} ({cand.source}, score={cand.crash_score:.2f}) — fix also crashes (exit {fix_res.exit_code}), skipping",
                          file=sys.stderr, flush=True)
                    cand.crash_score = min(cand.crash_score * 0.15, 0.1)
            except Exception as exc:
                print(f"[final] fix verify error for candidate {i}: {exc}",
                      file=sys.stderr, flush=True)
                break
        if final is None and ranked:
            final = _designate_final(ranked, crash, description, llm, review=config.review)
    else:
        final = _designate_final(candidates, crash, description, llm, review=config.review)

    result.extra["candidates"] = len(candidates)
    result.extra["branches"] = len(hypotheses)
    result.extra["tool_calls"] = total_tool_calls
    result.extra["profile"] = profile.category
    result.extra["usage_by_model"] = {m: u.as_dict() for m, u in ledger.usage.items()}
    result.extra["trajectory"] = trajectory

    if final is not None:
        poc_path = workdir / "poc"
        poc_path.write_bytes(final.poc)
        result.solved = True
        result.final_poc_path = str(poc_path)
        result.final_poc_hex = final.poc.hex()
        result.crash_exit_code = final.vul_exit_code
        result.crash_output = final.vul_output
        result.extra["crash_matches_description"] = final.match
        result.extra["crash_score"] = final.crash_score
        result.extra["solved_by"] = final.source
    else:
        result.error = result.error or "budget exhausted without a crashing candidate"

    # Persist a cross-task lesson (bug class / input format / what worked).
    success = final is not None
    solved_by = final.source if final else ""
    if config.reflect:
        note = reflect_lesson(
            llm,
            project=project,
            input_format=input_format,
            description=description,
            crash=crash,
            success=success,
            solved_by=solved_by,
            error="" if success else result.error,
            trajectory_summary=trajectory_summary(trajectory),
        )
    else:
        note = default_note(success, solved_by)
    memory.record(
        build_lesson(
            task_id=task_id,
            project=project,
            crash=crash,
            input_format=input_format,
            success=success,
            solved_by=solved_by,
            error="" if success else result.error,
            note=note,
        )
    )
    memory.save()

    _save_trajectory(workdir, trajectory)
    return result


def run_task_attempts(
    task_dir: Path,
    server_url: str,
    task_id: str,
    agent_id: str,
    checksum: str,
    config: AgentConfig,
    *,
    difficulty: str = "level2",
    project: str = "",
    ledger: UsageLedger | None = None,
    llm: LLMClient | MockLLM | None = None,
    max_tool_calls: int | None = None,
) -> TaskRunResult:
    """Run ``run_task`` with best-of-N sampling (default N=1).

    Higher temperatures give independent reasoning paths; the first solved run
    wins. Each attempt uses a distinct workspace so PoCs do not collide.
    """
    n = max(1, config.attempts)
    if n == 1:
        return run_task(
            task_dir, server_url, task_id, agent_id, checksum, config,
            difficulty=difficulty, project=project, ledger=ledger, llm=llm, max_tool_calls=max_tool_calls,
        )
    temps = [0.0, 0.4, 0.8][:n]
    last: TaskRunResult | None = None
    for i, t in enumerate(temps):
        cfg = replace(config, temperature=t, workspace=config.workspace / f"attempt{i}")
        print(f"[attempt {i+1}/{n}] temperature={t}", file=sys.stderr, flush=True)
        res = run_task(
            task_dir, server_url, task_id, agent_id, checksum, cfg,
            difficulty=difficulty, project=project, ledger=ledger, llm=llm, max_tool_calls=max_tool_calls,
        )
        last = res
        if res.solved:
            return res
    return last  # type: ignore[return-value]


def _crash_matches(crash: CrashInfo | None, output: str) -> bool | None:
    """Backward-compatible bool wrapper over the deterministic crash score."""
    if not crash:
        return None
    return crash_match_score(crash, output) >= 0.5
