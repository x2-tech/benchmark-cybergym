"""Cross-task memory: record lessons and reapply them to later tasks.

Implements the "观察 → 提取 → 分类 → 应用" loop the objective calls for:
after every task the coordinator records a structured lesson (what failed, what
worked, by which technical category), and before the next task it retrieves the
relevant lessons and injects them into the context so the model does not repeat
known-dead paths.

Categories are chosen to *generalize* across the ~188 projects: bug class
(sanitizer error type), input format (font / image / network / archive / …) and
sanitizer family, rather than raw project names.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .extract import CrashInfo

# project / file-extension -> coarse input format (for cross-project reuse)
_FORMAT_BY_PROJECT: dict[str, str] = {
    "freetype2": "font", "harfbuzz": "font", "ots": "font", "woff2": "font",
    "libxml2": "xml", "expat": "xml", "libxslt": "xml",
    "libredwg": "dwg", "libredwg2": "dwg",
    "ndpi": "network", "libpcap": "network", "wireshark": "network",
    "librawspeed": "image", "graphicsmagick": "image", "imagemagick": "image",
    "libjpeg": "image", "libpng": "image", "giflib": "image",
    "binutils": "elf", "elfutils": "elf", "llvm": "binary",
    "file": "file", "yara": "rules", "mruby": "script", "php": "script",
    "lua": "script", "ghostscript": "ps", "mupdf": "pdf", "poppler": "pdf",
    "zlib": "archive", "libarchive": "archive", "bzip2": "archive",
}
_FORMAT_BY_EXT: dict[str, str] = {
    ".ttf": "font", ".otf": "font", ".woff": "font", ".woff2": "font",
    ".xml": "xml", ".html": "xml",
    ".dwg": "dwg", ".dxf": "dwg",
    ".pcap": "network", ".cap": "network", ".pcapng": "network",
    ".raw": "image", ".cr2": "image", ".nef": "image", ".dng": "image",
    ".png": "image", ".jpg": "image", ".gif": "image", ".bmp": "image",
    ".pdf": "pdf", ".ps": "ps",
    ".elf": "elf", ".wasm": "binary",
    ".gz": "archive", ".bz2": "archive", ".zip": "archive", ".tar": "archive",
    ".mp3": "audio", ".wav": "audio", ".flac": "audio", ".mp4": "video",
}


def classify_format(project: str, file_list: list[str]) -> str:
    """Best-effort coarse input-format classification."""
    low = (project or "").lower()
    for key, fmt in _FORMAT_BY_PROJECT.items():
        if key in low or low in key:
            return fmt
    for f in file_list or []:
        ext = Path(f).suffix.lower()
        if ext in _FORMAT_BY_EXT:
            return _FORMAT_BY_EXT[ext]
    return "other"


@dataclass
class Lesson:
    task_id: str
    project: str
    bug_class: str
    sanitizer: str
    crash_func: str
    input_format: str
    success: bool
    solved_by: str = ""   # "grounded" | "fuzz" | "" (unsolved)
    error: str = ""
    note: str = ""
    updated_at: float = field(default_factory=time.time)


class MemoryStore:
    """Persistent, category-keyed lesson store (JSON-backed, append + dedupe)."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else None
        self._lessons: dict[str, Lesson] = {}

    # ---- persistence ----
    def load(self) -> "MemoryStore":
        if self.path and self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                for d in data:
                    try:
                        lesson = Lesson(**d)
                        self._lessons[lesson.task_id] = lesson
                    except Exception:  # noqa: BLE001 - skip malformed rows
                        continue
            except Exception:  # noqa: BLE001
                pass
        return self

    def save(self) -> None:
        if not self.path:
            return
        try:
            rows = [asdict(v) for v in self._lessons.values()]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(rows, indent=1))
        except Exception:  # noqa: BLE001
            pass

    # ---- record / retrieve ----
    def record(self, lesson: Lesson) -> None:
        self._lessons[lesson.task_id] = lesson

    def retrieve(
        self,
        *,
        project: str = "",
        bug_class: str = "",
        sanitizer: str = "",
        input_format: str = "",
        limit: int = 4,
    ) -> list[Lesson]:
        """Return the most relevant past lessons (most recent first)."""
        scored: list[tuple[int, float, Lesson]] = []
        for lesson in self._lessons.values():
            score = 0
            if input_format and lesson.input_format == input_format:
                score += 4
            if bug_class and lesson.bug_class and bug_class in lesson.bug_class:
                score += 3
            if sanitizer and lesson.sanitizer and sanitizer in lesson.sanitizer:
                score += 2
            if project and lesson.project == project:
                score += 5
            if score <= 0:
                continue
            scored.append((score, lesson.updated_at, lesson))
        scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
        return [l for _, _, l in scored[:limit]]

    def render(self, lessons: list[Lesson]) -> str:
        if not lessons:
            return ""
        lines = ["## Lessons from similar past tasks"]
        for l in lessons:
            verdict = "SOLVED" if l.success else "UNSOLVED"
            how = f" (via {l.solved_by})" if l.solved_by else ""
            lines.append(
                f"- [{l.bug_class or 'unknown'}/{l.input_format or 'other'}] "
                f"{l.project} {verdict}{how}: {l.note or l.error or 'no note'}"
            )
        return "\n".join(lines)


def build_lesson(
    task_id: str,
    project: str,
    crash: CrashInfo | None,
    *,
    input_format: str,
    success: bool,
    solved_by: str = "",
    error: str = "",
    note: str = "",
) -> Lesson:
    """Construct a lesson from a completed task (deterministic extraction)."""
    return Lesson(
        task_id=task_id,
        project=project or "",
        bug_class=(crash.error_type if crash else "") or "",
        sanitizer=(crash.sanitizer if crash else "") or "",
        crash_func=(crash.crash_func if crash else "") or "",
        input_format=input_format,
        success=success,
        solved_by=solved_by,
        error=(error or "")[:200],
        note=note,
    )


def default_note(success: bool, solved_by: str) -> str:
    """A cheap, useful default lesson note when no LLM reflection is available."""
    if not success:
        return "static analysis insufficient — try longer fuzz with format-specific seeds/dict"
    if solved_by == "fuzz":
        return "fuzz with repo seeds + dictionary solved this format"
    if solved_by.startswith("branch"):
        return "signature-driven static reasoning + candidate ranking solved it"
    return "solved"


_REFLECT_SYSTEM = """\
You review a vulnerability-reproduction attempt and extract ONE reusable lesson \
for future attempts on similar tasks (same bug class and input format). Reply \
with only that one lesson sentence — no JSON, no preamble, no quotes.\
"""


def reflect_lesson(
    llm,
    *,
    project: str,
    input_format: str,
    description: str,
    crash: CrashInfo | None,
    success: bool,
    solved_by: str,
    error: str,
    trajectory_summary: str,
) -> str:
    """Ask the model to reflect on a finished task and extract an actionable lesson.

    Falls back to the deterministic note when the model call fails or returns
    a trivial/empty lesson (deepseek-flash occasionally returns "...").
    """
    crash_sig = json.dumps(crash.as_dict())[:800] if crash else "(none)"
    prompt = (
        f"Project: {project or '(unknown)'}\n"
        f"Input format: {input_format or '(unknown)'}\n"
        f"Vulnerability description: {description[:1000]}\n"
        f"Crash signature: {crash_sig}\n"
        f"Outcome: {'SOLVED via ' + solved_by if success else 'UNSOLVED'}\n"
        f"Error: {error[:200]}\n"
        f"What was tried (last steps):\n{trajectory_summary[:1500]}\n"
        "\nState the one key lesson: what went wrong and what concrete action to take next time."
    )
    try:
        from .llm import system, user  # local import avoids a cycle at module load

        lesson = llm.chat_text(
            [system(_REFLECT_SYSTEM), user(prompt)],
            max_tokens=200,
            temperature=0.0,
        )
        lesson = lesson.strip().strip('"').strip()
        if lesson and len(lesson) >= 8 and lesson not in ("...", "null", "none"):
            return lesson[:300]
    except Exception:  # noqa: BLE001 - reflection is best-effort
        pass
    return default_note(success, solved_by)


def trajectory_summary(trajectory: list[dict], last: int = 12) -> str:
    """Compact the last N tool calls into a short text for the reflector."""
    rows = []
    for e in trajectory[-last:]:
        tool = e.get("tool", "?")
        result = str(e.get("result", ""))[:120].replace("\n", " ")
        rows.append(f"- {tool}: {result}")
    return "\n".join(rows) if rows else "(no tool calls recorded)"
