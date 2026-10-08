"""Parse a CyberGym ``error.txt`` (sanitizer crash report) into structured form.

This is the cheapest, highest-value static signal available at level2/level3:
it localizes the crashing function, file:line, sanitizer type and the libFuzzer
target, so the agent can read only the relevant code instead of the whole repo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Frame:
    func: str
    file: str = ""
    line: int = 0
    module: str = ""  # e.g. /out/magic_fuzzer or /lib/x86_64-linux-gnu/libc.so.6


@dataclass
class CrashInfo:
    sanitizer: str = ""
    error_type: str = ""
    crash_file: str = ""
    crash_line: int = 0
    crash_func: str = ""
    fuzzer_target: str = ""
    project: str = ""
    dedup_token: str = ""
    summary: str = ""
    origin: str = ""
    stack: list[Frame] = field(default_factory=list)

    @property
    def source_relative_path(self) -> str:
        """Strip the /src/<project>/ prefix if present (repo-relative path)."""
        prefix = f"/src/{self.project}/"
        if self.crash_file.startswith(prefix):
            return self.crash_file[len(prefix):]
        return self.crash_file

    def as_dict(self) -> dict:
        return {
            "sanitizer": self.sanitizer,
            "error_type": self.error_type,
            "crash_file": self.crash_file,
            "crash_line": self.crash_line,
            "crash_func": self.crash_func,
            "fuzzer_target": self.fuzzer_target,
            "project": self.project,
            "dedup_token": self.dedup_token,
            "summary": self.summary,
            "origin": self.origin,
            "stack": [{"func": f.func, "file": f.file, "line": f.line, "module": f.module} for f in self.stack[:24]],
        }


@dataclass
class SubmitFeedback:
    crashed: bool
    sanitizer_hit: bool
    target_func_reached: bool
    error_type_match: bool
    signal: str
    diagnosis: str


_SAN_RE = re.compile(r"\b(MemorySanitizer|AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|ThreadSanitizer|HWAddressSanitizer)\b")
_SUMMARY_RE = re.compile(
    r"SUMMARY:\s*(?P<san>\w+Sanitizer):\s*(?P<type>[^\s]+(?:\s+[^\s]+)?)\s+"
    r"(?P<file>[^\s:]+):(?P<line>\d+)(?::(?P<col>\d+))?\s+in\s+(?P<func>\S+)"
)
_FRAME_RE = re.compile(r"^\s*#(?P<n>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<body>.*?)\s*$")
_MODULE_RE = re.compile(r"\((?P<mod>/[^\s)]+)\)\s*$")
_LOC_RE = re.compile(r"^(?P<file>[^:\s]+)(?::(?P<line>\d+))?(?::(?P<col>\d+))?$")


def _parse_frame_body(body: str) -> Frame:
    body = body.strip()
    modm = _MODULE_RE.search(body)
    if modm:
        func = body[:modm.start()].rstrip()
        module = modm.group("mod").split("+")[0]
        return Frame(func=func, module=module)
    if " " in body:
        func, loc = body.rsplit(" ", 1)
    else:
        func, loc = body, ""
    func = func.rstrip()
    m = _LOC_RE.match(loc)
    if m:
        return Frame(func=func, file=m.group("file"), line=int(m.group("line") or 0))
    return Frame(func=func, file=loc)
_TARGET_RE = re.compile(r"/out/(?P<name>[A-Za-z0-9_.-]+)")
_PROJECT_RE = re.compile(r"/src/(?P<proj>[^/\s]+)/")
_DEDUP_RE = re.compile(r"DEDUP_TOKEN:\s*(?P<tok>\S+)")
_ORIGIN_RE = re.compile(r"(Uninitialized value was created|was created by an allocation|The buggy address belongs to|is located)")

# error type: also capture the ASAN `ERROR: AddressSanitizer: <type>` line
_ASAN_ERR_RE = re.compile(r"ERROR:\s*AddressSanitizer:\s*(?P<type>[\w-]+)")
_UBSAN_ERR_RE = re.compile(r"runtime error:\s*(?P<type>[\w -]+?)(?:\s|$)")


def parse_error_report(text: str) -> CrashInfo:
    info = CrashInfo()

    # sanitizer family
    m = _SAN_RE.search(text)
    if m:
        info.sanitizer = m.group(1)

    # SUMMARY line gives the canonical crash location + type + func
    m = _SUMMARY_RE.search(text)
    if m:
        info.error_type = m.group("type")
        info.crash_file = m.group("file")
        info.crash_line = int(m.group("line")) if m.group("line") else 0
        info.crash_func = m.group("func")
        info.summary = text[m.start():].splitlines()[0] if m.start() >= 0 else ""

    # ASAN / UBSAN error type fallbacks
    if not info.error_type:
        m = _ASAN_ERR_RE.search(text)
        if m:
            info.error_type = m.group("type")
        m = _UBSAN_ERR_RE.search(text)
        if m:
            info.error_type = m.group("type").strip()

    # fuzzer target from /out/<name>
    m = _TARGET_RE.search(text)
    if m:
        info.fuzzer_target = f"/out/{m.group('name')}"

    # project from /src/<project>/
    m = _PROJECT_RE.search(text)
    if m:
        info.project = m.group("proj")

    # dedup token
    m = _DEDUP_RE.search(text)
    if m:
        info.dedup_token = m.group("tok")

    # origin (where the bad memory came from)
    for line in text.splitlines():
        if _ORIGIN_RE.search(line):
            info.origin = line.strip()
            break

    # stack frames
    for line in text.splitlines():
        m = _FRAME_RE.match(line)
        if not m:
            continue
        info.stack.append(_parse_frame_body(m.group("body")))

    # The SUMMARY/TOP frame often points at a sanitizer interceptor
    # (__asan_memset, __interceptor_malloc) under /src/llvm-project, not the
    # vulnerable project code. Prefer the first frame in the project's own
    # source tree as the canonical crash location.
    for f in info.stack:
        if not f.file.startswith("/src/"):
            continue
        if f.file.startswith("/src/llvm-project/"):
            continue
        if f.func.startswith(("__asan_", "__interceptor_", "__msan_", "__ubsan_", "fuzzer::")):
            continue
        if f.func in {"LLVMFuzzerTestOneInput", "main", "__libc_start_main", "_start"}:
            continue
        info.crash_func = f.func
        info.crash_file = f.file
        info.crash_line = f.line
        pm = _PROJECT_RE.search(f.file)
        if pm:
            info.project = pm.group("proj")
        break

    # Last-resort fallback to the top frame if nothing resolved.
    if not info.crash_func and info.stack:
        top = info.stack[0]
        info.crash_func = top.func
        if top.file:
            info.crash_file = top.file
        info.crash_line = top.line

    return info


def parse_submit_feedback(
    exit_code: int | None,
    output: str,
    crash: CrashInfo | None,
) -> SubmitFeedback:
    """Parse oracle output into structured feedback for the next LLM attempt."""
    crashed = exit_code is not None and exit_code != 0
    sanitizer_hit = bool(_SAN_RE.search(output)) if output else False
    target_func = False
    error_match = False
    if crash:
        target_func = bool(crash.crash_func and crash.crash_func in output)
        error_match = bool(
            crash.error_type and crash.error_type.lower() in output.lower()
        )

    signal = ""
    if "SIGSEGV" in output:
        signal = "SIGSEGV"
    elif "SIGABRT" in output:
        signal = "SIGABRT"
    elif "SIGBUS" in output:
        signal = "SIGBUS"
    elif "timeout" in output.lower():
        signal = "timeout"

    if crashed and target_func:
        diagnosis = "Crashed at the target function -- this is likely the right bug."
    elif crashed and not target_func:
        diagnosis = "Crashed, but NOT at the target function -- likely an unrelated crash."
    elif exit_code == 0 and sanitizer_hit:
        diagnosis = "Sanitizer detected something but process did not crash -- input is close, needs refinement."
    elif exit_code == 0:
        diagnosis = "Clean exit -- input did not trigger the vulnerable path at all."
    else:
        diagnosis = "No response from oracle."

    return SubmitFeedback(
        crashed=crashed,
        sanitizer_hit=sanitizer_hit,
        target_func_reached=target_func,
        error_type_match=error_match,
        signal=signal,
        diagnosis=diagnosis,
    )
