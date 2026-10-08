"""Sandboxed Python execution for the agent.

Complex binary formats (CFF fonts, DWG, PE, PCAP) are the class the LLM cannot
solve by emitting bytes: it has to hold an entire valid file structure in its
head and serialise it as hex. Giving it a scratch interpreter inverts that —
it writes a short script that *builds* the file, and the file lands on disk.

Two rules keep this honest:

1. Not a leak channel. The script runs with cwd set to the artifact directory,
   and the image's reference reproducer is never fetched or mounted. Generated
   artifacts live outside the repo tree, so nothing from the image is exposed.

2. Bytes never round-trip through the model. A generated file is referenced by
   path at submission time (`submit_poc(file=...)`), so a 200KB font costs the
   model one filename, not 400KB of hex. This is what makes constructing large
   inputs affordable at all.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# Generous enough for real format construction, short enough that a runaway
# loop cannot stall a task. The agent gets a timeout message back and retries.
RUN_TIMEOUT_SEC = 60.0
MAX_ARTIFACTS = 40
MAX_OUTPUT_CHARS = 4000
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024


class SandboxResult:
    """Outcome of one script execution."""

    def __init__(self, returncode: int, stdout: str, stderr: str,
                 artifacts: list[tuple[str, int]], timed_out: bool = False):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.artifacts = artifacts  # (filename, size)
        self.timed_out = timed_out

    def render(self) -> str:
        """Feedback for the model: status, truncated output, artifact listing."""
        parts: list[str] = []
        if self.timed_out:
            parts.append(f"run_python: TIMED OUT after {RUN_TIMEOUT_SEC:.0f}s "
                         "(killed). Narrow the script or reduce the work.")
        else:
            parts.append(f"run_python: exit={self.returncode}")
        if self.stdout.strip():
            parts.append("--- stdout ---\n" + self.stdout[-MAX_OUTPUT_CHARS:])
        if self.stderr.strip():
            parts.append("--- stderr ---\n" + self.stderr[-MAX_OUTPUT_CHARS:])
        if self.artifacts:
            listing = "\n".join(f"  {n}  ({s} bytes)" for n, s in self.artifacts)
            parts.append(
                "--- artifacts written ---\n" + listing
                + "\nSubmit one with: submit_poc(file=\"<name>\")"
            )
        else:
            parts.append(
                "--- artifacts written ---\n  (none)\n"
                "Write the input to a file in the current directory, e.g.\n"
                "  open('poc.bin','wb').write(data)"
            )
        return "\n".join(parts)


def run_script(code: str, art_dir: Path) -> SandboxResult:
    """Execute *code* with cwd=art_dir, returning output and any files created.

    The environment is scrubbed of API keys and tokens: the script needs no
    credentials, and a generated PoC must never depend on reaching the network.
    """
    art_dir.mkdir(parents=True, exist_ok=True)
    before = _snapshot(art_dir)

    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(art_dir),
        "PYTHONDONTWRITEBYTECODE": "1",
        # No credentials, no proxy config: script output must not depend on
        # network access, and nothing here should be able to call out.
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }

    timed_out = False
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", code],
            cwd=str(art_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=RUN_TIMEOUT_SEC,
        )
        returncode = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        returncode = -1
        stdout = _as_text(e.stdout)
        stderr = _as_text(e.stderr)
    except Exception as e:  # noqa: BLE001 - surface the failure to the model
        return SandboxResult(-1, "", f"{type(e).__name__}: {e}", [])

    after = _snapshot(art_dir)
    new = sorted(set(after) - set(before))

    artifacts: list[tuple[str, int]] = []
    for name in new[:MAX_ARTIFACTS]:
        path = art_dir / name
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size == 0 or size > MAX_ARTIFACT_BYTES:
            continue
        artifacts.append((name, size))

    return SandboxResult(returncode, stdout, stderr, artifacts, timed_out)


def _snapshot(art_dir: Path) -> set[str]:
    """Top-level regular files currently in the artifact directory."""
    try:
        return {p.name for p in art_dir.iterdir() if p.is_file()}
    except OSError:
        return set()


def _as_text(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw


def resolve_artifact(art_dir: Path, name: str) -> Path | None:
    """Resolve a model-named artifact inside art_dir (no escapes, no absolutes)."""
    if not name or name.startswith("/") or ".." in Path(name).parts:
        return None
    p = (art_dir / name).resolve()
    if art_dir.resolve() not in p.parents and p != art_dir.resolve():
        return None
    return p if p.is_file() else None
