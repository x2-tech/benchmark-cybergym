"""Deterministic filesystem tools and the submission oracle.

These are used by the agent internally. The PoC-submission client reproduces the
exact wire format of the upstream ``submit.sh`` (multipart ``metadata`` + ``file``)
so we can call the vul oracle programmatically and parse the exit_code.
"""

from __future__ import annotations

import json
import os
import tarfile
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path


# --------------------------------------------------------------------------- #
# repo inspection
# --------------------------------------------------------------------------- #

def extract_tar(tar_path: Path | str, dest: Path | str, *, members_limit: int = 200_000) -> Path:
    """Safely extract a tar.gz, rejecting path traversal and absolute paths.

    Symlinks/hardlinks/devices are skipped (not extracted): many project repos
    ship test-data symlinks that are irrelevant to static analysis and would
    otherwise fail the whole task.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with tarfile.open(tar_path, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) > members_limit:
            raise ValueError(f"archive has too many entries: {len(members)}")
        safe: list[tarfile.TarInfo] = []
        for m in members:
            # Lexical containment check only. Path.resolve() must NOT be used
            # here: it follows symlinks, so an in-repo symlink (e.g. flac's
            # config.guess -> /usr/share/automake/...) resolves outside the
            # root and was rejected as traversal, killing the whole task.
            target = os.path.normpath(os.path.join(str(root), m.name))
            if target != str(root) and not target.startswith(str(root) + os.sep):
                raise ValueError(f"unsafe path in archive: {m.name}")
            if not (m.isfile() or m.isdir()):
                continue  # skip symlink / hardlink / device / fifo
            safe.append(m)
        # Extract only the vetted members — extractall() alone would happily
        # write the symlinks this loop just skipped.
        tf.extractall(root, members=safe)
    return root


def list_files(root: Path | str, *, max_entries: int = 2000, skip_dirs: set[str] | None = None) -> list[str]:
    skip = skip_dirs or {".git", "node_modules", "__pycache__"}
    out: list[str] = []
    for p in Path(root).rglob("*"):
        if any(part in skip for part in p.parts):
            continue
        if p.is_file():
            out.append(str(p.relative_to(root)))
        if len(out) >= max_entries:
            break
    return out


_SKIP_DIRS = {".git", "node_modules", "__pycache__", "testsuite", "ChangeLog", "po", "gdb", "ld", "opcodes",
              "intl", "libiberty", "bfd", "gold", "sim", "readline", "include", "contrib", "doc", "docs"}

_MAX_GREP_FILE = 2_000_000  # skip source files larger than 2 MB
_MAX_GREP_FILES = 20_000    # hard cap on files scanned


def grep(pattern: str, root: Path | str, *, max_hits: int = 200, include: str | None = None) -> list[dict]:
    import re

    try:
        rx = re.compile(pattern)
    except re.error as e:
        # The model authors these patterns, so malformed ones are routine
        # (unbalanced parens/brackets). Raise a tool-level error the agent can
        # read and correct instead of letting it abort the whole task.
        raise ValueError(
            f"invalid regex {pattern!r}: {e}. "
            "Fix the pattern and retry, or use a literal substring."
        ) from e
    hits: list[dict] = []
    scanned = 0
    for p in Path(root).rglob("*"):
        if not p.is_file():
            continue
        if include and not p.match(include):
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.suffix not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".swift", ".py", ".s", ".S", ""}:
            continue
        try:
            if p.stat().st_size > _MAX_GREP_FILE:
                continue
        except OSError:
            continue
        scanned += 1
        if scanned > _MAX_GREP_FILES:
            break
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                hits.append({"file": str(p.relative_to(root)), "line": i, "text": line.strip()[:300]})
                if len(hits) >= max_hits:
                    return hits
    return hits


def read_text(path: Path | str, *, offset: int = 1, limit: int = 200) -> str:
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(offset - 1, 0)
    end = start + limit
    return "\n".join(f"{i + 1}: {l}" for i, l in enumerate(lines[start:end], start=start))


# --------------------------------------------------------------------------- #
# submission oracle
# --------------------------------------------------------------------------- #

@dataclass
class SubmitResult:
    task_id: str
    exit_code: int | None
    output: str
    poc_id: str | None
    raw: dict

    @property
    def crashed(self) -> bool:
        return self.exit_code is not None and self.exit_code != 0


class SubmitClient:
    """Submit a PoC to the CyberGym vul oracle and parse the result."""

    def __init__(self, server_url: str, *, timeout: float = 300.0):
        self.server = server_url.rstrip("/")
        # The oracle runs one container per submission and its own wait is
        # capped at 300s, but concurrent submissions queue behind the docker
        # daemon, so a well-formed request can legitimately take much longer
        # than its own run to be answered. Giving up before that point throws
        # away a result the server already computed.
        self.timeout = timeout

    def submit_vul(
        self,
        poc: bytes,
        task_id: str,
        agent_id: str,
        checksum: str,
        *,
        timeout: float | None = None,
    ) -> SubmitResult:
        return self._submit("/submit-vul", poc, task_id, agent_id, checksum,
                            timeout=timeout if timeout is not None else self.timeout)

    def submit_fix(
        self,
        poc: bytes,
        task_id: str,
        agent_id: str,
        checksum: str,
        *,
        timeout: float | None = None,
        api_key: str | None = None,
    ) -> SubmitResult:
        """Submit to the private fix endpoint (requires the API key)."""
        return self._submit("/submit-fix", poc, task_id, agent_id, checksum,
                            timeout=timeout if timeout is not None else self.timeout, api_key=api_key)

    def _submit(
        self,
        path: str,
        poc: bytes,
        task_id: str,
        agent_id: str,
        checksum: str,
        *,
        timeout: float = 300.0,
        api_key: str | None = None,
    ) -> SubmitResult:
        metadata = json.dumps(
            {"task_id": task_id, "agent_id": agent_id, "checksum": checksum, "require_flag": False}
        )
        boundary = "----cybergym" + uuid.uuid4().hex
        body = b""
        body += (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="metadata"\r\n\r\n'
            f"{metadata}\r\n"
        ).encode("utf-8")
        body += (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="poc"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8")
        body += poc
        body += f"\r\n--{boundary}--\r\n".encode("utf-8")

        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        if api_key:
            headers["X-API-Key"] = api_key

        req = urllib.request.Request(
            f"{self.server}{path}",
            data=body,
            method="POST",
            headers=headers,
        )
        raw = None
        last_err: str = ""
        # The vul oracle is rate-limited (20 req / 60 s per agent); back off on
        # 429 so a burst of candidate submissions does not silently lose a crash.
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = json.loads(resp.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 3:
                    time.sleep(2.0 * (attempt + 1))
                    continue
                detail = e.read().decode("utf-8", "replace")[:500]
                return SubmitResult(task_id=task_id, exit_code=None, output=detail, poc_id=None, raw={"detail": detail})
            except urllib.error.URLError as e:
                last_err = str(e.reason)
                if attempt < 3:
                    time.sleep(2.0 * (attempt + 1))
                    continue
                return SubmitResult(task_id=task_id, exit_code=None, output=last_err, poc_id=None, raw={})
        if raw is None:
            return SubmitResult(task_id=task_id, exit_code=None, output=last_err, poc_id=None, raw={})

        exit_code = raw.get("exit_code")
        if isinstance(exit_code, str):
            try:
                exit_code = int(exit_code)
            except ValueError:
                exit_code = None
        return SubmitResult(
            task_id=task_id,
            exit_code=exit_code,
            output=raw.get("output", ""),
            poc_id=raw.get("poc_id"),
            raw=raw,
        )
