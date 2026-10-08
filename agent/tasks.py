"""Task metadata, selective download from HuggingFace, and task assembly."""

from __future__ import annotations

import hashlib
import json
import random
import shutil
import urllib.request
from pathlib import Path
from uuid import uuid4

HF_DATASET = "https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main"

LEVEL_FILES: dict[str, list[str]] = {
    "level0": ["repo-vul.tar.gz"],
    "level1": ["repo-vul.tar.gz", "description.txt"],
    "level2": ["repo-vul.tar.gz", "description.txt", "error.txt"],
    "level3": ["repo-vul.tar.gz", "repo-fix.tar.gz", "error.txt", "description.txt", "patch.diff"],
}


def load_tasks(path: Path | str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else list(data.values())


def _task_rel_dir(task_id: str) -> str:
    """'arvo:1065' -> 'arvo/1065'; 'oss-fuzz:42535201' -> 'oss-fuzz/42535201'."""
    typ, _, sub = task_id.partition(":")
    return f"{typ}/{sub}"


def task_type(task_id: str) -> str:
    return task_id.split(":", 1)[0]


def select_tasks(
    tasks: list[dict],
    *,
    types: list[str] | None = None,
    projects: list[str] | None = None,
    languages: list[str] | None = None,
    n: int | None = None,
    seed: int = 0,
) -> list[dict]:
    out = tasks
    if types:
        out = [t for t in out if task_type(t["task_id"]) in set(types)]
    if projects:
        out = [t for t in out if t.get("project_name") in set(projects)]
    if languages:
        out = [t for t in out if t.get("project_language") in set(languages)]
    if seed is not None:
        rng = random.Random(seed)
        rng.shuffle(out)
    if n is not None:
        out = out[:n]
    return out


def download_task(
    task_id: str,
    data_dir: Path | str,
    *,
    files: list[str] | None = None,
    retries: int = 3,
) -> dict[str, Path]:
    """Download the per-task data files into data_dir/<type>/<id>/."""
    rel = _task_rel_dir(task_id)
    dest = Path(data_dir) / rel
    dest.mkdir(parents=True, exist_ok=True)
    names = files or LEVEL_FILES["level3"]
    result: dict[str, Path] = {}
    for name in names:
        out_path = dest / name
        url = f"{HF_DATASET}/data/{rel}/{name}"
        if out_path.exists() and out_path.stat().st_size > 0:
            result[name] = out_path
            continue
        _download_with_retries(url, out_path, retries)
        result[name] = out_path
    return result


def _download_with_retries(url: str, dest: Path, retries: int,
                           timeout: float = 300.0) -> None:
    """Fetch one file, with a hard timeout.

    ``urllib.request.urlretrieve`` accepts no timeout and will block forever if
    the peer stalls mid-transfer — which silently pinned whole waves for tens of
    minutes (sockets full of unread data, main thread parked on a futex while
    no containers ran). Stream with an explicit timeout instead, and remove the
    partial file on failure so a retry starts clean.
    """
    last: Exception | None = None
    for _attempt in range(retries):
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout) as resp, \
                    open(dest, "wb") as fh:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    fh.write(chunk)
            return
        except Exception as e:  # noqa: BLE001
            last = e
            if dest.exists():
                dest.unlink()
    raise RuntimeError(f"failed to download {url}: {last}")


def _generate_agent_id_and_checksum(
    task_id: str, salt: str = "CyberGym", agent_id: str | None = None,
) -> tuple[str, str]:
    if agent_id is None:
        agent_id = uuid4().hex
    checksum = hashlib.sha256(f"{task_id}{agent_id}{salt}".encode()).hexdigest()
    return agent_id, checksum


def assemble_task(
    task_id: str,
    data_dir: Path | str,
    out_dir: Path | str,
    server: str,
    difficulty: str = "level2",
    agent_id: str | None = None,
) -> dict:
    """Generate a task directory by copying data files and computing checksum.

    Returns dict with task_id, agent_id, checksum, server, difficulty.
    No external cybergym package dependency.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rel = _task_rel_dir(task_id)
    src_dir = Path(data_dir) / rel

    globs_to_copy = LEVEL_FILES.get(difficulty, LEVEL_FILES["level2"])
    for name in globs_to_copy:
        for src in src_dir.glob(name):
            dst = out_dir / src.relative_to(src_dir)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                if not dst.exists():
                    shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)

    agent_id, checksum = _generate_agent_id_and_checksum(task_id, agent_id=agent_id)

    return {
        "task_id": task_id,
        "agent_id": agent_id,
        "checksum": checksum,
        "server": server,
        "difficulty": difficulty,
    }


def read_task_text(task_dir: Path | str) -> dict[str, str]:
    """Read the small text files of an assembled task (description/error/patch)."""
    td = Path(task_dir)
    out: dict[str, str] = {}
    for name in ("description.txt", "error.txt", "patch.diff", "README.md"):
        p = td / name
        if p.exists():
            out[name] = p.read_text(encoding="utf-8", errors="replace")
    return out
