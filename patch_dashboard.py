#!/usr/bin/env python3
"""Patch dashboard.py to aggregate solved results across every runs/*/results.jsonl.

The dashboard originally read a single file (runs/ec2-full/results.jsonl), so the
dedicated PoC-extraction run in runs/poc-extract/ was invisible and the solve count
appeared frozen at 1233 while the real count was 1440.
"""
from pathlib import Path

p = Path("/tmp/dashboard.py")
src = p.read_text()

OLD = '''def _latest_results() -> dict[str, dict]:
    """Last record per task_id (the runner rewrites entries on retry)."""
    latest: dict[str, dict] = {}
    if not RESULTS_FILE.exists():
        return latest
    for line in RESULTS_FILE.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        tid = r.get("task_id")
        if tid:
            latest[tid] = r
    return latest'''

NEW = '''def _latest_results() -> dict[str, dict]:
    """Best record per task_id across every run directory.

    Separate runners write to separate runs/*/results.jsonl trees (ec2-full,
    poc-extract, overnight-llm, ...). A task counts as solved if ANY directory
    says so, so a solved record always wins over a later failure.
    """
    latest: dict[str, dict] = {}
    files = sorted(RUNS_DIR.glob("*/results.jsonl"))
    if RESULTS_FILE.exists() and RESULTS_FILE not in files:
        files.append(RESULTS_FILE)
    for path in files:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            tid = r.get("task_id")
            if not tid:
                continue
            prev = latest.get(tid)
            if prev is None or (r.get("solved") and not prev.get("solved")):
                latest[tid] = r
    return latest'''

if OLD not in src:
    raise SystemExit("ERROR: _latest_results target not found — dashboard.py differs")

src = src.replace(OLD, NEW)

OLD_CONST = 'RESULTS_FILE = Path("/home/ubuntu/Benchmark/runs/ec2-full/results.jsonl")'
NEW_CONST = (
    'RUNS_DIR = Path("/home/ubuntu/Benchmark/runs")\n'
    'RESULTS_FILE = RUNS_DIR / "ec2-full" / "results.jsonl"'
)
if OLD_CONST not in src:
    raise SystemExit("ERROR: RESULTS_FILE constant not found")

src = src.replace(OLD_CONST, NEW_CONST, 1)
p.write_text(src)
print("patched OK")
