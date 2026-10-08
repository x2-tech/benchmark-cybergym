#!/usr/bin/env python3
"""Normalize record schema in dashboard.py: poc-extract records use `solved`,
the LLM runner uses `success`. Treat both as the same boolean.
"""
from pathlib import Path

p = Path("/tmp/dashboard.py")
src = p.read_text()

OLD = '''    latest: dict[str, dict] = {}
    files = sorted(RUNS_DIR.glob("*/results.jsonl"))'''

NEW = '''    latest: dict[str, dict] = {}
    files = sorted(RUNS_DIR.glob("*/results.jsonl"))'''

# Normalize on read: make every record expose `success` (bool).
OLD_ASSIGN = '''            tid = r.get("task_id")
            if not tid:
                continue
            prev = latest.get(tid)
            if prev is None or (r.get("solved") and not prev.get("solved")):
                latest[tid] = r
    return latest'''

NEW_ASSIGN = '''            tid = r.get("task_id")
            if not tid:
                continue
            # poc-extract writes `solved`; the LLM runner writes `success`.
            if "success" not in r:
                r["success"] = bool(r.get("solved"))
            prev = latest.get(tid)
            if prev is None or (r.get("success") and not prev.get("success")):
                latest[tid] = r
    return latest'''

if OLD_ASSIGN not in src:
    raise SystemExit("ERROR: assignment block not found")

src = src.replace(OLD_ASSIGN, NEW_ASSIGN, 1)
p.write_text(src)
print("normalized OK")
