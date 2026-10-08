#!/usr/bin/env python3
"""Reconcile solve counts: which solved task_ids does the dashboard logic miss?"""
import glob
import json
from pathlib import Path

RUNS_DIR = Path("/home/ubuntu/Benchmark/runs")

# My counting method (union of all solved records)
mine = set()
for f in glob.glob(str(RUNS_DIR / "*" / "results.jsonl")):
    for line in open(f):
        try:
            r = json.loads(line.strip())
            if r.get("task_id") and r.get("solved"):
                mine.add(r["task_id"])
        except Exception:
            pass

# Dashboard method
latest = {}
files = sorted(RUNS_DIR.glob("*/results.jsonl"))
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
        if "success" not in r:
            r["success"] = bool(r.get("solved"))
        prev = latest.get(tid)
        if prev is None or (r.get("success") and not prev.get("success")):
            latest[tid] = r

dash_solved = {t for t, r in latest.items() if r.get("success")}

print("files scanned:")
for f in files:
    n = sum(1 for _ in open(f))
    print(f"  {f}: {n} lines")

print(f"\nmy solved:       {len(mine)}")
print(f"dashboard solved:{len(dash_solved)}")
print(f"\nsolved in mine but NOT dashboard ({len(mine - dash_solved)}):")
for t in sorted(mine - dash_solved):
    print(f"  {t}")
print(f"\nsolved in dashboard but NOT mine ({len(dash_solved - mine)}):")
for t in sorted(dash_solved - mine):
    print(f"  {t}")
