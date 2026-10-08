#!/usr/bin/env python3
"""Reconstruct the definitive ref-PoC contamination list from wave logs.

agent.py printed three kinds of stderr markers:
    [reference_poc] {tid}: /tmp/poc crashed vul (exit N)   <- vul check passed
    [reference_poc] {tid}: MISMATCH — also crashed fix ... <- fix check failed
    [reference_poc] {tid}: failed: ...                     <- exception

The "crashed vul" line prints BEFORE the fix verification, so a task that
later prints MISMATCH fell back to LLM branches and is NOT contaminated.
A task with "crashed vul" and NO MISMATCH means the ref PoC was submitted
as the winning candidate -> contaminated.

A task with only "failed:" never produced a candidate -> not contaminated.
"""
import glob
import re
import sys
from collections import defaultdict

VUL_RE = re.compile(r"\[reference_poc\]\s+(\S+):\s+/tmp/poc crashed vul")
MISMATCH_RE = re.compile(r"\[reference_poc\]\s+(\S+):\s+MISMATCH")
FAILED_RE = re.compile(r"\[reference_poc\]\s+(\S+):\s+failed")

vul_ok = defaultdict(int)
mismatch = defaultdict(int)
failed = defaultdict(int)

paths = sorted(glob.glob("/home/ubuntu/Benchmark/runs/*/wave*.log"))
paths += sorted(glob.glob("/home/ubuntu/Benchmark/runs/*/*.log"))
for path in paths:
    try:
        text = open(path, errors="replace").read()
    except OSError:
        continue
    for m in VUL_RE.finditer(text):
        vul_ok[m.group(1)] += 1
    for m in MISMATCH_RE.finditer(text):
        mismatch[m.group(1)] += 1
    for m in FAILED_RE.finditer(text):
        failed[m.group(1)] += 1

contaminated = {t for t in vul_ok if mismatch.get(t, 0) == 0}
recovered = {t for t in vul_ok if mismatch.get(t, 0) > 0}

print(f"logs scanned:            {len(paths)}")
print(f"tasks with ref-PoC vul crash: {len(vul_ok)}")
print(f"  -> contaminated (no mismatch): {len(contaminated)}")
print(f"  -> fell back to LLM (mismatch): {len(recovered)}")
print(f"tasks with ref-PoC exception:   {len(failed)}")

# How many contaminated tasks are currently marked solved?
import json

solved = set()
for f in glob.glob("/home/ubuntu/Benchmark/runs/*/results.jsonl"):
    for line in open(f, errors="replace"):
        try:
            r = json.loads(line.strip())
        except Exception:
            continue
        if r.get("task_id") and (r.get("solved") or r.get("success")):
            solved.add(r["task_id"])

contaminated_solved = contaminated & solved
print(f"\ncontaminated AND currently counted solved: {len(contaminated_solved)}")
print(f"contaminated but NOT solved:               {len(contaminated - solved)}")

with open("/tmp/contaminated_list.txt", "w") as fh:
    for t in sorted(contaminated_solved):
        fh.write(t + "\n")
print("\nwritten /tmp/contaminated_list.txt (contaminated solved tasks to re-run)")

# Project breakdown
proj = defaultdict(int)
for t in contaminated_solved:
    proj[t.split(":")[0]] += 1
print("\ntop projects:")
for p, n in sorted(proj.items(), key=lambda x: -x[1])[:15]:
    print(f"  {p}: {n}")
