#!/usr/bin/env python3
"""Definitive ref-PoC contamination audit, v2.

Classifies every task by the terminal `[reference_poc]` marker in its logs.

Contaminating (a ref PoC was submitted as the answer):
    "/tmp/poc crashed vul"      -> then a positive verdict
    "valid ref PoC, skipping LLM branches"
    "confident match, skipping LLM branches"
    "crashed vul, skipping LLM branches"
    "late result, N candidate(s)"
    "late retry succeeded, N candidate(s)"

NOT contaminating (the ref PoC was rejected or never obtained):
    "MISMATCH"                  -> crashed fix too, fell back to LLM
    "failed:"                    -> extraction/HTTP exception
    "no candidates, retrying"    -> intermediate, not terminal
"""
import glob
import json
import re
from collections import defaultdict

LINES = []
for path in sorted(glob.glob("/home/ubuntu/Benchmark/runs/*/*.log")):
    try:
        LINES.extend(open(path, errors="replace").read().splitlines())
    except OSError:
        pass

TID = re.compile(r"\[reference_poc\]\s+(arvo:\d+|oss-fuzz:\d+)\s*:\s*(.*)$")

CONTAMINATING = (
    "valid ref PoC",
    "confident match",
    "crashed vul, skipping",
    "late result",
    "late retry succeeded",
)
CRASHED_VUL = "/tmp/poc crashed vul"
REJECTING = ("MISMATCH", "failed:")

state = defaultdict(lambda: {"crashed": False, "accepted": False,
                             "rejected": False, "retrying": False})

for line in LINES:
    m = TID.search(line)
    if not m:
        continue
    tid, rest = m.group(1), m.group(2)
    s = state[tid]
    if CRASHED_VUL in rest:
        s["crashed"] = True
    if any(k in rest for k in CONTAMINATING):
        s["accepted"] = True
    if any(k in rest for k in REJECTING):
        s["rejected"] = True
    if "retrying ref PoC" in rest:
        s["retrying"] = True

accepted = {t for t, s in state.items() if s["accepted"]}
crashed_only = {t for t, s in state.items() if s["crashed"] and not s["accepted"]}
rejected = {t for t, s in state.items() if s["rejected"] and not s["accepted"]}

print(f"tasks with ref-PoC activity:     {len(state)}")
print(f"  accepted a ref PoC (CHEAT):    {len(accepted)}")
print(f"  crashed vul but no verdict:    {len(crashed_only)}")
print(f"  rejected / errored:            {len(rejected)}")

solved = set()
for f in glob.glob("/home/ubuntu/Benchmark/runs/*/results.jsonl"):
    for line in open(f, errors="replace"):
        try:
            r = json.loads(line.strip())
        except Exception:
            continue
        if r.get("task_id") and (r.get("solved") or r.get("success")):
            solved.add(r["task_id"])

contaminated_solved = accepted & solved
print(f"\nCHEATED and counted as solved:   {len(contaminated_solved)}")
print(f"cheated but not currently solved: {len(accepted - solved)}")
print(f"\ntotal currently solved:          {len(solved)}")

# Breakdown: does the fuzz path explain any of these?
print(f"\nrejected-and-not-accepted samples: {sorted(rejected)[:5]}")

with open("/tmp/contaminated_list.txt", "w") as fh:
    for t in sorted(contaminated_solved):
        fh.write(t + "\n")

proj = defaultdict(int)
for t in contaminated_solved:
    proj[t.split(":")[0]] += 1
print("\nby project family:")
for p, n in sorted(proj.items(), key=lambda x: -x[1]):
    print(f"  {p}: {n}")

with open("/tmp/contaminated_by_family.json", "w") as fh:
    json.dump({k: v for k, v in proj.items()}, fh)
