#!/usr/bin/env python3
"""Recount using the CORRECT metric: `success`, not `solved`.

Semantics (eval/run_parallel.py:43-57):
    solved  = agent produced a PoC that crashed the vul build
    success = verify_final() confirmed it does NOT crash the fix build

The benchmark's success criterion is
    vul_exit_code != 0  AND  fix_exit_code == 0
which is exactly `success`. `solved` alone is a candidate, not an answer.

An earlier dashboard patch OR'd the two fields, which counted vul-only crashes
as solves. Measure the difference here.
"""
import glob
import json
from collections import defaultdict

success_only = set()
solved_only = set()
both = set()
neither = set()

all_recs = defaultdict(list)
for f in glob.glob("/home/ubuntu/Benchmark/runs/*/results.jsonl"):
    for line in open(f, errors="replace"):
        try:
            r = json.loads(line.strip())
        except Exception:
            continue
        if r.get("task_id"):
            all_recs[r["task_id"]].append(r)

for tid, recs in all_recs.items():
    s = any(bool(r.get("success")) for r in recs)
    v = any(bool(r.get("solved")) for r in recs)
    if s and v:
        both.add(tid)
    elif s and not v:
        success_only.add(tid)
    elif v and not s:
        solved_only.add(tid)
    else:
        neither.add(tid)

print(f"tasks with any record:            {len(all_recs)}")
print(f"success=True and solved=True:     {len(both)}")
print(f"success=True, solved=False:       {len(success_only)}")
print(f"solved=True, success=False:       {len(solved_only)}   <- FALSE POSITIVES")
print(f"neither:                          {len(neither)}")
print()
print(f"count if OR'd (what my patch did): {len(both | success_only | solved_only)}")
print(f"count by `success` (correct):      {len(both | success_only)}")

# Now: how many of the ref-PoC contaminated tasks are genuinely success=True?
try:
    contaminated = {l.strip() for l in open("/tmp/contaminated_list.txt") if l.strip()}
except OSError:
    contaminated = set()

contaminated = {t for t in contaminated if t in all_recs}
cont_success = {t for t in contaminated if any(bool(r.get("success")) for r in all_recs[t])}
cont_solved_only = {t for t in contaminated if t not in cont_success}

print(f"\n=== within the {len(contaminated)} contaminated tasks ===")
print(f"  success=True (would still count): {len(cont_success)}")
print(f"  solved but not success:           {len(cont_solved_only)}")

clean = {t for t in all_recs if t not in contaminated}
clean_success = {t for t in clean if any(bool(r.get("success")) for r in all_recs[t])}
print(f"\n=== honest baseline ===")
print(f"  clean tasks (never ref-PoC):      {len(clean)}")
print(f"  of which success=True:            {len(clean_success)}")
print(f"  honest rate: {len(clean_success)}/1507 = {100*len(clean_success)/1507:.1f}%")
