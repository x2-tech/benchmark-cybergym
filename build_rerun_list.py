#!/usr/bin/env python3
"""Rebuild the re-run list using the CORRECT metric.

An earlier list (/tmp/contaminated_list.txt) was built from records where
`task_id and (solved or success)` was truthy — which included vul-only
false positives. Rebuild using `success` only, so the list contains exactly
the tasks that currently count toward the score AND used the ref-PoC cheat.
"""
import glob
import json
from collections import defaultdict

recs = defaultdict(list)
for f in glob.glob("/home/ubuntu/Benchmark/runs/*/results.jsonl"):
    for line in open(f, errors="replace"):
        try:
            r = json.loads(line.strip())
        except Exception:
            continue
        if r.get("task_id"):
            recs[r["task_id"]].append(r)

contaminated = {l.strip() for l in open("/tmp/contaminated_list.txt") if l.strip()}
print(f"ref-PoC contaminated (audit v2): {len(contaminated)}")

# Correct metric: success only.
counting = {t for t, rs in recs.items() if any(bool(r.get("success")) for r in rs)}
print(f"tasks counting toward the score (success=True): {len(counting)}")

rerun = sorted(contaminated & counting)
print(f"\n=== RE-RUN LIST ===")
print(f"contaminated AND currently counting: {len(rerun)}")

# Sanity: how many contaminated tasks are NOT counting (already failed, no need)
not_counting = sorted(contaminated - counting)
print(f"contaminated but NOT counting (no re-run needed): {len(not_counting)}")

with open("/tmp/rerun_list.txt", "w") as fh:
    fh.write("\n".join(rerun) + "\n")
print("\nwritten /tmp/rerun_list.txt")

# Honest baseline excluding the re-run list.
clean = counting - contaminated
print(f"\n=== HONEST BASELINE ===")
print(f"counting and never ref-PoC: {len(clean)}/1507 = {100*len(clean)/1507:.1f}%")

# What the score becomes if the re-run recovers nothing.
print(f"if re-run recovers 0%:   {len(clean)}/1507 = {100*len(clean)/1507:.1f}%")
for pct in (10, 20, 30, 40, 50):
    got = len(clean) + round(len(rerun) * pct / 100)
    print(f"if re-run recovers {pct:2d}%:  {got}/1507 = {100*got/1507:.1f}%")
