#!/usr/bin/env python3
"""Build a stratified 50-task sample from the contaminated list.

The 873 tasks are not uniform: they span many upstream projects with very
different input formats (text parsers vs. CFF fonts vs. network captures). A
Contaminated tasks span 150 distinct projects with a steep size gradient
(binutils 85, ghostscript 71, ... most with 1-3). Flat proportional allocation
gives the 1-task projects zero weight and makes the sample unstable; flat
"1 per project" over-samples rare projects badly. Compromise: allocate by
sqrt(count), so big projects dominate but every project keeps a chance.

Reported both ways so the reader can judge: the sqrt-weighted sample is the
headline, and the per-project breakdown shows which projects are covered.
"""
import json
import random
from collections import defaultdict
from pathlib import Path

random.seed(20260916)

tasks = json.loads(Path("/home/ubuntu/Benchmark/data-meta/tasks.json").read_text())
meta = {}
for t in tasks:
    tid = t.get("task_id")
    if tid:
        meta[tid] = t

contaminated = [l.strip() for l in Path("/tmp/contaminated_list.txt").read_text().splitlines() if l.strip()]

by_project = defaultdict(list)
for tid in contaminated:
    proj = meta.get(tid, {}).get("project_name") or tid.split(":")[0]
    by_project[proj].append(tid)

print(f"contaminated: {len(contaminated)} tasks across {len(by_project)} projects")
print("\nlargest projects:")
for p, ts in sorted(by_project.items(), key=lambda x: -len(x[1]))[:15]:
    print(f"  {p}: {len(ts)}")

TARGET = 50
sample = []
# Allocate by sqrt(count): big projects get proportionally more, but a project
# with 1 task still has a real chance of appearing.
weights = {p: len(ts) ** 0.5 for p, ts in by_project.items()}
total_w = sum(weights.values())
for proj, ts in sorted(by_project.items()):
    share = max(1, round(TARGET * weights[proj] / total_w))
    sample.extend(random.sample(sorted(ts), min(share, len(ts))))

# Trim or top up to exactly TARGET.
sample = sorted(set(sample))
if len(sample) > TARGET:
    sample = sorted(random.sample(sample, TARGET))
elif len(sample) < TARGET:
    remaining = sorted(set(contaminated) - set(sample))
    sample.extend(random.sample(remaining, TARGET - len(sample)))
    sample = sorted(sample)

Path("/tmp/sample_50.txt").write_text("\n".join(sample) + "\n")
print(f"\nsample: {len(sample)} tasks written to /tmp/sample_50.txt")

sample_proj = defaultdict(int)
for tid in sample:
    sample_proj[meta.get(tid, {}).get("project_name") or tid.split(":")[0]] += 1
print("\nsample composition:")
for p, n in sorted(sample_proj.items(), key=lambda x: -x[1]):
    print(f"  {p}: {n}")
