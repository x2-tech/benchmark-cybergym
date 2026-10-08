#!/usr/bin/env python3
"""Split a task list into N shards and run each as its own eval.run process.

The batch runner is strictly sequential per process and the box has 8 vCPUs and
16 GB RAM idle during a single-task run, so throughput is bounded by shard count.
Each shard writes to its own run directory: separate output trees mean no two
processes ever touch the same results.jsonl, which keeps a re-run from
overwriting an earlier answer.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PY = "/home/ubuntu/venv312/bin/python"
BASE = Path("/home/ubuntu/Benchmark")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", required=True, help="file of task ids, one per line")
    ap.add_argument("--shards", type=int, default=4)
    ap.add_argument("--tag", required=True, help="run directory prefix")
    ap.add_argument("--extra", default="", help="extra eval.run flags")
    args = ap.parse_args()

    tasks = [l.strip() for l in Path(args.list).read_text().splitlines() if l.strip()]
    if not tasks:
        print("no tasks", file=sys.stderr)
        return 1

    # Round-robin rather than contiguous: adjacent ids share a project and thus
    # a docker image, so spreading them keeps each shard's pull working set
    # different instead of all four processes racing for the same image.
    shards: list[list[str]] = [[] for _ in range(args.shards)]
    for i, t in enumerate(tasks):
        shards[i % args.shards].append(t)

    procs = []
    for i, chunk in enumerate(shards):
        if not chunk:
            continue
        out = BASE / "runs" / f"{args.tag}-s{i}"
        log = BASE / "runs" / f"{args.tag}-s{i}.log"
        cmd = [PY, "-u", "-m", "eval.run", "--task-ids", *chunk, "--skip-download",
               "--out-dir", str(out)]
        if args.extra:
            cmd.extend(args.extra.split())
        print(f"shard {i}: {len(chunk)} tasks -> {out.name}", flush=True)
        with log.open("w") as fh:
            procs.append(subprocess.Popen(cmd, cwd=str(BASE), stdout=fh, stderr=fh))

    failed = 0
    for i, p in enumerate(procs):
        if p.wait() != 0:
            print(f"shard {i} exited {p.returncode}", file=sys.stderr)
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
