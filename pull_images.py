#!/usr/bin/env python3
"""Pre-pull task images in parallel.

The CyberGym oracle server pulls images lazily inside the request handler
(`server_utils.run_container`), so a missing image stalls the submitting agent
for the whole pull — multi-GB on the oss-fuzz images, tens of minutes serially.
Pulling ahead of time in parallel moves that wait off the critical path. Pulls
are network/disk bound rather than CPU bound, so a higher degree of parallelism
than vCPU count is safe.

Usage: pull_images.py --list tasks.txt [--parallel 8]
       pull_images.py --images missing_imgs.txt [--parallel 8]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

PULL_TIMEOUT = 3600


def image_for(task_id: str, suffix: str) -> str:
    kind, _, sub = task_id.partition(":")
    prefix = "n132/arvo" if kind == "arvo" else "cybergym/oss-fuzz"
    return f"{prefix}:{sub}{suffix}"


def local_images() -> set[str]:
    out = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                         capture_output=True, text=True).stdout
    return set(out.split())


def pull(image: str) -> tuple[str, bool, str]:
    try:
        r = subprocess.run(["docker", "pull", "--platform", "linux/amd64", image],
                           capture_output=True, text=True, timeout=PULL_TIMEOUT)
    except subprocess.TimeoutExpired:
        return image, False, "timeout"
    if r.returncode == 0:
        return image, True, ""
    err = (r.stderr or r.stdout or "").strip().splitlines()
    return image, False, err[-1][:120] if err else f"exit {r.returncode}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", help="task ids, one per line; pulls vul+fix")
    ap.add_argument("--images", help="explicit image names, one per line")
    ap.add_argument("--parallel", type=int, default=8)
    args = ap.parse_args()

    if args.images:
        targets = [l.strip() for l in Path(args.images).read_text().splitlines() if l.strip()]
    elif args.list:
        tasks = [l.strip() for l in Path(args.list).read_text().splitlines() if l.strip()]
        targets = [image_for(t, s) for t in tasks for s in ("-vul", "-fix")]
    else:
        print("need --list or --images", file=sys.stderr)
        return 2

    have = local_images()
    todo = [t for t in targets if t not in have]
    print(f"{len(targets)} images, {len(have)} local, {len(todo)} to pull "
          f"({args.parallel} parallel)", flush=True)
    if not todo:
        return 0

    ok = failed = 0
    done = 0
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        futs = {pool.submit(pull, img): img for img in todo}
        for fut in as_completed(futs):
            img, good, err = fut.result()
            done += 1
            if good:
                ok += 1
            else:
                failed += 1
                print(f"[pull] FAILED {img}: {err}", flush=True)
            if done % 5 == 0 or done == len(todo):
                print(f"  {done}/{len(todo)} done ({ok} ok, {failed} failed)", flush=True)
    print(f"finished: {ok} ok, {failed} failed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
