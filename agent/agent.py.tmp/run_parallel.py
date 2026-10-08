"""Parallel batch evaluation using concurrent.futures.

Usage:
    python3 -m eval.run_parallel --n 50 --workers 6 --out-dir runs/ec2-p1
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
import threading
import shutil
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from agent.agent import run_task_attempts
from agent.config import load_config
from agent.llm import UsageLedger
from agent.tasks import LEVEL_FILES, assemble_task, download_task, load_tasks, select_tasks
from eval.verify import verify_final

_write_lock = threading.Lock()
RELEASE = os.getenv("CYBERGYM_RELEASE", "unversioned")


def classify_failure(rec: dict) -> str:
    if rec.get("success") is True:
        return "verified_success"
    error = str(rec.get("error") or "")
    if "402" in error or "Insufficient Balance" in error or "余额" in error:
        return "provider_balance"
    if "FileNotFoundError" in error:
        return "archive_error"
    if "stalled" in error:
        return "stalled"
    if "tool-call budget" in error or "budget exhausted" in error:
        return "budget_exhausted"
    if "branch exhausted" in error:
        return "non_crashing_candidates"
    if rec.get("solved") is True and rec.get("fix_exit_code") not in (None, 0):
        return "fix_crash_or_failed_fix"
    if rec.get("solved") is True:
        return "candidate_unverified"
    return "no_crash"


def run_one(task_meta: dict, cfg, server: str, data_dir: Path, out_dir: Path,
            difficulty: str, api_key: str, ledger: UsageLedger) -> dict:
    task_id = task_meta["task_id"]
    rec: dict = {"task_id": task_id, "difficulty": difficulty,
                 "project": task_meta.get("project_name"), "release": RELEASE}
    t0 = time.time()
    try:
        download_task(task_id, data_dir, files=LEVEL_FILES[difficulty])
        task_dir = out_dir / "tasks" / (
            task_id.replace(":", "_")
            + f".run-{os.getpid()}-{threading.get_ident()}"
        )
        # Assemble in a private staging directory, then publish atomically.
        # Readers never observe a half-copied archive or a directory from a
        # previous retry.
        stage_dir = task_dir.with_name(task_dir.name + ".staging")
        shutil.rmtree(stage_dir, ignore_errors=True)
        task = assemble_task(task_id, data_dir, stage_dir, server, difficulty)
        if task_dir.exists():
            shutil.rmtree(task_dir, ignore_errors=True)
        stage_dir.rename(task_dir)
        # The task archive is the agent's only source checkout. Under a busy
        # multi-process retry wave, a partially-created task directory can be
        # observed between download/assembly and agent startup. Reassemble once
        # and fail explicitly rather than burning an entire LLM attempt.
        archive = task_dir / "repo-vul.tar.gz"
        if not archive.is_file() or archive.stat().st_size == 0:
            task = assemble_task(task_id, data_dir, task_dir, server, difficulty,
                                 agent_id=task["agent_id"])
        if not archive.is_file() or archive.stat().st_size == 0:
            raise FileNotFoundError(f"assembled task archive missing: {archive}")
        res = run_task_attempts(
            task_dir, server, task_id, task["agent_id"], task["checksum"], cfg,
            difficulty=difficulty, project=task_meta.get("project_name", ""),
            ledger=ledger,
        )
        rec.update(
            solved=res.solved, steps=res.steps,
            vul_exit_code=res.crash_exit_code, error=res.error,
            crash_matches_description=res.extra.get("crash_matches_description"),
            agent_id=task["agent_id"], checksum=task["checksum"],
        )
        if res.solved and res.final_poc_path:
            poc = Path(res.final_poc_path).read_bytes()
            ver = verify_final(poc, task_id, task["agent_id"],
                               task["checksum"], server, api_key=api_key)
            rec["verified"] = ver.success
            rec["fix_exit_code"] = ver.fix_exit_code
            rec["verification_reason"] = ver.reason
            if not ver.success and not rec.get("error"):
                rec["error"] = ver.reason or "final verification failed"
            rec["poc_sha256"] = hashlib.sha256(poc).hexdigest()
            evidence_dir = out_dir / "submission-materials" / task_id.replace(":", "_")
            evidence_dir.mkdir(parents=True, exist_ok=True)
            poc_path = evidence_dir / "poc"
            poc_path.write_bytes(poc)
            rec["poc_path"] = str(poc_path)
            rec["success"] = ver.success
        else:
            rec["verified"] = False
            rec["success"] = False
    except Exception as e:
        rec["error"] = repr(e)
        rec["success"] = False
        print(f"[ERROR] {task_id}: {repr(e)}", file=__import__("sys").stderr, flush=True)
        traceback.print_exc(file=__import__("sys").stderr)
    rec["wall_sec"] = round(time.time() - t0, 1)
    # Completion timestamp, so the dashboard can plot a real timeline rather
    # than inferring order from line position in results.jsonl.
    rec["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rec["failure_class"] = classify_failure(rec)
    return rec


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CyberGym parallel evaluation")
    ap.add_argument("--tasks", default="data-meta/tasks.json")
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--difficulty", default="level2")
    ap.add_argument("--projects", nargs="*", default=None)
    ap.add_argument("--types", nargs="*", default=None)
    ap.add_argument("--languages", nargs="*", default=None)
    ap.add_argument("--task-ids", nargs="*", default=None)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--server", default=None)
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--out-dir", default="runs/parallel")
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--resume", action="store_true",
                    help="skip tasks already in results.jsonl")
    ap.add_argument("--no-cleanup", action="store_true",
                    help="accepted for compatibility; this runner never removes "
                         "images itself (the outer runner owns image lifecycle, "
                         "which keeps them available for retries)")
    args = ap.parse_args(argv)

    cfg = load_config()
    problems = cfg.validate()
    if problems:
        print("missing config:", problems, file=sys.stderr)
        return 2

    server = args.server or cfg.server_url
    # Resolve paths before worker threads start. Agent tasks can run fuzzers and
    # subprocesses concurrently; relative paths are vulnerable to cwd changes
    # and made valid archives appear missing during retry attempts.
    data_dir = (Path(args.data_dir) if args.data_dir else cfg.data_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Each run gets its own workspace to prevent file collisions when
    # multiple seeds process the same task_id concurrently.
    cfg.workspace = (out_dir / "work").resolve()

    tasks = load_tasks(args.tasks)
    if args.task_ids:
        wanted = set(args.task_ids)
        tasks = [t for t in tasks if t["task_id"] in wanted]
    else:
        tasks = select_tasks(
            tasks, types=args.types, projects=args.projects,
            languages=args.languages, n=args.n, seed=args.seed,
        )

    results_path = out_dir / "results.jsonl"
    done_ids: set[str] = set()
    if args.resume and results_path.exists():
        for line in results_path.read_text().splitlines():
            if line.strip():
                done_ids.add(json.loads(line)["task_id"])
        print(f"Resuming: {len(done_ids)} already done, skipping them")
    tasks = [t for t in tasks if t["task_id"] not in done_ids]

    if not tasks:
        print("No tasks to run.")
        return 0

    print(f"Running {len(tasks)} tasks with {args.workers} workers")
    ledger = UsageLedger()
    api_key = args.api_key or os.getenv(
        "CYBERGYM_API_KEY", "cybergym-030a0cd7-5908-4862-8ab9-91f2bfc7b56d")

    solved = 0
    total = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {
            pool.submit(run_one, t, cfg, server, data_dir, out_dir,
                        args.difficulty, api_key, ledger): t
            for t in tasks
        }
        for fut in as_completed(futs):
            rec = fut.result()
            total += 1
            if rec.get("success"):
                solved += 1
            with _write_lock:
                with results_path.open("a") as f:
                    f.write(json.dumps(rec) + "\n")
            tag = "OK" if rec.get("success") else "FAIL"
            err = rec.get("error", "")
            if err:
                err = f" err={err[:60]}"
            print(f"[{total}/{len(tasks)}] {tag} {rec['task_id']} "
                  f"({rec['wall_sec']}s){err}", flush=True)

    all_recs = [json.loads(l) for l in results_path.read_text().splitlines()
                if l.strip()]
    total_all = len(all_recs)
    solved_all = sum(1 for r in all_recs if r.get("success"))
    summary = {
        "n": total_all, "solved": solved_all,
        "success_rate": round(solved_all / total_all, 4) if total_all else 0,
        "difficulty": args.difficulty,
        "models": {m: u.as_dict() for m, u in ledger.usage.items()},
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
