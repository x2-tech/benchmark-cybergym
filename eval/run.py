"""Batch evaluation: select tasks -> assemble -> run agent -> verify -> score.

Usage:
    python -m eval.run --tasks data-meta/tasks.json --n 10 --difficulty level2
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from agent.agent import run_task_attempts
from agent.config import load_config
from agent.llm import UsageLedger
from agent.tasks import LEVEL_FILES, assemble_task, download_task, load_tasks, select_tasks
from eval.verify import verify_final


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CyberGym batch evaluation")
    ap.add_argument("--tasks", default="data-meta/tasks.json")
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--difficulty", default="level2")
    ap.add_argument("--projects", nargs="*", default=None)
    ap.add_argument("--types", nargs="*", default=None)
    ap.add_argument("--languages", nargs="*", default=None)
    ap.add_argument("--task-ids", nargs="*", default=None, help="explicit task ids (e.g. arvo:10400)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--server", default=None)
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--out-dir", default="runs")
    ap.add_argument("--skip-download", action="store_true")
    ap.add_argument("--api-key", default=None)
    args = ap.parse_args(argv)

    cfg = load_config()
    problems = cfg.validate()
    if problems:
        print("missing config:", problems, file=sys.stderr)
        return 2

    server = args.server or cfg.server_url
    data_dir = Path(args.data_dir) if args.data_dir else cfg.data_dir
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tasks = load_tasks(args.tasks)
    if args.task_ids:
        wanted = set(args.task_ids)
        tasks = [t for t in tasks if t["task_id"] in wanted]
    else:
        tasks = select_tasks(
            tasks,
            types=args.types,
            projects=args.projects,
            languages=args.languages,
            n=args.n,
            seed=args.seed,
        )

    ledger = UsageLedger()
    results_path = out_dir / "results.jsonl"
    api_key = args.api_key or os.getenv("CYBERGYM_API_KEY", "cybergym-030a0cd7-5908-4862-8ab9-91f2bfc7b56d")

    done: set[str] = set()
    if results_path.exists():
        for line in results_path.read_text().splitlines():
            if line.strip():
                done.add(json.loads(line)["task_id"])
        if done:
            tasks = [t for t in tasks if t["task_id"] not in done]
            print(f"skipping {len(done)} already-completed tasks, {len(tasks)} remaining", flush=True)

    with results_path.open("a") as out:
        for i, t in enumerate(tasks, 1):
            task_id = t["task_id"]
            print(f"[{i}/{len(tasks)}] {task_id} ...", flush=True)
            rec: dict = {"task_id": task_id, "difficulty": args.difficulty, "project": t.get("project_name")}
            t0 = time.time()
            try:
                if not args.skip_download:
                    download_task(task_id, data_dir, files=LEVEL_FILES[args.difficulty])
                task_dir = out_dir / "tasks" / task_id.replace(":", "_")
                task = assemble_task(task_id, data_dir, task_dir, server, args.difficulty)
                res = run_task_attempts(
                    task_dir, server, task_id, task["agent_id"], task["checksum"], cfg,
                    difficulty=args.difficulty, project=t.get("project_name", ""), ledger=ledger,
                )
                rec.update(
                    solved=res.solved,
                    steps=res.steps,
                    vul_exit_code=res.crash_exit_code,
                    error=res.error,
                    crash_matches_description=res.extra.get("crash_matches_description"),
                )
                if res.solved and res.final_poc_path:
                    poc = Path(res.final_poc_path).read_bytes()
                    ver = verify_final(poc, task_id, task["agent_id"], task["checksum"], server, api_key=api_key)
                    rec["verified"] = ver.success
                    rec["fix_exit_code"] = ver.fix_exit_code
                    rec["success"] = ver.success
                else:
                    rec["verified"] = False
                    rec["success"] = False
            except Exception as e:  # noqa: BLE001
                rec["error"] = repr(e)
                rec["success"] = False
            rec["wall_sec"] = round(time.time() - t0, 1)
            # Completion timestamp for the dashboard timeline.
            rec["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            out.write(json.dumps(rec) + "\n")
            out.flush()
            print(f"    -> success={rec.get('success')} steps={rec.get('steps')} err={rec.get('error','')[:80]}", flush=True)
            if task_dir.exists():
                shutil.rmtree(task_dir, ignore_errors=True)

    # summary
    recs = [json.loads(l) for l in results_path.read_text().splitlines() if l.strip()]
    solved = sum(1 for r in recs if r.get("success"))
    summary = {
        "n": len(recs),
        "solved": solved,
        "success_rate": round(solved / len(recs), 4) if recs else 0.0,
        "difficulty": args.difficulty,
        "models": {m: u.as_dict() for m, u in ledger.usage.items()},
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
