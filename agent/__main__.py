"""CLI: run the agent on a single CyberGym task.

Example:
    OPENAI_BASE_URL=... OPENAI_API_KEY=... CYBERGYM_MODEL=... \
    python -m agent --task-id arvo:1065 --difficulty level2
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import run_task_attempts
from .config import load_config
from .tasks import LEVEL_FILES, assemble_task, download_task


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CyberGym PoV agent")
    ap.add_argument("--task-id", required=True)
    ap.add_argument("--difficulty", default="level2")
    ap.add_argument("--server", default=None, help="defaults to CYBERGYM_SERVER")
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--out-dir", default=None, help="assembled task dir (default: work/<task>_task)")
    ap.add_argument("--no-download", action="store_true")
    ap.add_argument("--only-assemble", action="store_true", help="just generate the task and exit")
    args = ap.parse_args(argv)

    cfg = load_config()
    problems = cfg.validate()
    if problems:
        print("missing config:", problems, file=sys.stderr)
        return 2

    data_dir = Path(args.data_dir) if args.data_dir else cfg.data_dir
    server = args.server or cfg.server_url

    if not args.no_download:
        try:
            download_task(args.task_id, data_dir, files=LEVEL_FILES[args.difficulty])
        except Exception as e:  # noqa: BLE001
            print(f"download failed (continuing if files exist): {e}", file=sys.stderr)

    out_dir = Path(args.out_dir) if args.out_dir else cfg.workspace / f"{args.task_id.replace(':', '_')}_task"
    task = assemble_task(args.task_id, data_dir, out_dir, server, args.difficulty)
    print(json.dumps(task, indent=2))
    if args.only_assemble:
        return 0

    res = run_task_attempts(
        out_dir,
        server,
        args.task_id,
        task["agent_id"],
        task["checksum"],
        cfg,
        difficulty=args.difficulty,
    )
    print(json.dumps(
        {
            "task_id": res.task_id,
            "solved": res.solved,
            "crash_exit_code": res.crash_exit_code,
            "final_poc_path": res.final_poc_path,
            "steps": res.steps,
            "error": res.error,
            "crash_matches_description": res.extra.get("crash_matches_description"),
        },
        indent=2,
    ))
    return 0 if res.solved else 1


if __name__ == "__main__":
    raise SystemExit(main())
