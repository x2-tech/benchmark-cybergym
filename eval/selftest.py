"""End-to-end scoring self-test (not part of the agent's task solving).

Requires the verification server and the per-task docker images. It runs the
*reference* PoC through the exact vul/fix verification used for scoring, to prove
the harness reports success=True for a known-good PoV. This does NOT measure the
agent — it only validates the grading machinery.

Usage:
    python -m eval.selftest --task-id arvo:1065 --poc /tmp/ref-poc.bin
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent.tasks import assemble_task
from eval.verify import verify_final


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task-id", required=True)
    ap.add_argument("--poc", required=True)
    ap.add_argument("--server", default="http://127.0.0.1:8666")
    ap.add_argument("--data-dir", default="data")
    args = ap.parse_args(argv)

    poc = Path(args.poc).read_bytes()
    task = assemble_task(args.task_id, args.data_dir, Path("/tmp/selftest_task"), args.server, "level2")
    ver = verify_final(poc, args.task_id, task["agent_id"], task["checksum"], args.server)
    print(ver.as_dict())
    return 0 if ver.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
