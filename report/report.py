"""Generate the CyberGym leaderboard submission report (SUBMISSION.yaml).

Converts a batch run's summary.json + results.jsonl into the exact schema in
CyberGym's SUBMISSION.md. Stdlib-only: a tiny YAML emitter for this fixed shape.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agent.llm import estimate_cost
from agent.config import load_config


def load_records(run_dir: Path) -> tuple[list[dict], dict]:
    summary = json.loads((run_dir / "summary.json").read_text())
    recs = [json.loads(l) for l in (run_dir / "results.jsonl").read_text().splitlines() if l.strip()]
    return recs, summary


def _scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if any(c in s for c in "\n\"':#{}[]"):
        return json.dumps(s)
    return s


def _emit(obj: Any, indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{k}:")
                lines.extend(_emit(v, indent + 1))
            elif isinstance(v, list) and not v:
                lines.append(f"{pad}{k}: []")
            else:
                lines.append(f"{pad}{k}: {_scalar(v)}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                items = list(item.items())
                for idx, (k, v) in enumerate(items):
                    prefix = "- " if idx == 0 else "  "
                    if isinstance(v, (dict, list)) and v:
                        lines.append(f"{pad}{prefix}{k}:")
                        lines.extend(_emit(v, indent + 1))
                    else:
                        lines.append(f"{pad}{prefix}{k}: {_scalar(v)}")
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    return lines


def build_submission(run_dir: Path, *, agent_name: str = "cybergym-agent", link: str = "", category: str = "agent") -> dict:
    recs, summary = load_records(run_dir)
    cfg = load_config()
    n = len(recs)
    success_rate = summary.get("success_rate", 0.0)

    models = []
    for model, usage in summary.get("models", {}).items():
        entry = {
            "name": model,
            "input_tokens": round(usage["input_tokens"] / n) if n else 0,
            "cache_read_tokens": round(usage["cache_read_tokens"] / n) if n else 0,
            "cache_creation_tokens": round(usage["cache_creation_tokens"] / n) if n else 0,
            "output_tokens": round(usage["output_tokens"] / n) if n else 0,
            "time_cost_sec": round(usage["time_cost_sec"] / n, 1) if n else 0.0,
            "llm_requests": round(usage["llm_requests"] / n, 2) if n else 0,
        }
        cost = estimate_cost(
            _UsageProxy(entry),
            cfg.price_per_mtok_in,
            cfg.price_per_mtok_out,
        )
        if cost is not None:
            entry["est_usd_cost"] = round(cost, 4)
        models.append(entry)

    return {
        "agent_name": agent_name,
        "success_rate": success_rate,
        "link": link,
        "category": category,
        "models": models,
    }


class _UsageProxy:
    def __init__(self, d: dict):
        self.__dict__.update(d)
        # attributes used by estimate_cost
        self.input_tokens = d["input_tokens"]
        self.cache_read_tokens = d["cache_read_tokens"]
        self.cache_creation_tokens = d["cache_creation_tokens"]
        self.output_tokens = d["output_tokens"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate SUBMISSION.yaml")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--agent-name", default="cybergym-agent")
    ap.add_argument("--link", default="")
    ap.add_argument("--category", default="agent")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    run_dir = Path(args.run_dir)
    sub = build_submission(run_dir, agent_name=args.agent_name, link=args.link, category=args.category)
    out = Path(args.out) if args.out else run_dir / "SUBMISSION.yaml"
    text = "\n".join(_emit(sub)) + "\n"
    out.write_text(text)
    print(f"wrote {out}")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
