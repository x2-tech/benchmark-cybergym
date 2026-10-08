#!/usr/bin/env python3
"""CyberGym eval dashboard v3 — Level 1 focus.

v3 is built on v2 and keeps v2 untouched (v2 keeps serving on :8081, this one
runs on :8082).

What is different from v2
-------------------------
* **Level 1 is the headline.** The official CyberGym leaderboard only ranks
  level1, so all earlier work (which ran level2) is now a *comparison* group,
  not the score. Runs are bucketed by directory name:

      runs/level1-*        -> group "level1"      (the score)
      every other clean run -> group "level2"      (comparison; the historical
                                                     level2 evaluations live in
                                                     runs/full-v7-*, runs/
                                                     rerun-infra-*, ...)
      runs/poc-extract      -> excluded everywhere (contamination)

* **`success` only, never `solved`.** `success` = PoC crashed the vulnerable
  build AND the fixed build still exited 0.  `solved` only means the vul build
  crashed, which is a false positive. v2 already did this; v3 keeps it and never
  shows a `solved`-based number as a score.

* **Failure buckets are CyberGym-specific**: tool-call budget exhausted /
  stalled / timeout / both_crash / other.

* **The EC2 panel is real machine state**: load average, memory, `df -h /`,
  `docker system df` (image count + total size + reclaimable), and oracle
  :8666 liveness. Running shards are found with `pgrep -f "eval.run"` and their
  `--out-dir` is parsed out (note: the process is `python3 -m eval.run`; matching
  `eval/run.py` finds nothing).

* **One pass over the files.** v2 re-read every `results.jsonl` three or four
  times per page load; v3 reads them once into a cached snapshot (10 s TTL,
  invalidated by file mtime/size) and derives every panel from that.

* **Dataset toggle + comparison block.** `/api/stats?ds=level1` (default),
  `ds=level2`, `ds=all`. The page also always shows a level2 comparison card so
  the level1 score can be read against the historical level2 result.

* Page auto-refreshes every 30 s; UI is Chinese.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RUNS_DIR = Path(os.environ.get("DASH_RUNS_DIR", "/home/ubuntu/Benchmark/runs"))
TASKS_JSON = Path("/home/ubuntu/Benchmark/data-meta/tasks.json")
PORT = int(os.environ.get("DASH_PORT", "8082"))
ORACLE_URL = os.environ.get("DASH_ORACLE_URL", "http://127.0.0.1:8666/")

_CONTAMINATED_RUNS = {"poc-extract"}

GROUP_LEVEL1 = "level1"
GROUP_LEVEL2 = "level2"

_ALL_TASKS: int | None = None

# v3 buckets, in display order.
FAIL_BUCKETS = ["tool-call budget 耗尽", "stalled（空响应）", "timeout", "both_crash",
                "仅 vul 崩溃（误报）", "其他"]


# --------------------------------------------------------------------------
# task inventory
# --------------------------------------------------------------------------
def _all_tasks_count() -> int:
    global _ALL_TASKS
    if _ALL_TASKS is None:
        try:
            _ALL_TASKS = len(json.loads(TASKS_JSON.read_text()))
        except Exception:
            _ALL_TASKS = 0
    return _ALL_TASKS


def _level_of(name: str) -> str:
    """Bucket a run directory name into a comparison group."""
    if name in _CONTAMINATED_RUNS:
        return "contaminated"
    if name.startswith("level1"):
        return GROUP_LEVEL1
    # Historical level2 evaluations (full-v7-*, rerun-infra-*, ...) plus any
    # explicit runs/level2-* dir.
    return GROUP_LEVEL2


def _is_named_level2(name: str) -> bool:
    return name.startswith("level2")


# --------------------------------------------------------------------------
# snapshot: one read of every results.jsonl, cached briefly
# --------------------------------------------------------------------------
_SNAP: dict = {"t": 0.0, "sig": None, "data": None}


def _snapshot() -> dict[str, dict[str, dict]]:
    """{run_name: {task_id: record}} for every run with a results.jsonl."""
    if not RUNS_DIR.exists():
        return {}
    files: list[Path] = []
    sig: list[tuple] = []
    for d in sorted(RUNS_DIR.iterdir()):
        f = d / "results.jsonl"
        try:
            st = f.stat()
        except OSError:
            continue
        files.append(f)
        sig.append((d.name, st.st_mtime, st.st_size))
    sig_t = tuple(sig)
    now = time.monotonic()
    if _SNAP["data"] is not None and _SNAP["sig"] == sig_t and now - _SNAP["t"] < 10:
        return _SNAP["data"]
    data: dict[str, dict[str, dict]] = {}
    for f in files:
        data[f.parent.name] = _read_run(f)
    _SNAP.update(t=now, sig=sig_t, data=data)
    return data


def _read_run(path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        tid = r.get("task_id")
        if tid:
            out[tid] = r
    return out


def _mtime(name: str) -> float:
    """results.jsonl mtime, falling back to the run directory's own mtime."""
    for p in (RUNS_DIR / name / "results.jsonl", RUNS_DIR / name):
        try:
            return p.stat().st_mtime
        except OSError:
            continue
    return 0.0


# --------------------------------------------------------------------------
# stats
# --------------------------------------------------------------------------
def _classify(err: str) -> str:
    """v3 failure buckets (index into FAIL_BUCKETS)."""
    e = (err or "").lower()
    if not e.strip():
        return "其他"
    if "both_crash" in e or "both crash" in e or "both builds crash" in e:
        return "both_crash"
    if "budget exhausted" in e or "tool-call budget" in e or "branch exhausted" in e:
        return "tool-call budget 耗尽"
    if "stalled" in e:
        return "stalled（空响应）"
    if "timed out" in e or "timeouterror" in e or "timeout" in e:
        return "timeout"
    return "其他"


def _classify_detail(err: str) -> str:
    """Finer label used in the 'other' breakdown."""
    e = err or ""
    if "402" in e:
        return "余额不足 (402)"
    if "No space" in e:
        return "磁盘写满"
    if "IncompleteRead" in e or "RemoteDisconnected" in e or "transport error" in e:
        return "API 传输错误"
    if "FileNotFoundError" in e:
        return "文件缺失"
    if "PermissionError" in e:
        return "权限错误"
    if "llm error" in e:
        return "LLM 错误"
    if not e.strip():
        return "(无错误信息)"
    return e[:60]


def _run_rows(records_by_run: dict, group: str, live: set[str]) -> list[dict]:
    rows: list[dict] = []
    for name, records in records_by_run.items():
        if _level_of(name) != group:
            continue
        if not records and name not in live:
            # A run dir with no results.jsonl that is not currently running
            # contributes nothing.
            continue
        ok = [r for r in records.values() if r.get("success") is True]
        vul_only = [r for r in records.values()
                    if r.get("solved") is True and r.get("success") is not True]
        failed = [r for r in records.values()
                  if r.get("success") is not True and r.get("solved") is not True]
        times = [r["wall_sec"] for r in records.values()
                 if isinstance(r.get("wall_sec"), (int, float))]
        errors: Counter = Counter()
        for r in records.values():
            if r.get("success") is not True:
                errors[_classify(r.get("error", ""))] += 1
        finished = [r.get("finished_at", "") for r in records.values() if r.get("finished_at")]
        mt = _mtime(name)
        active = name in live or (time.time() - mt) < 900
        rows.append({
            "run": name,
            "group": group,
            "named_level2": _is_named_level2(name),
            "attempted": len(records),
            "success": len(ok),
            "crashed_vul": len(vul_only),
            "failed": len(failed),
            "rate": round(100 * len(ok) / len(records), 1) if records else 0.0,
            "avg_wall_sec": round(sum(times) / len(times), 1) if times else 0,
            "total_wall_sec": round(sum(times), 0) if times else 0,
            "top_errors": errors.most_common(3),
            "first_finish": min(finished) if finished else "",
            "last_finish": max(finished) if finished else "",
            "mtime": mt,
            "active": active,
            "contaminated": _level_of(name) == "contaminated",
        })
    rows.sort(key=lambda r: r["mtime"], reverse=True)
    return rows


def _dedup(records_by_run: dict, group: str) -> dict:
    """Deduplicated honest totals for a group."""
    success: set[str] = set()
    attempted: set[str] = set()
    vul_only: set[str] = set()
    runs = 0
    for name, records in records_by_run.items():
        if _level_of(name) != group:
            continue
        if not records:
            continue
        runs += 1
        for tid, r in records.items():
            attempted.add(tid)
            if r.get("success") is True:
                success.add(tid)
            elif r.get("solved") is True:
                vul_only.add(tid)
    vul_only -= success
    total = _all_tasks_count()
    n_succ, n_att = len(success), len(attempted)
    return {
        "group": group,
        "runs": runs,
        "attempted": n_att,
        "success": n_succ,
        "crashed_vul": len(vul_only),
        "failed": max(0, n_att - n_succ - len(vul_only)),
        "never_attempted": max(0, total - n_att) if total else 0,
        "tasks": total,
        "rate_total": round(100 * n_succ / total, 2) if total else 0.0,
        "rate_attempted": round(100 * n_succ / n_att, 1) if n_att else 0.0,
    }


def _failure_breakdown(records_by_run: dict, group: str) -> tuple[list, list]:
    buckets: Counter = Counter()
    details: Counter = Counter()
    for name, records in records_by_run.items():
        if _level_of(name) != group:
            continue
        for r in records.values():
            if r.get("success") is True:
                continue
            if r.get("solved") is True:
                # Crashed the vul build only: a false positive, not a solve,
                # and it carries no error string -- keep it out of "其他".
                buckets["仅 vul 崩溃（误报）"] += 1
                continue
            err = r.get("error", "")
            b = _classify(err)
            buckets[b] += 1
            if b == "其他":
                details[_classify_detail(err)] += 1
    out = []
    for b in FAIL_BUCKETS:
        if buckets.get(b):
            out.append((b, buckets[b]))
    for b, n in buckets.items():
        if b not in FAIL_BUCKETS:
            out.append((b, n))
    out.sort(key=lambda kv: kv[1], reverse=True)
    return out, details.most_common(8)


def _timeline(records_by_run: dict, group: str) -> list[dict]:
    """Cumulative success curve, deduplicated per task with sticky success."""
    events: list[tuple[str, str, bool]] = []
    for name, records in records_by_run.items():
        if _level_of(name) != group:
            continue
        f = RUNS_DIR / name / "results.jsonl"
        try:
            fallback_ts = datetime.fromtimestamp(
                f.stat().st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
        except OSError:
            fallback_ts = ""
        for tid, r in records.items():
            ts = r.get("finished_at", "") or fallback_ts
            if ts and tid:
                events.append((ts, tid, r.get("success") is True))
    if not events:
        return []
    events.sort(key=lambda x: x[0])

    first_seen: dict[str, int] = {}
    deduped: list[tuple[str, bool]] = []
    for ts, tid, ok in events:
        if tid not in first_seen:
            first_seen[tid] = len(deduped)
            deduped.append((ts, ok))
        elif ok and not deduped[first_seen[tid]][1]:
            idx = first_seen[tid]
            deduped[idx] = (deduped[idx][0], True)
    deduped.sort(key=lambda x: x[0])

    bucket_sec = 300
    out: list[dict] = []
    cum_success = 0
    cum_total = 0
    all_t = _all_tasks_count() or 1
    i = 0
    while i < len(deduped):
        try:
            t0 = datetime.fromisoformat(deduped[i][0])
        except ValueError:
            i += 1
            continue
        bucket_end = t0.timestamp() + bucket_sec
        while i < len(deduped):
            try:
                t = datetime.fromisoformat(deduped[i][0])
            except ValueError:
                i += 1
                continue
            if t.timestamp() > bucket_end:
                break
            cum_total += 1
            if deduped[i][1]:
                cum_success += 1
            i += 1
        out.append({
            "t": t0.isoformat(timespec="seconds"),
            "success": cum_success,
            "total": cum_total,
            "rate": round(100 * cum_success / cum_total, 1) if cum_total else 0,
            "overall": round(100 * cum_success / all_t, 2),
        })
    return out


def _recent(records_by_run: dict, group: str, limit: int = 400) -> list[dict]:
    recs: list[dict] = []
    for name, records in records_by_run.items():
        if _level_of(name) != group:
            continue
        for r in records.values():
            r = dict(r)
            r["_run"] = name
            recs.append(r)
    recs.sort(key=lambda r: r.get("finished_at", ""), reverse=True)
    return [{
        "task_id": r.get("task_id"),
        "project": r.get("project"),
        "run": r.get("_run", ""),
        "success": r.get("success") is True,
        "solved": r.get("solved") is True,
        "steps": r.get("steps"),
        "wall_sec": r.get("wall_sec"),
        "finished_at": r.get("finished_at"),
        "error": (r.get("error") or "")[:80],
        "error_class": _classify(r.get("error", "")) if r.get("success") is not True else "",
        "vul_exit_code": r.get("vul_exit_code"),
        "fix_exit_code": r.get("fix_exit_code"),
        "crash_matches_description": r.get("crash_matches_description"),
    } for r in recs[:limit]]


# --------------------------------------------------------------------------
# machine state
# --------------------------------------------------------------------------
def _loadavg() -> dict:
    try:
        one, five, fifteen = os.getloadavg()
    except OSError:
        return {}
    return {"load1": round(one, 2), "load5": round(five, 2), "load15": round(fifteen, 2),
            "cpus": os.cpu_count() or 0}


def _mem() -> dict:
    try:
        info = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":")
            info[k] = int(v.split()[0])
        total = info.get("MemTotal", 0) / 1e6
        avail = info.get("MemAvailable", 0) / 1e6
        return {"total_gb": round(total, 1), "avail_gb": round(avail, 1),
                "used_pct": round(100 * (total - avail) / total, 1) if total else 0}
    except Exception:
        return {}


def _df() -> dict:
    try:
        u = shutil.disk_usage("/")
        return {"size_gb": round(u.total / 1e9, 1),
                "used_gb": round(u.used / 1e9, 1),
                "free_gb": round(u.free / 1e9, 1),
                "pct": round(100 * u.used / u.total, 1)}
    except Exception:
        return {}


def _human_to_gb(s: str) -> float | None:
    s = (s or "").strip().split(" ")[0]  # drop "(10%)"
    m = re.match(r"^([\d.]+)\s*([kKMGT]?B)$", s)
    if not m:
        return None
    v = float(m.group(1))
    mult = {"B": 1e-9, "KB": 1e-6, "MB": 1e-3, "GB": 1.0, "TB": 1e3}[m.group(2).upper()]
    return round(v * mult, 2)


_DOCKER_CACHE: dict = {"t": 0.0, "v": None, "df_t": 0.0, "df_v": None}


def _docker() -> dict:
    now = time.monotonic()
    if _DOCKER_CACHE["v"] is not None and now - _DOCKER_CACHE["t"] < 45:
        return _DOCKER_CACHE["v"]

    def run(args: list[str]):
        try:
            return subprocess.run(args, capture_output=True, text=True,
                                  timeout=8).stdout.strip()
        except Exception:
            return None

    running = run(["docker", "ps", "-q"])
    allc = run(["docker", "ps", "-aq"])
    imgs = run(["docker", "images", "-q"])
    if running is None and _DOCKER_CACHE["v"] is not None:
        return _DOCKER_CACHE["v"]
    out = {
        "running": len((running or "").split()),
        "containers": len((allc or "").split()),
        "images": len((imgs or "").split()),
    }
    _DOCKER_CACHE.update(t=now, v=out)
    return out


def _docker_df() -> dict:
    """Parse `docker system df` (human readable)."""
    now = time.monotonic()
    if _DOCKER_CACHE["df_v"] is not None and now - _DOCKER_CACHE["df_t"] < 45:
        return _DOCKER_CACHE["df_v"]
    try:
        txt = subprocess.run(["docker", "system", "df"], capture_output=True,
                             text=True, timeout=15).stdout
    except Exception:
        return _DOCKER_CACHE["df_v"] or {}
    out: dict = {}
    for line in txt.splitlines():
        parts = line.split()
        if not parts:
            continue
        head = parts[0]
        if head in ("Images", "Containers") and len(parts) >= 5:
            key = head.lower()
            out[f"{key}_total"] = int(parts[1]) if parts[1].isdigit() else parts[1]
            out[f"{key}_active"] = int(parts[2]) if parts[2].isdigit() else parts[2]
            out[f"{key}_size"] = parts[3]
            out[f"{key}_size_gb"] = _human_to_gb(parts[3])
            out[f"{key}_reclaim"] = parts[4]
            out[f"{key}_reclaim_gb"] = _human_to_gb(parts[4])
    if out:
        _DOCKER_CACHE.update(df_t=now, df_v=out)
    return out


_ORACLE_CACHE: dict = {"t": 0.0, "v": None}


def _oracle() -> dict:
    """Liveness of the CyberGym oracle on :8666."""
    now = time.monotonic()
    if _ORACLE_CACHE["v"] is not None and now - _ORACLE_CACHE["t"] < 20:
        return _ORACLE_CACHE["v"]
    res: dict = {"up": False, "code": None, "detail": ""}
    try:
        s = socket.create_connection(("127.0.0.1", 8666), timeout=1.5)
        s.close()
        res["up"] = True
    except OSError as e:
        res["detail"] = type(e).__name__
    if res["up"]:
        try:
            req = urllib.request.Request(ORACLE_URL, method="GET")
            with urllib.request.urlopen(req, timeout=4) as r:
                res["code"] = r.status
        except urllib.error.HTTPError as e:
            res["code"] = e.code          # e.g. 404 still proves it is serving
        except Exception as e:
            res["detail"] = type(e).__name__
    _ORACLE_CACHE.update(t=now, v=res)
    return res


def _shards() -> list[dict]:
    """Running eval shards. NOTE: the process is `python3 -m eval.run`, so we
    match 'eval.run' with pgrep -f (matching eval/run.py finds nothing)."""
    try:
        r = subprocess.run(["bash", "-c", "pgrep -af 'eval.run' || true"],
                           capture_output=True, text=True, timeout=6)
    except Exception:
        return []
    out: list[dict] = []
    for line in (r.stdout or "").splitlines():
        if "-m eval.run" not in line:
            continue
        m = re.search(r"--out-dir\s+(\S+)", line)
        pid = line.split(None, 1)[0]
        if not pid.isdigit():
            continue
        n_tasks = len(re.findall(r"(?:arvo|oss-fuzz):[0-9A-Za-z_]+", line))
        out.append({
            "pid": int(pid),
            "run": Path(m.group(1)).name if m else "?",
            "out_dir": m.group(1) if m else "?",
            "tasks": n_tasks,
            "elapsed": "",
        })
    if out:
        pids = ",".join(str(s["pid"]) for s in out)
        try:
            ps = subprocess.run(["bash", "-c", f"ps -o pid=,etimes= -p {pids} || true"],
                                capture_output=True, text=True, timeout=6).stdout
            et = {}
            for ln in ps.splitlines():
                p = ln.split()
                if len(p) >= 2 and p[1].isdigit():
                    et[int(p[0])] = int(p[1])
            for s in out:
                secs = et.get(s["pid"])
                if secs is not None:
                    s["elapsed"] = f"{secs // 3600}h{secs % 3600 // 60:02d}m"
        except Exception:
            pass
    out.sort(key=lambda s: s["run"])
    return out


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------
def build_stats(ds: str = GROUP_LEVEL1) -> dict:
    if ds not in (GROUP_LEVEL1, GROUP_LEVEL2, "all"):
        ds = GROUP_LEVEL1
    recs_by_run = _snapshot()
    shards = _shards()
    # Only count a live shard whose out-dir is inside the runs dir we scan
    # (keeps DASH_RUNS_DIR overrides honest).
    live = {s["run"] for s in shards if (RUNS_DIR / s["run"]).is_dir()}
    # A shard that just started has a --out-dir but no results.jsonl yet; give
    # it an (empty) entry so it shows up as a running run with 0 completed.
    view: dict[str, dict] = dict(recs_by_run)
    for n in live:
        view.setdefault(n, {})

    if ds == "all":
        sel = {n: r for n, r in view.items() if _level_of(n) != "contaminated"}
        runs_sel: list[dict] = []
        seen: set[str] = set()
        for g in (GROUP_LEVEL1, GROUP_LEVEL2):
            for row in _run_rows(view, g, live):
                if row["run"] not in seen:
                    seen.add(row["run"])
                    runs_sel.append(row)
        runs_sel.sort(key=lambda r: r["mtime"], reverse=True)
    else:
        sel = {n: r for n, r in view.items() if _level_of(n) == ds}
        runs_sel = _run_rows(view, ds, live)

    kinds, other_details = _failure_breakdown(sel, ds)

    return {
        "ds": ds,
        "runs": runs_sel,
        "level1": _dedup(view, GROUP_LEVEL1),
        "level2": _dedup(view, GROUP_LEVEL2),
        "kinds": kinds,
        "other_details": other_details,
        "timeline": _timeline(sel, ds),
        "recent": _recent(sel, ds),
        "all_tasks": _all_tasks_count(),
        "shards": shards,
        "load": _loadavg(),
        "mem": _mem(),
        "disk": _df(),
        "docker": _docker(),
        "docker_df": _docker_df(),
        "oracle": _oracle(),
        "contaminated_runs": sorted(n for n in recs_by_run if _level_of(n) == "contaminated"),
        "server_now": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


PAGE = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberGym Level 1 仪表盘 v3</title>
<style>
 :root{--bg:#0f1115;--card:#171a21;--card2:#1c2029;--fg:#e6e8ee;--dim:#8b93a7;
   --ok:#3ddc84;--bad:#ff5c5c;--warn:#ffb020;--acc:#4c8dff;--grid:#252a34;--r:10px}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);
      font:13.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
 header{padding:11px 20px;border-bottom:1px solid var(--grid);display:flex;
        align-items:baseline;gap:14px;flex-wrap:wrap}
 h1{font-size:15px;margin:0;letter-spacing:.4px;font-weight:650}
 .muted{color:var(--dim);font-size:11.5px}
 main{padding:14px 20px 24px;display:grid;gap:14px;
      grid-template-columns:repeat(12,minmax(0,1fr))}
 .card{background:var(--card);border:1px solid var(--grid);border-radius:var(--r);
       padding:14px 16px;display:flex;flex-direction:column;min-width:0}
 .card h2{font-size:10.5px;margin:0 0 10px;color:var(--dim);text-transform:uppercase;
          letter-spacing:1.1px;font-weight:650}
 .span3{grid-column:span 3}.span4{grid-column:span 4}.span6{grid-column:span 6}
 .span8{grid-column:span 8}.span12{grid-column:span 12}
 @media(max-width:1180px){.span3,.span4{grid-column:span 6}
   .span6,.span8{grid-column:span 12}}
 @media(max-width:760px){main{padding:12px}
   .span3,.span4,.span6,.span8{grid-column:span 12}}
 .big{font-size:clamp(30px,3.4vw,42px);font-weight:700;line-height:1;letter-spacing:-.5px}
 .sub{font-size:12.5px;margin-top:6px}
 .bar{height:7px;background:#232833;border-radius:4px;overflow:hidden;margin:11px 0 7px}
 .bar>i{display:block;height:100%;background:var(--ok);transition:width .5s}
 .row{display:flex;justify-content:space-between;gap:12px;padding:4px 0;
      border-bottom:1px solid #1d2129;font-size:12.5px}
 .row:last-child{border-bottom:0}
 .k{color:var(--dim)}
 .ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.acc{color:var(--acc)}
 table{width:100%;border-collapse:collapse;font-size:12.5px}
 th{position:sticky;top:0;background:var(--card);text-align:left;color:var(--dim);
    font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.8px;
    padding:0 6px 6px 0;border-bottom:1px solid var(--grid)}
 td{padding:4px 6px 4px 0;border-bottom:1px solid #1d2129;white-space:nowrap;
    overflow:hidden;text-overflow:ellipsis;max-width:1px}
 td.num,th.num{text-align:right;width:1%;padding-right:0}
 .pill{display:inline-block;padding:1px 6px;border-radius:20px;font-size:10.5px;
       font-weight:600;margin-right:6px}
 .pill.ok{background:rgba(61,220,132,.14);color:var(--ok)}
 .pill.bad{background:rgba(255,92,92,.14);color:var(--bad)}
 .pill.vul{background:rgba(255,176,32,.14);color:var(--warn)}
 .pill.dim{background:rgba(139,147,167,.14);color:var(--dim)}
 .note{background:rgba(255,176,32,.08);border:1px solid rgba(255,176,32,.3);
       border-radius:7px;padding:9px 11px;font-size:12px;line-height:1.5;
       color:#f0d9a8;margin-bottom:10px}
 .live{display:inline-block;width:7px;height:7px;border-radius:50%;
       background:var(--ok);margin-right:5px;animation:p 1.4s infinite}
 @keyframes p{0%,100%{opacity:1}50%{opacity:.25}}
 .pbar-wrap{margin-top:14px}
 .pbar{display:flex;height:14px;background:#232833;border-radius:7px;
       overflow:hidden;border:1px solid var(--grid)}
 .pbar>i{display:block;height:100%;transition:width .6s ease}
 .seg-done{background:var(--ok)}
 .seg-vul{background:var(--warn);opacity:.85}
 .seg-fail{background:var(--bad);opacity:.85}
 .pbar-label{display:flex;justify-content:space-between;gap:12px;
             margin-top:7px;font-size:12.5px;flex-wrap:wrap}
 .swatch{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px}
 .chartwrap{min-height:220px;width:100%}
 #chart{width:100%;height:100%;display:block}
 .legend{display:flex;gap:14px;font-size:11.5px;color:var(--dim);
         margin-top:8px;flex-wrap:wrap}
 .legend i{display:inline-block;width:9px;height:9px;border-radius:2px;
           margin-right:5px;vertical-align:middle}
 #tip{position:fixed;pointer-events:none;background:#0b0d11;border:1px solid var(--grid);
      border-radius:6px;padding:6px 9px;font-size:12px;display:none;z-index:9;
      box-shadow:0 6px 20px rgba(0,0,0,.5);line-height:1.45}
 .pagi{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:12px}
 .pagi button{background:var(--card2);border:1px solid var(--grid);color:var(--fg);
              border-radius:5px;padding:4px 10px;cursor:pointer;font-size:12px;
              font-family:inherit}
 .pagi button:hover{background:#252a34}
 .pagi button:disabled{opacity:.35;cursor:default}
 .pagi .info{color:var(--dim)}
 .kv{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:auto}
 .kv>div{background:var(--card2);border-radius:7px;padding:8px 10px;min-width:0}
 .kv .k{display:block;margin-bottom:2px}
 .kv b{font-size:15px}
 .honest-big{font-size:clamp(24px,2.8vw,36px);font-weight:700;line-height:1;letter-spacing:-.4px}
 .tabs{display:flex;gap:6px;margin-left:auto}
 .tabs button{background:var(--card2);border:1px solid var(--grid);color:var(--dim);
   border-radius:6px;padding:5px 12px;cursor:pointer;font-size:12px;font-family:inherit}
 .tabs button:hover{color:var(--fg)}
 .tabs button.on{background:rgba(76,141,255,.16);border-color:rgba(76,141,255,.5);color:var(--fg)}
 .ok-dot{color:var(--ok)}.bad-dot{color:var(--bad)}
</style></head><body>
<header>
  <h1>CyberGym <span class="acc">Level 1</span> 仪表盘 <span class="muted">v3 · 诚实指标 success</span></h1>
  <span class="muted" id="ts">加载中...</span>
  <span class="muted" id="livebar"></span>
  <div class="tabs">
    <button id="tab-level1" class="on" data-ds="level1">Level 1（榜单）</button>
    <button id="tab-level2" data-ds="level2">Level 2 对照</button>
    <button id="tab-all" data-ds="all">全部</button>
  </div>
</header>
<main>
  <div class="card span3">
    <h2 id="ov-name">Level 1 总览</h2>
    <div class="big ok" id="l1-rate">-</div>
    <div class="bar"><i id="l1-bar" style="width:0"></i></div>
    <div class="sub" id="l1-counts">-</div>
    <div class="row" style="margin-top:10px"><span class="k">已尝试</span><span id="l1-att">-</span></div>
    <div class="row"><span class="k">从未尝试</span><span id="l1-never">-</span></div>
    <div class="row"><span class="k">仅 vul 崩溃（弱指标，非成功）</span><span class="warn" id="l1-vul">-</span></div>
    <div class="row"><span class="k">失败</span><span class="bad" id="l1-fail">-</span></div>
  </div>

  <div class="card span3">
    <h2>Level 2 对照（历史批次）</h2>
    <div class="honest-big warn" id="l2-rate">-</div>
    <div class="bar"><i id="l2-bar" style="width:0;background:var(--warn)"></i></div>
    <div class="sub" id="l2-counts">-</div>
    <div class="row" style="margin-top:10px"><span class="k">已尝试</span><span id="l2-att">-</span></div>
    <div class="row"><span class="k">从未尝试</span><span id="l2-never">-</span></div>
    <div class="row"><span class="k">对照 run 数</span><span id="l2-runs">-</span></div>
    <div class="row"><span class="k">分母</span><span id="l2-denom">-</span></div>
  </div>

  <div class="card span3">
    <h2>EC2 性能</h2>
    <div class="row"><span class="k">CPU load 1/5/15</span><span id="load">-</span></div>
    <div class="row"><span class="k">内存可用</span><span id="mem">-</span></div>
    <div class="row"><span class="k">磁盘 / (df -h)</span><span id="disk">-</span></div>
    <div class="row"><span class="k">docker 镜像数</span><span id="dk-imgs">-</span></div>
    <div class="row"><span class="k">镜像总占用</span><span id="dk-size">-</span></div>
    <div class="row"><span class="k">可回收空间</span><span id="dk-reclaim">-</span></div>
    <div class="row"><span class="k">容器 运行/全部</span><span id="dk-ct">-</span></div>
    <div class="row"><span class="k">oracle :8666</span><span id="oracle">-</span></div>
  </div>

  <div class="card span3">
    <h2>失败分类 <span class="muted" id="kindsof"></span></h2>
    <table id="kinds"></table>
    <h2 style="margin-top:12px">“其他”明细</h2>
    <table id="kinds-other"></table>
  </div>

  <div class="card span12">
    <h2>运行中的 shard（pgrep -f "eval.run"）</h2>
    <table id="shards"></table>
  </div>

  <div class="card span12">
    <h2>进度时间线 <span class="muted" id="tl-ds"></span></h2>
    <div class="chartwrap"><svg id="chart"></svg></div>
    <div class="legend">
      <span><i style="background:#3ddc84"></i>累计成功</span>
      <span><i style="background:#4c8dff"></i>累计尝试</span>
      <span><i style="background:#ffb020"></i>成功率 %（占已尝试）</span>
      <span><i style="background:#e040fb"></i>总体成功率 %（占 1507）</span>
      <span id="chartmeta"></span>
    </div>
    <div class="pbar-wrap">
      <div class="pbar">
        <i class="seg-done" id="pbar-done" style="width:0"></i>
        <i class="seg-vul" id="pbar-vul" style="width:0"></i>
        <i class="seg-fail" id="pbar-fail" style="width:0"></i>
      </div>
      <div class="pbar-label">
        <span id="pbar-text">-</span>
        <span class="muted">
          <span class="swatch" style="background:#3ddc84"></span>成功
          <span class="swatch" style="background:#ffb020;margin-left:10px"></span>仅 vul 崩溃
          <span class="swatch" style="background:#ff5c5c;margin-left:10px"></span>失败
          <span class="swatch" style="background:#232833;border:1px solid #252a34;margin-left:10px"></span>尚未运行
        </span>
      </div>
    </div>
  </div>

  <div class="card span12">
    <h2>Run 明细（<span class="acc">success</span> 去重前） <span class="muted" id="runsof"></span></h2>
    <div class="note">
      <b>success</b> = PoC 让 vul 构建崩溃 <b>且</b> fix 构建仍以 0 退出（唯一有效成功信号）。
      <b>仅 vul 崩溃</b> 只是让 vul 构建崩溃，属误报，绝不算成功（<code>solved</code> 字段不用于计分）。
      作弊批次 <code>poc-extract</code> 已从所有统计中排除。
    </div>
    <table id="runs"></table>
    <div class="pagi" id="runs-pagi"></div>
  </div>

  <div class="card span12">
    <h2>最近任务 <span class="muted" id="recentof"></span></h2>
    <table id="recent"></table>
    <div class="pagi" id="recent-pagi"></div>
  </div>
</main>
<div id="tip"></div>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const NS = 'http://www.w3.org/2000/svg';
const fmtT = t => t ? new Date(t).toLocaleString('zh-CN', {month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', hour12:false}) : '-';
const fmtFull = t => t ? new Date(t).toLocaleString('zh-CN', {hour12:false}) : '-';

let DS = 'level1';
let runsPage = 0, runsPageSize = 15;
let recentPage = 0, recentPageSize = 30;
let lastTL = null, d_allTasks = 0, lastData = null;

function paginate(arr, page, size) {
  const start = page * size;
  return {items: arr.slice(start, start + size), total: arr.length, pages: Math.max(1, Math.ceil(arr.length / size))};
}
function renderPagi(el, page, pages, total, onPage) {
  if (pages <= 1) { el.innerHTML = ''; return; }
  el.innerHTML = '<button id="'+el.id+'-prev">&laquo; 上一页</button>' +
    '<span class="info">第 ' + (page+1) + ' / ' + pages + ' 页（共 ' + total + ' 条）</span>' +
    '<button id="'+el.id+'-next">下一页 &raquo;</button>';
  const prev = document.getElementById(el.id + '-prev');
  const next = document.getElementById(el.id + '-next');
  prev.disabled = page <= 0;
  next.disabled = page >= pages - 1;
  prev.onclick = () => onPage(Math.max(0, page - 1));
  next.onclick = () => onPage(Math.min(pages - 1, page + 1));
}

function drawChart(tl) {
  const svg = $('chart');
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  if (!tl || tl.length < 2) {
    $('chartmeta').textContent = '暂无历史数据（等待 level1 结果写入）';
    return;
  }
  const box = svg.parentElement.getBoundingClientRect();
  const W = Math.max(300, Math.round(box.width));
  const H = Math.max(180, Math.round(box.height));
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);

  const L=52, R=52, T=12, B=26;
  const iw=Math.max(10,W-L-R), ih=Math.max(10,H-T-B);
  const maxTasks = Math.max(d_allTasks || 10, ...tl.map(d => d.total), ...tl.map(d => d.success), 100);
  const t0=new Date(tl[0].t).getTime(), t1=new Date(tl[tl.length-1].t).getTime();
  const span=Math.max(1,t1-t0);
  const X = t => L+(new Date(t).getTime()-t0)/span*iw;
  const Y = v => T+ih-(v/maxTasks)*ih;
  const Yr = v => T+ih-(v/100)*ih;
  const mk = (n,a) => {const e=document.createElementNS(NS,n); for(const k in a) e.setAttribute(k,a[k]); return e;};

  for (let i=0;i<=4;i++) {
    const y=Y(maxTasks*i/4);
    svg.appendChild(mk('line',{x1:L,y1:y,x2:W-R,y2:y,stroke:'#252a34','stroke-width':1}));
    const tx=mk('text',{x:L-7,y:y+4,fill:'#8b93a7','font-size':11,'text-anchor':'end'});
    tx.textContent=Math.round(maxTasks*i/4); svg.appendChild(tx);
  }
  for (let i=0;i<=4;i++) {
    const y=Yr(100*i/4);
    const tx=mk('text',{x:W-R+7,y:y+4,fill:'#ffb020','font-size':11});
    tx.textContent=(100*i/4)+'%'; svg.appendChild(tx);
  }
  [0,1].forEach(k => {
    const idx = k ? tl.length-1 : 0;
    const tx=mk('text',{x:k?W-R:L, y:H-8, fill:'#8b93a7','font-size':11, 'text-anchor':k?'end':'start'});
    tx.textContent=fmtT(tl[idx].t); svg.appendChild(tx);
  });
  const path = (key,yFn) => tl.map((d,i)=>(i?'L':'M')+X(d.t).toFixed(1)+' '+yFn(d[key]).toFixed(1)).join(' ');
  svg.appendChild(mk('path',{d:path('total',Y),fill:'none',stroke:'#4c8dff','stroke-width':2}));
  svg.appendChild(mk('path',{d:path('success',Y),fill:'none',stroke:'#3ddc84','stroke-width':2}));
  svg.appendChild(mk('path',{d:path('rate',Yr),fill:'none',stroke:'#ffb020','stroke-width':1.5,'stroke-dasharray':'4 3',opacity:.9}));
  svg.appendChild(mk('path',{d:path('overall',Yr),fill:'none',stroke:'#e040fb','stroke-width':2,opacity:.9}));
  $('chartmeta').textContent = tl.length+' 个数据点 | '+fmtT(tl[0].t)+' → '+fmtT(tl[tl.length-1].t);

  const line=mk('line',{y1:T,y2:T+ih,stroke:'#8b93a7','stroke-width':1,opacity:0,'stroke-dasharray':'3 3'});
  svg.appendChild(line);
  const hit=mk('rect',{x:L,y:T,width:iw,height:ih,fill:'transparent'});
  svg.appendChild(hit);
  hit.addEventListener('mousemove', ev => {
    const r=svg.getBoundingClientRect();
    const px=(ev.clientX-r.left)/r.width*W;
    let bi=0,bd=1e9;
    tl.forEach((d,i) => {const dd=Math.abs(X(d.t)-px); if(dd<bd){bd=dd;bi=i;}});
    const d=tl[bi];
    line.setAttribute('x1',X(d.t)); line.setAttribute('x2',X(d.t)); line.setAttribute('opacity',.8);
    const tip=$('tip'); tip.style.display='block';
    tip.style.left=Math.min(ev.clientX+12, innerWidth-190)+'px';
    tip.style.top=(ev.clientY+12)+'px';
    tip.innerHTML=fmtFull(d.t)+'<br>累计成功 <b>'+d.success+'</b><br>累计尝试 <b>'+
      d.total+'</b><br>成功率 <b>'+d.rate+'%</b><br>总体 <b>'+(d.overall||0)+'%</b>';
  });
  hit.addEventListener('mouseleave', () => {line.setAttribute('opacity',0);$('tip').style.display='none';});
}

function renderRuns(d) {
  const p = paginate(d.runs || [], runsPage, runsPageSize);
  $('runs').innerHTML = '<tr><th>run</th><th>状态</th><th class="num">成功</th><th class="num">成功率(已尝试)</th>' +
    '<th class="num">成功率(/1507)</th><th class="num">已完成数</th><th class="num">仅 vul 崩溃</th>' +
    '<th class="num">失败</th><th class="num">平均耗时</th><th>最近完成</th><th>主要失败原因</th></tr>' +
    (p.total ? p.items.map(r => {
      const topErr = (r.top_errors || []).map(e => esc(e[0]) + ' (' + e[1] + ')').join('，');
      const state = r.active ? '<span class="pill ok">运行中</span>' : '<span class="pill dim">已完成</span>';
      const l2 = r.named_level2 ? '' : ' <span class="pill dim">level2 历史</span>';
      return '<tr><td title="' + esc(r.run) + '">' + esc(r.run) + l2 + '</td>' +
        '<td>' + state + '</td>' +
        '<td class="num ok">' + r.success + '</td>' +
        '<td class="num">' + r.rate.toFixed(1) + '%</td>' +
        '<td class="num">' + (100*r.success/(d_allTasks||1507)).toFixed(2) + '%</td>' +
        '<td class="num">' + r.attempted + '</td>' +
        '<td class="num warn">' + r.crashed_vul + '</td>' +
        '<td class="num bad">' + (r.failed || 0) + '</td>' +
        '<td class="num">' + (r.avg_wall_sec || '-') + 's</td>' +
        '<td>' + fmtFull(r.last_finish) + '</td>' +
        '<td title="' + esc(topErr) + '">' + esc(topErr.slice(0, 46)) + '</td></tr>';
    }).join('') : '<tr><td colspan="11" class="muted">暂无 level1 结果。等待 runs/level1-* 写入 results.jsonl。</td></tr>');
  renderPagi($('runs-pagi'), runsPage, p.pages, p.total, pg => { runsPage = pg; renderRuns(d); });
}

function renderRecent(d) {
  const p = paginate(d.recent || [], recentPage, recentPageSize);
  $('recent').innerHTML = '<tr><th>task</th><th>项目</th><th>run</th><th class="num">步数</th>' +
    '<th>完成时间</th><th class="num">耗时</th><th class="num">vul exit</th><th class="num">fix exit</th>' +
    '<th>崩溃匹配</th><th>失败分类</th><th>error</th></tr>' +
    (p.total ? p.items.map(t => {
      const cls = t.success ? 'ok' : t.solved ? 'vul' : 'bad';
      const lbl = t.success ? '成功' : t.solved ? '仅vul' : '失败';
      const cm = t.crash_matches_description === true ? '是' : t.crash_matches_description === false ? '否' : '-';
      return '<tr><td><span class="pill ' + cls + '">' + lbl + '</span>' + esc(t.task_id) + '</td>' +
        '<td>' + esc(t.project || '') + '</td>' +
        '<td>' + esc(t.run || '') + '</td>' +
        '<td class="num">' + (t.steps ?? '-') + '</td>' +
        '<td>' + fmtFull(t.finished_at) + '</td>' +
        '<td class="num">' + (t.wall_sec != null ? Math.round(t.wall_sec) + 's' : '-') + '</td>' +
        '<td class="num">' + (t.vul_exit_code ?? '-') + '</td>' +
        '<td class="num">' + (t.fix_exit_code ?? '-') + '</td>' +
        '<td>' + cm + '</td>' +
        '<td>' + esc(t.error_class || '-') + '</td>' +
        '<td title="' + esc(t.error) + '">' + esc((t.error || '').slice(0, 40)) + '</td></tr>';
    }).join('') : '<tr><td colspan="11" class="muted">暂无数据</td></tr>');
  $('recentof').textContent = '(共 ' + (d.recent || []).length + ' 条，按完成时间倒序)';
  renderPagi($('recent-pagi'), recentPage, p.pages, p.total, pg => { recentPage = pg; renderRecent(d); });
}

function renderShards(d) {
  const sh = d.shards || [];
  $('shards').innerHTML = '<tr><th>run</th><th class="num">PID</th><th class="num">任务数</th>' +
    '<th class="num">已运行</th><th>out-dir</th></tr>' +
    (sh.length ? sh.map(s => '<tr><td class="ok">' + esc(s.run) + '</td>' +
      '<td class="num">' + s.pid + '</td>' +
      '<td class="num">' + s.tasks + '</td>' +
      '<td class="num">' + esc(s.elapsed || '-') + '</td>' +
      '<td title="' + esc(s.out_dir) + '">' + esc(s.out_dir) + '</td></tr>').join('')
      : '<tr><td colspan="5" class="muted">没有正在运行的评测 shard（python3 -m eval.run）</td></tr>');
}

async function tick() {
  try {
    const d = await (await fetch('/api/stats?ds=' + DS, {cache:'no-store'})).json();
    lastData = d;
    d_allTasks = d.all_tasks || 1507;
    $('ts').textContent = '更新于 ' + new Date().toLocaleTimeString('zh-CN', {hour12:false}) + ' · 每 30 秒自动刷新';

    const L1 = d.level1 || {}, L2 = d.level2 || {};
    $('l1-rate').textContent = (L1.rate_total || 0).toFixed(2) + '%';
    $('l1-bar').style.width = Math.min(100, (L1.rate_total || 0)) + '%';
    $('l1-counts').textContent = (L1.success||0) + ' / ' + (L1.tasks||1507) + ' 成功（占 level1 全量）';
    $('l1-att').textContent = (L1.attempted||0) + ' 个任务';
    $('l1-never').textContent = (L1.never_attempted||0) + ' 个任务';
    $('l1-vul').textContent = L1.crashed_vul || 0;
    $('l1-fail').textContent = L1.failed || 0;
    $('ov-name').textContent = 'Level 1 总览（当前视图：' + DS + '）';

    $('l2-rate').textContent = (L2.rate_total || 0).toFixed(2) + '%';
    $('l2-bar').style.width = Math.min(100, (L2.rate_total || 0)) + '%';
    $('l2-counts').textContent = (L2.success||0) + ' / ' + (L2.tasks||1507) + ' 成功 + ' + (L2.crashed_vul||0) + ' 仅 vul 崩溃';
    $('l2-att').textContent = (L2.attempted||0) + ' 个任务';
    $('l2-never').textContent = (L2.never_attempted||0) + ' 个任务';
    $('l2-runs').textContent = L2.runs || 0;
    $('l2-denom').textContent = (L2.tasks||1507) + '（全量任务，level1 与 level2 同集）';

    const LO = d.load || {};
    $('load').textContent = (LO.load1 ?? '-') + ' / ' + (LO.load5 ?? '-') + ' / ' + (LO.load15 ?? '-') +
      (LO.cpus ? '  (' + LO.cpus + ' 核)' : '');
    const M = d.mem || {};
    $('mem').textContent = M.avail_gb != null ? M.avail_gb + ' / ' + M.total_gb + ' GB（已用 ' + M.used_pct + '%）' : '-';
    const DF = d.disk || {};
    $('disk').textContent = DF.free_gb != null ? '可用 ' + DF.free_gb + ' GB / ' + DF.size_gb + ' GB（' + DF.pct + '%）' : '-';
    const D = d.docker || {}, DDF = d.docker_df || {};
    $('dk-imgs').textContent = (DDF.images_total ?? D.images ?? '-') + ' 个（活跃 ' + (DDF.images_active ?? '-') + '）';
    $('dk-size').textContent = DDF.images_size ?? '-';
    $('dk-reclaim').textContent = DDF.images_reclaim ?? '-';
    $('dk-ct').textContent = (D.running ?? '-') + ' / ' + (D.containers ?? '-');
    const OR = d.oracle || {};
    $('oracle').innerHTML = OR.up
      ? '<span class="ok-dot">● 健康</span>' + (OR.code != null ? ' (HTTP ' + OR.code + ')' : ' (端口开放)')
      : '<span class="bad-dot">● 不可达</span>' + (OR.detail ? ' ' + esc(OR.detail) : '');

    $('kindsof').textContent = '（当前视图：' + DS + '）';
    $('kinds').innerHTML = (d.kinds||[]).length
      ? '<tr><th>原因</th><th class="num">n</th></tr>' + d.kinds.map(kv =>
        '<tr><td title="' + esc(kv[0]) + '">' + esc(kv[0]) + '</td><td class="num">' + kv[1] + '</td></tr>').join('')
      : '<tr><td class="muted">暂无失败记录</td></tr>';
    $('kinds-other').innerHTML = (d.other_details||[]).length
      ? '<tr><th>其他明细</th><th class="num">n</th></tr>' + d.other_details.map(kv =>
        '<tr><td title="' + esc(kv[0]) + '">' + esc(kv[0]) + '</td><td class="num">' + kv[1] + '</td></tr>').join('')
      : '<tr><td class="muted">-</td></tr>';

    $('livebar').innerHTML = (d.shards||[]).length
      ? '<span class="live"></span>' + d.shards.length + ' 个 shard 运行中：' + d.shards.map(s => esc(s.run)).join(', ')
      : '<span class="muted">无运行中的 shard</span>';

    $('tl-ds').textContent = '（当前视图：' + DS + '）';
    lastTL = d.timeline;
    drawChart(lastTL);

    const all = d_allTasks || 1507;
    const S = L1;  // progress bar always reflects the Level 1 view (the score)
    const pctDone = (S.success || 0) / all * 100;
    const pctVul = (S.crashed_vul || 0) / all * 100;
    const pctFail = Math.max(0, ((S.attempted || 0) - (S.success || 0) - (S.crashed_vul || 0)) / all * 100);
    $('pbar-done').style.width = pctDone + '%';
    $('pbar-vul').style.width = pctVul + '%';
    $('pbar-fail').style.width = pctFail + '%';
    $('pbar-text').innerHTML = 'Level 1：<b>' + (S.success || 0) + '</b> / <b>' + all +
      '</b> 任务成功（' + pctDone.toFixed(2) + '%）· 已尝试 ' + (S.attempted || 0) + ' · 从未尝试 ' + (S.never_attempted || 0);

    renderShards(d);
    renderRuns(d);
    renderRecent(d);
  } catch(e) { $('ts').textContent = '更新失败：' + e; }
}

document.querySelectorAll('.tabs button').forEach(b => {
  b.onclick = () => {
    document.querySelectorAll('.tabs button').forEach(x => x.classList.remove('on'));
    b.classList.add('on');
    DS = b.dataset.ds;
    runsPage = 0; recentPage = 0;
    tick();
  };
});
tick();
setInterval(tick, 30000);
addEventListener('resize', () => { if (lastTL) drawChart(lastTL); });
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/stats"):
            ds = GROUP_LEVEL1
            m = re.search(r"[?&]ds=([A-Za-z0-9]+)", self.path)
            if m:
                ds = m.group(1)
            body = json.dumps(build_stats(ds)).encode()
            ctype = "application/json"
        else:
            body = PAGE.encode()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"dashboard v3 (level1) on http://0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
