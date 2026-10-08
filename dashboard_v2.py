#!/usr/bin/env python3
"""CyberGym eval dashboard v2 — honest solve tracking.

Differences from v1, all deliberate:

* **`success` is the only success signal.** v1 computed
  `success = bool(r["success"]) or bool(r["solved"])`. `solved` means only that
  the PoC crashed the *vulnerable* build; a task is not solved unless
  `verify_final()` also confirms the *fixed* build still exits 0. OR-ing the two
  counts every vul-only false positive as a win. v2 shows `success` as the
  headline and `crashed_vul` separately, labelled as the weaker signal it is.

* **Every run is reported separately, never merged.** v1 collapsed all
  `runs/*/results.jsonl` into one number keyed by task, "solved wins over
  failure", which made a contaminated run indistinguishable from a clean one.
  v2 keeps per-run rows so the honest harness run can be compared against the
  old contaminated one and the difference is visible rather than averaged away.

* **Contamination is surfaced, not hidden.** Records produced with the
  `/tmp/poc` extraction path are flagged (CyberGym FAQ Q5 names that path as
  leakage), so a run that cheated can never read as a legitimate score.

* **Machine pressure is live.** With several shards running at once the useful
  question is whether the box is actually saturated, so load, memory, docker
  container/image counts and active pulls are polled together.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RUNS_DIR = Path(os.environ.get("DASH_RUNS_DIR", "/home/ubuntu/Benchmark/runs"))
TASKS_JSON = Path("/home/ubuntu/Benchmark/data-meta/tasks.json")
PORT = int(os.environ.get("DASH_PORT", "8081"))

_CONTAMINATED_RUNS = {"ec2-full", "poc-extract", "rerun-fixes", "rerun-fixes-v2",
                      "ec2-wave1", "ec2-wave2"}

_ALL_TASKS: int | None = None


def _all_tasks_count() -> int:
    global _ALL_TASKS
    if _ALL_TASKS is None:
        try:
            _ALL_TASKS = len(json.loads(TASKS_JSON.read_text()))
        except Exception:
            _ALL_TASKS = 0
    return _ALL_TASKS


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


def _run_summary(name: str, records: dict[str, dict], *, finished_only: bool = True) -> dict:
    ok = [r for r in records.values() if r.get("success") is True]
    vul_only = [r for r in records.values()
                if r.get("solved") is True and r.get("success") is not True]
    failed = [r for r in records.values()
              if r.get("success") is not True and r.get("solved") is not True]
    times = [r["wall_sec"] for r in ok if isinstance(r.get("wall_sec"), (int, float))]
    all_times = [r["wall_sec"] for r in records.values() if isinstance(r.get("wall_sec"), (int, float))]
    contaminated = name in _CONTAMINATED_RUNS

    errors: Counter = Counter()
    for r in records.values():
        if r.get("success") is not True:
            errors[_classify(r.get("error", ""))] += 1

    projects: Counter = Counter()
    for r in records.values():
        p = r.get("project", "?")
        projects[p] += 1

    finished_times = [r.get("finished_at", "") for r in records.values() if r.get("finished_at")]
    first_finish = min(finished_times) if finished_times else ""
    last_finish = max(finished_times) if finished_times else ""

    return {
        "run": name,
        "attempted": len(records),
        "success": len(ok),
        "crashed_vul": len(vul_only),
        "failed": len(failed),
        "rate": round(100 * len(ok) / len(records), 1) if records else 0.0,
        "avg_wall_sec": round(sum(times) / len(times), 1) if times else 0,
        "total_wall_sec": round(sum(all_times), 0) if all_times else 0,
        "contaminated": contaminated,
        "active": not finished_only or (time.time() - _mtime(name)) < 900,
        "top_errors": errors.most_common(3),
        "top_projects": projects.most_common(5),
        "first_finish": first_finish,
        "last_finish": last_finish,
    }


def _mtime(name: str) -> float:
    try:
        return (RUNS_DIR / name / "results.jsonl").stat().st_mtime
    except OSError:
        return 0.0


def _all_runs() -> list[dict]:
    if not RUNS_DIR.exists():
        return []
    runs = []
    for d in sorted(RUNS_DIR.iterdir()):
        f = d / "results.jsonl"
        if not f.is_file():
            continue
        recs = _read_run(f)
        if not recs:
            continue
        runs.append(_run_summary(d.name, recs))
    runs.sort(key=lambda r: _mtime(r["run"]), reverse=True)
    return runs


def _honest_total(runs: list[dict]) -> dict:
    clean = [r for r in runs if not r["contaminated"]]
    success_tasks: set[str] = set()
    attempted_tasks: set[str] = set()
    vul_only_tasks: set[str] = set()
    for r in clean:
        recs = _read_run(RUNS_DIR / r["run"] / "results.jsonl")
        for tid, rec in recs.items():
            attempted_tasks.add(tid)
            if rec.get("success") is True:
                success_tasks.add(tid)
            elif rec.get("solved") is True:
                vul_only_tasks.add(tid)
    vul_only_tasks -= success_tasks
    attempted = len(attempted_tasks)
    return {
        "runs": len(clean),
        "attempted": attempted,
        "success": len(success_tasks),
        "crashed_vul": len(vul_only_tasks),
        "tasks": _all_tasks_count(),
        "rate_attempted": round(100 * len(success_tasks) / attempted, 1) if attempted else 0.0,
        "rate_total": round(100 * len(success_tasks) / _all_tasks_count(), 1) if _all_tasks_count() else 0.0,
    }


def _classify(err: str) -> str:
    e = err or ""
    if "402" in e:
        return "balance (402)"
    if "IncompleteRead" in e or "transport error" in e or "connection error" in e:
        return "API transport"
    if "stalled" in e:
        return "stalled (empty resp)"
    if "budget exhausted" in e or "tool-call budget" in e or "branch exhausted" in e:
        return "budget exhausted"
    if "No space" in e:
        return "disk full"
    if "download" in e:
        return "download fail"
    if "timed out" in e or "TimeoutError" in e:
        return "task timeout"
    if "llm error" in e:
        return "llm error"
    if "FileNotFoundError" in e:
        return "file not found"
    if not e.strip():
        return "(no error msg)"
    return e[:48]


def _loadavg() -> dict:
    try:
        one, five, fifteen = os.getloadavg()
    except OSError:
        return {}
    return {"load1": round(one, 2), "load5": round(five, 2), "load15": round(fifteen, 2)}


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
        return {"free_gb": round(u.free / 1e9, 1), "pct": round(100 * u.used / u.total, 1)}
    except Exception:
        return {}


_DOCKER_CACHE: dict = {"t": 0.0, "v": None}


def _docker() -> dict:
    now = time.monotonic()
    if _DOCKER_CACHE["v"] is not None and now - _DOCKER_CACHE["t"] < 45:
        return _DOCKER_CACHE["v"]

    def run(args: list[str]):
        try:
            return subprocess.run(args, capture_output=True, text=True,
                                  timeout=6).stdout.strip()
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


def _procs() -> dict:
    def count(pat: str) -> int:
        try:
            r = subprocess.run(["bash", "-c", f"pgrep -fc '{pat}' || true"],
                               capture_output=True, text=True, timeout=5)
            return int((r.stdout or "0").strip() or 0)
        except Exception:
            return 0
    return {
        "runners": count("eval.run"),
        "pulls": count("docker pull"),
    }


def _timeline_from_runs() -> list[dict]:
    """Build a timeline from all clean run results, bucketed by 5-min intervals."""
    events: list[tuple[str, bool]] = []
    for d in RUNS_DIR.iterdir():
        if d.name in _CONTAMINATED_RUNS:
            continue
        f = d / "results.jsonl"
        if not f.is_file():
            continue
        for line in f.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = r.get("finished_at", "")
            if ts:
                events.append((ts, r.get("success") is True))

    if not events:
        return []

    events.sort(key=lambda x: x[0])

    bucket_sec = 300
    out: list[dict] = []
    cum_success = 0
    cum_total = 0
    i = 0
    while i < len(events):
        try:
            t0 = datetime.fromisoformat(events[i][0])
        except ValueError:
            i += 1
            continue
        bucket_end = t0.timestamp() + bucket_sec
        while i < len(events):
            try:
                t = datetime.fromisoformat(events[i][0])
            except ValueError:
                i += 1
                continue
            if t.timestamp() > bucket_end:
                break
            cum_total += 1
            if events[i][1]:
                cum_success += 1
            i += 1
        rate = round(100 * cum_success / cum_total, 1) if cum_total else 0
        out.append({
            "t": t0.isoformat(timespec="seconds"),
            "success": cum_success,
            "total": cum_total,
            "rate": rate,
        })

    return out


def _all_task_results() -> list[dict]:
    """All task results across all runs, for the Recent Tasks table with full fields."""
    all_recs: list[dict] = []
    for d in sorted(RUNS_DIR.iterdir()):
        f = d / "results.jsonl"
        if not f.is_file():
            continue
        run_name = d.name
        contaminated = run_name in _CONTAMINATED_RUNS
        for line in f.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            r["_run"] = run_name
            r["_contaminated"] = contaminated
            all_recs.append(r)

    all_recs.sort(key=lambda r: r.get("finished_at", ""), reverse=True)
    return all_recs


def build_stats() -> dict:
    runs = _all_runs()
    clean = [r for r in runs if not r["contaminated"]]
    active = [r for r in runs if r["active"]]

    active_clean = sorted([r for r in clean if r["active"]],
                          key=lambda r: r["attempted"], reverse=True)
    headline = (active_clean[0] if active_clean
                else clean[0] if clean
                else active[0] if active
                else (runs[0] if runs else None))

    failed_kinds: Counter = Counter()
    by_project: Counter = Counter()
    if headline:
        recs = _read_run(RUNS_DIR / headline["run"] / "results.jsonl")
        for r in recs.values():
            if r.get("success") is not True:
                failed_kinds[_classify(r.get("error", ""))] += 1
        for r in recs.values():
            if r.get("success") is not True:
                by_project[r.get("project", "?")] += 1

    all_recs = _all_task_results()

    return {
        "headline": headline,
        "active_runs": [r["run"] for r in active],
        "runs": runs,
        "honest": _honest_total(runs),
        "kinds": failed_kinds.most_common(),
        "by_project": by_project.most_common(12),
        "recent_total": len(all_recs),
        "recent": [
            {"task_id": r.get("task_id"), "project": r.get("project"),
             "success": r.get("success") is True, "solved": r.get("solved") is True,
             "steps": r.get("steps"), "wall_sec": r.get("wall_sec"),
             "finished_at": r.get("finished_at"),
             "error": (r.get("error") or "")[:70],
             "run": r.get("_run", ""),
             "contaminated": r.get("_contaminated", False),
             "vul_exit_code": r.get("vul_exit_code"),
             "fix_exit_code": r.get("fix_exit_code"),
             "difficulty": r.get("difficulty", ""),
             "crash_matches_description": r.get("crash_matches_description"),
             }
            for r in all_recs[:500]
        ],
        "timeline": _timeline_from_runs(),
        "load": _loadavg(),
        "mem": _mem(),
        "disk": _df(),
        "docker": _docker(),
        "procs": _procs(),
        "all_tasks": _all_tasks_count(),
        "server_now": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberGym v2 — honest</title>
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
 .note{background:rgba(255,176,32,.08);border:1px solid rgba(255,176,32,.3);
       border-radius:7px;padding:9px 11px;font-size:12px;line-height:1.5;
       color:#f0d9a8;margin-bottom:10px}
 .live{display:inline-block;width:7px;height:7px;border-radius:50%;
       background:var(--ok);margin-right:5px;animation:p 1.4s infinite}
 @keyframes p{0%,100%{opacity:1}50%{opacity:.25}}

 /* Progress bar */
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

 /* Chart */
 .chartwrap{min-height:220px;width:100%}
 #chart{width:100%;height:100%;display:block}
 .legend{display:flex;gap:14px;font-size:11.5px;color:var(--dim);
         margin-top:8px;flex-wrap:wrap}
 .legend i{display:inline-block;width:9px;height:9px;border-radius:2px;
           margin-right:5px;vertical-align:middle}
 #tip{position:fixed;pointer-events:none;background:#0b0d11;border:1px solid var(--grid);
      border-radius:6px;padding:6px 9px;font-size:12px;display:none;z-index:9;
      box-shadow:0 6px 20px rgba(0,0,0,.5);line-height:1.45}

 /* Pagination */
 .pagi{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:12px}
 .pagi button{background:var(--card2);border:1px solid var(--grid);color:var(--fg);
              border-radius:5px;padding:4px 10px;cursor:pointer;font-size:12px;
              font-family:inherit}
 .pagi button:hover{background:#252a34}
 .pagi button:disabled{opacity:.35;cursor:default}
 .pagi .info{color:var(--dim)}

 /* KV grid */
 .kv{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:auto}
 .kv>div{background:var(--card2);border-radius:7px;padding:8px 10px;min-width:0}
 .kv .k{display:block;margin-bottom:2px}
 .kv b{font-size:15px}

 /* Honest totals card */
 .honest-big{font-size:clamp(24px,2.8vw,36px);font-weight:700;line-height:1;letter-spacing:-.4px}
</style></head><body>
<header>
  <h1>CyberGym v2 <span class="muted">honest metric</span></h1>
  <span class="muted" id="ts">loading...</span>
  <span class="muted" id="livebar"></span>
</header>
<main>
  <!-- Row 1: headline cards -->
  <div class="card span3">
    <h2 id="hlname">Current run</h2>
    <div class="big" id="rate">-</div>
    <div class="bar"><i id="ratebar" style="width:0"></i></div>
    <div class="sub" id="counts">-</div>
    <div class="row" style="margin-top:10px"><span class="k">crashed vul only</span><span class="warn" id="vulonly">-</span></div>
    <div class="row"><span class="k">avg wall / success</span><span id="avgwall">-</span></div>
  </div>

  <div class="card span3">
    <h2>Honest totals (deduplicated)</h2>
    <div class="honest-big ok" id="honest-rate">-</div>
    <div class="bar"><i id="honest-bar" style="width:0"></i></div>
    <div class="sub" id="honest-counts">-</div>
    <div class="row" style="margin-top:10px"><span class="k">clean runs</span><span id="honest-runs">-</span></div>
    <div class="row"><span class="k">benchmark total</span><span id="alltasks">-</span></div>
  </div>

  <div class="card span3">
    <h2>Machine pressure</h2>
    <div class="row"><span class="k">load 1 / 5 / 15</span><span id="load">-</span></div>
    <div class="row"><span class="k">memory avail</span><span id="mem">-</span></div>
    <div class="row"><span class="k">containers running</span><span id="ctrun">-</span></div>
    <div class="row"><span class="k">docker images</span><span id="imgs">-</span></div>
    <div class="row"><span class="k">agent runners</span><span id="runners">-</span></div>
    <div class="row"><span class="k">image pulls active</span><span id="pulls">-</span></div>
    <div class="row"><span class="k">disk free</span><span id="disk">-</span></div>
  </div>

  <div class="card span3">
    <h2>Failures by cause <span class="muted" id="kindsof"></span></h2>
    <table id="kinds"></table>
  </div>

  <!-- Row 2: timeline chart + progress bar -->
  <div class="card span12">
    <h2>Progress timeline (honest runs)</h2>
    <div class="chartwrap"><svg id="chart"></svg></div>
    <div class="legend">
      <span><i style="background:#3ddc84"></i>success (cumulative)</span>
      <span><i style="background:#4c8dff"></i>attempted (cumulative)</span>
      <span><i style="background:#ffb020"></i>success rate %</span>
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
          <span class="swatch" style="background:#3ddc84"></span>success
          <span class="swatch" style="background:#ffb020;margin-left:10px"></span>crashed vul only
          <span class="swatch" style="background:#ff5c5c;margin-left:10px"></span>failed
          <span class="swatch" style="background:#232833;border:1px solid #252a34;margin-left:10px"></span>not yet run
        </span>
      </div>
    </div>
  </div>

  <!-- Row 3: runs table -->
  <div class="card span12">
    <h2>Runs - each reported separately, never merged</h2>
    <div class="note">
      <b>success</b> = PoC crashed the vulnerable build AND the fixed build still exits 0.
      <b>crashed vul</b> = crashed the vulnerable build only - a false positive, never a solve.
      Runs marked <b>contaminated</b> used the <code>/tmp/poc</code> extraction path
      (CyberGym FAQ Q5 leakage) and are excluded from the honest totals.
    </div>
    <table id="runs"></table>
    <div class="pagi" id="runs-pagi"></div>
  </div>

  <!-- Row 4: recent tasks + by project -->
  <div class="card span8">
    <h2>Recent tasks <span class="muted" id="recentof"></span></h2>
    <table id="recent"></table>
    <div class="pagi" id="recent-pagi"></div>
  </div>

  <div class="card span4">
    <h2>Not solved, by project</h2>
    <table id="proj"></table>
  </div>
</main>
<div id="tip"></div>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const NS = 'http://www.w3.org/2000/svg';
const fmtT = t => new Date(t).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});

// Pagination state
let runsPage = 0, runsPageSize = 15;
let recentPage = 0, recentPageSize = 30;
let lastData = null;
let lastTL = null;
let d_allTasks = 0;

function paginate(arr, page, size) {
  const start = page * size;
  return {items: arr.slice(start, start + size), total: arr.length, pages: Math.ceil(arr.length / size)};
}

function renderPagi(el, page, pages, total, onPage) {
  if (pages <= 1) { el.innerHTML = ''; return; }
  el.innerHTML = '<button id="'+el.id+'-prev">&laquo; Prev</button>' +
    '<span class="info">Page ' + (page+1) + ' / ' + pages + ' (' + total + ' total)</span>' +
    '<button id="'+el.id+'-next">Next &raquo;</button>';
  const prev = document.getElementById(el.id + '-prev');
  const next = document.getElementById(el.id + '-next');
  prev.disabled = page <= 0;
  next.disabled = page >= pages - 1;
  prev.onclick = () => { onPage(Math.max(0, page - 1)); };
  next.onclick = () => { onPage(Math.min(pages - 1, page + 1)); };
}

function drawChart(tl) {
  const svg = $('chart');
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  if (!tl || tl.length < 2) {
    $('chartmeta').textContent = 'waiting for history...';
    return;
  }
  const box = svg.parentElement.getBoundingClientRect();
  const W = Math.max(300, Math.round(box.width));
  const H = Math.max(180, Math.round(box.height));
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);

  const L=52, R=52, T=12, B=26;
  const iw=Math.max(10,W-L-R), ih=Math.max(10,H-T-B);
  const maxTasks = d_allTasks || Math.max(10, ...tl.map(d => d.total));
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

  $('chartmeta').textContent = tl.length+' pts | '+fmtT(tl[0].t)+' -> '+fmtT(tl[tl.length-1].t);

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
    tip.style.left=Math.min(ev.clientX+12, innerWidth-170)+'px';
    tip.style.top=(ev.clientY+12)+'px';
    tip.innerHTML=fmtT(d.t)+'<br>success <b>'+d.success+'</b><br>attempted <b>'+
      d.total+'</b><br>rate <b>'+d.rate+'%</b>';
  });
  hit.addEventListener('mouseleave', () => {line.setAttribute('opacity',0);$('tip').style.display='none';});
}

function renderRuns(d) {
  const p = paginate(d.runs || [], runsPage, runsPageSize);
  $('runs').innerHTML = '<tr><th>run</th><th class="num">success</th><th class="num">rate</th>' +
    '<th class="num">crashed vul</th><th class="num">failed</th><th class="num">attempted</th>' +
    '<th class="num">avg wall</th><th class="num">total wall</th>' +
    '<th>first finish</th><th>last finish</th><th>top errors</th><th>state</th></tr>' +
    p.items.map(r => {
      const topErr = (r.top_errors || []).map(e => esc(e[0]) + ' (' + e[1] + ')').join(', ');
      return '<tr><td>' + esc(r.run) + '</td>' +
        '<td class="num ' + (r.contaminated?'':'ok') + '">' + r.success + '</td>' +
        '<td class="num">' + r.rate.toFixed(1) + '%</td>' +
        '<td class="num warn">' + r.crashed_vul + '</td>' +
        '<td class="num bad">' + (r.failed || 0) + '</td>' +
        '<td class="num">' + r.attempted + '</td>' +
        '<td class="num">' + (r.avg_wall_sec || '-') + 's</td>' +
        '<td class="num">' + (r.total_wall_sec ? Math.round(r.total_wall_sec/60) + 'm' : '-') + '</td>' +
        '<td>' + (r.first_finish ? fmtT(r.first_finish) : '-') + '</td>' +
        '<td>' + (r.last_finish ? fmtT(r.last_finish) : '-') + '</td>' +
        '<td title="' + esc(topErr) + '">' + esc(topErr.slice(0, 50)) + '</td>' +
        '<td>' + (r.contaminated ? '<span class="pill bad">contaminated</span>' : '') +
                 (r.active ? '<span class="pill ok">active</span>' : '') + '</td></tr>';
    }).join('');
  renderPagi($('runs-pagi'), runsPage, p.pages, p.total, pg => { runsPage = pg; renderRuns(d); });
}

function renderRecent(d) {
  const p = paginate(d.recent || [], recentPage, recentPageSize);
  $('recent').innerHTML = '<tr><th>task</th><th>project</th><th>run</th><th class="num">steps</th>' +
    '<th>finished</th><th class="num">wall</th><th class="num">vul exit</th><th class="num">fix exit</th>' +
    '<th>crash match</th><th>error</th></tr>' +
    p.items.map(t => {
      const cls = t.success ? 'ok' : t.solved ? 'vul' : 'bad';
      const lbl = t.success ? 'SOLVED' : t.solved ? 'VUL-ONLY' : 'FAIL';
      const cm = t.crash_matches_description === true ? 'yes' : t.crash_matches_description === false ? 'no' : '-';
      return '<tr><td><span class="pill ' + cls + '">' + lbl + '</span>' + esc(t.task_id) + '</td>' +
        '<td>' + esc(t.project || '') + '</td>' +
        '<td>' + esc(t.run || '') + (t.contaminated ? ' <span class="pill bad">C</span>' : '') + '</td>' +
        '<td class="num">' + (t.steps ?? '-') + '</td>' +
        '<td>' + (t.finished_at ? new Date(t.finished_at).toLocaleTimeString() : '-') + '</td>' +
        '<td class="num">' + (t.wall_sec != null ? Math.round(t.wall_sec) + 's' : '-') + '</td>' +
        '<td class="num">' + (t.vul_exit_code ?? '-') + '</td>' +
        '<td class="num">' + (t.fix_exit_code ?? '-') + '</td>' +
        '<td>' + cm + '</td>' +
        '<td title="' + esc(t.error) + '">' + esc((t.error || '').slice(0, 46)) + '</td></tr>';
    }).join('');
  $('recentof').textContent = '(' + (d.recent_total || 0) + ' total)';
  renderPagi($('recent-pagi'), recentPage, p.pages, p.total, pg => { recentPage = pg; renderRecent(d); });
}

async function tick() {
  try {
    const d = await (await fetch('/api/stats', {cache:'no-store'})).json();
    lastData = d;
    $('ts').textContent = 'updated ' + new Date().toLocaleTimeString();
    const h = d.headline;
    if (h) {
      $('hlname').textContent = 'Current run - ' + h.run + (h.contaminated ? '  (CONTAMINATED)' : '');
      $('rate').textContent = h.rate.toFixed(1) + '%';
      $('rate').className = 'big ' + (h.contaminated ? 'bad' : h.rate >= 50 ? 'ok' : h.rate >= 25 ? 'warn' : 'bad');
      $('ratebar').style.width = Math.min(100, h.rate) + '%';
      $('ratebar').style.background = h.contaminated ? 'var(--bad)' : 'var(--ok)';
      $('counts').textContent = h.success + ' success / ' + h.attempted + ' attempted';
      $('vulonly').textContent = h.crashed_vul;
      $('avgwall').textContent = (h.avg_wall_sec || 0) + 's';
    }

    // Honest totals
    const hon = d.honest || {};
    const honRateAttempted = hon.rate_attempted || 0;
    const honRateTotal = hon.rate_total || 0;
    $('honest-rate').textContent = honRateAttempted.toFixed(1) + '%';
    $('honest-bar').style.width = Math.min(100, honRateAttempted) + '%';
    $('honest-counts').textContent = hon.success + ' solved / ' + hon.attempted +
      ' attempted (' + honRateTotal.toFixed(1) + '% of ' + hon.tasks + ' total)';
    if (hon.crashed_vul) $('honest-counts').textContent += ' + ' + hon.crashed_vul + ' vul-only';
    $('honest-runs').textContent = hon.runs;
    $('alltasks').textContent = d.all_tasks;

    // Machine pressure
    const L = d.load || {};
    $('load').textContent = (L.load1 ?? '-') + ' / ' + (L.load5 ?? '-') + ' / ' + (L.load15 ?? '-');
    const M = d.mem || {};
    $('mem').textContent = M.avail_gb != null ? M.avail_gb + ' GB / ' + M.total_gb + ' GB (' + M.used_pct + '%)' : '-';
    const D = d.docker || {}, P = d.procs || {};
    $('ctrun').textContent = D.running ?? '-';
    $('imgs').textContent = D.images ?? '-';
    $('runners').textContent = P.runners ?? '-';
    $('pulls').textContent = P.pulls ?? '-';
    $('disk').textContent = d.disk && d.disk.free_gb != null ? d.disk.free_gb + ' GB (' + d.disk.pct + '%)' : '-';
    $('livebar').innerHTML = (d.active_runs||[]).length
      ? '<span class="live"></span>active: ' + d.active_runs.join(', ')
      : '<span class="muted">no run written in the last 15 min</span>';

    // Failure chart
    $('kinds').innerHTML = (d.kinds||[]).length
      ? '<tr><th>cause</th><th class="num">n</th></tr>' + d.kinds.map(function(kv) {
        return '<tr><td title="' + esc(kv[0]) + '">' + esc(kv[0]) + '</td><td class="num">' + kv[1] + '</td></tr>';
      }).join('')
      : '<tr><td class="muted">none</td></tr>';
    $('kindsof').textContent = h ? '(' + h.run + ')' : '';

    // By project
    $('proj').innerHTML = (d.by_project||[]).length
      ? '<tr><th>project</th><th class="num">n</th></tr>' + d.by_project.map(function(kv) {
        return '<tr><td>' + esc(kv[0]) + '</td><td class="num">' + kv[1] + '</td></tr>';
      }).join('')
      : '<tr><td class="muted">none</td></tr>';

    // Timeline chart
    d_allTasks = d.all_tasks || 0;
    lastTL = d.timeline;
    drawChart(lastTL);

    // Progress bar
    const all = d.all_tasks || 1;
    const honS = (hon.success || 0);
    // For progress bar, sum across all clean runs
    let totalAttempted = 0, totalVul = 0;
    (d.runs || []).filter(function(r) { return !r.contaminated; }).forEach(function(r) {
      totalAttempted += r.attempted;
      totalVul += r.crashed_vul;
    });
    const pctDone = honS / all * 100;
    const pctVul = totalVul / all * 100;
    const pctFail = Math.max(0, (totalAttempted - honS - totalVul) / all * 100);
    $('pbar-done').style.width = pctDone + '%';
    $('pbar-vul').style.width = pctVul + '%';
    $('pbar-fail').style.width = pctFail + '%';
    $('pbar-text').innerHTML = '<b>' + honS + '</b> of <b>' + all +
      '</b> tasks solved (' + pctDone.toFixed(1) + '%)';

    // Paginated tables
    renderRuns(d);
    renderRecent(d);
  } catch(e) { $('ts').textContent = 'update failed: ' + e; }
}
tick();
setInterval(tick, 5000);
addEventListener('resize', function() { if (lastTL) drawChart(lastTL); });
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/stats"):
            body = json.dumps(build_stats()).encode()
            ctype = "application/json"
        else:
            body = PAGE.encode()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"dashboard v2 on http://0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
