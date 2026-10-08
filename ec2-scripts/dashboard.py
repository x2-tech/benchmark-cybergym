#!/usr/bin/env python3
"""CyberGym eval dashboard — live view + timeline history of the EC2 batch run.

Serves a self-refreshing HTML page on :8080 plus a JSON API at /api/stats.
Read-only: reads results.jsonl, the runner status log and docker/OS counters.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RESULTS_FILE = Path("/home/ubuntu/Benchmark/runs/ec2-full/results.jsonl")
STATUS_LOG = Path("/tmp/eval_status.log")
TASKS_JSON = Path("/home/ubuntu/Benchmark/data-meta/tasks.json")
PORT = int(os.environ.get("DASH_PORT", "8080"))

_ALL_TASKS: int | None = None


def _all_tasks_count() -> int:
    """Total tasks in the benchmark — the denominator for the progress bar."""
    global _ALL_TASKS
    if _ALL_TASKS is None:
        try:
            _ALL_TASKS = len(json.loads(TASKS_JSON.read_text()))
        except Exception:
            _ALL_TASKS = 0
    return _ALL_TASKS

# STATUS lines look like:
#   [2026-09-15 08:44:59] STATUS: 323/332 = 97.3% | avail=112 waves=4/10 ...
_STATUS_RE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+STATUS:\s+(\d+)/(\d+)\s*=\s*([\d.]+)%"
)


def _latest_results() -> dict[str, dict]:
    """Last record per task_id (the runner rewrites entries on retry)."""
    latest: dict[str, dict] = {}
    if not RESULTS_FILE.exists():
        return latest
    for line in RESULTS_FILE.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        tid = r.get("task_id")
        if tid:
            latest[tid] = r
    return latest


def _timeline(bucket_sec: int = 300) -> list[dict]:
    """History of (time, solved, attempted, rate) parsed from the runner log.

    The runner writes a STATUS line every ~15s, so this reconstructs the whole
    run even though results.jsonl only gained timestamps later. Retries make the
    raw counters dip, so we also emit a monotonic `best` envelope for a clean
    progress line while keeping the instantaneous rate honest.
    """
    if not STATUS_LOG.exists():
        return []
    pts: list[tuple[datetime, int, int, float]] = []
    for line in STATUS_LOG.read_text(errors="replace").splitlines():
        m = _STATUS_RE.match(line.strip())
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
        except ValueError:
            continue
        pts.append((ts, int(m.group(2)), int(m.group(3)), float(m.group(4))))
    if not pts:
        return []

    out: list[dict] = []
    best_solved = best_total = 0
    i = 0
    while i < len(pts):
        window_start = pts[i][0]
        j = i
        while (j < len(pts)
               and (pts[j][0] - window_start).total_seconds() < bucket_sec):
            j += 1
        chunk = pts[i:j]
        ts = chunk[-1][0]
        solved = chunk[-1][1]
        total = chunk[-1][2]
        rate = chunk[-1][3]
        best_solved = max(best_solved, max(c[1] for c in chunk))
        best_total = max(best_total, max(c[2] for c in chunk))
        out.append({
            "t": ts.isoformat(timespec="seconds"),
            "solved": solved,
            "total": total,
            "rate": rate,
            "best_solved": best_solved,
            "best_total": best_total,
        })
        i = j
    return out


def _classify(err: str) -> str:
    e = err or ""
    if "402" in e:
        return "balance (402)"
    if "IncompleteRead" in e or "transport error" in e or "connection error" in e:
        return "API transport"
    if "stalled" in e:
        return "stalled (empty resp)"
    if "budget exhausted" in e or "tool-call budget" in e:
        return "budget exhausted"
    if "branch exhausted" in e:
        return "branch exhausted"
    if "No space" in e:
        return "disk full"
    if "download" in e:
        return "download fail"
    if not e.strip():
        return "(no error msg)"
    return e[:48]


def _runner_status() -> dict:
    out = {"raw": "", "solved": None, "total": None, "rate": None, "waves": None,
           "max_waves": None, "inflight": None, "ready": None, "avail": None,
           "load": None}
    if not STATUS_LOG.exists():
        return out
    lines = [l for l in STATUS_LOG.read_text(errors="replace").splitlines()
             if "STATUS:" in l]
    if not lines:
        return out
    last = lines[-1]
    out["raw"] = last
    m = re.search(r"(\d+)/(\d+)\s*=\s*([\d.]+)%", last)
    if m:
        out["solved"], out["total"], out["rate"] = (
            int(m.group(1)), int(m.group(2)), float(m.group(3)))
    for key, pat in (("waves", r"waves=(\d+)/(\d+)"), ("inflight", r"inflight=(\d+)"),
                     ("ready", r"ready=(\d+)"), ("avail", r"avail=(\d+)"),
                     ("load", r"load=(\d+)")):
        mm = re.search(pat, last)
        if mm:
            if key == "waves":
                out["waves"], out["max_waves"] = int(mm.group(1)), int(mm.group(2))
            else:
                out[key] = int(mm.group(1))
    return out


def _df() -> dict:
    try:
        u = shutil.disk_usage("/")
        return {"total_gb": u.total / 1e9, "used_gb": u.used / 1e9,
                "free_gb": u.free / 1e9, "pct": 100 * u.used / u.total}
    except Exception:
        return {}


_DOCKER_CACHE: dict = {"t": 0.0, "v": None}


def _docker_counts() -> dict:
    """Docker image/container counts, cached.

    `docker images` gets slow when the daemon is busy pulling, and the page
    polls every 5s — running it each time both wastes work and times out,
    which showed up as a bogus "0 images". Cache it for a minute instead.
    """
    import time as _t
    now = _t.monotonic()
    if _DOCKER_CACHE["v"] is not None and now - _DOCKER_CACHE["t"] < 60:
        return _DOCKER_CACHE["v"]

    def run(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=60).stdout.strip()
        except Exception:
            return None

    imgs = run(["docker", "images", "-q"])
    cons = run(["docker", "ps", "-q"])
    prev = _DOCKER_CACHE["v"]
    if imgs is None and prev is not None:
        return prev                      # keep last good reading on timeout
    out = {"images": len((imgs or "").split()),
           "containers_running": len((cons or "").split())}
    _DOCKER_CACHE.update(t=now, v=out)
    return out


def _pulls_active() -> int:
    try:
        r = subprocess.run(
            ["bash", "-c", "ps -eo args | grep -c 'docker pull --platform'"],
            capture_output=True, text=True, timeout=15)
        return max(0, int((r.stdout or "0").strip() or 0) - 1)
    except Exception:
        return 0


def build_stats() -> dict:
    latest = _latest_results()
    solved = [r for r in latest.values() if r.get("success")]
    failed = [r for r in latest.values() if not r.get("success")]

    kinds = Counter(_classify(r.get("error", "")) for r in failed)
    infra = {"balance (402)", "API transport", "stalled (empty resp)", "disk full",
             "download fail", "(no error msg)"}
    real = [r for r in failed if _classify(r.get("error", "")) not in infra]

    times = [r.get("wall_sec") for r in solved
             if isinstance(r.get("wall_sec"), (int, float))]

    # Recent tasks: prefer the real completion timestamp, fall back to file order.
    recent = list(latest.values())[-14:]
    recent.reverse()

    return {
        "solved": len(solved),
        "failed": len(failed),
        "total": len(latest),
        "rate": 100 * len(solved) / len(latest) if latest else 0,
        "real_failed": len(real),
        "kinds": kinds.most_common(),
        "by_project": Counter(r.get("project", "?") for r in real).most_common(12),
        "recent": [
            {"task_id": r.get("task_id"), "project": r.get("project"),
             "success": r.get("success"), "wall_sec": r.get("wall_sec"),
             "finished_at": r.get("finished_at"),
             "error": (r.get("error") or "")[:70]}
            for r in recent
        ],
        "avg_wall_sec": round(sum(times) / len(times), 1) if times else 0,
        "all_tasks": _all_tasks_count(),
        "runner": _runner_status(),
        "timeline": _timeline(),
        "disk": _df(),
        "docker": _docker_counts(),
        "pulls": _pulls_active(),
        "server_now": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberGym Eval</title>
<style>
 :root{
   --bg:#0f1115; --card:#171a21; --card2:#1c2029; --fg:#e6e8ee; --dim:#8b93a7;
   --ok:#3ddc84; --bad:#ff5c5c; --warn:#ffb020; --acc:#4c8dff; --grid:#252a34;
   --r:10px;
 }
 *{box-sizing:border-box}
 html,body{height:100%}
 body{margin:0;background:var(--bg);color:var(--fg);
      font:13.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
      -webkit-font-smoothing:antialiased}
 header{padding:12px 20px;border-bottom:1px solid var(--grid);
        display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
 h1{font-size:15px;margin:0;letter-spacing:.4px;font-weight:650}
 .muted{color:var(--dim);font-size:11.5px}
 main{padding:14px 20px 24px;display:grid;gap:14px;
      grid-template-columns:repeat(12,minmax(0,1fr));align-items:stretch}
 .card{background:var(--card);border:1px solid var(--grid);border-radius:var(--r);
       padding:14px 16px;display:flex;flex-direction:column;min-width:0;min-height:0}
 .card h2{font-size:10.5px;margin:0 0 10px;color:var(--dim);
          text-transform:uppercase;letter-spacing:1.1px;font-weight:650;flex:0 0 auto}
 .span3{grid-column:span 3} .span4{grid-column:span 4}
 .span5{grid-column:span 5} .span6{grid-column:span 6}
 .span7{grid-column:span 7} .span8{grid-column:span 8} .span12{grid-column:span 12}
 @media(max-width:1180px){
   .span3,.span4{grid-column:span 6}
   .span5,.span7,.span8{grid-column:span 12}
 }
 @media(max-width:760px){
   main{padding:12px;gap:12px}
   .span3,.span4,.span5,.span6,.span7,.span8{grid-column:span 12}
 }
 .big{font-size:clamp(28px,3.2vw,40px);font-weight:700;line-height:1;
      letter-spacing:-.5px}
 .bar{height:7px;background:#232833;border-radius:4px;overflow:hidden;margin:12px 0 6px}
 .bar>i{display:block;height:100%;background:var(--ok);transition:width .5s ease}
 .row{display:flex;justify-content:space-between;gap:12px;padding:4px 0;
      border-bottom:1px solid #1d2129;font-size:12.5px}
 .row:last-child{border-bottom:0}
 .k{color:var(--dim)}
 .ok{color:var(--ok)} .bad{color:var(--bad)} .warn{color:var(--warn)}
 .acc{color:var(--acc)}
 .kv{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:auto}
 .kv>div{background:var(--card2);border-radius:7px;padding:8px 10px;min-width:0}
 .kv .k{display:block;margin-bottom:2px}
 .kv b{font-size:15px}
 .scroll{overflow:auto;flex:1 1 auto;min-height:0}
 table{width:100%;border-collapse:collapse;font-size:12.5px}
 th{position:sticky;top:0;background:var(--card);text-align:left;color:var(--dim);
    font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.8px;
    padding:0 6px 6px 0;border-bottom:1px solid var(--grid)}
 td{padding:4px 6px 4px 0;border-bottom:1px solid #1d2129;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:1px}
 td.num,th.num{text-align:right;width:1%;padding-right:0}
 .pill{display:inline-block;padding:1px 6px;border-radius:20px;font-size:10.5px;
       font-weight:600;margin-right:6px}
 .pill.ok{background:rgba(61,220,132,.14);color:var(--ok)}
 .pill.bad{background:rgba(255,92,92,.14);color:var(--bad)}
 .chartwrap{flex:1 1 auto;min-height:200px;width:100%}
 .pbar-wrap{margin-top:14px;flex:0 0 auto}
 .pbar{display:flex;height:14px;background:#232833;border-radius:7px;
       overflow:hidden;border:1px solid var(--grid)}
 .pbar>i{display:block;height:100%;transition:width .6s ease}
 .seg-done{background:var(--ok)}
 .seg-fail{background:var(--bad);opacity:.85}
 .pbar-label{display:flex;justify-content:space-between;gap:12px;
             margin-top:7px;font-size:12.5px;flex-wrap:wrap}
 .swatch{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px}
 #chart{width:100%;height:100%;display:block}
 .legend{display:flex;gap:14px;font-size:11.5px;color:var(--dim);
         margin-top:8px;flex-wrap:wrap;flex:0 0 auto}
 .legend i{display:inline-block;width:9px;height:9px;border-radius:2px;
           margin-right:5px;vertical-align:middle}
 #tip{position:fixed;pointer-events:none;background:#0b0d11;border:1px solid var(--grid);
      border-radius:6px;padding:6px 9px;font-size:12px;display:none;z-index:9;
      box-shadow:0 6px 20px rgba(0,0,0,.5);line-height:1.45}
</style></head><body>
<header>
  <h1>CyberGym Eval</h1>
  <span class="muted" id="ts">loading…</span>
  <span class="muted" id="runner"></span>
</header>
<main>
  <div class="card span4">
    <h2>Solve rate</h2>
    <div class="big" id="rate">–</div>
    <div class="bar"><i id="ratebar" style="width:0"></i></div>
    <div class="muted" id="counts"></div>
    <div class="kv">
      <div><span class="k muted">real failures</span><b class="bad" id="realfail">–</b></div>
      <div><span class="k muted">avg wall</span><b id="avgwall">–</b></div>
    </div>
  </div>

  <div class="card span4">
    <h2>Runner</h2>
    <div class="row"><span class="k">waves</span><span id="waves">–</span></div>
    <div class="row"><span class="k">inflight</span><span id="inflight">–</span></div>
    <div class="row"><span class="k">ready queue</span><span id="ready">–</span></div>
    <div class="row"><span class="k">images available</span><span id="avail">–</span></div>
    <div class="row"><span class="k">load (1m)</span><span id="load">–</span></div>
    <div class="row"><span class="k">pulls active</span><span id="pulls">–</span></div>
    <div class="row"><span class="k">disk free</span><span id="disk">–</span></div>
  </div>

  <div class="card span4">
    <h2>Failures by cause</h2>
    <div class="scroll"><table id="kinds"></table></div>
  </div>

  <div class="card span12">
    <h2>Progress timeline</h2>
    <div class="chartwrap"><svg id="chart"></svg></div>
    <div class="legend">
      <span><i style="background:#3ddc84"></i>solved (cumulative)</span>
      <span><i style="background:#4c8dff"></i>attempted (cumulative)</span>
      <span><i style="background:#ffb020"></i>success rate %</span>
      <span id="chartmeta"></span>
    </div>
    <div class="pbar-wrap">
      <div class="pbar">
        <i class="seg-done" id="pbar-done" style="width:0"></i>
        <i class="seg-fail" id="pbar-fail" style="width:0"></i>
      </div>
      <div class="pbar-label">
        <span id="pbar-text">–</span>
        <span class="muted">
          <span class="swatch" style="background:#3ddc84"></span>solved
          <span class="swatch" style="background:#ff5c5c;margin-left:10px"></span>attempted, failed
          <span class="swatch" style="background:#232833;border:1px solid #252a34;margin-left:10px"></span>not yet run
        </span>
      </div>
    </div>
  </div>

  <div class="card span5">
    <h2>Real failures by project</h2>
    <div class="scroll"><table id="proj"></table></div>
  </div>

  <div class="card span7">
    <h2>Recent tasks</h2>
    <div class="scroll"><table id="recent"></table></div>
  </div>
</main>
<div id="tip"></div>
<script>
const $ = id => document.getElementById(id);
const NS = 'http://www.w3.org/2000/svg';
const fmtT = t => new Date(t).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
let lastTL = null;

function drawChart(tl){
  const svg = $('chart');
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  if (!tl || tl.length < 2){
    $('chartmeta').textContent = 'waiting for history…'; return;
  }
  // Size to the real container so the chart fills its card exactly.
  const box = svg.parentElement.getBoundingClientRect();
  const W = Math.max(300, Math.round(box.width));
  const H = Math.max(170, Math.round(box.height));
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);

  const L=52, R=52, T=12, B=26;
  const iw=Math.max(10,W-L-R), ih=Math.max(10,H-T-B);
  const maxTasks = Math.max(10, ...tl.map(d=>d.best_total));
  const t0=new Date(tl[0].t).getTime(), t1=new Date(tl[tl.length-1].t).getTime();
  const span=Math.max(1,t1-t0);
  const X=t=>L+(new Date(t).getTime()-t0)/span*iw;
  const Y=v=>T+ih-(v/maxTasks)*ih;
  const Yr=v=>T+ih-(v/100)*ih;
  const mk=(n,a)=>{const e=document.createElementNS(NS,n);
    for(const k in a) e.setAttribute(k,a[k]); return e;};

  for(let i=0;i<=4;i++){
    const y=Y(maxTasks*i/4);
    svg.appendChild(mk('line',{x1:L,y1:y,x2:W-R,y2:y,stroke:'#252a34','stroke-width':1}));
    const tx=mk('text',{x:L-7,y:y+4,fill:'#8b93a7','font-size':11,'text-anchor':'end'});
    tx.textContent=Math.round(maxTasks*i/4); svg.appendChild(tx);
  }
  for(let i=0;i<=4;i++){
    const y=Yr(100*i/4);
    const tx=mk('text',{x:W-R+7,y:y+4,fill:'#ffb020','font-size':11});
    tx.textContent=(100*i/4)+'%'; svg.appendChild(tx);
  }
  [0,1].forEach(k=>{
    const idx = k? tl.length-1 : 0;
    const tx=mk('text',{x:k?W-R:L, y:H-8, fill:'#8b93a7','font-size':11,
                        'text-anchor':k?'end':'start'});
    tx.textContent=fmtT(tl[idx].t); svg.appendChild(tx);
  });

  const path=(key,yFn)=>tl.map((d,i)=>(i?'L':'M')+X(d.t).toFixed(1)+' '+yFn(d[key]).toFixed(1)).join(' ');
  svg.appendChild(mk('path',{d:path('best_total',Y),fill:'none',stroke:'#4c8dff','stroke-width':2}));
  svg.appendChild(mk('path',{d:path('best_solved',Y),fill:'none',stroke:'#3ddc84','stroke-width':2}));
  svg.appendChild(mk('path',{d:path('rate',Yr),fill:'none',stroke:'#ffb020',
                             'stroke-width':1.5,'stroke-dasharray':'4 3',opacity:.9}));

  $('chartmeta').textContent = tl.length+' pts · '+fmtT(tl[0].t)+' → '+fmtT(tl[tl.length-1].t);

  const line=mk('line',{y1:T,y2:T+ih,stroke:'#8b93a7','stroke-width':1,opacity:0,'stroke-dasharray':'3 3'});
  svg.appendChild(line);
  const hit=mk('rect',{x:L,y:T,width:iw,height:ih,fill:'transparent'});
  svg.appendChild(hit);
  hit.addEventListener('mousemove',ev=>{
    const r=svg.getBoundingClientRect();
    const px=(ev.clientX-r.left)/r.width*W;
    let bi=0,bd=1e9;
    tl.forEach((d,i)=>{const dd=Math.abs(X(d.t)-px); if(dd<bd){bd=dd;bi=i;}});
    const d=tl[bi];
    line.setAttribute('x1',X(d.t)); line.setAttribute('x2',X(d.t)); line.setAttribute('opacity',.8);
    const tip=$('tip'); tip.style.display='block';
    tip.style.left=Math.min(ev.clientX+12, innerWidth-170)+'px';
    tip.style.top=(ev.clientY+12)+'px';
    tip.innerHTML=fmtT(d.t)+'<br>solved <b>'+d.best_solved+'</b><br>attempted <b>'+
      d.best_total+'</b><br>rate <b>'+d.rate.toFixed(1)+'%</b>';
  });
  hit.addEventListener('mouseleave',()=>{line.setAttribute('opacity',0);$('tip').style.display='none';});
}

async function tick(){
  try{
    const r = await fetch('/api/stats', {cache:'no-store'});
    const d = await r.json();
    $('ts').textContent = 'updated ' + new Date().toLocaleTimeString();
    $('rate').textContent = d.rate.toFixed(1) + '%';
    $('rate').className = 'big ' + (d.rate >= 99 ? 'ok' : d.rate >= 90 ? 'warn' : 'bad');
    $('ratebar').style.width = d.rate + '%';
    $('counts').textContent = d.solved + ' solved / ' + d.total + ' attempted';
    $('realfail').textContent = d.real_failed;
    $('avgwall').textContent = d.avg_wall_sec + 's';
    const ru = d.runner || {};
    $('waves').textContent = (ru.waves ?? '–') + ' / ' + (ru.max_waves ?? '–');
    $('inflight').textContent = ru.inflight ?? '–';
    $('ready').textContent = ru.ready ?? '–';
    $('avail').textContent = ru.avail ?? '–';
    $('load').textContent = ru.load ?? '–';
    $('pulls').textContent = d.pulls;
    $('disk').textContent = d.disk.free_gb.toFixed(0)+' GB ('+d.disk.pct.toFixed(0)+'% used)';
    const i = ru.raw ? ru.raw.indexOf('] ') : -1;
    $('runner').textContent = ru.raw ? (i >= 0 ? ru.raw.slice(i + 2) : ru.raw) : '';
    lastTL = d.timeline; drawChart(lastTL);
    const all = d.all_tasks || 0;
    const pctDone = all ? d.solved / all * 100 : 0;
    const pctFail = all ? (d.total - d.solved) / all * 100 : 0;
    $('pbar-done').style.width = pctDone + '%';
    $('pbar-fail').style.width = pctFail + '%';
    $('pbar-text').innerHTML = '<b>' + d.solved + '</b> of <b>' + all +
      '</b> tasks solved · ' + d.total + ' attempted (' + pctDone.toFixed(1) + '%)';
    $('kinds').innerHTML = d.kinds.length
      ? '<tr><th>cause</th><th class="num">n</th></tr>' + d.kinds.map(([k,v]) =>
        `<tr><td title="${k}">${k}</td><td class="num">${v}</td></tr>`).join('')
      : '<tr><td class="muted">none</td></tr>';
    $('proj').innerHTML = d.by_project.length
      ? '<tr><th>project</th><th class="num">n</th></tr>' + d.by_project.map(([k,v]) =>
        `<tr><td>${k}</td><td class="num">${v}</td></tr>`).join('')
      : '<tr><td class="muted">none</td></tr>';
    $('recent').innerHTML = '<tr><th>task</th><th>project</th><th>time</th>' +
      '<th class="num">wall</th><th>error</th></tr>' + d.recent.map(t =>
      `<tr><td><span class="pill ${t.success?'ok':'bad'}">${t.success?'OK':'FAIL'}</span>${t.task_id}</td>` +
      `<td>${t.project||''}</td>` +
      `<td>${t.finished_at ? new Date(t.finished_at).toLocaleTimeString() : '—'}</td>` +
      `<td class="num">${t.wall_sec??''}s</td>` +
      `<td title="${(t.error||'').replace(/"/g,'&quot;')}">${(t.error||'').slice(0,48)}</td></tr>`).join('');
  }catch(e){ $('ts').textContent = 'update failed: ' + e; }
}
tick(); setInterval(tick, 5000);
addEventListener('resize', () => { if (lastTL) drawChart(lastTL); });
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
    print(f"dashboard on http://0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
