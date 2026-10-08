"""Evaluation runner v2 — 7 waves of 12, auto-cleanup SOLVED images only."""
import json, os, subprocess, time, re, signal, sys
from pathlib import Path
from datetime import datetime

RESULTS_DIR = Path("/home/ubuntu/Benchmark/runs/ec2-full")
RESULTS_FILE = RESULTS_DIR / "results.jsonl"
STATUS_LOG = Path("/tmp/eval_status.log")
BENCHMARK_DIR = Path("/home/ubuntu/Benchmark")
TASKS_JSON = BENCHMARK_DIR / "data-meta" / "tasks.json"

TASKS_CACHE = json.loads(TASKS_JSON.read_text()) if TASKS_JSON.exists() else []

MAX_WAVES = 10         # adaptive; moves between MIN_WAVES and HARD_MAX_WAVES
MIN_WAVES = 2
HARD_MAX_WAVES = 12    # never exceed — caps concurrent tasks at 144
TASKS_PER_WAVE = 12
CHECK_INTERVAL = 15
MAX_RETRIES = 3
MAX_ATTEMPTS = MAX_RETRIES + 1   # initial run + retries, tracked in memory
LOAD_LIMIT = 240       # machine is I/O-bound, load avg overstates CPU pressure
CONTAINER_TIMEOUT = 300
MAX_WAVE_SECONDS = 2700   # kill a wave stuck longer than this (no task timeout
                          # exists downstream, so a hung download would pin its
                          # slot forever and starve the pipeline)

# task_id -> how many times we've dispatched it. Kept in memory because the
# retry path deletes the task's results.jsonl line (so --resume re-runs it),
# which makes the task invisible to the done/failed sets on the next cycle.
attempts: dict[str, int] = {}

# last successful get_available() result, used if docker momentarily stalls
_last_available: set[str] = set()

# task_id -> last failed record. Retrying requires deleting the task's
# results.jsonl line (so run_parallel --resume re-runs it); we keep the record
# here so an exhausted task can be written back instead of silently vanishing
# from the tally.
last_failure: dict[str, dict] = {}

# Adaptive scaling thresholds (load1 per CPU core)
LOAD_PER_CORE_UP = 14.0    # above this: back off one wave
LOAD_PER_CORE_DOWN = 6.0   # below this (and queue is deep): add one wave
NCORES = os.cpu_count() or 8

wave_counter = 1400
inflight_tasks = set()
cleaned_tasks = set()  # images already cleaned, avoid re-checking


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with open(STATUS_LOG, "a") as f:
        f.write(line + "\n")


def get_done():
    done = {}
    if RESULTS_FILE.exists():
        for line in RESULTS_FILE.read_text().splitlines():
            if line.strip():
                try:
                    r = json.loads(line)
                    done[r["task_id"]] = r.get("success", False)
                except:
                    pass
    return done


def get_available():
    """Task ids whose vul+fix images are both local.

    Returns the previous snapshot rather than raising if the daemon is busy —
    a timeout here used to abort the whole dispatch cycle (caught and logged
    as ERROR), stalling the run even though eval work was fine.
    """
    global _last_available
    try:
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, timeout=90
        )
    except Exception as e:
        log(f"get_available: docker images failed ({e}); reusing last snapshot")
        return _last_available
    images = set(result.stdout.strip().split("\n"))
    tasks = set()
    for img in images:
        if img.endswith("-vul"):
            base = img.rsplit("-vul", 1)[0]
            if base + "-fix" in images:
                if "n132/arvo:" in img:
                    sub = img.split("n132/arvo:")[1].replace("-vul", "")
                    tasks.add(f"arvo:{sub}")
                elif "cybergym/oss-fuzz:" in img:
                    sub = img.split("cybergym/oss-fuzz:")[1].replace("-vul", "")
                    tasks.add(f"oss-fuzz:{sub}")
    _last_available = tasks
    return tasks


def get_waves():
    result = subprocess.run(
        ["ps", "aux"], capture_output=True, text=True, timeout=10
    )
    waves = []
    tasks_in_flight = set()
    for line in result.stdout.split("\n"):
        if "run_parallel" in line and "ec2-full" in line and "grep" not in line:
            tids = set(re.findall(r'(arvo:\d+|oss-fuzz:\d+)', line))
            tasks_in_flight.update(tids)
            pid_m = re.search(r'^\S+\s+(\d+)', line)
            if pid_m:
                waves.append(int(pid_m.group(1)))
    return waves, tasks_in_flight


def kill_old_containers():
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}} {{.RunningFor}}"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            cid, running = parts
            if "minute" in running or "hour" in running:
                mins = 0
                if "hour" in running:
                    mins = 60
                else:
                    m = re.search(r'(\d+)\s*minute', running)
                    if m:
                        mins = int(m.group(1))
                if mins >= 5:
                    subprocess.run(["docker", "kill", cid], timeout=10,
                                   capture_output=True)
                    log(f"Killed stuck container {cid} (running {running})")
    except Exception as e:
        log(f"Container cleanup error: {e}")


CLEAN_BATCH = 6        # tasks per cycle. Raised from 3: solved-task images
                       # accumulate faster than they were reclaimed, and the
                       # free-space floor was retreating ~35GB/cycle. There is
                       # no dangling-image garbage to prune, so draining the
                       # solved backlog is the only lever.
CLEAN_MIN_FREE_GB = 400   # below this, stop cleaning and warn
CLEANER_SRC = r'''
import subprocess, sys
removed = 0
for tid in sys.argv[1:]:
    typ, _, sub = tid.partition(":")
    prefix = "n132/arvo" if typ == "arvo" else "cybergym/oss-fuzz"
    for suffix in ("-vul", "-fix"):
        try:
            r = subprocess.run(["docker", "rmi", "-f", f"{prefix}:{sub}{suffix}"],
                               capture_output=True, text=True, timeout=120)
            if r.returncode == 0:
                removed += 1
        except Exception:
            pass
print(removed, flush=True)
'''
_clean_proc = None     # background cleaner process handle
_pull_procs = []       # background image-pull processes

PULL_PARALLEL = 2      # starting value; adapts to idle capacity (see below)
PULL_MIN = 2
PULL_MAX = 10          # each pull extracts GBs; too many at once spikes
                       # Docker's transient space and fails with ENOSPC. Safe
                       # at 10 now that _count_active_pulls() accounts for
                       # orphaned pulls across runner restarts.
PULL_MIN_READY = 40    # only pull while the ready queue is below this depth
PULL_IDLE_PER_CORE = 3.0   # below this load/core the machine is idle -> pull harder


def _active_pull_images() -> set[str]:
    """Images currently being pulled by ANY process on the host.

    Doubles as a cap and a de-duplicator. Counting pulls alone was not enough:
    without knowing *which* images were already in flight, each cycle relaunched
    pulls for the same few images, so every slot queued behind Docker's
    per-image lock and network throughput collapsed to zero. Scanning the host
    (rather than our own Popen handles) also accounts for pulls orphaned by a
    runner restart.
    """
    try:
        r = subprocess.run(["ps", "-eo", "args"], capture_output=True,
                           text=True, timeout=15)
    except Exception:
        return {img for _, img in _pull_procs}
    out: set[str] = set()
    for line in (r.stdout or "").splitlines():
        m = re.search(r"docker pull --platform \S+ (\S+)", line)
        if m:
            out.add(m.group(1))
    return out
PULL_SRC = r'''
import subprocess, sys
subprocess.run(["docker", "pull", "--platform", "linux/amd64", sys.argv[1]],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
'''


def maintain_image_pulls(ready_depth: int, load1: float, skip: set[str]):
    """Top up the local image cache — lazily, and only as hard as we can afford.

    Pulling is worth doing when the machine would otherwise go idle, and the
    oss-fuzz images are large enough that pre-fetching them wastes disk and
    bandwidth. So:
      * stay idle while the ready queue is deep enough to keep workers busy
      * prefer arvo (small) over oss-fuzz (multi-GB) tasks
      * prefer completing a half-present pair, which yields a runnable task
      * scale parallelism with spare capacity: when eval load is low (the pull
        is the critical path) pull hard; when the box is busy, back right off
        so pulls don't thrash the disk out from under running containers.
    """
    global _pull_procs, PULL_PARALLEL
    _pull_procs = [p for p in _pull_procs if p.poll() is None]

    if ready_depth >= PULL_MIN_READY:
        return                      # enough queued work — don't compete for I/O

    lpc = load1 / NCORES
    if lpc < PULL_IDLE_PER_CORE:
        PULL_PARALLEL = min(PULL_MAX, PULL_PARALLEL + 1)
    elif lpc > PULL_IDLE_PER_CORE * 3:
        PULL_PARALLEL = max(PULL_MIN, PULL_PARALLEL - 1)

    active = _active_pull_images()
    slots = PULL_PARALLEL - len(active)
    if slots <= 0:
        return

    try:
        res = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                             capture_output=True, text=True, timeout=30)
        have = set(res.stdout.strip().split("\n"))
    except Exception:
        return

    todo = []
    for t in TASKS_CACHE:
        tid = t["task_id"]
        if tid in skip:
            # Already solved: cleanup removes these images, so re-pulling them
            # just feeds an infinite pull/delete loop that starves real work.
            continue
        typ, _, sub = tid.partition(":")
        is_arvo = typ == "arvo"
        prefix = "n132/arvo" if is_arvo else "cybergym/oss-fuzz"
        vul, fix = f"{prefix}:{sub}-vul", f"{prefix}:{sub}-fix"
        missing = [i for i in (vul, fix) if i not in have]
        if not missing:
            continue
        # sort key: finish partial pairs first, then small (arvo) before big
        # (oss-fuzz) — big images are pulled only once nothing cheaper is left.
        todo.append((0 if len(missing) == 1 else 1, 0 if is_arvo else 1, missing))

    todo.sort(key=lambda x: (x[0], x[1]))
    for _, _, imgs in todo:
        for img in imgs:
            if slots <= 0:
                return
            if img in active:
                continue          # already downloading — don't duplicate
            _pull_procs.append(subprocess.Popen(
                [sys.executable, "-c", PULL_SRC, img],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True))
            slots -= 1


def cleanup_solved_images(successful, inflight):
    """Remove Docker images ONLY for successfully solved tasks.

    At most CLEAN_BATCH tasks per cycle, in a BACKGROUND process, so the
    dispatch loop is never blocked by slow `docker rmi` calls.
    Pending/failed tasks are never touched.
    """
    global cleaned_tasks, _clean_proc

    if _clean_proc is not None:
        if _clean_proc.poll() is None:
            return  # still busy — try again next cycle
        _clean_proc = None

    to_clean = sorted(successful - inflight - cleaned_tasks)
    if not to_clean:
        return

    batch = to_clean[:CLEAN_BATCH]
    cleaned_tasks.update(batch)   # reserve so we don't re-queue the same tasks
    _clean_proc = subprocess.Popen(
        [sys.executable, "-c", CLEANER_SRC, *batch],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    log(f"CLEANUP: queued {len(batch)} solved tasks "
        f"({len(cleaned_tasks)}/{len(successful)} cleaned)")


def kill_stuck_waves():
    """Kill waves that have been running far longer than any healthy task.

    A wave stuck on a hung network read holds its concurrency slot forever;
    killing it lets the task fall back into the retry path.
    """
    killed = 0
    try:
        out = subprocess.run(["ps", "-eo", "pid,etimes,args"],
                             capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return 0
    for line in out.splitlines():
        if "eval.run_parallel" not in line or "ec2-full" not in line:
            continue
        if "ps -eo" in line or "grep" in line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid_s, etimes_s, cmd = parts
        try:
            pid, etimes = int(pid_s), int(etimes_s)
        except ValueError:
            continue
        if etimes <= MAX_WAVE_SECONDS:
            continue
        try:
            os.kill(pid, signal.SIGKILL)
            killed += 1
            log(f"Killed stuck wave pid={pid} after {etimes}s "
                f"[{cmd[-90:]}]")
        except Exception:
            pass
    return killed


def launch_wave(task_ids):
    global wave_counter
    wave_counter += 1
    wid = wave_counter
    for tid in task_ids:
        attempts[tid] = attempts.get(tid, 0) + 1

    ids_str = " ".join(task_ids)
    workers = min(len(task_ids), TASKS_PER_WAVE)
    log_file = RESULTS_DIR / f"wave{wid}.log"

    cmd = (
        f"cd {BENCHMARK_DIR} && python3 -m eval.run_parallel "
        f"--task-ids {ids_str} --workers {workers} "
        f"--out-dir {RESULTS_DIR} --resume --no-cleanup "
        f">> {log_file} 2>&1"
    )
    subprocess.Popen(["bash", "-c", cmd], start_new_session=True)
    log(f"WAVE {wid}: {len(task_ids)} tasks [{ids_str}]")


def main():
    global inflight_tasks, MAX_WAVES
    log("=== EVAL RUNNER V2 STARTED ===")
    log(f"MAX_WAVES={MAX_WAVES} (adaptive), TASKS={TASKS_PER_WAVE}, "
        f"LOAD_LIMIT={LOAD_LIMIT}, CORES={NCORES}")


    while True:
        try:
            kill_old_containers()
            kill_stuck_waves()

            done = get_done()
            available = get_available()
            waves, inflight_tasks = get_waves()
            load1 = os.getloadavg()[0]

            successful = {tid for tid, ok in done.items() if ok}
            failed = {tid for tid, ok in done.items() if not ok}
            # Exclude tasks that exhausted their attempt budget. This has to be
            # driven by the in-memory counter, not by the done/failed sets: the
            # retry path deletes the results line so --resume re-runs the task,
            # leaving it absent from both sets and therefore perpetually
            # "ready" — which spammed a new wave every 15s forever.
            exhausted = {tid for tid, n in attempts.items() if n >= MAX_ATTEMPTS}
            ready = sorted(available - successful - inflight_tasks - exhausted)

            # Only clean images for SOLVED tasks, never for pending/failed
            cleanup_solved_images(successful, inflight_tasks)

            # Keep pulling images for tasks we haven't run yet (lazily)
            maintain_image_pulls(len(ready), load1, successful)

            # Retries: drop the failed task's results line so run_parallel
            # --resume will actually run it again. Re-queueing is already
            # handled by `ready` above, gated on the attempt budget. Stash the
            # record so an exhausted task can be restored below.
            for tid in list(failed):
                if tid in available and tid not in inflight_tasks:
                    if attempts.get(tid, 0) < MAX_ATTEMPTS and RESULTS_FILE.exists():
                        kept: list[str] = []
                        dropped: list[dict] = []
                        for l in RESULTS_FILE.read_text().splitlines():
                            if not l.strip():
                                continue
                            try:
                                rec = json.loads(l)
                            except json.JSONDecodeError:
                                kept.append(l)
                                continue
                            if rec.get("task_id") == tid:
                                dropped.append(rec)
                            else:
                                kept.append(l)
                        if dropped:
                            last_failure[tid] = dropped[-1]
                        RESULTS_FILE.write_text("\n".join(kept) + "\n" if kept else "")

            # A task whose budget is spent but which has no line in
            # results.jsonl would be invisible to the tally (and to --resume).
            # Write its last known failure back so nothing is silently lost.
            for tid in exhausted:
                if tid not in done and tid in last_failure:
                    try:
                        with open(RESULTS_FILE, "a") as f:
                            f.write(json.dumps(last_failure[tid]) + "\n")
                        log(f"RESTORED final result for exhausted task {tid}")
                    except Exception as e:
                        log(f"restore failed for {tid}: {e}")

            n_done = len(successful)
            n_total = n_done + len(failed)
            rate = n_done / n_total * 100 if n_total else 0
            n_active_waves = len(waves) // 2
            lpc = load1 / NCORES   # load per core

            # --- Adaptive concurrency: scale waves to observed pressure ---
            old = MAX_WAVES
            if lpc > LOAD_PER_CORE_UP and MAX_WAVES > MIN_WAVES:
                MAX_WAVES -= 1
            elif lpc < LOAD_PER_CORE_DOWN and len(ready) > TASKS_PER_WAVE:
                MAX_WAVES += 1
            MAX_WAVES = max(MIN_WAVES, min(HARD_MAX_WAVES, MAX_WAVES))

            log(f"STATUS: {n_done}/{n_total} = {rate:.1f}% | "
                f"avail={len(available)} waves={n_active_waves}/{MAX_WAVES} "
                f"inflight={len(inflight_tasks)} ready={len(ready)} "
                f"load={load1:.0f} ({lpc:.1f}/core)")
            if MAX_WAVES != old:
                log(f"ADAPT: max_waves {old} -> {MAX_WAVES} "
                    f"(load/core={lpc:.1f}, ready={len(ready)})")

            if n_active_waves < MAX_WAVES and ready and load1 < LOAD_LIMIT:
                batch = ready[:TASKS_PER_WAVE]
                launch_wave(batch)

        except Exception as e:
            log(f"ERROR: {e}")
            import traceback
            traceback.print_exc()

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
