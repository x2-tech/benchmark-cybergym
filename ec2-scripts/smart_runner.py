"""Smart evaluation runner — prevents duplicates, manages concurrency properly."""
import json, os, subprocess, time, threading, re
from pathlib import Path
from datetime import datetime

RESULTS_DIR = Path("/home/ubuntu/Benchmark/runs/ec2-full")
RESULTS_FILE = RESULTS_DIR / "results.jsonl"
STATUS_LOG = Path("/tmp/smart_status.log")
BENCHMARK_DIR = Path("/home/ubuntu/Benchmark")

MAX_WAVES = 4             # Max concurrent wave processes
TASKS_PER_WAVE = 6        # Workers per wave
CHECK_INTERVAL = 30       # Check every 30s
MAX_RETRIES = 3
LOAD_LIMIT = 70

_lock = threading.Lock()
_wave_counter = 800
_inflight = set()         # task_ids currently being processed

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with open(STATUS_LOG, "a") as f:
        f.write(line + "\n")

def get_done_ids():
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

def get_available_tasks():
    result = subprocess.run(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
        capture_output=True, text=True
    )
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
    return tasks

def get_wave_info():
    """Get running wave PIDs and their task IDs."""
    result = subprocess.run(
        ["ps", "aux"], capture_output=True, text=True
    )
    waves = []
    for line in result.stdout.split("\n"):
        if "run_parallel" in line and "ec2-full" in line and "grep" not in line:
            # Extract task IDs from command line
            match = re.findall(r'(arvo:\d+|oss-fuzz:\d+)', line)
            pid_match = re.search(r'^\S+\s+(\d+)', line)
            if pid_match:
                pid = int(pid_match.group(1))
                waves.append({"pid": pid, "tasks": set(match)})
    return waves

def launch_wave(task_ids):
    global _wave_counter
    with _lock:
        _wave_counter += 1
        wave_id = _wave_counter
        _inflight.update(task_ids)
    
    ids_str = " ".join(task_ids)
    workers = min(len(task_ids), TASKS_PER_WAVE)
    log_file = RESULTS_DIR / f"wave{wave_id}.log"
    
    cmd = (
        f"cd {BENCHMARK_DIR} && python3 -m eval.run_parallel "
        f"--task-ids {ids_str} --workers {workers} "
        f"--out-dir {RESULTS_DIR} --resume --no-cleanup "
        f">> {log_file} 2>&1"
    )
    
    subprocess.Popen(["bash", "-c", cmd], start_new_session=True)
    log(f"WAVE {wave_id}: {len(task_ids)} tasks [{ids_str}]")

def main():
    global _inflight
    log("=== SMART RUNNER STARTED ===")
    log(f"MAX_WAVES={MAX_WAVES}, TASKS_PER_WAVE={TASKS_PER_WAVE}")
    
    retry_count = {}
    last_report_time = 0
    
    while True:
        try:
            done = get_done_ids()
            available = get_available_tasks()
            
            # Update inflight based on what waves are still running
            waves = get_wave_info()
            active_tasks = set()
            for w in waves:
                active_tasks.update(w["tasks"])
            _inflight = active_tasks  # Sync with reality
            
            successful = {tid for tid, ok in done.items() if ok}
            failed = {tid for tid, ok in done.items() if not ok}
            
            # Ready = available, not done successfully, not in-flight
            ready = available - successful - _inflight
            
            # Add failed tasks for retry
            for tid in failed:
                if tid in available and tid not in _inflight:
                    count = retry_count.get(tid, 0)
                    if count < MAX_RETRIES:
                        # Remove from results so --resume picks it up
                        lines = RESULTS_FILE.read_text().splitlines() if RESULTS_FILE.exists() else []
                        kept = [l for l in lines if l.strip() and json.loads(l).get("task_id") != tid]
                        RESULTS_FILE.write_text("\n".join(kept) + "\n" if kept else "")
                        retry_count[tid] = count + 1
                        ready.add(tid)
            
            load1, = os.getloadavg()[:1]
            n_done = len(successful)
            n_total = len(done)
            rate = n_done / n_total * 100 if n_total else 0
            n_fail = len(failed)
            
            now = time.time()
            if now - last_report_time >= 60:  # Report every minute
                log(f"STATUS: {n_done}/{n_total} = {rate:.1f}% | "
                    f"fail={n_fail} imgs={len(available)} waves={len(waves)} "
                    f"inflight={len(_inflight)} ready={len(ready)} "
                    f"load={load1:.0f}")
                
                # Per-project stats
                projects = {}
                for line in (RESULTS_FILE.read_text().splitlines() if RESULTS_FILE.exists() else []):
                    if line.strip():
                        r = json.loads(line)
                        p = r.get("project", "?") or "?"
                        if p not in projects:
                            projects[p] = [0, 0]
                        if r.get("success"):
                            projects[p][0] += 1
                        projects[p][1] += 1
                for p, (s, t) in sorted(projects.items()):
                    log(f"  {p}: {s}/{t}")
                last_report_time = now
            
            # Launch new waves if capacity available
            n_waves = len(waves)
            if n_waves < MAX_WAVES and ready and load1 < LOAD_LIMIT:
                batch = sorted(ready)[:TASKS_PER_WAVE]
                launch_wave(batch)
                ready -= set(batch)
                
                # Launch a second if still room
                if n_waves + 1 < MAX_WAVES and ready and load1 < LOAD_LIMIT * 0.8:
                    batch2 = sorted(ready)[:TASKS_PER_WAVE]
                    launch_wave(batch2)
            
        except Exception as e:
            log(f"ERROR: {e}")
            import traceback
            traceback.print_exc()
        
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
