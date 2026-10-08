"""Overnight autonomous runner: max throughput + auto-retry + continuous pull."""
import json, subprocess, time, os, sys

BENCHMARK = "/home/ubuntu/Benchmark"
RESULTS_DIR = f"{BENCHMARK}/runs/ec2-full"
RESULTS_FILE = f"{RESULTS_DIR}/results.jsonl"
STATUS_FILE = "/tmp/overnight_status.log"
CHECK_INTERVAL = 15
MAX_CONCURRENT = 40  # Aggressively high — tasks are 95% API-wait
BATCH_SIZE = 15
MAX_RETRIES = 2      # Retry failed tasks up to 2 times

os.makedirs(RESULTS_DIR, exist_ok=True)

# Track retries
retry_count = {}  # task_id -> attempts

def get_images():
    r = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                       capture_output=True, text=True)
    return set(l.strip() for l in r.stdout.strip().split("\n") if l.strip() and "none" not in l)

def get_results():
    results = {}
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE) as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    tid = r["task_id"]
                    # Keep last result per task (retry overwrites)
                    results[tid] = r
    return results

def get_in_progress():
    r = subprocess.run(["ps", "aux"], capture_output=True, text=True)
    tasks = set()
    for line in r.stdout.split("\n"):
        if "run_parallel" in line and "--task-ids" in line:
            after = line.split("--task-ids")[1]
            for token in after.split():
                if ":" in token and not token.startswith("-"):
                    tasks.add(token)
                elif token.startswith("-"):
                    break
    return tasks

def find_ready(tasks, images, done_ok, in_progress, retryable):
    ready = []
    retry = []
    for t in tasks:
        tid = t["task_id"]
        if tid in in_progress:
            continue
        typ, _, sub = tid.partition(":")
        prefix = "n132/arvo" if typ == "arvo" else "cybergym/oss-fuzz"
        has_imgs = f"{prefix}:{sub}-vul" in images and f"{prefix}:{sub}-fix" in images
        if not has_imgs:
            continue
        if tid in done_ok:
            continue
        if tid in retryable:
            retry.append(tid)
        elif tid not in {r for r in get_results()}:
            ready.append(tid)
    return ready, retry

def launch(task_ids, wave_num):
    ids_str = " ".join(task_ids)
    cmd = (f"cd {BENCHMARK} && python3 -m eval.run_parallel "
           f"--task-ids {ids_str} --workers {len(task_ids)} "
           f"--out-dir {RESULTS_DIR} --resume --no-cleanup "
           f">> {RESULTS_DIR}/wave{wave_num}.log 2>&1")
    subprocess.Popen(["bash", "-c", cmd])
    return ids_str

def write_status(msg):
    with open(STATUS_FILE, "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    print(msg, flush=True)

def main():
    tasks = json.load(open(f"{BENCHMARK}/data-meta/tasks.json"))
    wave = 500
    last_report = 0

    write_status(f"Overnight runner started: {len(tasks)} tasks, max {MAX_CONCURRENT} concurrent")

    # Start continuous image pull in background if not running
    pull_running = subprocess.run(["pgrep", "-f", "pull_all_tasks"], capture_output=True).returncode == 0
    if not pull_running:
        subprocess.Popen(["bash", "-c",
            "cat /tmp/pull_all_tasks.txt | xargs -P6 -I{} docker pull {} > /tmp/pull_all_live.log 2>&1"])
        write_status("Started background pull for all task images (P6)")

    while True:
        imgs = get_images()
        results = get_results()
        in_prog = get_in_progress()

        done_ok = {tid for tid, r in results.items() if r.get("success")}
        done_fail = {tid for tid, r in results.items() if not r.get("success")}

        # Identify retryable failures
        retryable = set()
        for tid in done_fail:
            cnt = retry_count.get(tid, 0)
            if cnt < MAX_RETRIES:
                retryable.add(tid)

        ready, retry_list = find_ready(tasks, imgs, done_ok, in_prog, retryable)

        n_img = len([i for i in imgs if "arvo" in i or "oss-fuzz" in i])
        ok = len(done_ok)
        total_done = len(results)
        slots = MAX_CONCURRENT - len(in_prog)

        # Periodic detailed report (every 5 min)
        now = time.time()
        if now - last_report > 300:
            by_proj = {}
            for tid, r in results.items():
                p = r.get("project", "?")
                by_proj.setdefault(p, [0, 0])
                by_proj[p][0] += 1
                if r.get("success"):
                    by_proj[p][1] += 1
            
            report = f"REPORT: {ok}/{total_done} = {ok/total_done*100:.1f}% | imgs={n_img} run={len(in_prog)} ready={len(ready)} retry={len(retry_list)}"
            for p, (t, s) in sorted(by_proj.items(), key=lambda x: -x[1][0]):
                if t > 0:
                    report += f"\n  {p}: {s}/{t}"
            if done_fail - retryable:  # permanent failures
                report += f"\n  PERMANENT FAILS: {done_fail - retryable}"
            write_status(report)
            last_report = now

        # Launch new tasks
        if slots > 0:
            # Priority: new tasks first, then retries
            batch = []
            if ready:
                batch = ready[:min(BATCH_SIZE, slots)]
            elif retry_list and slots > 0:
                batch = retry_list[:min(5, slots)]
                for tid in batch:
                    retry_count[tid] = retry_count.get(tid, 0) + 1
                    # Remove old result so --resume doesn't skip it
                    if os.path.exists(RESULTS_FILE):
                        with open(RESULTS_FILE) as f:
                            lines = f.readlines()
                        with open(RESULTS_FILE, "w") as f:
                            for line in lines:
                                if line.strip():
                                    r = json.loads(line)
                                    if r["task_id"] not in batch:
                                        f.write(line)
                write_status(f"Retrying {len(batch)} failed tasks: {' '.join(batch)}")

            if batch:
                wave += 1
                ids = launch(batch, wave)
                write_status(f"[wave {wave}] +{len(batch)}: {ids}")

        # Memory info  
        try:
            with open("/proc/meminfo") as f:
                lines = f.readlines()
                total_mem = int(lines[0].split()[1]) // 1024
                avail_mem = int(lines[2].split()[1]) // 1024
                used_pct = round((1 - avail_mem/total_mem) * 100)
        except:
            used_pct = 0

        status = f"imgs={n_img} done={ok}/{total_done}/{len(tasks)} run={len(in_prog)} mem={used_pct}%"
        print(f"[{time.strftime('%H:%M:%S')}] {status}", flush=True)

        if total_done >= len(tasks) and not in_prog:
            write_status(f"ALL DONE! {ok}/{total_done} = {ok/total_done*100:.1f}%")
            break

        # Check if all available tasks are done/running
        if not ready and not retry_list and not in_prog:
            write_status(f"Waiting for more images... {n_img} available, {ok}/{total_done} done")

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
