"""Sustainable runner: 12 concurrent tasks on 8-CPU machine."""
import json, subprocess, time, os

BENCHMARK = "/home/ubuntu/Benchmark"
RESULTS_DIR = f"{BENCHMARK}/runs/ec2-full"
RESULTS_FILE = f"{RESULTS_DIR}/results.jsonl"
CHECK_INTERVAL = 20
MAX_CONCURRENT = 12  # Sweet spot for 8 CPUs with API-bound tasks
BATCH_SIZE = 6
MAX_RETRIES = 3

os.makedirs(RESULTS_DIR, exist_ok=True)
retry_count = {}

def get_images():
    r = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                       capture_output=True, text=True, timeout=30)
    return set(l.strip() for l in r.stdout.strip().split("\n") if l.strip() and "none" not in l)

def get_results():
    results = {}
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE) as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    results[r["task_id"]] = r
    return results

def get_in_progress():
    r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
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

def find_ready(tasks, images, results, in_progress):
    ready = []
    retry = []
    done_ok = {tid for tid, r in results.items() if r.get("success")}
    done_fail = {tid for tid, r in results.items() if not r.get("success")}
    
    for t in tasks:
        tid = t["task_id"]
        if tid in in_progress or tid in done_ok:
            continue
        typ, _, sub = tid.partition(":")
        prefix = "n132/arvo" if typ == "arvo" else "cybergym/oss-fuzz"
        if f"{prefix}:{sub}-vul" not in images or f"{prefix}:{sub}-fix" not in images:
            continue
        if tid in done_fail:
            if retry_count.get(tid, 0) < MAX_RETRIES:
                retry.append(tid)
        else:
            ready.append(tid)
    return ready, retry

def launch(task_ids, wave_num):
    ids_str = " ".join(task_ids)
    cmd = (f"cd {BENCHMARK} && python3 -m eval.run_parallel "
           f"--task-ids {ids_str} --workers {len(task_ids)} "
           f"--out-dir {RESULTS_DIR} --resume --no-cleanup "
           f">> {RESULTS_DIR}/wave{wave_num}.log 2>&1")
    subprocess.Popen(["bash", "-c", cmd])

def write_log(msg):
    with open("/tmp/sustainable_status.log", "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    print(msg, flush=True)

def main():
    tasks = json.load(open(f"{BENCHMARK}/data-meta/tasks.json"))
    wave = 600
    last_report = 0

    write_log(f"Sustainable runner: {len(tasks)} tasks, max {MAX_CONCURRENT}")

    while True:
        try:
            imgs = get_images()
            results = get_results()
            in_prog = get_in_progress()
            ready, retry = find_ready(tasks, imgs, results, in_prog)
            
            ok = sum(1 for r in results.values() if r.get("success"))
            n_done = len(results)
            n_img = len([i for i in imgs if "arvo" in i or "oss-fuzz" in i])
            slots = MAX_CONCURRENT - len(in_prog)

            # Load check
            with open("/proc/loadavg") as f:
                load1 = float(f.read().split()[0])

            now = time.time()
            if now - last_report > 300:
                by_proj = {}
                for r in results.values():
                    p = r.get("project", "?")
                    by_proj.setdefault(p, [0, 0])
                    by_proj[p][0] += 1
                    if r.get("success"): by_proj[p][1] += 1
                
                report = f"REPORT: {ok}/{n_done} = {ok/n_done*100:.1f}% | imgs={n_img} run={len(in_prog)} ready={len(ready)} retry={len(retry)} load={load1:.0f}"
                for p, (t, s) in sorted(by_proj.items(), key=lambda x: -x[1][0]):
                    report += f"\n  {p}: {s}/{t}"
                write_log(report)
                last_report = now

            # Don't launch if load is too high (>60 on 8 CPUs)
            if load1 > 60:
                print(f"[{time.strftime('%H:%M:%S')}] load={load1:.0f} HIGH, waiting...", flush=True)
                time.sleep(30)
                continue

            if slots > 0:
                batch = []
                if ready:
                    batch = ready[:min(BATCH_SIZE, slots)]
                elif retry:
                    batch = retry[:min(3, slots)]
                    for tid in batch:
                        retry_count[tid] = retry_count.get(tid, 0) + 1
                        # Remove old result
                        with open(RESULTS_FILE) as f:
                            lines = f.readlines()
                        with open(RESULTS_FILE, "w") as f:
                            for line in lines:
                                if line.strip() and json.loads(line)["task_id"] not in batch:
                                    f.write(line)
                    write_log(f"Retrying {len(batch)}: {' '.join(batch)}")

                if batch:
                    wave += 1
                    launch(batch, wave)
                    write_log(f"[wave {wave}] +{len(batch)}: {' '.join(batch)}")

            print(f"[{time.strftime('%H:%M:%S')}] {ok}/{n_done}/{len(tasks)} run={len(in_prog)} load={load1:.0f}", flush=True)
        except Exception as e:
            print(f"Error: {e}", flush=True)

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
