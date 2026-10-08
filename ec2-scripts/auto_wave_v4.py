"""Auto-wave v4: max throughput, continuous pull for all 1507 tasks."""
import json, subprocess, time, os

BENCHMARK = "/home/ubuntu/Benchmark"
RESULTS_DIR = f"{BENCHMARK}/runs/ec2-full"
RESULTS_FILE = f"{RESULTS_DIR}/results.jsonl"
CHECK_INTERVAL = 15
MAX_CONCURRENT = 30  # Tasks are API-bound, not CPU/mem bound
BATCH_SIZE = 10

os.makedirs(RESULTS_DIR, exist_ok=True)

def get_images():
    r = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                       capture_output=True, text=True)
    return set(l.strip() for l in r.stdout.strip().split("\n") if l.strip() and "none" not in l)

def get_done():
    done = set()
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE) as f:
            for line in f:
                if line.strip():
                    done.add(json.loads(line)["task_id"])
    return done

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

def find_ready(tasks, images, done, in_progress):
    ready = []
    for t in tasks:
        tid = t["task_id"]
        if tid in done or tid in in_progress:
            continue
        typ, _, sub = tid.partition(":")
        prefix = "n132/arvo" if typ == "arvo" else "cybergym/oss-fuzz"
        if f"{prefix}:{sub}-vul" in images and f"{prefix}:{sub}-fix" in images:
            ready.append(tid)
    return ready

def launch(task_ids, wave_num):
    ids_str = " ".join(task_ids)
    cmd = (f"cd {BENCHMARK} && python3 -m eval.run_parallel "
           f"--task-ids {ids_str} --workers {len(task_ids)} "
           f"--out-dir {RESULTS_DIR} --resume --no-cleanup "
           f">> {RESULTS_DIR}/wave{wave_num}.log 2>&1")
    subprocess.Popen(["bash", "-c", cmd])
    print(f"[wave {wave_num}] +{len(task_ids)}: {ids_str}", flush=True)

def get_stats():
    ok = total = 0
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE) as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    total += 1
                    if r.get("success"): ok += 1
    return ok, total

def main():
    # Load ALL tasks, not just first 50
    tasks = json.load(open(f"{BENCHMARK}/data-meta/tasks.json"))
    wave = 400
    
    # Track how many tasks we're targeting
    target = len(tasks)
    print(f"Auto-wave v4: {target} tasks, max {MAX_CONCURRENT} concurrent", flush=True)

    while True:
        imgs = get_images()
        done = get_done()
        in_prog = get_in_progress()
        ready = find_ready(tasks, imgs, done, in_prog)
        ok, n_done = get_stats()
        
        n_img = len([i for i in imgs if "arvo" in i or "oss-fuzz" in i])
        slots = MAX_CONCURRENT - len(in_prog)
        
        # Memory and load info
        try:
            with open("/proc/loadavg") as f:
                load1 = f.read().split()[0]
            with open("/proc/meminfo") as f:
                lines = f.readlines()
                total_mem = int(lines[0].split()[1]) // 1024
                avail_mem = int(lines[2].split()[1]) // 1024
                used_pct = round((1 - avail_mem/total_mem) * 100)
        except:
            load1 = "?"
            used_pct = "?"

        print(f"[{time.strftime('%H:%M:%S')}] imgs={n_img} done={ok}/{n_done}/{target} "
              f"run={len(in_prog)} ready={len(ready)} load={load1} mem={used_pct}%",
              flush=True)

        if n_done >= target:
            pct = ok/n_done*100 if n_done else 0
            print(f"ALL {target} TASKS DONE! {ok}/{n_done} = {pct:.1f}%", flush=True)
            break

        if ready and slots > 0:
            batch = ready[:min(BATCH_SIZE, slots)]
            wave += 1
            launch(batch, wave)

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
