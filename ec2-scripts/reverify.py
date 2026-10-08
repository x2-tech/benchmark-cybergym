"""Re-verify tasks that found PoCs but timed out during verification."""
import json, sys, os
sys.path.insert(0, os.path.expanduser("~/Benchmark"))
from pathlib import Path
from eval.verify import verify_final
from agent.tasks import assemble_task, download_task, LEVEL_FILES

server = "http://127.0.0.1:8666"
api_key = os.getenv("CYBERGYM_API_KEY", "cybergym-030a0cd7-5908-4862-8ab9-91f2bfc7b56d")
data_dir = Path(os.path.expanduser("~/Benchmark/data"))

# Find tasks with solved=True but no successful verification
unverified = []
seen = {}
for l in open(os.path.expanduser("~/Benchmark/runs/ec2-full/results.jsonl")):
    d = json.loads(l)
    seen[d["task_id"]] = d

for tid, d in sorted(seen.items()):
    if d.get("solved") and d.get("fix_exit_code") is None and not d.get("success"):
        poc_path = Path(os.path.expanduser(f"~/Benchmark/work/{tid.replace(:, _)}/poc"))
        if poc_path.exists():
            unverified.append((tid, poc_path, d))

print(f"Found {len(unverified)} tasks to re-verify")

results = []
for tid, poc_path, orig in unverified:
    poc = poc_path.read_bytes()
    print(f"Verifying {tid}...", end=" ", flush=True)
    try:
        download_task(tid, data_dir, files=LEVEL_FILES["level2"])
        task_dir = Path(os.path.expanduser(f"~/Benchmark/runs/ec2-full/tasks/{tid.replace(:, _)}"))
        task = assemble_task(tid, data_dir, task_dir, server, "level2")
        ver = verify_final(poc, tid, task["agent_id"], task["checksum"], server, api_key=api_key)
        status = "SUCCESS" if ver.success else f"FAIL (fix_exit={ver.fix_exit_code})"
        print(status)
        results.append({"task_id": tid, "success": ver.success, "fix_exit_code": ver.fix_exit_code})
    except Exception as e:
        print(f"ERROR: {e}")
        results.append({"task_id": tid, "success": False, "error": str(e)})

# Write results
with open("/tmp/reverify_results.json", "w") as f:
    json.dump(results, f, indent=2)

successes = sum(1 for r in results if r.get("success"))
print(f"\nResults: {successes}/{len(results)} verified successfully")
