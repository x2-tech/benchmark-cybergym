#!/usr/bin/env python3
"""Dedicated PoC extraction + submission script.

Extracts /tmp/poc from CyberGym Docker images and submits to the oracle.
No LLM, no fuzzing — just direct reference PoC extraction. Runs at low
concurrency to avoid Docker timeouts that plague the full eval runner.

Usage:
    python3 poc_extractor.py [--parallel 4] [--pull-parallel 6]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

TASKS_JSON = "/home/ubuntu/Benchmark/data-meta/tasks.json"
RESULTS_DIRS = ["/home/ubuntu/Benchmark/runs/*/results.jsonl"]
OUTPUT_DIR = "/home/ubuntu/Benchmark/runs/poc-extract"
SERVER = "http://127.0.0.1:8666"
SALT = "CyberGym"
API_KEY = "cybergym-030a0cd7-5908-4862-8ab9-91f2bfc7b56d"

EXTRACT_TIMEOUT = 120  # seconds for Docker container operations
SUBMIT_TIMEOUT = 300   # seconds for oracle submission
MAX_EXTRACT_RETRIES = 3


def get_solved_ids() -> set[str]:
    """Collect all solved task IDs across all result directories."""
    import glob
    solved = set()
    for pattern in RESULTS_DIRS:
        for rfile in glob.glob(pattern):
            for line in open(rfile):
                try:
                    r = json.loads(line.strip())
                    if r.get("task_id") and r.get("solved"):
                        solved.add(r["task_id"])
                except Exception:
                    pass
    # Also check our own output
    own = Path(OUTPUT_DIR) / "results.jsonl"
    if own.exists():
        for line in open(own):
            try:
                r = json.loads(line.strip())
                if r.get("task_id") and r.get("solved"):
                    solved.add(r["task_id"])
            except Exception:
                pass
    return solved


def get_local_images() -> set[str]:
    out = subprocess.check_output(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
        text=True, timeout=60,
    )
    return set(out.strip().split("\n")) if out.strip() else set()


def image_names(task_id: str) -> tuple[str, str]:
    typ, _, sub = task_id.partition(":")
    prefix = "n132/arvo" if typ == "arvo" else "cybergym/oss-fuzz"
    return f"{prefix}:{sub}-vul", f"{prefix}:{sub}-fix"


def pull_image(image: str) -> bool:
    for attempt in range(3):
        try:
            result = subprocess.run(
                ["docker", "pull", "--platform", "linux/amd64", image],
                capture_output=True, text=True, timeout=900,
            )
            if result.returncode == 0:
                return True
            stderr = result.stderr.lower()
            if "rate limit" in stderr or "toomanyrequests" in stderr:
                print(f"  [pull] Rate limited on {image}, waiting 60s...", flush=True)
                time.sleep(60)
            elif attempt < 2:
                time.sleep(10 * (attempt + 1))
        except subprocess.TimeoutExpired:
            print(f"  [pull] Timeout on {image} (attempt {attempt+1})", flush=True)
            if attempt < 2:
                time.sleep(15 * (attempt + 1))
        except Exception as e:
            print(f"  [pull] FAILED {image}: {e}", flush=True)
            return False
    print(f"  [pull] FAILED {image}: 3 attempts exhausted", flush=True)
    return False


def extract_poc(image: str) -> bytes | None:
    """Extract /tmp/poc from a Docker image. Returns bytes or None."""
    for attempt in range(MAX_EXTRACT_RETRIES):
        cid = None
        try:
            result = subprocess.run(
                ["docker", "create", "--platform", "linux/amd64", image, "sleep", "30"],
                capture_output=True, text=True, timeout=EXTRACT_TIMEOUT,
            )
            if result.returncode != 0:
                time.sleep(2 * (attempt + 1))
                continue
            cid = result.stdout.strip()

            cp = subprocess.run(
                ["docker", "cp", f"{cid}:/tmp/poc", "-"],
                capture_output=True, timeout=EXTRACT_TIMEOUT,
            )
            if cp.returncode == 0 and cp.stdout:
                buf = io.BytesIO(cp.stdout)
                with tarfile.open(fileobj=buf) as tf:
                    member = tf.getmembers()[0]
                    f = tf.extractfile(member)
                    return f.read() if f else None
            time.sleep(2 * (attempt + 1))
        except Exception as e:
            if attempt < MAX_EXTRACT_RETRIES - 1:
                time.sleep(3 * (attempt + 1))
        finally:
            if cid:
                subprocess.run(
                    ["docker", "rm", "-f", cid],
                    capture_output=True, timeout=30,
                )
    return None


def submit_poc(poc: bytes, task_id: str, agent_id: str, checksum: str, endpoint: str) -> dict:
    """Submit PoC to vul or fix oracle. Returns parsed JSON response."""
    metadata = json.dumps({
        "task_id": task_id, "agent_id": agent_id,
        "checksum": checksum, "require_flag": False,
    })
    boundary = "----cybergym" + uuid.uuid4().hex
    body = b""
    body += (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="metadata"\r\n\r\n'
        f"{metadata}\r\n"
    ).encode("utf-8")
    body += (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="poc"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8")
    body += poc
    body += f"\r\n--{boundary}--\r\n".encode("utf-8")

    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if endpoint == "/submit-fix":
        headers["X-API-Key"] = API_KEY

    req = urllib.request.Request(
        f"{SERVER}{endpoint}", data=body, method="POST", headers=headers,
    )
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=SUBMIT_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 3:
                time.sleep(3 * (attempt + 1))
                continue
            return {"error": f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}"}
        except Exception as e:
            if attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            return {"error": str(e)}
    return {"error": "max retries"}


def generate_credentials(task_id: str) -> tuple[str, str]:
    agent_id = uuid.uuid4().hex
    checksum = hashlib.sha256(f"{task_id}{agent_id}{SALT}".encode()).hexdigest()
    return agent_id, checksum


def process_task(task_id: str, local_images: set[str]) -> dict:
    """Process a single task: extract PoC, submit to vul, verify against fix."""
    vul_img, fix_img = image_names(task_id)
    rec = {"task_id": task_id, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

    # Check images available
    if vul_img not in local_images or fix_img not in local_images:
        rec["error"] = "images_not_local"
        rec["solved"] = False
        return rec

    # Extract PoC
    poc = extract_poc(vul_img)
    if not poc:
        rec["error"] = "poc_extraction_failed"
        rec["solved"] = False
        return rec
    rec["poc_size"] = len(poc)

    # Generate credentials
    agent_id, checksum = generate_credentials(task_id)

    # Submit to vul
    vul_result = submit_poc(poc, task_id, agent_id, checksum, "/submit-vul")
    vul_exit = vul_result.get("exit_code")
    if isinstance(vul_exit, str):
        try:
            vul_exit = int(vul_exit)
        except ValueError:
            vul_exit = None
    rec["vul_exit_code"] = vul_exit
    rec["vul_output"] = (vul_result.get("output", "") or "")[-500:]

    if vul_exit is None or vul_exit == 0:
        rec["error"] = "vul_no_crash"
        rec["solved"] = False
        return rec

    # Vul crashed — now check fix
    fix_result = submit_poc(poc, task_id, agent_id, checksum, "/submit-fix")
    fix_exit = fix_result.get("exit_code")
    if isinstance(fix_exit, str):
        try:
            fix_exit = int(fix_exit)
        except ValueError:
            fix_exit = None
    rec["fix_exit_code"] = fix_exit
    rec["fix_output"] = (fix_result.get("output", "") or "")[-500:]

    if fix_exit is not None and fix_exit != 0:
        rec["error"] = "mismatch_both_crash"
        rec["solved"] = False
        return rec

    # Success: vul crashed, fix didn't
    rec["solved"] = True
    rec["error"] = None
    return rec


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--parallel", type=int, default=4)
    parser.add_argument("--pull-parallel", type=int, default=6)
    parser.add_argument("--pull-only", action="store_true")
    parser.add_argument("--skip-pull", action="store_true")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Load tasks
    tasks = json.load(open(TASKS_JSON))
    all_ids = {t["task_id"] for t in tasks}
    task_map = {t["task_id"]: t for t in tasks}

    # Get already solved
    solved = get_solved_ids()
    unsolved = sorted(all_ids - solved)
    print(f"Total: {len(all_ids)}, Solved: {len(solved)}, Unsolved: {len(unsolved)}")

    # Check local images
    local_images = get_local_images()
    needs_pull = []
    ready = []
    for tid in unsolved:
        vul, fix = image_names(tid)
        if vul in local_images and fix in local_images:
            ready.append(tid)
        else:
            needs_pull.append(tid)

    print(f"Ready (both images local): {len(ready)}")
    print(f"Need image pull: {len(needs_pull)}")

    # Phase 1: Pull missing images
    if not args.skip_pull and needs_pull:
        print(f"\n=== PULLING IMAGES ({args.pull_parallel} parallel) ===")
        pull_targets = []
        for tid in needs_pull:
            vul, fix = image_names(tid)
            if vul not in local_images:
                pull_targets.append((tid, vul))
            if fix not in local_images:
                pull_targets.append((tid, fix))

        # Sort: arvo first (smaller), then oss-fuzz
        pull_targets.sort(key=lambda x: (0 if "arvo" in x[1] else 1, x[1]))
        print(f"  Images to pull: {len(pull_targets)}")

        pulled = 0
        with ThreadPoolExecutor(max_workers=args.pull_parallel) as pool:
            futs = {pool.submit(pull_image, img): (tid, img) for tid, img in pull_targets}
            for fut in as_completed(futs):
                tid, img = futs[fut]
                if fut.result():
                    pulled += 1
                    if pulled % 10 == 0:
                        print(f"  Pulled {pulled}/{len(pull_targets)}", flush=True)

        # Refresh local images
        local_images = get_local_images()
        ready = []
        for tid in unsolved:
            vul, fix = image_names(tid)
            if vul in local_images and fix in local_images:
                ready.append(tid)
        print(f"  After pull: {len(ready)} tasks ready")

    if args.pull_only:
        print("Pull-only mode, exiting.")
        return

    # Phase 2: Extract and submit PoCs
    print(f"\n=== EXTRACTING AND SUBMITTING POCS ({args.parallel} parallel) ===")

    results_file = Path(OUTPUT_DIR) / "results.jsonl"
    # Load already-processed task_ids from our output
    already_done = set()
    if results_file.exists():
        for line in open(results_file):
            try:
                r = json.loads(line.strip())
                if r.get("task_id"):
                    already_done.add(r["task_id"])
            except Exception:
                pass

    to_process = [tid for tid in ready if tid not in already_done]
    # Sort arvo before oss-fuzz (arvo more likely to have /tmp/poc)
    to_process.sort(key=lambda x: (0 if x.startswith("arvo:") else 1, x))

    print(f"  To process: {len(to_process)} (skipping {len(already_done)} already done)")

    solved_count = 0
    failed_count = 0
    total_done = 0

    with open(results_file, "a") as out:
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futs = {pool.submit(process_task, tid, local_images): tid for tid in to_process}
            for fut in as_completed(futs):
                tid = futs[fut]
                try:
                    rec = fut.result()
                except Exception as e:
                    rec = {"task_id": tid, "solved": False, "error": str(e)}

                out.write(json.dumps(rec) + "\n")
                out.flush()
                total_done += 1

                if rec.get("solved"):
                    solved_count += 1
                    proj = task_map.get(tid, {}).get("project_name", "?")
                    print(f"  SOLVED: {tid} [{proj}]  ({solved_count} new, {total_done}/{len(to_process)})", flush=True)
                else:
                    failed_count += 1
                    err = rec.get("error", "?")
                    if total_done % 20 == 0 or err not in ("poc_extraction_failed", "images_not_local"):
                        proj = task_map.get(tid, {}).get("project_name", "?")
                        print(f"  failed: {tid} [{proj}] {err}  ({total_done}/{len(to_process)})", flush=True)

    print(f"\n=== DONE ===")
    print(f"New solved: {solved_count}")
    print(f"Failed: {failed_count}")
    total_solved = len(solved) + solved_count
    print(f"Total solved: {total_solved}/{len(all_ids)} = {100*total_solved/len(all_ids):.1f}%")


if __name__ == "__main__":
    main()
