#!/usr/bin/env python3
"""Probe a mismatch task: is the fix-build crash deterministic? Same signal?

If fix build crashes only sometimes, the ref PoC is fine and the oracle/harness
is flaky. If it crashes every time, the mismatch is genuine and needs a
*targeted* input that distinguishes the two builds.
"""
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import urllib.request
import uuid

SERVER = "http://127.0.0.1:8666"
SALT = "CyberGym"
API_KEY = "cybergym-030a0cd7-5908-4862-8ab9-91f2bfc7b56d"


def extract_poc(image: str) -> bytes:
    cid = subprocess.check_output(
        ["docker", "create", "--platform", "linux/amd64", image, "sleep", "30"],
        text=True,
    ).strip()
    try:
        raw = subprocess.check_output(["docker", "cp", f"{cid}:/tmp/poc", "-"])
        with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
            return tf.extractfile(tf.getmembers()[0]).read()
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)


def submit(poc: bytes, task_id: str, agent_id: str, checksum: str, endpoint: str) -> dict:
    metadata = json.dumps({
        "task_id": task_id, "agent_id": agent_id,
        "checksum": checksum, "require_flag": False,
    })
    b = "----cg" + uuid.uuid4().hex
    body = (
        f'--{b}\r\nContent-Disposition: form-data; name="metadata"\r\n\r\n{metadata}\r\n'
    ).encode()
    body += (
        f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="poc"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    body += poc + f"\r\n--{b}--\r\n".encode()
    h = {"Content-Type": f"multipart/form-data; boundary={b}"}
    if endpoint == "/submit-fix":
        h["X-API-Key"] = API_KEY
    req = urllib.request.Request(f"{SERVER}{endpoint}", data=body, method="POST", headers=h)
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read().decode())


def main():
    tid = sys.argv[1]
    runs = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    arvo_sub = tid.split(":")[1]
    vul_img = f"n132/arvo:{arvo_sub}-vul"

    poc = extract_poc(vul_img)
    print(f"PoC size: {len(poc)} bytes", flush=True)

    vul_exits, fix_exits = [], []
    fix_outputs = []
    for i in range(runs):
        aid = uuid.uuid4().hex
        ck = hashlib.sha256(f"{tid}{aid}{SALT}".encode()).hexdigest()
        vr = submit(poc, tid, aid, ck, "/submit-vul")
        fr = submit(poc, tid, aid, ck, "/submit-fix")
        v = vr.get("exit_code")
        f = fr.get("exit_code")
        vul_exits.append(v)
        fix_exits.append(f)
        fix_outputs.append((fr.get("output") or "")[-300:])
        print(f"--- run {i+1} ---", flush=True)
        print(f"  vul_exit={v}  fix_exit={f}", flush=True)

    print("\n=== SUMMARY ===", flush=True)
    print(f"vul exits: {vul_exits}", flush=True)
    print(f"fix exits: {fix_exits}", flush=True)
    if all(x == 0 for x in fix_exits):
        print("VERDICT: fix build is FLAKY — ref PoC works. Retry until it passes.", flush=True)
    elif len(set(fix_exits)) > 1:
        print("VERDICT: fix build NONDETERMINISTIC — retry may succeed.", flush=True)
    else:
        print("VERDICT: fix build crashes consistently — genuine mismatch, needs LLM.", flush=True)
        print("\nLast fix output tail:", flush=True)
        print(fix_outputs[-1], flush=True)


if __name__ == "__main__":
    main()
