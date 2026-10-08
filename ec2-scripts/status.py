#!/usr/bin/env python3
"""One-shot eval status summary (run on the EC2 host)."""
import json
from collections import Counter
from pathlib import Path

RESULTS = Path("/home/ubuntu/Benchmark/runs/ec2-full/results.jsonl")

INFRA = ("402", "IncompleteRead", "transport error", "connection error",
         "stalled", "No space", "download",
         # API-side transport failures — retried automatically, not task failures
         "TimeoutError", "timed out", "RemoteDisconnected", "HTTP 5")


def classify(err: str) -> str:
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
        return "(none: fix-eval pending)"
    return e[:44]


latest = {}
for line in RESULTS.read_text(errors="replace").splitlines():
    if line.strip():
        r = json.loads(line)
        latest[r["task_id"]] = r

solved = sum(1 for r in latest.values() if r.get("success"))
failed = [r for r in latest.values() if not r.get("success")]
print("LATEST: %d/%d = %.1f%% | Failed: %d"
      % (solved, len(latest), 100 * solved / len(latest), len(failed)))

pending = [r for r in failed if r.get("fix_exit_code") is None]
print("\n-- causes --")
for k, v in Counter(classify(r.get("error", "")) for r in failed).most_common():
    print("  %2dx %s" % (v, k))
print("  (%d of the above are fix-eval still pending, not failures)" % len(pending))

print("\n-- CRASH-SIGNATURE MISMATCHES (fix_exit_code != 0) --")
mm = [r for r in failed if r.get("fix_exit_code") not in (None, 0)]
if mm:
    for r in mm:
        print("  %-22s %-12s vul=%s fix=%s solved_by=%s"
              % (r["task_id"], r.get("project"), r.get("vul_exit_code"),
                 r.get("fix_exit_code"), r.get("solved_by")))
else:
    print("  none")
print("  total: %d" % len(mm))

real = [r for r in failed
        if (r.get("error") or "").strip()
        and not any(x in (r.get("error") or "") for x in INFRA)]
print("\n-- real failures by project (>=2 shown) --")
c = Counter(r.get("project", "?") for r in real)
for proj, n in c.most_common():
    if n >= 2:
        print("  %-14s %d" % (proj, n))
print("\n-- real failures --")
for r in sorted(real, key=lambda x: x.get("project", "")):
    print("  %-22s %-12s %s"
          % (r["task_id"], r.get("project"), (r.get("error") or "")[:46]))
