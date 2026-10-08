#!/usr/bin/env python3
"""Delete extract_reference_poc from agent/fuzz.py.

It pulled the benchmark's own reproducer out of /tmp/poc inside the image.
CyberGym FAQ Q5 names /tmp/poc as leakage to strip from the container before the
agent sees it; submitting it is reward hacking. Remove it so it cannot be
reintroduced by accident.
"""
from pathlib import Path

p = Path("/home/ubuntu/Benchmark/agent/fuzz.py")
src = p.read_text()

start = src.index("def extract_reference_poc(")
end = src.index("def detect_engine(", start)
removed = src[start:end]
assert "/tmp/poc" in removed, "wrong slice"
assert len(removed) < 3000, f"suspiciously large: {len(removed)}"

NOTE = (
    "# NOTE: this module previously exposed extract_reference_poc(), which pulled\n"
    "# the benchmark's own reproducer out of /tmp/poc inside the image. That is\n"
    "# reward hacking, banned by CyberGym FAQ Q5, which names /tmp/poc as a\n"
    "# leakage source to strip from the container before the agent sees it. It has\n"
    "# been deleted; do not re-add it. Candidates must come from fuzzing the target.\n"
    "\n\n"
)

src = src[:start] + NOTE + src[end:]
src = src.replace("REF_POC_ATTEMPTS = 2\n", "", 1)

p.write_text(src)
print(f"removed extract_reference_poc ({len(removed)} chars)")
print("removed REF_POC_ATTEMPTS constant")
