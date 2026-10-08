#!/usr/bin/env python3
"""Fix dashboard schema normalization.

Some records carry BOTH keys with disagreeing values, e.g.
    {"solved": true, "success": false}
because the LLM runner wrote `success: false` and a later PoC-extraction pass
appended `solved: true` to the same record. A task is solved if EITHER says so,
so `success` must be OR'd with `solved`, not merely defaulted from it.
"""
from pathlib import Path

p = Path("/tmp/dashboard.py")
src = p.read_text()

OLD = '''            # poc-extract writes `solved`; the LLM runner writes `success`.
            if "success" not in r:
                r["success"] = bool(r.get("solved"))'''

NEW = '''            # Records may carry both keys with disagreeing values: the LLM
            # runner writes `success`, a later PoC-extraction pass appends
            # `solved`. Solved wins if either is true.
            r["success"] = bool(r.get("success")) or bool(r.get("solved"))'''

if OLD not in src:
    raise SystemExit("ERROR: normalization block not found")

src = src.replace(OLD, NEW, 1)
p.write_text(src)
print("fixed OK")
