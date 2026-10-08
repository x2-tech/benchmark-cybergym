#!/usr/bin/env python3
"""End-to-end check: real LLMClient against the gateway config."""
import os
import sys
from pathlib import Path

sys.path.insert(0, "/home/ubuntu/Benchmark")
env = {}
for line in Path("/home/ubuntu/.deepseek.config.env").read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    env[k.strip()] = v.strip().strip("'\"")

from agent.llm import LLMClient

c = LLMClient(base_url=env["OPENAI_BASE_URL"], api_key=env["OPENAI_API_KEY"],
              model=env.get("MODEL", "deepseek-flash"))
print("endpoint:", c.endpoint)
try:
    txt = c.chat_text([{"role": "user", "content": "Reply with exactly: ok"}], max_tokens=200)
    print("chat_text ->", repr(txt.strip()[:60]))
except Exception as e:
    print("FAIL:", type(e).__name__, str(e)[:200])

try:
    d = c.chat_json([{"role": "user",
                      "content": 'Return JSON {"status":"ok","n":1}'}], max_tokens=200)
    print("chat_json ->", d)
except Exception as e:
    print("FAIL json:", type(e).__name__, str(e)[:200])
