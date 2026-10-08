#!/usr/bin/env python3
"""Verify the API gateway in .env actually answers. Reads .env directly."""
import json
import os
import urllib.request
from pathlib import Path

env = Path("/home/ubuntu/Benchmark/.env")
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip("'\""))

base = os.environ["OPENAI_BASE_URL"].rstrip("/")
url = base if base.endswith("/chat/completions") else base + "/chat/completions"
model = os.environ.get("MODEL", "deepseek-flash")

body = json.dumps({
    "model": model,
    "messages": [{"role": "user", "content": "reply with the single word: ok"}],
    "max_tokens": 10,
}).encode()

req = urllib.request.Request(
    url, data=body,
    headers={"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"],
             "Content-Type": "application/json"},
)
print(f"endpoint: {url}")
print(f"model:    {model}")
try:
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.loads(r.read())
        txt = d["choices"][0]["message"]["content"].strip()
        print(f"GATEWAY OK: {txt[:60]}")
except Exception as e:
    print(f"GATEWAY FAIL: {type(e).__name__}: {str(e)[:300]}")
