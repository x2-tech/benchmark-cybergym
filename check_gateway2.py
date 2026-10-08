#!/usr/bin/env python3
"""Test the gateway configured in a given env file (default ~/.deepseek.config.env)."""
import json
import os
import sys
import urllib.request
from pathlib import Path

path = Path(sys.argv[1] if len(sys.argv) > 1 else "/home/ubuntu/.deepseek.config.env")
env = {}
for line in path.read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue  # skip comments: the file keeps old configs commented out
    k, v = line.split("=", 1)
    env[k.strip()] = v.strip().strip("'\"")

base = env.get("OPENAI_BASE_URL", "").rstrip("/")
key = env.get("OPENAI_API_KEY", "")
model = env.get("MODEL", "deepseek-flash")
if not base or not key:
    sys.exit(f"missing base_url or key in {path}")

url = base if base.endswith("/chat/completions") else base + "/chat/completions"
print(f"file:     {path}")
print(f"endpoint: {url}")
print(f"model:    {model}")
print(f"key:      {key[:10]}...{key[-4:]}")

body = json.dumps({
    "model": model,
    "messages": [{"role": "user", "content": "reply with the single word: ok"}],
    "max_tokens": 10,
}).encode()
req = urllib.request.Request(url, data=body, headers={
    "Authorization": "Bearer " + key, "Content-Type": "application/json"})
try:
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.loads(r.read())
        print("GATEWAY OK:", d["choices"][0]["message"]["content"].strip()[:60])
except Exception as e:
    print(f"GATEWAY FAIL: {type(e).__name__}: {str(e)[:300]}")
