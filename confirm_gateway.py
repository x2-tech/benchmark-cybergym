#!/usr/bin/env python3
"""Confirm the gateway returns real content via the /v1 path."""
import json
import urllib.request
from pathlib import Path

env = {}
for line in Path("/home/ubuntu/.deepseek.config.env").read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    env[k.strip()] = v.strip().strip("'\"")

base = env["OPENAI_BASE_URL"].rstrip("/") + "/v1/chat/completions"
key = env["OPENAI_API_KEY"]

for model in ["deepseek-flash", "deepseek-v4-pro"]:
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": "Reply with exactly: ok"}],
        "max_tokens": 200,
    }).encode()
    req = urllib.request.Request(base, data=body, headers={
        "Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            d = json.loads(r.read())
            msg = d["choices"][0]["message"]
            content = (msg.get("content") or "").strip()
            reasoning = (msg.get("reasoning_content") or "").strip()
            usage = d.get("usage", {})
            print(f"{model}: content={content[:50]!r} reasoning={len(reasoning)}c usage={usage}")
    except Exception as e:
        print(f"{model}: FAIL {type(e).__name__}: {str(e)[:200]}")
