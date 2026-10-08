#!/usr/bin/env python3
"""Probe gateway path/model variants to find the one that answers."""
import json
import urllib.request
import urllib.error
from pathlib import Path

path = Path("/home/ubuntu/.deepseek.config.env")
env = {}
for line in path.read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    env[k.strip()] = v.strip().strip("'\"")

base = env["OPENAI_BASE_URL"].rstrip("/")
key = env["OPENAI_API_KEY"]

paths = ["/chat/completions", "/v1/chat/completions"]
models = [env.get("MODEL", "deepseek-flash"), "deepseek-chat", "deepseek-v3", "gpt-4o-mini"]

for p in paths:
    for m in models:
        url = base + p
        body = json.dumps({"model": m, "max_tokens": 10,
                           "messages": [{"role": "user", "content": "say ok"}]}).encode()
        req = urllib.request.Request(url, data=body, headers={
            "Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                d = json.loads(r.read())
                txt = d["choices"][0]["message"]["content"].strip()[:40]
                print(f"OK    {p:24s} {m:16s} -> {txt}")
        except urllib.error.HTTPError as e:
            detail = e.read()[:120].decode(errors="replace")
            print(f"HTTP{e.code} {p:24s} {m:16s} -> {detail}")
        except Exception as e:
            print(f"ERR   {p:24s} {m:16s} -> {type(e).__name__}: {str(e)[:90]}")

# Also try listing models, which usually reveals the right id.
for p in ["/models", "/v1/models"]:
    req = urllib.request.Request(base + p, headers={"Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            d = json.loads(r.read())
            ids = [m.get("id") for m in d.get("data", [])][:15]
            print(f"MODELS {p} -> {ids}")
    except Exception as e:
        print(f"MODELS {p} -> {type(e).__name__}: {str(e)[:90]}")
