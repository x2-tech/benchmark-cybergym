#!/usr/bin/env python3
"""Make LLMClient tolerate an API gateway base URL.

Previously any base_url not ending in /chat/completions got that suffix
appended verbatim, so a gateway base like https://cf.api.fan resolved to
https://cf.api.fan/chat/completions -> 404. Gateways conventionally serve the
OpenAI-compatible surface under /v1, so insert /v1 when the base carries no
path at all. Bases that already specify a path (including ones ending in /v1)
are left untouched.
"""
from pathlib import Path
from urllib.parse import urlsplit

p = Path("/home/ubuntu/Benchmark/agent/llm.py")
src = p.read_text()

OLD = """        if base_url.endswith("/"):
            base_url = base_url[:-1]
        if not base_url.endswith("/chat/completions"):
            base_url += "/chat/completions"
        self.endpoint = base_url"""

NEW = """        if base_url.endswith("/"):
            base_url = base_url[:-1]
        if not base_url.endswith("/chat/completions"):
            # A bare host has no path, but gateways and most providers serve
            # the OpenAI-compatible surface under /v1. An explicit path (e.g.
            # ".../v1" or a self-hosted "/api/openai") is used as given.
            if not urlsplit(base_url).path:
                base_url += "/v1"
            base_url += "/chat/completions"
        self.endpoint = base_url"""

assert OLD in src, "endpoint construction block not found"
src = src.replace(OLD, NEW, 1)

if "from urllib.parse import urlsplit" not in src:
    anchor = "from typing import Any"
    assert anchor in src, "import anchor not found"
    src = src.replace(anchor, "from urllib.parse import urlsplit\n" + anchor, 1)

p.write_text(src)
print("patched agent/llm.py")
