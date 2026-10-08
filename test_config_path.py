#!/usr/bin/env python3
"""Verify the exact code path run.sh uses: AgentConfig loads the env files,
then LLMClient is built from that config."""
import sys
sys.path.insert(0, "/home/ubuntu/Benchmark")

from agent.config import AgentConfig
from agent.llm import LLMClient

cfg = AgentConfig.from_env() if hasattr(AgentConfig, "from_env") else AgentConfig()
print("config base_url:", getattr(cfg, "base_url", "?"))
print("config model:   ", getattr(cfg, "model", "?"))
print("config key:     ", str(getattr(cfg, "api_key", ""))[:10] + "...")

client = LLMClient(
    base_url=cfg.base_url,
    api_key=cfg.api_key,
    model=cfg.model,
    api_key_fallback=getattr(cfg, "api_key_second", ""),
)
print("client endpoint:", client.endpoint)
txt = client.chat_text([{"role": "user", "content": "Reply with exactly: ok"}], max_tokens=200)
print("RESULT:", repr(txt.strip()[:60]))
