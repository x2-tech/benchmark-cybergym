# Deployment & Local Testing

## Prerequisites

- Python 3.12+
- Docker Desktop (with Rosetta emulation on Apple Silicon, or an x86-64 Linux host)
- An OpenAI-compatible API endpoint (DeepSeek, Qwen, etc.)

## 1. Environment Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e 'third_party/cybergym-upstream[server]'
.venv/bin/pip install pytest
```

## 2. Configuration

Copy and edit `.env`:

```bash
OPENAI_BASE_URL=https://api.deepseek.com/v1
OPENAI_API_KEY=sk-your-key
CYBERGYM_MODEL=deepseek-v4-pro
CYBERGYM_REASONING_MODEL=deepseek-v4-pro   # used for hypothesis planning
# CYBERGYM_CHEAP_MODEL=deepseek-flash      # optional, unused for now

# optional cost tracking
CYBERGYM_PRICE_IN=0.14
CYBERGYM_PRICE_OUT=0.28
```

The agent reads all config from environment variables. See `agent/config.py` for the
full list.

## 3. Start the Verification Server

The server runs per-task Docker images to verify PoCs. Pull images for the tasks
you want to test:

```bash
docker pull --platform linux/amd64 n132/arvo:1065-vul
docker pull --platform linux/amd64 n132/arvo:1065-fix
```

Start the server:

```bash
.venv/bin/python -m cybergym.server --host 127.0.0.1 --port 8666 \
    --log_dir server_poc --db_path server_poc/poc.db
```

## 4. Run a Single Task

```bash
.venv/bin/python -m agent --task-id arvo:1065 --difficulty level2
```

This runs the full agent loop: crash extraction, hypothesis planning, PoC generation,
oracle submission, and verification.

## 5. Batch Evaluation

Run N tasks sampled from the task pool:

```bash
.venv/bin/python -m eval.run --tasks data-meta/tasks.json --n 20 --difficulty level2
```

Filter by project, type, or explicit task IDs:

```bash
# specific projects only
.venv/bin/python -m eval.run --n 10 --projects graphicsmagick binutils

# explicit task IDs
.venv/bin/python -m eval.run --task-ids arvo:1065 arvo:10400

# filter by language
.venv/bin/python -m eval.run --n 10 --languages c cpp
```

Results go to `runs/results.jsonl` (per-task) and `runs/summary.json` (aggregate).

## 6. Generate Leaderboard Report

```bash
.venv/bin/python -m report.report --run-dir runs --agent-name my-agent
```

## 7. Task Profiling (New)

The agent now classifies tasks into three categories with different strategies:

| Category | Fuzz Duration | LLM Budget | Hypotheses | When |
|---|---|---|---|---|
| `text` | 0s | full (20 tool calls) | 3 | Text-based tasks (patch, config) |
| `simple_binary` | 60s | full (20 tool calls) | 2 | Known LLM-solvable binaries |
| `complex_binary` | 180s | reduced (12 calls) | 1 | Fuzz-primary targets |

Classification is automatic based on project name and description keywords.
Override behavior by editing `agent/profile.py`.

## 8. Running Tests

```bash
.venv/bin/python -m pytest tests/ -v
```

Current suite: 60 tests covering agent parsing, crash extraction, evidence tracking,
hypothesis planning, memory, profile classification, feedback parsing, trivial crash
detection, and tool integration.

## 9. Selftest (Grading Machinery Validation)

Validate that the verification server correctly scores a known-good PoC:

```bash
.venv/bin/python -m eval.selftest --task-id arvo:1065 --poc /path/to/ref-poc.bin
```

This does NOT test the agent — it validates the grading infrastructure.

## Troubleshooting

- **Docker wedges on Apple Silicon**: Enable Rosetta emulation in Docker Desktop
  settings, or restart Docker Desktop between large runs.
- **Server connection refused**: Ensure `CYBERGYM_SERVER=http://127.0.0.1:8666`
  matches the running server, or leave it unset (defaults to `127.0.0.1:8666`).
- **Missing images**: Each task needs its `{vul,fix}` image pair. The server will
  return errors for tasks whose images aren't pulled.
