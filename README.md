# cybergym-agent

A cost-sensitive PoV-reproduction agent for the [CyberGym](https://github.com/sunblaze-ucb/cybergym)
benchmark (vulnerability reproduction: produce a raw input that crashes the vulnerable
build but not the patched build). Built from scratch in this repo; targets any
OpenAI-compatible model (DeepSeek / Qwen / …) with strict token/cost accounting.

## What it does

1. **Localize** — parses `error.txt` (sanitizer report) into a structured crash
   signature (sanitizer, crash func/file:line, libFuzzer target, dedup token), then
   reads only the crash-site source + the fuzzer harness instead of the whole repo.
2. **Generate** — asks the model for a candidate input (`poc_hex` / `poc_b64` / `poc_text`).
3. **Oracle loop** — submits the candidate to the vul binary via the official
   `submit.sh` wire format; a non-zero `exit_code` means it crashed.
4. **Verify** — the final PoC must also **not** crash the fix binary (final-submission
   metric, per `SUBMISSION.md`).
5. **Report** — aggregates `success_rate` + per-model token/time/cost into
   `SUBMISSION.yaml` in the exact leaderboard schema.

## Layout

```
agent/     the agent (stdlib-only core)
eval/      batch orchestration + verification
report/    leaderboard submission generation
tests/     unit tests (pytest)
data-meta/tasks.json    1507-task metadata
third_party/cybergym-upstream/   official harness (server + task generation)
docs/PLAN.md   strategy & roadmap
```

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e 'third_party/cybergym-upstream[server]'   # server + gen_task
.venv/bin/pip install pytest                                       # dev
.venv/bin/python -m pytest                                          # 14 tests
```

## Run a single task

```bash
export OPENAI_BASE_URL=https://your-provider/v1
export OPENAI_API_KEY=sk-...
export CYBERGYM_MODEL=deepseek-chat
# optional pricing for cost report:
export CYBERGYM_PRICE_IN=0.14 CYBERGYM_PRICE_OUT=0.28   # USD / 1M tokens

# start the verification server (needs the per-task docker images, see below)
.venv/bin/python -m cybergym.server --host 127.0.0.1 --port 8666 \
    --log_dir server_poc --db_path server_poc/poc.db

.venv/bin/python -m agent --task-id arvo:1065 --difficulty level2
```

## Batch evaluation + report

```bash
.venv/bin/python -m eval.run --tasks data-meta/tasks.json --n 20 --difficulty level2
.venv/bin/python -m report.report --run-dir runs --agent-name my-agent
```

## Server images

Verification runs the per-task docker images (`n132/arvo:<id>-{vul,fix}`,
`cybergym/oss-fuzz:<id>-{vul,fix}`). Pull only what you need:

```bash
docker pull --platform linux/amd64 n132/arvo:1065-vul
docker pull --platform linux/amd64 n132/arvo:1065-fix
```

## Environment notes

- **This is a macOS/Apple-Silicon caveat**: the target images are x86-64 Linux.
  Docker Desktop's amd64 emulation works but is unstable under heavy
  sanitizer loads on this machine (observed to wedge after one large run,
  requiring a Docker Desktop restart). For a reliable oracle loop, either
  enable **Rosetta emulation** in Docker Desktop, or run the server + agent on an
  **x86-64 Linux host**. The agent code itself is platform-independent.
- Data files are downloaded per-task from the CyberGym HuggingFace dataset; the
  full 10TB image set is never required — only the images for the tasks you run.
