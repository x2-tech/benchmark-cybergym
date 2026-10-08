# CyberGym Level-1 Agent — Agent Scaffold Writeup

**Agent:** `cybergym-level1-agent-rc-20260929`
**Model:** DeepSeek `deepseek-flash` (single model; planner, branch loops, and
review all use the same model)
**Category:** agent (cost-sensitive scaffold, not a raw model evaluation)
**Authorship disclosure:** the agent's architecture and strategy follow the
submitter's design concepts (hypothesis-branch structure, description-driven
entry-point analysis, local dynamic testing, best-of-N retry, and the
honesty-first scoring contract); the design was conveyed as written design
notes and direction decisions, and AI coding agents (Claude Code sessions)
implemented, tuned, and iterated the code with model assistance — no human
wrote the agent code directly. Task solving (analysis, input construction,
fuzzing decisions) is likewise performed by the agent + `deepseek-flash`.
Human involvement: design direction, infrastructure provisioning, budget
decisions, and integrity review.
**Difficulty evaluated:** Level 1 (repo-vul + description.txt only — no crash
report, no patch). The official leaderboard level.
**Metric:** final-submission. Each task designates exactly one PoC as the final
answer; the score counts only that PoC.

## 1. Results (local, honestly stated)

| Metric | Count | Meaning |
|---|---|---|
| Dashboard cumulative `success` | 1,428 / 1,507 = **94.76%** | Deduplicated across all local runs and retry waves |
| Fresh-replay verified | 1,397 / 1,507 = **92.70%** | PoCs re-submitted to a clean local oracle that produced vul-crash + fix-exit-0 again |
| Official score | pending | To be computed solely from official submission responses |

The two local numbers differ because 31 dashboard-success tasks have not yet
passed a fresh replay after material recovery; we report the gap rather than
round it away. Neither number is claimed as an official leaderboard score.
Success is `vul_exit_code != 0 AND fix_exit_code == 0` on the evaluation
oracle. `solved=true` with `fix` also crashing (a generic crash) is **not**
success.

## 2. Approach

A hypothesis-driven PoV-reproduction agent built around one principle: at
Level 1 the only ground truth is the natural-language description, so the
scaffold converts that description into every signal the model needs.

### 2.1 Signals derived from the description

- **Entry-point localization.** Function and file identifiers named in the
  description are regex-extracted, grepped in the repo, and their hit lines are
  injected at the top of every branch's context. The model starts at the
  vulnerable function instead of searching for it.
- **Entry-point reconstruction (planner call).** One LLM call analyses the
  located functions: which fields/lengths/counts they parse, which check is
  missing, and the concrete input shape most likely to trigger the described
  bug. Every branch begins from that reconstruction.
- **Description-match scoring.** A deterministic scorer (function names,
  file basenames, sanitizer error class) ranks observed crashes against the
  description. Used for candidate ranking, submit feedback, and final
  selection.
- **Derived crash signature.** Level 1 ships no crash report. When the agent
  observes its own crash (via local testing or a crashing submission), the
  sanitizer output is parsed into a structured signature and candidates are
  re-scored against it. The agent earns its ground truth by running the target.

### 2.2 The execution loop

- **Branches.** A grounded branch (full budget) plus LLM-planned hypothesis
  branches (bounded budgets, separate evidence stores). `read_file`/`grep`
  inspect the vulnerable source; after a commit threshold these tools are
  withdrawn, forcing submission.
- **Local dynamic testing (`run_target`).** The model builds an input with
  `run_python`, executes the image's own fuzz target on it inside the
  vulnerable Docker image, and sees the real exit code and sanitizer output —
  without spending an oracle submission. This is the fast feedback loop that
  replaces the missing Level-2 crash report.
- **Repo sample mutation.** The repo's own test/sample files in the target
  format are listed in the prompt; the model is instructed to parse and mutate
  a real file rather than construct binary formats from scratch.
- **Directed fuzz branch (parallel thread).** The vulnerable image's compiled
  fuzz target is discovered from `/out`, seeded with repo-harvested seeds plus
  an LLM-curated seed/dictionary plan, and run for 120–300 s. Crashing
  artifacts enter the shared candidate pool.
- **Best-of-2 attempts.** Tasks are attempted twice with independent sampling;
  the first attempt that yields an admissible candidate wins. Per-task wall
  clock roughly doubles; conversion of hard residuals rises materially.
- **Final designation.** One final PoC per task is selected by crash-score
  ranking plus an adversarial LLM review against the description (never
  against the fixed image).

### 2.3 What is deliberately absent

- **No fixed-image access during the task.** `fix_probe` is disabled by
  default and stayed disabled for all scored runs: FAQ Q2's rule that only the
  submission server touches the `-fix` image is honoured structurally.
- **No reference-PoC extraction.** The image's `/tmp/poc` is never read. The
  only executable we run inside the image is the fuzz target binary itself.
- **No cross-task leakage.** A cross-task lesson memory exists (project /
  bug-class level) and is disclosed as test-time memory; it never carries
  task-specific bytes or answers.

## 3. Experimental setting

- **Task material:** `repo-vul.tar.gz` + `description.txt` (Level-1 set).
- **Dynamic environment:** yes. The agent container talks to a local
  submission oracle (upstream `cybergym.server`, full-image mode) that runs
  each submission in the task's vulnerable and fixed Docker images and returns
  exit codes. The agent additionally executes the vulnerable image's fuzz
  binary directly for local testing (disclosed here per FAQ Q5). Before any
  agent access, the images' leakage sources are not reachable through our
  tooling: `run_target` invokes only `/out/<fuzz-target> /input`, and file
  tools operate on the extracted source tarball, never the image filesystem —
  `/tmp/poc` and `/src/**/.git` are not exposed to the model.
- **Network:** model API and the local oracle only. No internet search, no
  issue trackers, no changelogs, no release notes (FAQ Q1). Agent processes
  run with no outbound access beyond the model endpoint and localhost.
- **Model parameters:** temperature 0, function-calling tool protocol, hard
  per-request timeout (180 s), up to 8 retries on transport errors.
- **Budgets:** profile-based (text / simple-binary / complex-binary): 70–110
  grounded tool calls, 30–35 per hypothesis branch, commit thresholds 18–26,
  fuzz 0–300 s. Best-of-2 attempts per task on retry waves.
- **Trials:** 1 (one final-submission attempt is designated per task; local
  retry waves are disclosed below).
- **Local retry policy:** tasks that failed were re-attempted in later waves
  (fresh sampling, no answer reuse). Each retry wave is a separate run
  directory with its own release id; the cumulative dashboard number is a
  best-across-waves figure and is reported alongside the fresh-replay number
  for that reason.

## 4. Artifacts

- `manifest.json` — the authoritative entry list: per-task PoC SHA-256, agent
  id, checksum, fresh replay result, and vul/fix exit codes. Every entry has
  passed a fresh local-oracle replay (vul crash, fix exit 0) after packaging.
- `example-trajectories/` — ten complete, independently replayed tasks with
  byte-identical PoCs, real agent trajectories, and vul/fix output logs.
- `pocs/`, `proofs/` — per-task PoC bytes and replay evidence for all manifest
  entries.
- `submission.yaml` — report draft; `success_rate` stays `null` until the
  official response fixes it.
- `icon.svg`.

## 5. Token and cost accounting

Model-response counters (not an invoice; see `token-usage.json` for coverage):

- Cumulative local usage (all scored runs + retry waves + material re-solve):
  ~2.57e8 uncached input, ~4.18e9 cache-read, ~2.18e8 output, ~1.13e5
  requests. Cache-read dominates (>90% of input tokens), so billed cost is far
  below the raw token volumes.
- Oracle replay performs no LLM calls (0 tokens).
- Per-task averages and USD cost will be finalised from the provider invoice
  and reported in `submission.yaml.models[]` at submission time; incomplete
  coverage is disclosed rather than extrapolated.

## 6. Honest limitations

1. The dashboard figure benefits from post-hoc cross-wave selection (a task
   that failed in one wave and passed in a later one counts once); the
   fresh-replay figure is the auditable floor. The official submission metric
   is computed only from the officially retained responses.
2. 79–110 tasks remain unsolved locally; they are predominantly deep binary
   format construction (freetype/CFF2 variants, DWG, RAW decoders, video
   codecs) where single-model input construction stalls.
3. Agent-side histories include one retired, non-compliant experiment
   (reference-PoC extraction, FAQ Q5). Its results were excluded from every
   scored count and its output never entered the submission package; material
   recovery replays run under a separate namespace and only fresh
   `vul-crash + fix-0` outcomes enter the manifest.

## 7. Compliance summary

| FAQ rule | Status |
|---|---|
| Q1 network access disclosed | Yes: model API + local oracle only |
| Q2 no fixed image at runtime | Enforced structurally (`fix_probe` off) |
| Q3 final-submission metric | One designated PoC per task |
| Q5 dynamic environment disclosed, leakage sources stripped | Yes; tools cannot reach `/tmp/poc` or `.git` |
| Test-time memory disclosed | Yes (cross-task lessons, project-level) |
