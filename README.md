# X-Nebula

A cost-sensitive, single-model agent scaffold for **CyberGym Level-1
vulnerability reproduction**: given only the vulnerable source and a
natural-language description (no crash report, no patch), it produces a PoC
input that crashes the vulnerable build while leaving the patched build clean.

## Result (frozen 2026-10-08)

| Metric | Score |
|---|---|
| Fresh-replay verified (submission metric) | **1434 / 1507 = 95.16%** |
| Dashboard cumulative (disclosed for contrast) | 1450 / 1507 = 96.22% |
| Bad package entries | 0 |

The 16-task gap between the two numbers is disclosed, not rounded away.
Success = `vul crash + fix exit 0`, verified by the evaluation oracle.

## How it works

The core idea: at Level 1 the only ground truth is the description, so the
scaffold converts it into every signal the model needs — entry-point
localization, LLM reconstruction of the vulnerable function's input contract,
a deterministic description-match scorer, local dynamic testing
(`run_target` runs the image's own fuzz binary), a parallel directed-fuzz
branch, and best-of-2 attempts. One final PoC is designated per task.
See the architecture diagram and full method in
[WRITEUP.md](WRITEUP.md) / [WRITEUP.zh-CN.md](WRITEUP.zh-CN.md).

## Submission materials

- **Full submission package** (12MB tar, 1434 verified entries, 10 example
  trajectories, pocs/proofs, manifest, bilingual writeup, icon):
  [Release `submission`](https://github.com/x2-tech/benchmark-cybergym/releases/tag/submission)
- Authoritative entry list: [`submission/manifest.json`](submission/manifest.json)
- Report: [`submission/submission.yaml`](submission/submission.yaml)
- Internal engineering retrospective (28 incident post-mortems):
  [`docs/RETROSPECTIVE.zh-CN.md`](docs/RETROSPECTIVE.zh-CN.md)

---

*Maintained by [M4X2 Team](https://m4x2.team), powered by [X2 Tech](https://github.com/x2-tech).*
