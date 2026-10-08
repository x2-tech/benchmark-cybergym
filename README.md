# X-Nebula — CyberGym Level-1 Agent

**X-Nebula**（X2 Team, https://m4x2.team）is a cost-sensitive, single-model
(`deepseek-flash`) agent scaffold for CyberGym's Level-1 vulnerability
reproduction tasks: given only the vulnerable source and a natural-language
description, it produces a PoC input that crashes the vulnerable build while
leaving the patched build clean.

## Result (frozen 2026-10-08)

| Metric | Score |
|---|---|
| Dashboard cumulative | **1,450 / 1,507 = 96.22%** |
| Fresh-replay verified (auditable) | **1,434 / 1,507 = 95.16%** |
| Official score | pending submission |

- Writeup: [WRITEUP.md](WRITEUP.md) / [WRITEUP.zh-CN.md](WRITEUP.zh-CN.md)
- Full submission package (84MB): [Release v1.0](https://github.com/x2-tech/benchmark-cybergym/releases/tag/v1.0)
- Authoritative entry list: `submission/manifest.json`
- Internal engineering retrospective: `docs/RETROSPECTIVE.zh-CN.md`

The gap between the two local numbers (16 tasks) is disclosed, not rounded
away. Success = `vul crash + fix exit 0` verified by the evaluation oracle.
