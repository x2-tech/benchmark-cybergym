# docs 目录索引（2026-10-07 更新）

| 文件 | 状态 | 说明 |
|------|------|------|
| `RETROSPECTIVE.zh-CN.md` | ✅ 最新 | 全工程复盘（28 个问题→解法→教训），内部用 |
| `ARCHITECTURE.md` | ⚠️ 旧版 | 2026-09-11 编写（20 题样本时代）。当前架构以
  仓库根 `WRITEUP.md` 的 §2 Approach 为准（含 level1 四件套、run_target、
  入口点分析、best-of-2、无限重试），待重写 |
| `DEPLOY.md` | ⚠️ 旧版 | EC2 基础部署仍适用；但当前还有 9 个 cron
  （包刷新/重放/池子监督器/三清理/看门狗/跨级清单/批次监控）未记录，待补 |
| `archive/` | 历史存档 | 9/11 时代的 WRITEUP（0.35 时代）、RESULTS-v2、
  PLAN、FINDINGS-round2 —— **数字已过时勿引用**（当时含后来被判定为
  作弊的 /tmp/poc 提取数据），仅作历史参考 |

**权威文件位置**：
- 提交 writeup（双语）：仓库根 `WRITEUP.md` / `WRITEUP.zh-CN.md`（同步在
  `official-submission-level1-20260930/` 内）
- 权威成绩与材料：`official-submission-level1-20260930/manifest.json`
- 实时状态：`http://3.87.69.200:8082/`（V3 看板）
- 剩余事项：仓库根 `TODO.md`
