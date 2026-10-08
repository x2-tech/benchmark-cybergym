# CyberGym 官方提交 TODO（2026-10-07 状态）

## 当前成绩
- **Level 1 dashboard: 1444/1507 = 95.89%**（持续爬升，2 小时/轮重试）
- 包条目（fresh-replay 验证）: 1417+，坏条目 0，完整示例 10
- Level 2 冻结: 1429 纯口径（94.82%）/ 1474 并集（97.81%）

## 机器侧（AI 自动/进行中）
- [ ] **缺口 23 题专项波**（r5，8 shard，运行中）—— dashboard 成功但缺 fresh proof 的题，
      全部需重解出新 PoC（16 题 PoC 已丢 + 7 题旧 PoC 重放失败）
- [ ] 池子重试继续（缺口优先排序已修；2 小时/轮；转化 5-10%/轮的硬核残余）
- [ ] 全部跑完后：最终验证 → 冻结包 → `success_rate` 以 fresh-replay 数定稿
- [ ] 材料吸收链路保持（重放 cron 10 分钟 + 包刷新 cron 15 分钟）

## 用户侧（需要你做）
- [ ] **发布 writeup**：建公开 GitHub 仓库（建议内容：WRITEUP.md + WRITEUP.zh-CN.md +
      agent 源码 + manifest.json + icon.svg），把 URL 填进 submission.yaml 的 `link`
- [ ] **定 cost**：从 DeepSeek API 账单取实际金额；token 底数已备好
      （主评测 2.27亿 in / 33.2亿 cache / 1.89亿 out / 95,691 请求 + 材料波 0.30亿 / 8.69亿 / 0.29亿 / 17,587 请求）
- [ ] **官方提交**：邮件 zhun.wang@berkeley.edu 或 GitHub issue，附
      official-submission-level1-20260930 包（85MB：pocs/ proofs/ manifest 示例 icon writeup）
- [ ] **归档官方回复**，official_score 从回复计算（当前保持 null）

## 本地已同步的资产（/Users/i/Desktop/Benchmark/）
- `official-submission-level1-20260930/` —— 官方提交包（85MB，本次同步）
- `agent/`、`eval/` —— 最新代码（EC2 演化版，含假期 session 的 run_parallel 等）
- `WRITEUP.md` + `WRITEUP.zh-CN.md` —— 双语 writeup（含作者披露）
- `docs/RETROSPECTIVE.zh-CN.md` —— 复盘文档（28 问题，仅内部）
- `backup_from_ec2/` —— level2 备份 tar、cross_level_manifest、verify_current.py

## 诚实性纪律（不变）
- 唯一 success 口径（vul 崩 + fix=0，oracle 判定）
- 排除 poc-extract 系的独立重算 = 与 dashboard 精确一致
- 双口径披露（fresh-replay vs dashboard）不四舍五入
- success_rate 保持 null 直到官方定稿
