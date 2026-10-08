# CyberGym 提交 TODO（2026-10-08 冻结版）

## ✅ 已冻结的最终结果
- **Level 1 dashboard: 1450/1507 = 96.22%**
- **Fresh-replay 验证（可审计下界）: 1434/1507 = 95.16%**（16 题缺口如实披露）
- 坏条目 0 / 完整示例 10 / icon-x2.ico / Agent 名 X-Nebula
- Level 2 冻结存档: 1429 纯口径（94.82%）/ 1474 并集
- 远程任务全部停止（解题类 cron 已停，保留 3 个清理类）

## 用户侧剩余三步（按序）
- [ ] **提交**：邮件 zhun.wang@berkeley.edu 或 GitHub issue
      - link: https://github.com/x2-tech/benchmark-cybergym
      - 附件：Release v1.0 的 tar（13MB）或指向 Release URL + icon-x2.ico
      - 正文含 submission.yaml（link 填上述 URL、cost 按 DeepSeek 账单填入）
- [ ] **cost 定稿**：DeepSeek 账单金额 → submission.yaml 的 est_usd_cost
      （token 底数：2.57亿 in / 41.8亿 cache / 2.18亿 out / 11.3万请求；93% 输入命中缓存）
- [ ] **归档官方回复** → official_score 从回复计算（当前保持 null）

## 可选（提交后）
- [ ] README 门面已写（X-Nebula + 冻结数字）；ARCHITECTURE/DEPLOY 重写
- [ ] 同事交叉验证（docs/VERIFICATION-GUIDE.md 五节）
- [ ] EC2 机器：确认无费用后可关闭（清理 cron 无害但机器按小时计费）
