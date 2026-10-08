# cybergym-agent — 架构说明

本文档描述当前 agent 的多分支协调架构（在单一 DeepSeek 模型上实现的
"Sangfor Agent Swarm" 廉价版）。

## 总览

```
eval/run.py                 # 批量编排 + 最终差分校验（vul 崩溃 / fix 不崩溃）
      │
      ▼
agent/agent.py  run_task    # 协调器：规划假设 → 跑分支 → 排名 → 指定唯一 final
      ├─ hypothesis.py       # planner：从崩溃签名 + bug class 生成假设
      ├─ run_branch          # 单个隔离的探索分支（工具闭环，收集候选）
      │     ├─ evidence.py   # 证据去重（read/grep/候选输入）
      │     └─ tools.py      # read_file / grep / submit_poc（vul oracle）
      ├─ _fuzz_branch        # 镜像内定向 fuzz（与 LLM 分支并发）
      ├─ memory.py           # 跨任务记忆：按 bug class / 输入格式记录与复用经验
      └─ _designate_final    # 排名 + 对抗式评审 → 唯一 final PoC
```

## 核心设计决策

### 1. 候选集 + 唯一 final（final-submission 口径）

分支**不再在第一次崩溃时返回**。每个分支把命中的崩溃都收集为 `Candidate`，
协调器在全部候选里做去重 + 排名，最后**只指定一个 final PoC**（写盘到
`work/<task>/poc`）。真正的 vul/fix 差分校验由 `eval/verify.py` 在 agent 返回后
执行 —— agent 在搜索期间**从不访问 `-fix` 镜像**（FAQ Q2）。

### 2. 崩溃签名打分（fix-blind 的"对应性"先验）

`evidence.crash_match_score(crash, output)` 把观察到的崩溃栈和描述中的崩溃签名
逐项比对（函数名 > 文件 basename > dedup-token > sanitizer 类型），得到 0..1 分。
这是 agent 在没有 fix 侧信息时判断"这个崩溃是不是目标漏洞"的最强确定性先验。

### 3. 假设分支（有界探索）

`hypothesis.plan_hypotheses` 让 planner 提出 2..N 个互不相同的假设（输入形态 /
触发机制），每个假设开一条**隔离上下文**的分支。**grounded 分支**（签名驱动、
不加假设引导）永远第一个跑、使用完整预算，保证不劣于旧单循环基线。

### 4. 证据持久化

`evidence.EvidenceStore` 跨分支去重：
- read_file / grep 命中缓存，重复时返回 nudge 而不是再灌一遍内容；
- 候选输入按 sha1 去重，避免重复提交同一 PoC；
- 已发现的崩溃作为"事实"注入后续分支的 prompt。

### 5. 动态裁决（提前收敛）

- 分支内命中 `crash_score >= 0.7` 的自信崩溃即返回（避免为找更优解空烧 token）。
- 协调器在任一分支拿到自信候选后**停止继续开新分支**。

### 6. fuzz 一等分支（三引擎）

`fuzz.py` 的镜像内 fuzz 不再只是兜底：作为独立分支与 LLM 分支**并发**运行，用仓库
自带测试数据 + 官方种子语料/字典做种子，崩溃产物统一进候选集参与排名。

关键：镜像按 `FUZZING_ENGINE` 分为 **libfuzzer / afl / honggfuzz** 三类，`fuzz_target`
先 `detect_engine` 再分派到对应驱动（AFL 2.x 与 AFL++ 都兼容、honggfuzz 用
`--crashdir` 收崩溃、AFL 需 `abort_on_error=1:symbolize=0`）。否则 afl/honggfuzz
目标会被当成 libFuzzer 调用而**秒退、一个崩溃都找不到**。

### 7. 跨任务记忆（memory）

`memory.py` 实现"观察 → 提取 → 分类 → 应用"闭环：每题结束后把结果沉淀为一条
`Lesson`（bug class / sanitizer / 输入格式 / 是否解出 / 解法来源 / 教训），持久化到
`data-meta/memory.json`；下一题开跑前按（项目 / bug class / 输入格式）检索相关教训并
注入上下文，避免重走已知死路。输入格式用项目名 + 文件扩展名启发式归类（font / xml /
dwg / network / image / archive / …），跨项目泛化。

教训的"提取"用一次 LLM 反思（`reflect_lesson`）：把描述 + 崩溃签名 + 轨迹摘要 + 结果
喂给模型，让它写一句可复用的经验（失败在哪、下次怎么做）；模型返回空/"..."时回退到
确定性默认教训。这样记忆内容从"静态模板"升级为"每题具体观察"。

## 预算模型

| 配置 | 默认 | 含义 |
|---|---|---|
| `CYBERGYM_HYPOTHESES` | 3 | 分支数（含 grounded） |
| `CYBERGYM_GROUNDED_TOOL_CALLS` | 20 | grounded 分支工具预算（=旧单循环） |
| `CYBERGYM_BRANCH_TOOL_CALLS` | 8 | 每个假设分支工具预算 |
| `CYBERGYM_COMMIT_AT` | 8 | 读够 N 次后收回 read/grep，只留 submit |
| `CYBERGYM_STALL_STEPS` | 8 | 连续空响应 N 次才判定卡死 |
| `CYBERGYM_FUZZ_SECONDS` | 20 | 镜像内定向 fuzz 时长 |
| `CYBERGYM_REVIEW` | true | 对 final 候选做一次对抗式评审 |

## 与单循环基线的关系

`CYBERGYM_HYPOTHESES=1 CYBERGYM_FUZZ_SECONDS=0` 时，协调器退化为接近旧的
单循环 agent（grounded 分支 + 候选收集），便于 ablation 对照。
