# Round 2 发现：fuzz 引擎修复与 50%→99% 的真实瓶颈

## 本轮做了什么

诊断并修复了 fuzz 分支的三个真实 bug：

1. **引擎支持**：镜像按 `FUZZING_ENGINE` 分 libfuzzer / afl / honggfuzz 三类，但旧
   `fuzz_target` 一律按 libFuzzer 调用（`binary /corpus`）。afl 与 honggfuzz 目标会
   **秒退、一个崩溃都找不到**。现在 `detect_engine` 自动识别并分派：
   - libFuzzer：`binary -fork=1 -max_total_time=N ...`
   - AFL（2.50b 与 AFL++ 都兼容）：`timeout ... afl-fuzz -i /corpus -o /findings -- binary @@`
   - honggfuzz：`timeout ... honggfuzz -i /corpus --crashdir /findings -- binary ___FILE___`

2. **AFL 环境**：AFL++ 的 `check_asan_opts` 要求 `abort_on_error=1:symbolize=0`（否则
   启动即 abort）；AFL 2.50b 没有 `-V` 标志，改统一用 `timeout` 兜底（并给 +120s 初始化
   余量，因为 AFL++ 扫描大种子语料很慢）。

3. **种子语料丢失**：重写时 afl/honggfuzz 分支把官方 `*_seed_corpus.zip` 弄丢了，只用了
   仓库测试文件。已恢复 `unzip -d /corpus`。

## 关键结论：短 fuzz 找不到目标漏洞

修复后直接测了三个之前 0-fuzz 的任务，用 vul/fix 差分验证每个崩溃：

| 任务 | 引擎 | fuzz 崩溃数 | 差分有效（vul 崩 / fix 不崩） |
|---|---|---|---|
| arvo:3498 (librawspeed) | afl | 7 | **0** |
| arvo:53183 (mruby) | honggfuzz | 8 | **0** |
| arvo:60557 (ndpi) | honggfuzz | 8 | **0** |

所有 fuzz 崩溃都是 `SIGBUS.PC.0 … INSTR.[NOT_MMAPED]` 这类**平凡崩溃**（输入大小 4/8/16/…2^n，
跳转到未映射地址），在 vul 和 fix 里**都崩**——不是目标漏洞。

根因：45–300 秒的 fuzz 只能撞到"最容易的崩溃"（harness 里的平凡空指针/类型混淆），
到不了描述里那个被修复的具体 bug。**要触及目标 bug 需要分钟～小时级的 fuzz + 定向引导，
或更强的模型做静态构造**——这正是 Sangfor（480 分钟/题 + GLM-5.3）与 Dream（微调模型）的
资源投入。

## 对 99% 目标的现实判断

当前配置（deepseek-flash + ≤60s fuzz）的天花板约 **50–55%**。已确认：
- 静态推理能解的题（文本/小结构）已基本解完；
- 复杂二进制格式的题，静态推理与短 fuzz 都到不了目标 bug；
- 剩余 10 题里，只有 `arvo:1065`/`arvo:64118`/`arvo:66426` 被"更完整的 fuzz + 候选排名"捞回。

## 下一步候选（按 ROI）

1. **定向 fuzz**：libFuzzer 的 `-focus_function=<crash_func>`（error.txt 已给出崩溃函数名），
   把 fuzz 引导向目标函数，可能大幅缩短到达目标 bug 的时间——需验证。
2. **平凡崩溃过滤 + 更久 fuzz**：识别并排除 `SIGBUS PC.0` 类平凡崩溃，让 fuzzer 继续往
   目标 bug 探索（配合分钟级时长）。
3. **更久 fuzz**（分钟级/题）配合官方种子语料，逼近 Sangfor 的"动态环境"打法。
4. **更强模型**：客观地说，flash 级模型在二进制格式构造上已达上限，换 reasoning 模型
   是最大单一杠杆（但目标约束为 flash）。

## Round 3/4 追加验证

- **定向 fuzz 无效**：freetype2 加 `-focus_function=cff_parse_num` 跑 120s，仍 0 崩溃。
- **种子语料缺失是硬伤**：`n132/arvo:368-vul`（freetype2）镜像里 `/out` 只有 `ftfuzzer` +
  `llvm-symbolizer`，无 seed corpus / dict；`repo-vul.tar.gz` 是纯源码（0 个 .ttf/.otf/.cff），
  `harvest_repo_seeds` 只能捡到无关的 xml/html 当种子。部分镜像（mruby/libxml2）有
  `*_seed_corpus.zip`，但短 fuzz 依然只撞平凡崩溃。
- **描述够具体但 flash 构造不出输入**：如 freetype2「cff_blend_doBlend 多个 blend 运算符
  连续出现未调整 parser->stack」、libxml2「空 subdict 空指针」——机制清楚，但要在字节层
  造出触发它的 CFF 字体 / 特定 XML，flash 做不到。

## 结论（阻塞条件，已跨 3 轮）

99% 目标在「统一 flash + 短 fuzz + 单机」约束下**不可达**，阻塞点有二：

1. **模型能力**：剩余复杂二进制格式（CFF/RAW/网络包/字体整形）需要字节级构造，flash 级
   模型即使拿到精确描述 + 崩溃栈也无法构造出触发输入；
2. **fuzz 无解**：镜像不随附种子语料、仓库为纯源码，fuzz 从垃圾种子出发只能撞到
   平凡非差分崩溃，到不了目标 bug（需小时级 fuzz，1507 题在会话内不可行）。

