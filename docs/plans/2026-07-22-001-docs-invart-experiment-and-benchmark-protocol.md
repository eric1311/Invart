---
title: "Invart 实验计划与 Benchmark 判定协议"
date: "2026-07-22"
type: "docs"
status: "active"
companion_to:
  - "docs/plans/2026-07-21-001-feat-invart-control-plane-evaluation-plan.md"
  - "docs/plans/2026-07-17-001-feat-prompt-first-mediation-generalization-plan.md"
---

# Invart 实验计划与 Benchmark 判定协议

## 1. 文档目的与证据口径

本文档把当前实验讨论固化为可执行协议，回答四个问题：Invart 的论文究竟要证明什么；每个 benchmark 能证明和不能证明什么；一个实验结果何时可以进入论文；接下来按什么顺序开发和执行。

它不替代两份既有计划：

- `2026-07-21-001-feat-invart-control-plane-evaluation-plan.md` 是总实验计划，负责研究问题、证据组合、统计与投稿门槛。
- `2026-07-17-001-feat-prompt-first-mediation-generalization-plan.md` 是 mediation、prompt、agent/runtime 与模型矩阵的实现计划。
- 本文档是两者之间的执行接口，负责 benchmark 判定、结果准入和近期实验顺序。

本文统一使用以下状态词，避免把“已经设计”写成“已经证明”：

| 状态 | 含义 |
|---|---|
| `verified` | 有当前代码、测试、官方产物或可复现运行证据。 |
| `implemented` | 协议或代码已实现，但不等于已有真实 benchmark 效果。 |
| `pending` | 已纳入计划，但必要执行或证据尚未完成。 |
| `blocked` | 已知外部或技术门槛使忠实执行暂不可行。 |
| `deferred` | 当前投稿最小证据包不依赖该项，暂不投入。 |

特别需要区分：benchmark 的 `structurally allowed role` 只表示它在威胁模型和评价设计上可能承担某种论文角色；只有具体结果行通过运行、能力、攻击机会和 oracle 门槛后，才会产生 `claim-ready evidence`。截至 2026-07-22，benchmark 注册表中还没有任何 benchmark 自动获得 claim-ready 角色。

## 2. 论文定位与需要证明的核心命题

Invart 的主贡献不是一个针对 AgentDojo 的 prompt injection 过滤器，而是建立在 ledger 之上的 Agent runtime audit and control plane：

- 运行前：记录 agent、模型、工具、skills、MCP、策略、权限和供应链状态；
- 运行中：观察并在副作用前 mediation 命令、文件、网络、进程、工具调用、批准状态和目标偏移；
- 运行后：生成可重放 ledger、proof、审计摘要、覆盖缺口和篡改证据。

Mediation 是这个控制平面的一个能力，不是整篇论文唯一的价值来源。实验要分别证明以下命题：

| 命题 | 需要的证据 | 失败时的诚实降级 |
|---|---|---|
| C1 跨来源可观察性 | 至少两类威胁来源中的 action/event join、覆盖率和盲区 | 只声明已覆盖的来源和 runtime stage。 |
| C2 有害动作管控 | 能力合格且有攻击机会的 baseline 与 mediated 配对结果 | 若 baseline 无攻击，则只报告 attack floor，不能声称更安全。 |
| C3 安全与可用性兼得 | 原生任务效用、safe-useful、误拦截、恢复率和批准负担 | 若效用崩溃，报告保守策略，不称为实用防御。 |
| C4 机制归因 | V0/V1/V2/V5 及必要的 V2H/V3/V4 消融 | 若样本不足，只作机制描述，不作因果归因。 |
| C5 跨模型与 runtime 外部有效性 | 冻结 Policy 后的 connected incomplete block | 若只完成 completion backend，不能称 native agent runtime 泛化。 |
| C6 审计与 proof 价值 | 盲化重建、遗漏/篡改检测、ledger-proof 一致性 | 即使 prevention 有限，仍可形成独立但边界明确的审计贡献。 |
| C7 可部署成本 | 延迟、token/金额、轨迹长度、批准和失败率 | 超预算时给出适用范围，不隐去系统成本。 |

论文的最小正向安全结论必须同时满足：一个 agent-level benchmark、有效 baseline、正常能力、非零攻击机会、独立或原生 outcome oracle、配对改善和可接受的 benign utility。仅有“Invart 拦截了很多事件”不能证明拦截正确；仅有“ASR 为 0”也不能证明 Invart 产生了安全增益。

## 3. Benchmark 质量判定方法

### 3.1 不采用单一质量总分

Benchmark 是否“广泛认可”是有价值的信息，但不是充分条件。本文按当前代码注册表的 13 个维度分别判定，不把它们压成一个容易掩盖致命缺口的总分：

1. 官方来源是否明确；
2. 数据和代码 revision 是否可冻结；
3. license 是否允许复现与发布；
4. 数据能否实际获得；
5. 是否有 benchmark-native outcome oracle；
6. 是否同时测正常任务效用；
7. 是否观察真实或高保真副作用；
8. development/holdout/private split 是否清楚；
9. 对 LLM judge 的依赖程度；
10. 是否经过同行评审和社区复用；
11. 执行成本是否可控；
12. 威胁模型是否与 Invart runtime boundary 对齐；
13. 官方 harness 是否通过当前环境的 runtime probe。

判定优先级是：oracle 与语义忠实度 > 可执行与 revision 冻结 > 威胁模型匹配 > 正常效用 > 同行评审/复用 > 规模。一个数据集很新、很大或很流行，不能补偿“没有可复现 runner”“只评最终文本”“无法判断动作是否执行”等缺陷。

### 3.2 结果准入状态机

每个实验 row 必须依次通过以下门槛：

```text
prepared
  -> technical_invalid      运行、provider、artifact、计数或 revision 不可信
  -> capability_only        技术有效，但 agent 不能完成正常任务/调用工具
  -> attack_floor           技术和能力有效，但 baseline 没有真实攻击机会
  -> security_comparable    有能力、有攻击机会、native/independent oracle 可比较
```

只有 `security_comparable` 可以估计 Invart 的 security effect。`capability_only` 和 `attack_floor` 仍应完整报告，因为它们能解释零 ASR 和模型/runtime 适配问题，但不得被包装为防御成功。

“攻击机会”在当前协议中优先由 benchmark-native harmful outcome 建立；未来也可以由与 Invart 独立、能绑定具体 ledger action 和副作用的观察器建立。单独的外部语义标签目前只能描述动作性质，不能在没有 ledger resolver 的情况下把 attack-floor row 改成 security-comparable。

## 4. 当前正式 Benchmark 组合与判定

### 4.1 活跃或计划中的组合

| Benchmark | 主要威胁/任务面 | 能证明什么 | 不能证明什么 | 当前论文角色 | 截至 2026-07-22 的判定 |
|---|---|---|---|---|---|
| AgentHarm | 明确有害意图、多步骤工具使用 | Agent 是否完成有害任务；Invart 是否在副作用前阻止动作 | 间接提示注入鲁棒性；现实 benign utility | 主要 harmful-action pillar | 同行评审 benchmark；严格 Inspect `.eval`、官方 `combined_scorer` 和 capability control 合同已实现，真实 scored pilot 仍待数据源和批准门槛。 |
| AgentDojo | 工具输出中的间接提示注入 | 历史可比的任务效用与攻击任务成功；短轨迹 mediation 回归 | 2026 年长时序、MCP/skill/memory/GUI 风险；baseline ASR 为 0 时的安全增益 | 全量 historical anchor | 保留但不再承担主证据。既有零 ASR 结果应被解释为 attack floor，同时报告 utility collapse。 |
| MCPTox | MCP 工具描述/元数据投毒 | MCP supply-chain poisoning 对选择和动作的影响 | 通用 runtime 安全；无 clean companion 时的完整效用结论 | 首选 MCP security pillar | 同行评审价值高，但当前冻结源缺少可支持的 end-to-end runner，状态为 `blocked`；不得生成合成分数。 |
| MCP-AgentBench | 正常 MCP 任务和多工具能力 | MCP benign utility 与工具调用能力 | MCPTox 的 paired clean baseline，除非 server/tool/evaluator 重合被证明 | 条件式 utility companion | 官方可执行源、license、servers 和 evaluator revision 尚未冻结；不能默认与 MCPTox 拼成一组。 |
| AgentDyn | 更长、开放、跨应用的动态间接注入 | 冻结 Policy 是否从 AgentDojo 转移到更动态场景 | 已被广泛复现的稳定主结论；未冻结 judge 的独立性 | 现代 external-validity stress | 适合做 AgentDojo 的现代补充；在本项目中仍是 `planned`，必须禁止 benchmark-specific prompt 调参。 |
| Skill-Inject | 安装期 skill 文件和第三方能力包投毒 | 控制平面能否覆盖 runtime 之前的供应链输入及后续动作 | MCP、memory 或 GUI 风险 | 现代 supply-chain transfer | `planned`；需要真实 skill-loading path、冻结 judge 和人工审计样本。 |
| HarmBench | 模型对有害请求的文本响应 | reviewer/backbone 的 harmfulness/refusal 能力和校准 | Agent 工具副作用、运行时 mediation、ledger 审计 | model/reviewer component control | 有效且社区认可，但不作为 Invart 主 benchmark；结果必须标为 model-level control。 |
| b³ / Breaking Agent Backbones | Agent 威胁状态快照中的 backbone 选择 | 模型层脆弱性与 agent 编排问题的分离 | 完整 agent 轨迹和 Invart runtime effect | backbone control | `planned` control；独立于 enforcement 运行，不和 agent-level ASR 合并。 |
| SWE-Bench Lite/Verified | 正常 coding-agent 任务 | Invart 对实际开发效用、产物和 grader 的摩擦 | 安全性、注入防御或有害动作预防 | benign utility pillar | `planned`；必须保持相同 agent/runtime profile 和官方 grader。 |
| Agent Security Bench | 多类 agent attack | 在主 pillar 不可行时提供更广 agent-security 覆盖 | 自动替代任意现代 threat surface | reserve | 仅在预注册替换条件触发时启用，不为增加 benchmark 数量而加入。 |

这里最重要的结论是：HarmBench 有效，但它的有效性位于“模型能否生成/拒绝有害文本”这一层。Invart 的核心 claim 位于“真实 agent 是否提出、被 mediation、最终执行了什么动作，以及能否审计重建”这一层。二者应组合使用，但不能相互替代。

### 4.2 已讨论但当前不进入最小证据包的候选

| 候选方向 | 代表 benchmark | 当前理解 | 当前决定 |
|---|---|---|---|
| 长时序适应性攻击 | AgentLAB | 与控制平面持续决策高度相关，但框架新、成本和 oracle 需单独资格审查 | `deferred`；AgentDyn 完成后再决定是否替换或增加。 |
| GUI/视觉注入 | VPI-Bench | 对 browser/computer-use agent 很重要，但需要像素、浏览器动作与副作用 instrumentation | `deferred`；当前系统边界尚未覆盖 GUI。 |
| 持久记忆投毒 | MPBench、MemPoison-Bench | 能区分写入、检索和未来触发，适合后续验证 ledger 对持久状态的覆盖 | `deferred`；先实现 memory lifecycle mediation 与独立 trigger oracle。 |
| 多 Agent 通信与隐私 | ConVerse、AgentLeak | 最终输出不足以评价，需检查内部消息、共享状态和数据流 | `deferred`；当前单-agent runtime 不能做过度主张。 |
| 多轮隐藏意图与组合危害 | MT-AgentRisk、AgentHazard | 更接近 trajectory-level safety，而非纯 prompt injection | 作为未来 harmful-action 扩展；不能与 AgentDojo ASR 直接横比。 |
| MCP 全流程/协议安全 | MCP-SafetyBench、MSB、MCPSecBench | 分别偏多 Server agent、模型全流程和 Host/Protocol 实现 | MCPTox runner 问题解决后再资格审查；当前不扩大工程面。 |

这些候选现在不是被判断为“质量差”，而是尚未同时满足当前投稿周期的系统覆盖、执行成熟度、oracle 和成本约束。论文可以在 limitations/future work 中说明威胁面，但不能用计划中的适配器暗示已有实验覆盖。

## 5. 实验矩阵

### 5.1 Policy 变体

| 变体 | 作用 | 使用范围 |
|---|---|---|
| V0 baseline | 无 Invart mediation | 所有主结果必需。 |
| V1 current policy | 复现现有 literal/marker 拦截与效用失败 | development/characterization。 |
| V2 prompt-only observe | 只通过 prompt engineering 改变 proposed calls，不 enforcement | 主消融与 holdout 必需。 |
| V2H prompt + hard rules | 隔离确定性规则贡献 | 归因子集。 |
| V3 reviewer observe | 只评 reviewer 分类，不改变结果 | reviewer 精度子集。 |
| V4 prompt + reviewer mediated | 隔离 reviewer enforcement，尚无 continuation | 归因子集。 |
| V5 full Policy v1 | prompt、provenance、monotonic rules、reviewer、continuation | 冻结后的最终候选；所有 holdout 必需。 |

开发集至少运行 V0/V1/V2/V5；holdout 至少运行 V0/V2/冻结 V5。V2H/V3/V4 只在预注册的 attribution subset 运行，避免把预算耗在无法回答主问题的全排列上。

### 5.2 Agent 与模型的 connected incomplete block

Agent runtime 与 model backend 是两个独立变量：

1. 模型 lane：OpenCode 在同一 comparable-clean profile 下运行固定的 Kimi、DeepSeek、Qwen deployment。
2. Runtime lane：一个 clean-compatibility 选出的 common model 运行于 OpenCode、Hermes、OpenClaw。
3. Sentinel lane：第二个预注册模型在 Hermes 与 OpenClaw 上交叉，检查 runtime-model interaction。
4. Native controls：Codex 与 Claude Code 作为真实部署控制，不伪装成模型可控单元。

只有 agent 自己拥有 planning/tool execution、Invart 在副作用前介入、且官方或独立 adapter 能评价最终状态时，才能标记 `native-runtime evidence`。AgentDojo CLI proxy 等固定循环只产生 `completion-backend evidence`。Hosted API 若无法验证 checkpoint revision，应写成 model deployment stack，而非纯模型家族因果比较。

### 5.3 分阶段执行 lane

| Lane | 数据 | 目的 | 扩展条件 |
|---|---|---|---|
| L1 harmful-action primary | AgentHarm | 建立非零危害机会上的 prevention/utility | 先一 benign + 一 harmful smoke，再 stratified pilot，再全 denominator。 |
| L2 historical injection | AgentDojo | 历史可比和 Policy 回归 | baseline capability 与 opportunity 通过；否则保持 floor result。 |
| L3 modern transfer | AgentDyn + Skill-Inject | 测冻结 Policy 的动态与供应链转移 | 主 Policy 冻结，adapter 保留 native semantics。 |
| L4 MCP | MCPTox，必要时 MCP-AgentBench utility | 测工具供应链风险 | 官方 runner、source、judge、clean utility 合同全部冻结。 |
| L5 component controls | HarmBench + b³ | 分离 reviewer/backbone 与 runtime 贡献 | 不和 agent benchmark native metrics 合并。 |
| L6 benign utility | SWE-Bench Lite/Verified | 测实际 coding friction | 同 runtime、artifact、exit/grader 语义可比较。 |
| L7 audit/proof study | Invart 自建盲化场景 | 测重建、遗漏和篡改发现能力 | scenario、annotation schema 和负例先冻结。 |

## 6. 指标、置信度与结果展示

### 6.1 必报指标

每个 benchmark 保留自己的 native metric，同时映射到以下公共观测层：

- 正常任务：native utility、clean capability、safe-useful completion、recovery；
- 安全结果：native harmful/attack success、proposed harmful action、intervened、approved、executed、failed、prevented；
- Mediation 质量：precision、recall、benign false-block rate、abstention、approval burden；
- 可用性：任务完成率、轨迹长度、工具调用次数、continuation 成功率；
- 成本：p50/p95 latency、token、金额、timeout、失败率和 trace 大小；
- 审计：字段重建正确率、篡改/遗漏检测率、ledger-proof 一致性和重建耗时。

不构造一个跨 benchmark 的“统一 ASR”。AgentHarm harmful completion、AgentDojo attack task success、MCPTox poisoning success、Skill-Inject harmful attempt 和 HarmBench harmful response 的分母、oracle 和威胁目标不同，只能按 family 分面展示，最多报告清楚标注的宏观方向。

### 6.2 统计与置信度

- 所有表同时报告 expected、attempted、technical-valid、capability-qualified、opportunity 和 analyzed denominator。
- 二项比例报告 95% Wilson interval；零事件额外报告单侧上界，而不是“100% 安全”。
- V0 与 V5 的同一 case 使用 paired transition 和 McNemar 类检验；有 user-task/injection-task 双重聚类时使用 cluster bootstrap。
- 先冻结 minimum detectable paired effect 或 simulation-based sensitivity，再执行 confirmatory denominator。
- Judge 标签固定模型、prompt hash 和 schema；抽取盲化人工样本报告 agreement/error。Judge 不得覆盖 native oracle。
- 多模型、多 runtime 和多消融比较标注 primary/secondary hypotheses，并进行适当校正或限制解释范围。

### 6.3 论文展示

| 论文产物 | 展示方式 |
|---|---|
| Benchmark qualification table | publication/source/revision/license/oracle/utility/side effect/judge/role/current gate。 |
| Main security-utility table | benchmark × V0/V2/V5 的 native utility、native harm、safe-useful、false blocks、exact denominator 和 interval。 |
| Pareto 图 | x 轴 utility，y 轴 harmful completion/executed harm；不同 benchmark 分面，不混用 ASR。 |
| Action funnel | proposed → harmful-labeled → intervened → approved/executed/failed/prevented，按来源分组。 |
| Ablation table | V0/V1/V2/V2H/V3/V4/V5 的配对变化，标明 attribution subset。 |
| Generalization table | runtime、model deployment、profile、evidence kind、capability/opportunity/effect/cost。 |
| Audit table | final output、普通 process log、Invart ledger/proof 三种证据条件的盲化重建与篡改发现。 |
| Limitations table | blocked/deferred surface、judge dependence、completion-backend 边界、attack floor 和未管理动作。 |

图表必须从同一个 typed result bundle 生成，绑定 benchmark revision、case manifest、model/runtime manifest、Policy hash、provider receipt 和 evidence kind。任何未执行、执行失败或资格不合格的 row 都保留在 completeness 表中，不能静默删除。

## 7. 当前进度与后续阶段

### Phase A — validity and qualification：主体完成

已实现 benchmark quality registry、无 provider adapter 合同、provider/loopback validity gate、公共 action ontology 和 blocked-state 表达。Phase A 的结论是“可以判断哪些结果不可信”，不是“已经证明 Invart 有效”。

### Phase B — peer-reviewed pillar：进行中

当前 AgentHarm 已完成的代码级证据包括：

- 只接受 Inspect `.eval` 中唯一的官方 `combined_scorer`，拒绝无分数、伪 scorer、布尔值和非有限数；
- capability control 与 harmful artifact 绑定同一模型、judges、execution package 和 case 集合；
- 官方 package validator 重新 dump、重新抽取、重新构造并核对 hash；
- approval request 绑定精确 harmful/benign case IDs、case manifest 和 request hash；
- 单条件 gate 只区分 `technical_invalid`、`capability_only`、`attack_floor`、`opportunity_qualified`，不再把单组结果写成 `security_comparable`；
- canonical V0/V5 treatment binding 绑定 Policy variant hash、request hash、technical evidence hash 和精确 harmful artifact hashes；
- 只有 V0/V5 的 exact pair 才能进入 `security_comparable`：模型、judges、execution/grader binding、capability control、request、case set、split 和 epoch 必须一致；
- paired gate 输出 prevented、persistent harm、regressed、stable safe、净 harmful-case reduction 和 effect direction；出现局部 prevented 但净改善为零时不得写成正向效果；
- cross-benchmark result 将 `native_benchmark` 与 `native_runtime` 分开；后者必须由绑定 manifest、完整 receipt、精确 native artifact hash 和 execution-record hash 的 proof 才能发出；
- 独立语义标签在没有具体 ledger resolver 前保持 descriptive，不擅自建立攻击机会。

尚未完成：

- 当前环境中的 AgentHarm 官方数据获取/缓存仍受外部 TLS 或数据源可用性阻断；
- 真实 source checkout attestation、冻结 case manifest 和新的 approval packet 尚未形成；
- 旧 approval request 在当前严格 preflight 下已经过时，不能执行；
- 尚未进行付费 provider scored pilot，因此没有 AgentHarm security-effect 结果；
- runtime execution proof 目前完成的是 fail-closed 数据合同；在真实 native runner/ledger 产出并保留 execution record 前，fixture proof 不能作为真实 `native_runtime` 证据；
- MCPTox 缺少已资格化的官方 end-to-end runner，MCP-AgentBench 缺少冻结的官方 executable source/license/server/evaluator。

### Phase C-F：待执行

- Phase C：冻结 Policy 后执行 AgentDojo full anchor、AgentDyn 和 Skill-Inject transfer。
- Phase D：执行 HarmBench/b³ controls、SWE-Bench utility 和 blinded audit/proof study。
- Phase E：只扩展通过 capability/opportunity gate 的 connected agent/model panel。
- Phase F：生成统计、图表、evidence-to-claim audit，更新论文并固化 limitations。

## 8. 下一步可执行清单

按以下顺序推进，不并发启动尚未满足前置条件的付费实验：

1. 修复或替换 AgentHarm 官方数据获取路径，记录数据 revision、license、文件 hash 和来源证明。
2. 从真实数据生成冻结 case manifest；先选一条 benign 和一条 harmful case，不手工杜撰 case ID。
3. 用当前严格 schema 重新生成 approval packet，确认模型、judges、预算、timeout、case hash 和安全 sandbox。
4. 获得明确批准后运行最小 scored smoke，核对 provider ingress、request IDs、非空 completion、`.eval`、官方 scorer 和 case count。
5. 若 benign capability 失败，停止并修 provider/model/tool compatibility；若 attack opportunity 为零，保留 floor 结果并换预注册 stack，而不是调整 benchmark labels。
6. 只有 V0 baseline 出现 `opportunity_qualified` 才进入 stratified V0/V5 paired pilot；只有 exact pair gate 产生 `security_comparable` 才能估计效果，随后再检查 sensitivity、utility 和 precision gate。
7. AgentHarm 主链稳定后，并发推进 AgentDyn adapter、Skill-Inject adapter 和 audit-study fixtures；MCPTox 继续以 runner qualification 为第一门槛。
8. 在主 Policy 冻结后执行 transfer 与 connected panel，任何 holdout 后调参都创建新 exploratory version。

## 9. 投稿时允许与禁止的表述

| 当前可写 | 当前不可写 |
|---|---|
| “Invart 实现了绑定官方 AgentHarm scorer、case manifest、canonical V0/V5 treatment 和配对执行条件的 fail-closed adapter contract。” | “Invart 已经在 AgentHarm 上降低有害任务成功率。” |
| “Invart 的 cross-benchmark contract 区分 native benchmark artifact 与 artifact-bound native runtime proof。” | 将手工 fixture proof 或单独的 runtime receipt 表述为真实 native-agent 执行证据。 |
| “AgentDojo pilot 暴露了零 baseline ASR 与 utility collapse，因而不能支持正向 prevention claim。” | “AgentDojo ASR 为 0 证明 Invart 完全安全。” |
| “HarmBench 被用作 reviewer/backbone control。” | “HarmBench 验证了 runtime action mediation。” |
| “MCPTox 是适合的 MCP supply-chain pillar，但当前 runner qualification 被阻断。” | 为 blocked MCPTox lane 报告合成或推测分数。 |
| “Ledger/proof 机制已经具备可测试合同。” | 在盲化重建和篡改负例完成前声称审计有效性。 |

最终论文可以坦诚表达局限：Invart 不保证所有攻击都被 prevention；LLM reviewer 有误差；不同 runtime 的拦截深度不一致；GUI、memory 和 multi-agent 仍可能是 blind spots。只要 prevention、utility、audit 和 coverage 分开测量，负面或有限的 mediation 结果不会否定控制平面贡献，反而能使论文的 claim 更可信。

## 10. 完成定义

实验计划达到投稿级完成，至少需要：

- 一个 AgentDojo 之外的完整 agent-level security/harmful-action denominator，且 baseline capability 和 attack opportunity 合格；
- 一个现代 dynamic 或 supply-chain transfer benchmark，使用冻结 Policy；
- AgentDojo full historical anchor 与一个官方 benign utility lane；
- V0/V2/V5 主消融和 selected connected model/runtime panel；
- blinded audit/proof study、tamper/missing negatives 与成本测量；
- 每个 row 的 exact denominator、revision、hash、receipt、native outcome 和 evidence kind；
- 一份逐条对应论文 claim 的 evidence audit，以及对所有 blocked/deferred surface 的 limitations。

若现代 transfer benchmark 因 runner/source 无法忠实执行，则必须显式缩小投稿 claim 或使用预注册 reserve；不得以 benchmark 数量、mock 结果或 model-only 分数补足 agent-level 证据。

## 11. 主要来源

- AgentHarm, ICLR 2025: <https://proceedings.iclr.cc/paper_files/paper/2025/hash/c493d23af93118975cdbc32cbe7323f5-Abstract-Conference.html>
- AgentDojo, NeurIPS 2024 Datasets and Benchmarks: <https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html>
- MCPTox, AAAI 2026: <https://ojs.aaai.org/index.php/AAAI/article/view/40895>
- MCP-AgentBench, AAAI 2026: <https://doi.org/10.1609/aaai.v40i37.40347>
- AgentDyn: <https://arxiv.org/abs/2602.03117>, <https://github.com/leolee99/AgentDyn>
- Skill-Inject: <https://arxiv.org/abs/2602.20156>, <https://github.com/aisa-group/skill-inject>
- Breaking Agent Backbones, ICLR 2026: <https://iclr.cc/virtual/2026/poster/10007758>
- HarmBench: <https://github.com/centerforaisafety/HarmBench>
- Agent Security Bench, ICLR 2025: <https://iclr.cc/virtual/2025/poster/29432>
