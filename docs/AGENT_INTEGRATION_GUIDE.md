# FQDN Forge Agent 接入指南

> 面向后续维护 Agent、自动化 Agent、AI/MCP/Skill 集成者。<br>
> 目标：让 Agent 在不误解项目定位、不破坏离线安全边界的前提下，快速定位代码、调用平台、验证改动并提交可审计结果。

## 1. 一句话定位

FQDN Forge 是一个**仅 loopback、完全离线、使用合成数据**的被动式子域名/FQDN 收集器测试站。

它模拟被动数据来源和网络故障，用来测试未来的收集器；它本身不是收集器、扫描器、DNS 枚举器、资产系统或公网代理。

## 2. 首先必须遵守的边界

任何 Agent 在读取、修改或运行项目时都不得破坏以下规则：

- 只绑定 `127.0.0.1` / loopback；不能改成 `0.0.0.0` 或局域网监听。
- 不访问公网，不查真实 DNS，不读取系统代理环境变量，不连接真实代理。
- 不增加真实 API Key、Cookie、密码、Token、外部 URL 或公网 IP 配置。
- 不把 `scenarios/`、truth、fixture 当成未来收集器应读取的公开合同。
- 不让 GUI 自行给出权威判定；最终 verdict 只能由服务端/核心裁判产生。
- 不把 capability、fake key、Authorization 或 Cookie 写入报告、导出、localStorage、URL 或日志。
- 不提交 `artifacts/`、`target/`、浏览器 profile、截图、临时报告或大生成文件。

如果某项需求必须突破上述边界，先停止并要求明确授权；不要自行扩展项目范围。

## 3. 代码与数据地图

```text
crates/lab-core/
  场景模型、fixture、FQDN 规范化、裁判、运行状态、计划、回放、coverage、campaign、soak、analysis read model

crates/lab-server/
  仅 loopback 的 HTTP 控制 API、本地来源响应、代理/CONNECT 模拟、计划 API、分析 API

crates/lab-cli/
  场景运行、conformance、campaign、coverage、baseline、soak、plan、analysis 命令

crates/lab-console/
  本地浏览器控制台、双语文字、计划编辑器、GUI 1.0 分析页面

scenarios/
  114 个合成场景；内部测试定义，不是外部收集器合同

fixtures/
  可重复的计划和浏览器/API 测试夹具

scripts/
  完整验证与浏览器回归脚本

artifacts/
  本地运行产物；Git 忽略
```

建议先阅读：

- [README](../README.md) / [中文 README](../README.zh-CN.md)
- 根目录外的 GUI/版本需求文档（仅作实现参考，不能提交进仓库）

README 是当前架构、local console、public manifest contract 与安全边界的
权威入口；不要依赖已删除的历史 `ARCHITECTURE.md`、`CONSOLE.md` 或
`CONSOLE_DEMO.md`。

## 4. 三种正确的使用方式

### 4.1 验证内置测试站

```powershell
cargo run -p lab-cli -- validate
cargo run -p lab-cli -- run --all
.\scripts\verify.ps1 -Repeat 20
```

用于确认场景、裁判、来源模拟、代理、额度、回放、campaign、soak 和安全边界没有回归。

### 4.2 测试外部收集器

```powershell
cargo run -p lab-cli -- serve --port 18080
```

外部收集器正确流程：

```text
创建 scoped run
  → 读取该 run 的 manifest
  → 只请求 manifest 返回的本地来源和本地代理端点
  → 提交发现结果、证据、来源状态
  → 获取服务端生成的 audit 与 report
  → 验证 reset/delete 后旧 capability 失效
```

外部收集器只能依赖公开 HTTP 合同；不能读取 `scenarios/`、truth 或 fixture。
若 manifest 声明非秘密的 `cancel_after_requests`，collector 在完成指定数量的
request attempt 后必须停止调度新的 source/page request；该 Lab-only control 不得
被当作 production collection instruction。

### 4.3 读取分析结果

优先使用 CLI 或 loopback 分析 API，不要抓取 GUI 页面 HTML：

```powershell
cargo run -p lab-cli -- analysis overview --format json
cargo run -p lab-cli -- analysis coverage --format json
cargo run -p lab-cli -- analysis replay list --format json
cargo run -p lab-cli -- analysis campaign list --format json
cargo run -p lab-cli -- analysis soak list --format json
cargo run -p lab-cli -- analysis evidence --run <run-id> --format json
cargo run -p lab-cli -- analysis timeline --run <run-id> --format json
cargo run -p lab-cli -- analysis trends --format json
```

分析结果是只读、服务端生成、脱敏、可分页/截断的。读取分析结果不能创建 run、不能修改 artifact、不能重新激活 capability。

## 5. 实验计划与 GUI 0.2.2

实验计划用于组合本地来源、分页、认证、额度、代理、故障、数据规模和预期行为。

关键规则：

- GUI、CLI、API 共享同一服务端计划校验逻辑；
- GUI 只是编辑草稿，不能成为唯一入口；
- 高级 JSON 与普通表单必须无损；
- 多个 fault、`403`、来源级覆盖不能被普通编辑静默删除；
- `revision` / `If-Match` 用于防止并发覆盖；
- 导入到 GUI 只进入草稿，点击保存才写入计划存储；
- CLI/API 的 `plan import` 仍是明确的持久化导入操作。

常用命令：

```powershell
cargo run -p lab-cli -- plan list --format json
cargo run -p lab-cli -- plan validate --file .\fixtures\plans\gui_022_advanced.json --format json
cargo run -p lab-cli -- plan create --file .\fixtures\plans\gui_022_advanced.json --format json
cargo run -p lab-cli -- plan simulate --id <plan-id> --format json
cargo run -p lab-cli -- plan export --id <plan-id> --output .\plan.json --format json
```

## 6. GUI 1.0 分析层

GUI 1.0 展示已有 artifacts 的只读分析，不增加新的测试或网络能力。

| 页面/读取模型 | 用途 |
|---|---|
| Analysis overview | 近期运行、coverage、replay、campaign、soak 摘要 |
| Coverage | 已覆盖、部分覆盖、缺失、例外和关联场景/活动 |
| Replay differences | matched/mismatch、provenance、字段差异 |
| Campaign | mutation 结果、种子、失败分类 |
| Soak | 并发、操作数、资源与生命周期摘要 |
| Evidence graph | run → source → evidence → FQDN → verdict 关系 |
| Timeline & trends | 审计事件的虚拟时间顺序和有界历史趋势 |

新增或修改分析功能时：

1. 先在 `lab-core` 定义稳定、脱敏、只读的 Analysis Read Model；
2. 再由 `lab-server` 提供 loopback API；
3. 再增加 CLI JSON/Markdown 输出；
4. 最后才修改 GUI；
5. 必须限制列表、图节点、图边、timeline 与 trend 点，不能让浏览器加载无限数据；
6. 图表必须有表格或文字替代视图；
7. 不能将原始 artifact 或敏感字段直接交给浏览器。

## 7. 修改前后的标准流程

### 7.1 修改前

1. 运行 `codegraph sync .` 更新索引。
2. 使用 CodeGraph 定位符号、调用关系和影响范围；不要先用大范围 grep 重建结构。
3. 检查 `git status --short`；保留用户已有的无关修改。
4. 阅读最接近的需求文档、对应测试和相关 scenario/fixture。
5. 明确改动仍是“离线测试站能力”，而不是收集器能力。

### 7.2 修改后

最小验证按改动类型选择：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

若修改 GUI 0.2.2：

```powershell
node .\scripts\gui_browser_regression.mjs
```

若修改 GUI 1.0 或 analysis：

```powershell
node .\scripts\gui_100_browser_regression.mjs
```

若修改场景、网络、代理、核心、CLI、服务端、计划或分析读取模型：

```powershell
.\scripts\verify.ps1 -Repeat 20
.\scripts\verify.ps1 -Stress -Repeat 20
```

发布前始终检查：

```powershell
git diff --check
git status --short
git diff --stat
```

## 8. Git 与产物规则

`.gitignore` 必须继续忽略：

```text
/target
/target-*
/reports
/artifacts
```

允许提交：源码、合成 scenario、fixture、测试脚本、必要本地图标和文档。

禁止提交：运行报告、campaign/soak 输出、coverage 输出、浏览器 profile、截图、临时文件、真实凭据、下载的外部数据。

根目录 `E:/code/jnsec` 中的过程性需求文档用于 Agent 协作，不属于 `fqdn-forge` 仓库提交内容。

## 9. 快速故障判断

| 现象 | 优先检查 |
|---|---|
| 场景失败 | scenario 的 assertions、审计、来源请求合同、seed 与报告 |
| 外部客户端失败 | manifest、capability、请求路径、提交格式、audit 里的预期拒绝 |
| 计划保存/校验异常 | 草稿、revision、服务端 validation issue、GUI 0.2.2 浏览器回归 |
| 分析页空或错误 | artifacts 根目录、Analysis Read Model、filter/limit、diagnostics、脱敏与索引 |
| 图表/时间线异常 | 服务端读模型是否正确、是否截断，再检查 GUI；不要在页面端重新计算 truth |
| 浏览器测试失败 | 临时 artifacts、浏览器焦点/动画帧、loopback 请求和控制台错误 |

## 10. 完成定义

一个 Agent 的改动只有同时满足以下条件才算完成：

- 没有扩大为真实收集、扫描、DNS 或公网访问；
- 没有破坏 loopback、脱敏、capability 和运行隔离；
- CLI/API/GUI 的职责边界仍清晰；
- 新增行为有确定性测试与合成夹具；
- 相应的格式、Clippy、Rust、浏览器和完整验证通过；
- Git 不含生成产物或敏感内容；
- 改动、验收结果和剩余风险可审计。
