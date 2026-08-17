<p align="right">
  <a href="./README.md"><kbd>English</kbd></a>
  <a href="./README.zh-CN.md"><kbd>中文</kbd></a>
</p>

# FQDN Forge

> 一个可重复、仅本机运行的被动式子域名/FQDN 收集器离线测试平台。

**FQDN Forge 不是子域名收集器。** 它用于开发、验证和回归测试未来的收集器：以完全合成、可控的数据模拟证书日志、Passive DNS、网页档案、代码搜索、威胁情报、搜索结果、通用 REST、代理、额度、分页、压缩和故障，而不连接这些真实服务。

当前版本：**v1.4.1，包含 GUI 1.0 分析工作区。**

> [!IMPORTANT]
> 平台只绑定 `127.0.0.1`，不访问公网、不查询真实 DNS、不主动扫描、不连接真实代理，也不处理真实凭据。

后续 Agent 请先阅读 [Agent 接入指南](docs/AGENT_INTEGRATION_GUIDE.md)。

## 它能测试什么

当前共有 **114 个确定性场景**。它们帮助未来的收集器验证：是否按正确协议请求被动数据源、是否正确提取与规范化 FQDN、是否保留证据、是否遵守额度与重试、是否能在真实常见的接口异常下稳定工作。

| 分类 | 已覆盖内容举例 |
|---|---|
| 被动来源形态 | 证书、Passive DNS、网页档案 URL、搜索结果、威胁情报、代码文本、CSV、HTML、嵌套 JSON、通用 REST |
| 域名正确性 | 通配符、根域、重复、大小写、尾随点、URL host、Unicode/Punycode、越界相似域名 |
| 请求合同 | Query、POST body、Header、假 Key、page/offset/cursor/Link 分页和来源专属格式 |
| 接口行为 | 空结果、401/403、429/Retry-After、5xx、超时、断连、损坏数据、大响应、取消 |
| 网络路径 | 本地 HTTP 代理、代理认证、CONNECT、目标规范化、gzip/deflate/brotli、chunked 和 framing 异常 |
| 生命周期 | 隔离运行、提交/报告 API、reset/delete、过期 capability、审计、额度、证据合并、严格回放和 coverage policy |
| 稳定性 | 种子化 mutation campaign、组合故障、并发、100,000 条压力数据、release soak、资源泄漏检查 |

所有数据均为合成数据。给定相同 seed，会得到相同 fixture、请求顺序与预期结果。

## 快速开始

前置条件：稳定版 Rust/Cargo。完整验证脚本使用 Windows PowerShell；CLI 本身可跨平台运行。

```powershell
# 校验全部 114 个场景定义；不会启动服务。
cargo run -p lab-cli -- validate

# 查看场景和分组。
cargo run -p lab-cli -- list

# 运行全部内置回归场景。
cargo run -p lab-cli -- run --all

# 启动本机浏览器控制台。
cargo run -p lab-cli -- console

# 完整发布级验证。
.\scripts\verify.ps1 -Repeat 20
```

## 本地控制台与 GUI 1.0

控制台地址会打印为：`http://127.0.0.1:<port>/console/`。

```powershell
# 默认启动并打开浏览器。
cargo run -p lab-cli -- console

# 仅启动，不自动打开浏览器。
cargo run -p lab-cli -- console --no-open

# 使用指定 loopback 端口。
cargo run -p lab-cli -- console --port 18081 --no-open
```

控制台包含：首页、场景、运行、审计、报告、实验计划、分析概览、Coverage、回放差异、Campaign、Soak、证据关系、时间线与趋势、设置。

GUI 1.0 仅分析已保存的本地 artifact，可视化内容包括：

- 测试覆盖矩阵和缺口；
- 严格回放的差异与 provenance；
- mutation campaign 和 soak 的结果；
- 运行—来源—证据—FQDN—结论关系；
- 请求、429、重试、冷却、代理和取消的虚拟时间线；
- 有边界限制的历史趋势。

GUI 不会自行裁判、不会重新运行场景，也不会读取或暴露未脱敏的原始凭据。capability 与 fake key 仅存在于短期内存，不进入 localStorage、URL、报告或导出文件。

## 自动化读取分析结果

浏览器不是唯一入口。AI、MCP、Skill、脚本或其他自动化工具应调用 CLI/loopback API，而不是解析页面 HTML。

```powershell
cargo run -p lab-cli -- analysis overview --format json
cargo run -p lab-cli -- analysis coverage --format markdown
cargo run -p lab-cli -- analysis replay list --format json
cargo run -p lab-cli -- analysis campaign list --format json
cargo run -p lab-cli -- analysis soak list --format json
cargo run -p lab-cli -- analysis evidence --run <run-id> --format json
cargo run -p lab-cli -- analysis timeline --run <run-id> --format json
cargo run -p lab-cli -- analysis trends --format json
```

分析 API/CLI 输出由服务端生成并脱敏，支持筛选、分页或截断；不会包含 capability、fake key、Authorization、Cookie 或外部目标。

## 对接未来的收集器

启动本地服务：

```powershell
cargo run -p lab-cli -- serve --port 18080
```

未来收集器先创建一个受控运行，再读取该运行的 manifest 中返回的本地来源端点、目标域名、假认证信息和（按需）本地代理端点。随后请求本地来源、提交发现结果与证据，最后读取由服务端独立裁判的报告和审计。

收集器不得依赖 `scenarios/`、fixture 文件或 truth 文件；这些属于测试站内部实现，而不是外部合同。

## 目录概览

```text
crates/
  lab-core/       场景、fixture、裁判、状态、回放、coverage、campaign、analysis read model
  lab-server/     loopback HTTP 控制/来源/代理服务
  lab-console/    双语本地控制台、DTO、GUI 和分析页面
  lab-cli/        命令行、黑盒客户端、验证工具
scenarios/        合成场景定义、断言与 fixture
fixtures/         计划与其他测试夹具
scripts/          完整验证与浏览器回归脚本
docs/             架构、控制台说明和 Agent 接入指南
coverage-policy.yaml
```

## 验收与提交前检查

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
node .\scripts\gui_browser_regression.mjs
node .\scripts\gui_100_browser_regression.mjs
.\scripts\verify.ps1 -Repeat 20
.\scripts\verify.ps1 -Stress -Repeat 20
```

正式通过意味着：114 个场景通过；普通和压力重复验证均为 20 轮、0 失败；GUI 0.2.2 浏览器回归为 17/17；GUI 1.0 浏览器回归为 18/18；无公网访问、无真实 DNS、无敏感数据泄露。

`target/`、`artifacts/`、`reports/` 都是本地产物，已经被 Git 忽略，绝不能提交。

## 项目状态

FQDN Forge 的功能范围已封板：它是一个成熟的、本地、离线、可自动化、可视化的被动式子域名收集器测试站，不是收集器本身。后续仅应进行 bug 修复、性能优化、文档、发布和新增合成测试夹具。
