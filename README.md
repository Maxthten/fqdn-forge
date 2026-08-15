# FQDN Forge 1.4

FQDN Forge 是完全离线、确定性的被动 FQDN 收集器测试站，不是生产收集器。它只在 `127.0.0.1` 上监听和访问合成 fixture；不进行公网访问、真实 DNS 查询、主动扫描、真实 API 调用或密钥处理。

## 常用命令

```powershell
cargo run -p lab-cli -- validate
cargo run -p lab-cli -- list
cargo run -p lab-cli -- run --all
cargo run -p lab-cli -- run --group network
cargo run -p lab-cli -- run --group proxy
cargo run -p lab-cli -- run --group quota
cargo run -p lab-cli -- run --group transport
cargo run -p lab-cli -- run --group combination
cargo run -p lab-cli -- run --group lifecycle
cargo run -p lab-cli -- run --scenario 059-seed-reproducible --seed 59
cargo run -p lab-cli -- run --scenario 055-high-unique-100k
cargo run -p lab-cli -- self-test
cargo run -p lab-cli -- repeat --count 20
cargo run -p lab-cli -- replay --report artifacts/reports/<report>.json
cargo run -p lab-cli -- replay --strict --report artifacts/reports/091-pagination-second-page-rate-limit-default-seed-91.json
cargo run -p lab-cli -- campaign list
cargo run -p lab-cli -- campaign run --campaign 107-json-structural-mutation-campaign --seed 10701
cargo run -p lab-cli -- campaign replay --report artifacts/campaigns/107-json-structural-mutation-campaign-seed-10701.json
cargo run -p lab-cli -- coverage --format json --output artifacts/coverage.json
cargo run -p lab-cli -- coverage --format markdown --output artifacts/coverage.md
cargo run -p lab-cli -- coverage --check
cargo run -p lab-cli -- baseline generate --profile v1.4-core
cargo run -p lab-cli -- baseline check
cargo run -p lab-cli -- soak run --preset smoke --seed 11100
cargo run -p lab-cli -- soak run --preset release --seed 11100
cargo run -p lab-cli -- proxy-regression
cargo run -p lab-cli -- conformance --scenario 062-proxy-http-forward-success
cargo run -p lab-cli -- serve --port 18080
.\scripts\verify.ps1
```

场景 001～090 保持既有回归覆盖。091～100 叠加分页、配额、代理与传输故障；101～106 回归代理规范化边界及 run 生命周期；107～110 是有界、seed 驱动且可重放的变异 campaign；111～114 覆盖生命周期 soak、来源回放、覆盖矩阵和逻辑基线。每个场景都有 `scenario.yaml`、`truth.yaml`、`assertions.yaml` 和本地合成 fixture。

`coverage` 从场景元数据生成 JSON 或 Markdown 矩阵；`baseline` 比较确定性的语义与逻辑指标，不把 wall-clock 当成跨机器门槛；`soak` 输出固定 seed 的 action trace 和资源不变量。`proxy-regression` 会运行 101～104，并使用原始 TCP 报文验证 hostname、非规范 IPv4、IPv6、userinfo、编码、fragment、Host 歧义和 CL/TE 冲突都在 source 转发及 quota 决策之前被拒绝。

## 运行会话 API

自动化必须先创建 scoped session：

```text
POST /api/runs  {"scenario_id":"021-internet-search-nested-json","seed":21}
```

随后所有来源请求必须携带返回的 `x-lab-run-id`。每个 run 独有响应序列、分页、代理、配额、审计和报告；reset/delete 不影响其他 run，且 reset 会轮换 `x-lab-run-access-token`，旧 token 必须立即失效。报告写入 `artifacts/reports/`，使用 `schema_version: "1.4.0"`，包含 seed、target domain、真值、断言、代理/配额/传输审计、覆盖标签、场景/fixture/campaign provenance、诊断摘要、指标、违规及 strict replay 多差异信息。敏感 header、请求体字段和 URL 凭据会被脱敏。

服务只允许 loopback。Reference Runner 在建立请求前使用 egress guard 拒绝公网、非 loopback 主机和重定向目标；因此整个测试流程不依赖互联网。
