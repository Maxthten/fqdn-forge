# FQDN Forge 1.3

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
cargo run -p lab-cli -- run --scenario 059-seed-reproducible --seed 59
cargo run -p lab-cli -- run --scenario 055-high-unique-100k
cargo run -p lab-cli -- self-test
cargo run -p lab-cli -- repeat --count 20
cargo run -p lab-cli -- replay --report artifacts/reports/<report>.json
cargo run -p lab-cli -- replay --strict --report artifacts/reports/079-deflate-success-default.json
cargo run -p lab-cli -- conformance --scenario 062-proxy-http-forward-success
cargo run -p lab-cli -- serve --port 18080
.\scripts\verify.ps1
```

场景 001～060 和 067～078 保持既有回归覆盖；061～066 模拟 direct、HTTP forward proxy、CONNECT、认证、故障与 egress 隔离；079～090 覆盖 deflate、brotli、chunked、配额、恢复、缓存可观察行为与并发原子性。每个场景都有 `scenario.yaml`、`truth.yaml`、`assertions.yaml` 和本地合成 fixture。

## 运行会话 API

自动化必须先创建 scoped session：

```text
POST /api/runs  {"scenario_id":"021-internet-search-nested-json","seed":21}
```

随后所有来源请求必须携带返回的 `x-lab-run-id`。每个 run 独有响应序列、分页、代理、配额、审计和报告；reset/delete 不影响其他 run。报告写入 `artifacts/reports/`，包含 `schema_version: "1.3.0"`、seed、target domain、真值、断言、代理/配额/传输审计、指标、违规和 replay 信息。敏感 header、请求体字段和 URL 凭据会被脱敏。

服务只允许 loopback。Reference Runner 在建立请求前使用 egress guard 拒绝公网、非 loopback 主机和重定向目标；因此整个测试流程不依赖互联网。
