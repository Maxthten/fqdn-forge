# jnsec-lab

`jnsec-lab` 是完全本地、确定性的被动子域名收集实验室。它只模拟合成的上游资料源，默认仅监听并访问 `127.0.0.1`，不含真实公网采集、DNS 查询或主动探测。

```powershell
cargo run -p lab-cli -- validate
cargo run -p lab-cli -- list
cargo run -p lab-cli -- run --all
cargo run -p lab-cli -- run --scenario 019-large-dataset --profile stress
cargo run -p lab-cli -- self-test
cargo run -p lab-cli -- serve --port 18080
.\scripts\verify.ps1
.\scripts\verify.ps1 -Stress
```

每个场景都包含 `scenario.yaml`、`truth.yaml`、`assertions.yaml`、合成 fixture 和简短说明。`scenario.yaml` 是端点、请求匹配、响应序列、分页和故障注入的唯一行为来源；不依赖 Rust 中的场景编号映射。

`run` 会启动临时 localhost 服务，先经 `POST /api/runs` 创建独立 `run_id`，再执行内置参考适配器、核对真值与请求契约，并将脱敏 JSON 报告写入 `artifacts/reports/`。每个 source 请求都必须携带 `x-lab-run-id`；缺失、无效或未知 ID 只会进入服务端未关联诊断日志，绝不会返回 fixture 或消耗其他运行的响应序列。

## Run Session 控制 API

所有正式自动化都使用以下 scoped API：

- `POST /api/runs`：传入 `{ "scenario_id": "012-pagination-success" }`，创建 UUID 会话并返回 `base_url` 与必须携带的请求头。
- `GET /api/runs`、`GET /api/runs/{run_id}`：列出或读取会话元数据。
- `GET /api/runs/{run_id}/requests`、`/truth`、`/report`：读取该会话的脱敏审计、真值和报告；尚无报告时返回 `{ "report": null }`。
- `POST /api/runs/{run_id}/reset`、`POST /api/runs/{run_id}/report`、`DELETE /api/runs/{run_id}`：仅重置、写入报告或删除指定会话。

未知 scenario 创建会返回 `400`；无效 run ID 返回 `400`，未知 scoped run 返回 `404`，未知 source run 返回 `409`，且不会泄露 fixture。旧的 `/api/requests`、`/api/truth`、`/api/report` 和 `/api/reset` 只服务 `serve --scenario` 的开发兼容会话，响应带 `deprecated: true`，将来会移除；自动化不得使用它们。

`scripts/verify.ps1` 依次执行格式化、Clippy、全量 Rust 测试、静态 `validate`、20 场景回归和 `self-test`，任一步失败即非零退出。`-Stress` 会额外验证 019 的 100,000 条数据档。控制面仅提供 JSON API；可视化页面、HTML GUI 和图表仍不在本版本范围内。
