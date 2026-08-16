# Architecture

`lab-core` 定义 YAML 模型、固定 SourceKind 注册表、静态校验、域名/URL 规范化、egress guard、通用参考 Runner 和真值裁判。`lab-server` 只绑定 `127.0.0.1`，按场景数据回放 fixture，并维护 RunSession。`lab-cli` 提供 validate、list、run、repeat、replay、self-test、serve 和 `console`。`lab-console` 提供 GUI 0.1 的双语只读 DTO、脱敏审计/报告模型以及随二进制打包的本地 HTML/CSS/JavaScript；没有 MCP、AI 或外部资源依赖。

每个 RunSession 用 UUID 隔离，拥有 scenario、seed、响应序列、审计和报告。任何来源请求缺少或携带未知 `x-lab-run-id` 都不会读取 fixture 或消耗响应序列。锁只在短暂内存更新期间持有；响应体生成、延迟和 HTTP I/O 都在锁外进行。

Runner 使用场景声明的 JSON 路径、HTML/CSV/text 解析、请求模板、认证 header、page/offset/cursor/Link 分页、POST body 分页、Retry-After 和故障响应，不按 scenario id 分支。响应读取受大小上限约束；429 使用 virtual wait，绝不等待真实限流时间；重定向禁用且外部地址在连接前拒绝。

V1.2 报告的机器可读顶层包括 `schema_version`、`lab_version`、`run_id`、`scenario_id`、`seed`、`target_domain`、`result`、`truth`、`assertions`、`requests`、`metrics` 和 `violations`。请求审计使用脱敏 header/body 摘要，并记录 response sequence、状态、是否匹配、是否消耗和出网拦截字段。
