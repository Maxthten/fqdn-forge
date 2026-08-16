//! Safe read models and bundled assets for the offline FQDN Forge Console.
//! This crate never exposes scenario truth, fixtures, capabilities, or fake
//! credentials to the browser-facing models.

use std::{env, fs, path::PathBuf};

use lab_core::{
    AuditEventType, AuditRecord, ControlAuditRecord, DeletedRunSummary, LoadedScenario, RunReport,
    RunSession, ScenarioRepository,
};
use serde::Deserialize;
use serde_json::{Value, json};

pub struct ConsoleAsset {
    pub content_type: &'static str,
    pub body: &'static str,
}

#[must_use]
pub fn asset(path: &str) -> Option<ConsoleAsset> {
    match path {
        "/console/" | "/console/index.html" => Some(ConsoleAsset {
            content_type: "text/html; charset=utf-8",
            body: include_str!("../assets/index.html"),
        }),
        "/console/app.js" => Some(ConsoleAsset {
            content_type: "application/javascript; charset=utf-8",
            body: include_str!("../assets/app.js"),
        }),
        "/console/style.css" => Some(ConsoleAsset {
            content_type: "text/css; charset=utf-8",
            body: include_str!("../assets/style.css"),
        }),
        _ => None,
    }
}

#[must_use]
pub fn scenario_catalog(repository: &ScenarioRepository) -> Value {
    json!({"scenarios": repository.all().iter().map(scenario_value).collect::<Vec<_>>()})
}

/// Returns the latest complete local verification record when the verification
/// script has written one. The record is informational only and never contains
/// runs, scenario truth, fixture data, or credentials.
#[must_use]
pub fn latest_verification_summary() -> Value {
    let path = env::current_dir()
        .map(|directory| directory.join("artifacts/console/verification-summary.json"))
        .unwrap_or_else(|_| PathBuf::from("artifacts/console/verification-summary.json"));
    fs::read(path)
        .ok()
        .and_then(|bytes| verification_value_from_bytes(&bytes))
        .unwrap_or_else(|| {
            json!({
                "available": false,
                "status": "not_recorded",
                "message": "No complete local verification has been recorded for this workspace yet.",
            })
        })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationRecord {
    schema_version: u8,
    status: String,
    completed_at: String,
    command: String,
    repeat: u32,
    scenario_count: u16,
    release_soak_operations: u32,
}

fn verification_value_from_bytes(bytes: &[u8]) -> Option<Value> {
    let record = serde_json::from_slice::<VerificationRecord>(bytes).ok()?;
    if record.schema_version != 1
        || record.status != "passed"
        || record.completed_at.is_empty()
        || record.command.is_empty()
        || record.repeat == 0
        || record.scenario_count != 114
        || record.release_soak_operations < 1_000
    {
        return None;
    }
    Some(json!({
        "available": true,
        "status": record.status,
        "completed_at": record.completed_at,
        "command": record.command,
        "repeat": record.repeat,
        "scenario_count": record.scenario_count,
        "release_soak_operations": record.release_soak_operations,
    }))
}

#[must_use]
pub fn scenario_value(loaded: &LoadedScenario) -> Value {
    let scenario = &loaded.scenario;
    let category = category_for(&scenario.id);
    let zh_name = zh_name_for(&scenario.id).unwrap_or("本地固定测试场景");
    let source_types = scenario
        .endpoints
        .iter()
        .map(|endpoint| format!("{:?}", endpoint.source_kind))
        .collect::<Vec<_>>();
    let source_details = scenario
        .endpoints
        .iter()
        .map(|endpoint| {
            json!({
                "source_id": endpoint.id,
                "source_type": format!("{:?}", endpoint.source_kind),
                "method": format!("{:?}", endpoint.request_match.method),
                "local_simulated": true,
                "uses_fake_auth": !endpoint.request_headers.is_empty(),
                "allows_retry": endpoint.allow_retry,
                "pagination": endpoint.pagination,
                "quota_rules": endpoint.quota.len(),
            })
        })
        .collect::<Vec<_>>();
    let category_zh = category_label_zh(category);
    json!({
        "id": scenario.id,
        "category": category,
        "risk_tag": risk_for(category),
        "default_seed": scenario.seed,
        "source_types": source_types,
        "sources": source_details,
        "display": {
            "en": {"name": scenario.name, "description": scenario.description},
            "zh": {
                "name": zh_name,
                "description": format!("本地固定测试数据，用于验证{}。", zh_name),
            },
        },
        "guidance": {
            "en": {
                "verifies": format!("Verifies {}.", scenario.description),
                "behaviour": format!("This is a fixed local {} scenario with {} source(s).", category, scenario.endpoints.len()),
                "collector_expectation": "Use only manifest-advertised loopback endpoints, preserve audit evidence, and submit through the local protocol.",
            },
            "zh": {
                "verifies": format!("验证：{}。", zh_name),
                "behaviour": format!("这是一个固定的本地{}场景，包含 {} 个来源。", category_zh, scenario.endpoints.len()),
                "collector_expectation": "收集器只能使用 manifest 公布的 loopback 地址，保留审计证据，并通过本地协议提交结果。",
            },
        },
        "simulation": {
            "network_mode": format!("{:?}", scenario.network_profile.mode),
            "proxy_required": scenario.network_profile.proxy_must_be_used,
            "connect_involved": format!("{:?}", scenario.network_profile.mode) == "ConnectProxy",
            "allows_retry": scenario.network_profile.allow_retry,
            "virtual_timeout_ms": scenario.network_profile.virtual_timeout_ms,
            "fault_script_steps": scenario.fault_script.len(),
            "all_local": true,
        },
    })
}

#[must_use]
pub fn run_value(
    run: &RunSession,
    target_domain: Option<String>,
    report: Option<&RunReport>,
) -> Value {
    json!({
        "run_id": run.run_id,
        "short_id": run.run_id.chars().take(8).collect::<String>(),
        "scenario_id": run.scenario_id,
        "seed": run.seed,
        "target_domain": target_domain,
        "created_at": run.created_at.to_rfc3339(),
        "last_activity_at": run.last_activity_at.to_rfc3339(),
        "status": run.status,
        "report_status": report.map(|value| format!("{:?}", value.status)),
    })
}

#[must_use]
pub fn deleted_run_value(run: &DeletedRunSummary) -> Value {
    json!({
        "run_id": run.run_id,
        "short_id": run.run_id.chars().take(8).collect::<String>(),
        "scenario_id": run.scenario_id,
        "seed": run.seed,
        "created_at": run.created_at.to_rfc3339(),
        "deleted_at": run.deleted_at.to_rfc3339(),
        "status": "deleted",
    })
}

#[must_use]
pub fn audit_value(source: &[AuditRecord], control: &[ControlAuditRecord]) -> Value {
    let mut entries = source
        .iter()
        .map(|record| {
            let operation = match record.event_type {
                AuditEventType::SourceRequest => "source",
                AuditEventType::ProxyRequest if record.method.eq_ignore_ascii_case("CONNECT") => "CONNECT",
                AuditEventType::ProxyRequest => "proxy",
                AuditEventType::QuotaDecision => "quota",
                AuditEventType::Lifecycle => "lifecycle",
            };
            json!({
                "timestamp": record.timestamp.to_rfc3339(), "sequence": record.sequence,
                "operation": operation, "source_id": record.endpoint_id,
                "method": record.method, "path": record.path,
                "query_keys": record.query.keys().collect::<Vec<_>>(),
                "header_names": redacted_header_names(record), "status": record.response_status,
                "through_proxy": record.proxy_mode.is_some(),
                "quota_consumed": record.quota_consumed || record.consumed,
                "expected_rejection": record.blocked || record.external_target_rejected || record.quota_rate_limited,
                "matched": record.matched, "retry_after": record.retry_after,
                "virtual_wait_ms": record.virtual_wait_ms, "failure": record.mismatch_reasons,
                "proxy_reason": record.proxy_reason, "content_encoding": record.content_encoding,
                "transport_fault": record.transport_fault,
            })
        })
        .collect::<Vec<_>>();
    entries.extend(control.iter().map(|record| json!({
        "timestamp": record.timestamp.to_rfc3339(), "sequence": 0,
        "operation": record.operation, "source_id": Value::Null,
        "method": record.method, "path": record.path,
        "query_keys": Vec::<String>::new(), "header_names": Vec::<String>::new(),
        "status": if record.outcome == "rejected" { 403 } else { 200 },
        "through_proxy": false, "quota_consumed": false,
        "expected_rejection": record.outcome == "rejected",
        "matched": record.outcome != "rejected", "retry_after": Value::Null,
        "virtual_wait_ms": 0, "failure": Vec::<String>::new(),
        "proxy_reason": Value::Null, "content_encoding": Value::Null, "transport_fault": Value::Null,
    })));
    entries.sort_by_key(|entry| {
        entry
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    });
    json!({"entries": entries})
}

#[must_use]
pub fn report_value(report: &RunReport) -> Value {
    let raw_report = redact_value(serde_json::to_value(report).expect("RunReport is serializable"));
    json!({
        "summary": {
            "status": report.status, "scenario_id": report.scenario_id, "seed": report.seed,
            "target_domain": report.target_domain, "started_at": report.started_at.to_rfc3339(),
            "finished_at": report.finished_at.to_rfc3339(),
            "metrics": {
                "correct_findings": report.metrics.unique_fqdns,
                "missed_findings": report.metrics.false_negatives,
                "unexpected_findings": report.metrics.false_positives,
                "filtered": report.metrics.filtered_candidates,
                "source_count": report.source_statuses.len(), "request_count": report.metrics.request_count,
                "retry_count": report.metrics.retry_count, "virtual_wait_ms": report.metrics.virtual_wait_ms,
                "rejected_count": report.request_summary.rejected_egress_attempts,
            },
            "findings": report.findings, "filtered_candidates": report.filtered,
            "source_statuses": report.source_statuses, "assertions": report.assertions,
            "diagnostics": {"failures": report.failures, "violations": report.violations, "summary": report.diagnostics},
            "reproduction_command": report.replay_command, "submission": report.submission,
        },
        "raw_report": raw_report,
    })
}

#[must_use]
pub fn has_zh_translation(id: &str) -> bool {
    zh_name_for(id).is_some()
}

fn redacted_header_names(record: &AuditRecord) -> Vec<String> {
    let headers = if record.redacted_headers.is_empty() {
        &record.headers
    } else {
        &record.redacted_headers
    };
    headers.keys().cloned().collect()
}

fn redact_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(redact_value).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .filter_map(|(key, value)| {
                    let normalized = key.to_ascii_lowercase();
                    if normalized == "truth" {
                        return None;
                    }
                    let sensitive = normalized.contains("capability")
                        || normalized.contains("authorization")
                        || normalized.contains("credential")
                        || normalized.contains("access_token")
                        || normalized.contains("api_key")
                        || normalized == "headers"
                        || normalized == "body";
                    Some((
                        key,
                        if sensitive {
                            Value::String("[redacted]".to_owned())
                        } else {
                            redact_value(value)
                        },
                    ))
                })
                .collect(),
        ),
        value => value,
    }
}

fn category_for(id: &str) -> &'static str {
    let number = id
        .split('-')
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or_default();
    match number {
        1..=10 | 21..=36 => "basic_sources",
        11..=20 | 37..=50 => "api_behavior",
        51..=60 => "data_correctness",
        61 => "network",
        62..=66 | 101..=104 => "proxy",
        67..=72 | 105..=106 => "lifecycle",
        73..=84 => "transport",
        85..=93 => "quota",
        94..=100 => "combination_faults",
        _ => "stability",
    }
}

fn risk_for(category: &str) -> &'static str {
    match category {
        "proxy" | "transport" | "combination_faults" => "high",
        "quota" | "lifecycle" | "api_behavior" => "medium",
        _ => "low",
    }
}

fn category_label_zh(category: &str) -> &'static str {
    match category {
        "basic_sources" => "基础来源",
        "api_behavior" => "接口行为",
        "data_correctness" => "数据正确性",
        "network" => "网络",
        "proxy" => "代理",
        "quota" => "额度与冷却",
        "transport" => "传输",
        "combination_faults" => "组合故障",
        "lifecycle" => "生命周期",
        _ => "稳定性",
    }
}

fn zh_name_for(id: &str) -> Option<&'static str> {
    Some(match id {
        "001-basic-certificate" => "基础证书名称提取",
        "002-basic-archive" => "基础归档 URL 提取",
        "003-basic-passive-dns" => "被动 DNS 历史记录",
        "004-basic-code-search" => "代码片段域名提取",
        "005-multi-source-overlap" => "多来源重叠去重",
        "006-wildcard-and-root" => "通配符与根域过滤",
        "007-scope-boundaries" => "作用域边界",
        "008-normalization" => "规范化处理",
        "009-url-host-extraction" => "URL 主机提取",
        "010-time-evidence-merge" => "时间与证据合并",
        "011-empty-success" => "空结果成功响应",
        "012-pagination-success" => "分页成功",
        "013-pagination-duplicate-loop" => "分页重复游标循环",
        "014-authentication-errors" => "认证错误分类",
        "015-rate-limit-retry" => "限流重试",
        "016-upstream-server-failure" => "上游服务失败",
        "017-timeout-and-disconnect" => "超时与断连",
        "018-malformed-hostile-payload" => "畸形恶意载荷",
        "019-large-dataset" => "大规模数据集",
        "020-cancellation-and-egress-guard" => "取消与出站防护",
        "021-internet-search-nested-json" => "嵌套 JSON 网络搜索",
        "022-internet-search-partial" => "网络搜索不完整字段",
        "023-threat-intel-evidence" => "威胁情报证据",
        "024-threat-intel-noise" => "威胁情报畸形噪声",
        "025-search-engine-html" => "搜索引擎 HTML",
        "026-search-engine-links" => "搜索引擎跟踪与外部链接",
        "027-organization-domains" => "组织关联域名",
        "028-organization-conflict" => "组织弱关联冲突",
        "029-user-import-csv" => "用户导入有效 CSV",
        "030-user-import-invalid" => "用户导入重复与无效 CSV",
        "031-generic-json-deep" => "通用 JSON 深层路径",
        "032-generic-json-types" => "通用 JSON 混合字段类型",
        "033-generic-html-text" => "通用 HTML 链接与文本",
        "034-generic-html-noise" => "通用 HTML 注释与噪声",
        "035-custom-rest-header" => "自定义 REST 请求头协议",
        "036-custom-rest-post" => "自定义 REST POST 协议",
        "037-page-pagination" => "页码分页",
        "038-offset-pagination" => "偏移量分页",
        "039-post-cursor-pagination" => "POST 正文游标分页",
        "040-link-header-pagination" => "Link 请求头分页",
        "041-empty-page" => "空页终止",
        "042-cursor-loop" => "游标回退与循环",
        "043-retry-after-seconds" => "Retry-After 秒数",
        "044-retry-after-date" => "Retry-After HTTP 日期",
        "045-retry-after-invalid" => "无效和封顶 Retry-After",
        "046-no-content" => "204 无内容成功",
        "047-wrong-content-type" => "错误 Content-Type 的 JSON",
        "048-html-error-json" => "伪装 JSON 的 HTML 错误页",
        "049-unicode-punycode" => "Unicode 与 Punycode",
        "050-url-boundaries" => "URL 用户信息端口与编码",
        "051-multilevel-scope" => "多级目标域作用域",
        "052-time-conflict" => "多来源时间冲突",
        "053-evidence-conflict" => "多来源证据冲突",
        "054-duplicate-evidence" => "大量重复证据合并",
        "055-high-unique-100k" => "十万高唯一记录",
        "056-multi-source-large" => "多来源大数据",
        "057-slow-fast-sources" => "慢速与快速来源混合",
        "058-cancel-pagination" => "分页期间取消",
        "059-seed-reproducible" => "Seed 可复现性",
        "060-seed-variation" => "不同 Seed 数据变化",
        "061-network-direct-profile" => "直连本地网络配置",
        "062-proxy-http-forward-success" => "HTTP 正向代理成功",
        "063-proxy-auth-and-redaction" => "代理认证与脱敏",
        "064-proxy-connect-lifecycle" => "CONNECT 生命周期",
        "065-proxy-faults-and-timeouts" => "代理拒绝故障",
        "066-proxy-egress-and-cross-run-denied" => "代理出站与跨运行拒绝",
        "067-external-submission-pass" => "外部收集器提交通过",
        "068-external-submission-missing" => "外部提交缺失结果基线",
        "069-external-submission-out-of-scope" => "外部提交作用域基线",
        "070-external-submission-evidence-time" => "外部提交证据与时间基线",
        "071-source-status-audit-conflict" => "来源状态与审计冲突",
        "072-duplicate-cross-run-submission" => "重复与跨运行提交",
        "073-gzip-json-success" => "Gzip JSON 成功",
        "074-gzip-corrupt-stream" => "损坏 Gzip 流",
        "075-gzip-decoded-limit" => "Gzip 解压大小限制",
        "076-content-length-anomaly" => "Content-Length 异常",
        "077-strict-replay-success" => "严格回放语义成功",
        "078-strict-replay-difference" => "严格回放语义差异",
        "079-deflate-success" => "Deflate 成功",
        "080-brotli-success" => "Brotli 成功",
        "081-deflate-corrupt-stream" => "损坏 Deflate 流",
        "082-brotli-decoded-limit" => "Brotli 解压大小限制",
        "083-chunked-success" => "分块响应成功",
        "084-chunked-truncated" => "截断分块响应",
        "085-quota-per-source" => "每来源额度耗尽",
        "086-quota-per-key" => "每 Key 额度耗尽",
        "087-quota-global-run" => "全局运行额度",
        "088-quota-recovery-http-date" => "HTTP 日期额度恢复",
        "089-cache-observable-audit" => "可观察缓存审计",
        "090-quota-concurrent-atomicity" => "并发额度原子性",
        "091-pagination-second-page-rate-limit" => "分页第二页限流",
        "092-rate-limit-retry-deflate-success" => "限流重试 Deflate 成功",
        "093-quota-recovery-brotli-success" => "额度恢复 Brotli 成功",
        "094-proxy-auth-then-source-rate-limit" => "代理认证后来源限流",
        "095-proxy-reset-then-retry-success" => "代理重置后重试成功",
        "096-connect-tunnel-truncated-payload" => "CONNECT 隧道截断载荷",
        "097-source-503-then-chunked-success" => "来源 503 后分块成功",
        "098-chunked-content-length-conflict" => "分块与 Content-Length 冲突",
        "099-multi-source-global-quota-isolation" => "多来源全局额度隔离",
        "100-cancel-during-quota-recovery" => "额度恢复期间取消",
        "101-proxy-target-canonicalization" => "代理目标规范化",
        "102-proxy-authority-header-ambiguity" => "代理权威请求头歧义",
        "103-proxy-encoded-and-userinfo-targets" => "代理编码与用户信息目标",
        "104-proxy-framing-and-header-limits" => "代理分帧与请求头限制",
        "105-stale-capability-after-reset-delete" => "重置删除后的过期 capability",
        "106-concurrent-cross-run-lifecycle" => "并发跨运行生命周期",
        "107-json-structural-mutation-campaign" => "JSON 结构变异 Campaign",
        "108-text-html-csv-mutation-campaign" => "文本 HTML CSV 变异 Campaign",
        "109-pagination-token-mutation-campaign" => "分页令牌变异 Campaign",
        "110-transport-framing-mutation-campaign" => "传输分帧变异 Campaign",
        "111-mixed-lifecycle-soak" => "混合生命周期 Soak",
        "112-concurrent-mixed-fault-soak" => "并发混合故障 Soak",
        "113-replay-provenance-and-multi-diff" => "回放溯源与多差异",
        "114-coverage-and-baseline-integrity" => "覆盖率与基线完整性",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{asset, has_zh_translation};
    #[test]
    fn chinese_translation_registry_covers_bounds() {
        assert!(has_zh_translation("001-basic-certificate"));
        assert!(has_zh_translation("114-coverage-and-baseline-integrity"));
        assert!(!has_zh_translation("999-not-a-scenario"));
    }

    #[test]
    fn bundled_gui_assets_enforce_the_light_local_console_contract() {
        let html = asset("/console/").expect("console HTML").body;
        let css = asset("/console/style.css")
            .expect("console stylesheet")
            .body;
        let script = asset("/console/app.js").expect("console script").body;

        assert!(html.contains("color-scheme\" content=\"light"));
        assert!(html.contains("/console/style.css"));
        assert!(!html.contains("theme.css"));
        assert!(!html.contains("https://"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("cdn"));

        assert!(!css.contains("prefers-color-scheme"));
        assert!(!css.contains("data-theme"));
        assert!(!css.contains("color-scheme: dark"));

        assert!(!script.contains("fqdn-forge.theme"));
        assert!(!script.contains("data-theme"));
        assert!(!script.contains("data-action=\"theme\""));
        assert!(!script.contains("Copy/download"));
        assert!(!script.contains("复制/下载"));
        assert!(script.contains("COPY_COOLDOWN_MS"));
        assert!(script.contains("copyToClipboard"));
        assert!(script.contains("scenarioFilter"));
        assert!(script.contains("matching.map(scenarioCard)"));
        assert!(!script.contains("${state.scenarios.map(scenarioCard).join(\"\")}"));
        assert!(!script.contains("document.querySelectorAll(\".scenario-row\")"));
        assert!(script.contains("currentScenarioDetails"));
        assert!(script.contains("soakOperations"));
        assert!(script.contains("已复制"));
        assert!(script.contains("没有找到匹配场景"));
    }
}
