use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    AssertionResults, Assertions, AuditEventType, AuditRecord, CollectorRun, CompressionReport,
    FilterExpectation, NetworkReport, QuotaReport, ReportStatus, RequestSummary, RunReport,
    RunStatus, SubmissionEvidence, SubmissionFinding, TransportReport, Truth,
};

pub struct JudgeInput<'a> {
    pub run_id: Uuid,
    pub scenario_id: &'a str,
    pub seed: u64,
    pub target_domain: &'a str,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub collector_run: &'a CollectorRun,
    pub truth: &'a Truth,
    pub assertions: &'a Assertions,
    pub audit: &'a [AuditRecord],
    pub rejected_egress_urls: &'a [String],
}

pub fn judge_run(input: JudgeInput<'_>) -> RunReport {
    let JudgeInput {
        run_id,
        scenario_id,
        seed,
        target_domain,
        started_at,
        finished_at,
        collector_run,
        truth,
        assertions,
        audit,
        rejected_egress_urls,
    } = input;
    let actual_fqdns = collector_run
        .observations
        .iter()
        .map(|observation| observation.fqdn.clone())
        .collect::<BTreeSet<_>>();
    let expected_fqdns = truth
        .expected_fqdns
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_fqdns_pass = if truth.allow_additional_fqdns {
        expected_fqdns.is_subset(&actual_fqdns)
            && truth
                .minimum_unique_fqdns
                .is_none_or(|minimum| actual_fqdns.len() >= minimum)
    } else {
        actual_fqdns == expected_fqdns
            && truth
                .minimum_unique_fqdns
                .is_none_or(|minimum| actual_fqdns.len() >= minimum)
    };
    let forbidden_pass = truth
        .forbidden_fqdns
        .iter()
        .all(|fqdn| !actual_fqdns.contains(fqdn));
    let evidence_pass = evidence_matches(collector_run, truth);
    let filter_pass = filters_match(collector_run, &truth.expected_filter_reasons);
    let actual_run_status = derive_run_status(&collector_run.source_statuses);
    let source_pass = source_statuses_match(
        &collector_run.source_statuses,
        &truth.expected_source_status,
    ) && actual_run_status == truth.expected_run_status;
    let request_contract =
        request_contract_matches(audit, assertions, collector_run.virtual_waited_ms);
    let egress_guard = rejected_egress_urls.len() == assertions.expected_rejected_egress_attempts;
    let network = network_matches(audit, assertions);
    let quota = quota_matches(audit, assertions);
    let transport = transport_matches(audit, assertions);
    let results = AssertionResults {
        expected_fqdns: expected_fqdns_pass,
        forbidden_fqdns: forbidden_pass,
        evidence: evidence_pass,
        filter_reasons: filter_pass,
        source_status: source_pass,
        request_contract,
        egress_guard,
        network,
        quota,
        transport,
        submission_consistency: true,
    };
    let mut failures = Vec::new();
    if !expected_fqdns_pass {
        failures.push(format!(
            "FQDN mismatch: expected {expected_fqdns:?}, actual {actual_fqdns:?}"
        ));
    }
    if !forbidden_pass {
        failures.push("forbidden FQDN was emitted".to_owned());
    }
    if !evidence_pass {
        failures.push("evidence did not meet scenario truth".to_owned());
    }
    if !filter_pass {
        failures.push("filter reasons did not meet scenario truth".to_owned());
    }
    if !source_pass {
        failures.push("source status or aggregate run status did not match truth".to_owned());
    }
    if !request_contract {
        failures.push("request contract did not match assertions.yaml".to_owned());
    }
    if !egress_guard {
        failures.push(format!(
            "rejected egress count mismatch: expected {}, actual {}",
            assertions.expected_rejected_egress_attempts,
            rejected_egress_urls.len()
        ));
    }
    if !network {
        failures.push("network proxy contract did not match assertions.yaml".to_owned());
    }
    if !quota {
        failures.push("quota decision contract did not match assertions.yaml".to_owned());
    }
    if !transport {
        failures.push("transport contract did not match assertions.yaml".to_owned());
    }
    let requests = RequestSummary {
        total: audit.len(),
        unmatched: audit.iter().filter(|record| !record.matched).count(),
        extra: audit.iter().filter(|record| record.extra).count(),
        rejected_egress_attempts: rejected_egress_urls.len(),
    };
    let status = if results.passed() {
        ReportStatus::Passed
    } else {
        ReportStatus::Failed
    };
    let mut report = RunReport {
        schema_version: crate::V14_SCHEMA_VERSION.to_owned(),
        lab_version: crate::V14_SCHEMA_VERSION.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        run_id: run_id.to_string(),
        scenario_id: scenario_id.to_owned(),
        seed,
        target_domain: target_domain.to_owned(),
        started_at,
        finished_at,
        status,
        result: status,
        actual_run_status,
        expected_run_status: truth.expected_run_status,
        source_statuses: collector_run.source_statuses.clone(),
        findings: findings_from_collector(collector_run),
        filtered: collector_run.filtered.clone(),
        assertions: results,
        truth: truth.clone(),
        requests: audit.to_vec(),
        request_summary: requests,
        virtual_waited_ms: collector_run.virtual_waited_ms,
        metrics: collector_run.metrics.clone(),
        failures,
        violations: Vec::new(),
        replay_command: format!(
            "cargo run -p lab-cli -- replay --strict --report artifacts/reports/{scenario_id}-default-seed-{seed}.json"
        ),
        reproducible: true,
        submission: Default::default(),
        semantic_fingerprint: String::new(),
        replay: Default::default(),
        compression: compression_from_audit(audit),
        network: network_from_audit(audit),
        quota: quota_from_audit(audit),
        transport: transport_from_audit(audit),
        provenance: Default::default(),
        diagnostics: Default::default(),
        audit: audit.to_vec(),
    };
    refresh_semantic_fingerprint(&mut report);
    report
}

#[must_use]
pub fn network_from_audit(audit: &[AuditRecord]) -> NetworkReport {
    let proxy = audit
        .iter()
        .filter(|record| record.event_type == AuditEventType::ProxyRequest)
        .collect::<Vec<_>>();
    let direct = audit
        .iter()
        .filter(|record| {
            record.event_type == AuditEventType::SourceRequest && record.correlation_id.is_none()
        })
        .count();
    NetworkReport {
        mode: proxy
            .iter()
            .filter_map(|record| record.proxy_mode)
            .next()
            .unwrap_or_default(),
        proxy_requests: proxy.len(),
        direct_source_requests: direct,
        egress_denied: proxy.iter().any(|record| record.external_target_rejected),
        reasons: proxy
            .iter()
            .filter_map(|record| record.proxy_reason.clone())
            .collect(),
    }
}

#[must_use]
pub fn quota_from_audit(audit: &[AuditRecord]) -> QuotaReport {
    let decisions = audit
        .iter()
        .filter(|record| record.event_type == AuditEventType::QuotaDecision)
        .collect::<Vec<_>>();
    QuotaReport {
        decisions: decisions.len(),
        consumed: decisions
            .iter()
            .filter(|record| record.quota_consumed)
            .count(),
        rate_limited: decisions
            .iter()
            .filter(|record| record.quota_rate_limited)
            .count(),
        recovery_virtual_wait_ms: decisions
            .iter()
            .filter_map(|record| record.quota_recovery_virtual_wait_ms)
            .max()
            .unwrap_or(0),
    }
}

#[must_use]
pub fn transport_from_audit(audit: &[AuditRecord]) -> TransportReport {
    let records = audit
        .iter()
        .filter(|record| record.event_type == AuditEventType::SourceRequest)
        .collect::<Vec<_>>();
    TransportReport {
        transfer_mode: records
            .iter()
            .filter_map(|record| record.transfer_mode)
            .next(),
        chunk_count: records.iter().map(|record| record.chunk_count).sum(),
        malformed: records
            .iter()
            .any(|record| record.transport_fault.is_some()),
        limit_violation: records
            .iter()
            .find_map(|record| record.compression_limit_violation.clone()),
    }
}

#[must_use]
pub fn findings_from_collector(run: &CollectorRun) -> Vec<SubmissionFinding> {
    run.observations
        .iter()
        .map(|observation| SubmissionFinding {
            fqdn: observation.fqdn.clone(),
            evidence: vec![SubmissionEvidence {
                source_id: observation.source_name.clone(),
                source_kind: observation.source_kind,
                record_id: observation.record_id.clone(),
                url: observation.evidence.get("url").cloned(),
                observed_at: observation.observed_at,
                tags: observation.tags.clone(),
                confidence: observation.confidence,
            }],
        })
        .collect()
}

#[must_use]
pub fn compression_from_audit(audit: &[AuditRecord]) -> CompressionReport {
    CompressionReport {
        wire_bytes: audit.iter().map(|record| record.wire_bytes).sum(),
        decoded_bytes: audit.iter().map(|record| record.decoded_bytes).sum(),
        encoding: audit
            .iter()
            .filter_map(|record| record.content_encoding.clone())
            .find(|encoding| !encoding.eq_ignore_ascii_case("identity")),
        limit_violation: audit
            .iter()
            .find_map(|record| record.compression_limit_violation.clone()),
    }
}

pub fn refresh_semantic_fingerprint(report: &mut RunReport) {
    report.semantic_fingerprint = semantic_fingerprint(report);
}

#[must_use]
pub fn semantic_fingerprint(report: &RunReport) -> String {
    let canonical = semantic_projection(report);
    let encoded = serde_json::to_vec(&canonical).expect("semantic projection is serializable");
    let digest = Sha256::digest(encoded);
    format!("sha256-{digest:x}")
}

#[must_use]
pub fn semantic_difference(previous: &RunReport, current: &RunReport) -> Option<String> {
    first_difference(
        "$",
        &semantic_projection(previous),
        &semantic_projection(current),
    )
}

pub fn semantic_projection(report: &RunReport) -> Value {
    let mut findings = report.findings.clone();
    findings.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
    for finding in &mut findings {
        finding.evidence.sort_by(|left, right| {
            (
                &left.source_id,
                &left.record_id,
                &left.url,
                &left.observed_at,
            )
                .cmp(&(
                    &right.source_id,
                    &right.record_id,
                    &right.url,
                    &right.observed_at,
                ))
        });
    }
    let requests = report
        .requests
        .iter()
        .map(|record| {
            json!({
                "sequence": record.sequence,
                "method": record.method,
                "path": record.path,
                "query": record.query,
                "headers": record.headers,
                "body": record.body_summary,
                "endpoint_id": record.endpoint_id,
                "response_index": record.response_index,
                "response_status": record.response_status,
                "before_submission": record.before_submission,
                "consumed": record.consumed,
                "matched": record.matched,
                "blocked_egress": record.external_target_rejected,
                "virtual_wait_ms": record.virtual_wait_ms,
                "wire_bytes": record.wire_bytes,
                "decoded_bytes": record.decoded_bytes,
                "content_encoding": record.content_encoding,
                "compression_limit_violation": record.compression_limit_violation,
                "event_type": record.event_type,
                "proxy_mode": record.proxy_mode,
                "proxy_target": record.proxy_target,
                "proxy_authentication": record.proxy_authentication,
                "proxy_reason": record.proxy_reason,
                "correlation_id": record.correlation_id,
                "quota_scope": record.quota_scope,
                "quota_remaining_before": record.quota_remaining_before,
                "quota_remaining_after": record.quota_remaining_after,
                "quota_consumed": record.quota_consumed,
                "quota_rate_limited": record.quota_rate_limited,
                "quota_recovery_virtual_wait_ms": record.quota_recovery_virtual_wait_ms,
                "transfer_mode": record.transfer_mode,
                "chunk_count": record.chunk_count,
                "transport_fault": record.transport_fault,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version": report.schema_version,
        "scenario_id": report.scenario_id,
        "seed": report.seed,
        "target_domain": report.target_domain,
        "status": report.status,
        "findings": findings,
        "filtered": report.filtered,
        "source_statuses": report.source_statuses,
        "requests": requests,
        "request_count": report.metrics.request_count,
        "retry_count": report.metrics.retry_count,
        "virtual_wait_ms": report.virtual_waited_ms,
        "cancelled": report.metrics.cancelled,
        "submission": {
            "received": report.submission.received,
            "accepted": report.submission.accepted,
            "finding_count": report.submission.finding_count,
        },
    })
}

fn first_difference(path: &str, left: &Value, right: &Value) -> Option<String> {
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            let keys = left.keys().chain(right.keys()).collect::<BTreeSet<_>>();
            keys.into_iter().find_map(|key| {
                let next = format!("{path}.{key}");
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) => first_difference(&next, left, right),
                    _ => Some(format!("{next}: field presence differs")),
                }
            })
        }
        (Value::Array(left), Value::Array(right)) => {
            if left.len() != right.len() {
                return Some(format!(
                    "{path}: array length {} != {}",
                    left.len(),
                    right.len()
                ));
            }
            left.iter()
                .zip(right)
                .enumerate()
                .find_map(|(index, (left, right))| {
                    first_difference(&format!("{path}[{index}]"), left, right)
                })
        }
        _ if left != right => Some(format!("{path}: {left} != {right}")),
        _ => None,
    }
}

fn evidence_matches(run: &CollectorRun, truth: &Truth) -> bool {
    truth.expected_observations.iter().all(|(fqdn, expected)| {
        let observations = run
            .observations
            .iter()
            .filter(|observation| &observation.fqdn == fqdn)
            .collect::<Vec<_>>();
        observations.len() >= expected.min_count
            && expected.source_kinds.iter().all(|source| {
                observations
                    .iter()
                    .any(|observation| observation.source_kind == *source)
            })
            && expected.source_names.iter().all(|source| {
                observations
                    .iter()
                    .any(|observation| observation.source_name == *source)
            })
            && expected.record_ids.iter().all(|record_id| {
                observations
                    .iter()
                    .any(|observation| observation.record_id.as_deref() == Some(record_id))
            })
            && expected.tags.iter().all(|tag| {
                observations
                    .iter()
                    .any(|observation| observation.tags.iter().any(|actual| actual == tag))
            })
            && expected.minimum_confidence.is_none_or(|minimum| {
                observations
                    .iter()
                    .filter_map(|observation| observation.confidence)
                    .any(|confidence| confidence >= minimum)
            })
            && (!expected.requires_time
                || observations
                    .iter()
                    .any(|observation| observation.observed_at.is_some()))
    })
}

fn filters_match(run: &CollectorRun, expected: &[FilterExpectation]) -> bool {
    expected.iter().all(|wanted| {
        run.filtered
            .iter()
            .any(|actual| actual.value == wanted.value && actual.reason == wanted.reason)
    })
}

fn request_contract_matches(
    audit: &[AuditRecord],
    assertions: &Assertions,
    virtual_waited_ms: u64,
) -> bool {
    let source_audit = audit
        .iter()
        .filter(|record| record.event_type == AuditEventType::SourceRequest)
        .collect::<Vec<_>>();
    source_audit.len() == assertions.expected_requests
        && source_audit.iter().filter(|record| !record.matched).count()
            == assertions.expected_unmatched_requests
        && assertions
            .endpoint_requests
            .iter()
            .all(|(endpoint, expected)| {
                source_audit
                    .iter()
                    .filter(|record| record.endpoint_id.as_deref() == Some(endpoint))
                    .count()
                    == *expected
            })
        && assertions
            .required_paths
            .iter()
            .all(|path| source_audit.iter().any(|record| &record.path == path))
        && assertions
            .forbidden_paths
            .iter()
            .all(|path| source_audit.iter().all(|record| &record.path != path))
        && assertions
            .request_sequence
            .iter()
            .enumerate()
            .all(|(index, expected)| {
                source_audit.get(index).is_some_and(|actual| {
                    actual.endpoint_id.as_deref() == Some(&expected.endpoint)
                        && expected.response_index.is_none_or(|response_index| {
                            actual.response_index == Some(response_index)
                        })
                })
            })
        && assertions
            .timing
            .min_virtual_wait_ms
            .is_none_or(|minimum| virtual_waited_ms >= minimum)
        && assertions
            .timing
            .max_virtual_wait_ms
            .is_none_or(|maximum| virtual_waited_ms <= maximum)
}

fn network_matches(audit: &[AuditRecord], assertions: &Assertions) -> bool {
    let proxy = audit
        .iter()
        .filter(|record| record.event_type == AuditEventType::ProxyRequest)
        .collect::<Vec<_>>();
    let direct_source = audit.iter().any(|record| {
        record.event_type == AuditEventType::SourceRequest && record.correlation_id.is_none()
    });
    assertions
        .expected_proxy_requests
        .is_none_or(|expected| proxy.len() == expected)
        && assertions
            .require_proxy
            .is_none_or(|required| !required || !proxy.is_empty())
        && (!assertions.forbid_direct_source || !direct_source)
}

fn quota_matches(audit: &[AuditRecord], assertions: &Assertions) -> bool {
    let decisions = audit
        .iter()
        .filter(|record| record.event_type == AuditEventType::QuotaDecision)
        .collect::<Vec<_>>();
    assertions
        .expected_quota_decisions
        .is_none_or(|expected| decisions.len() == expected)
        && (!assertions.require_quota_rate_limited
            || decisions.iter().any(|record| record.quota_rate_limited))
}

fn transport_matches(audit: &[AuditRecord], assertions: &Assertions) -> bool {
    let source = audit
        .iter()
        .filter(|record| record.event_type == AuditEventType::SourceRequest)
        .collect::<Vec<_>>();
    assertions
        .required_content_encoding
        .as_ref()
        .is_none_or(|encoding| {
            source.iter().any(|record| {
                record
                    .content_encoding
                    .as_deref()
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(encoding))
            })
        })
        && assertions.required_transfer_mode.is_none_or(|mode| {
            source
                .iter()
                .any(|record| record.transfer_mode == Some(mode))
        })
        && assertions
            .required_transport_fault
            .as_ref()
            .is_none_or(|fault| {
                source
                    .iter()
                    .any(|record| record.transport_fault.as_deref() == Some(fault))
            })
}

fn derive_run_status(
    statuses: &std::collections::BTreeMap<String, crate::SourceStatus>,
) -> RunStatus {
    if !statuses.is_empty()
        && statuses
            .values()
            .all(|status| *status == crate::SourceStatus::Cancelled)
    {
        return RunStatus::Cancelled;
    }
    let success = statuses
        .values()
        .filter(|status| {
            matches!(
                status,
                crate::SourceStatus::Success
                    | crate::SourceStatus::Succeeded
                    | crate::SourceStatus::Completed
            )
        })
        .count();
    if success == statuses.len() {
        RunStatus::Success
    } else if success > 0 {
        RunStatus::PartialSuccess
    } else {
        RunStatus::Failure
    }
}

fn source_statuses_match(
    actual: &std::collections::BTreeMap<String, crate::SourceStatus>,
    expected: &std::collections::BTreeMap<String, crate::SourceStatus>,
) -> bool {
    actual.len() == expected.len()
        && actual.iter().all(|(source, actual)| {
            expected
                .get(source)
                .is_some_and(|expected| source_status_equivalent(*actual, *expected))
        })
}

fn source_status_equivalent(actual: crate::SourceStatus, expected: crate::SourceStatus) -> bool {
    use crate::SourceStatus::{Completed, Succeeded, Success};
    matches!(
        (actual, expected),
        (
            Success | Succeeded | Completed,
            Success | Succeeded | Completed
        )
    ) || actual == expected
}
