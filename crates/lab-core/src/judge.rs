use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    AssertionResults, Assertions, AuditRecord, CollectorRun, FilterExpectation, ReportStatus,
    RequestSummary, RunReport, RunStatus, Truth,
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
    let source_pass = collector_run.source_statuses == truth.expected_source_status
        && actual_run_status == truth.expected_run_status;
    let request_contract =
        request_contract_matches(audit, assertions, collector_run.virtual_waited_ms);
    let egress_guard = rejected_egress_urls.len() == assertions.expected_rejected_egress_attempts;
    let results = AssertionResults {
        expected_fqdns: expected_fqdns_pass,
        forbidden_fqdns: forbidden_pass,
        evidence: evidence_pass,
        filter_reasons: filter_pass,
        source_status: source_pass,
        request_contract,
        egress_guard,
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
    RunReport {
        schema_version: "1.2".to_owned(),
        lab_version: "1.2".to_owned(),
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
        assertions: results,
        truth: truth.clone(),
        requests: audit.to_vec(),
        request_summary: requests,
        virtual_waited_ms: collector_run.virtual_waited_ms,
        metrics: collector_run.metrics.clone(),
        failures,
        violations: Vec::new(),
        replay_command: format!(
            "cargo run -p lab-cli -- replay --report artifacts/reports/{scenario_id}-default.json"
        ),
        reproducible: true,
        audit: audit.to_vec(),
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
    audit.len() == assertions.expected_requests
        && audit.iter().filter(|record| !record.matched).count()
            == assertions.expected_unmatched_requests
        && assertions
            .endpoint_requests
            .iter()
            .all(|(endpoint, expected)| {
                audit
                    .iter()
                    .filter(|record| record.endpoint_id.as_deref() == Some(endpoint))
                    .count()
                    == *expected
            })
        && assertions
            .required_paths
            .iter()
            .all(|path| audit.iter().any(|record| &record.path == path))
        && assertions
            .forbidden_paths
            .iter()
            .all(|path| audit.iter().all(|record| &record.path != path))
        && assertions
            .request_sequence
            .iter()
            .enumerate()
            .all(|(index, expected)| {
                audit.get(index).is_some_and(|actual| {
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
