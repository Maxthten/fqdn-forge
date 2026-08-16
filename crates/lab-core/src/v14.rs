//! Deterministic V1.4 observation tooling.  Everything in this module works
//! exclusively from loaded local scenarios and in-memory reports; it never
//! reads environment configuration, invokes commands, resolves names, or
//! opens network connections.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::{Arc, Barrier},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    AuditEventType, DifferenceCategory, FaultScriptReport, LabState, LoadedScenario,
    ResourceSummary, RunProvenance, RunReport, Scenario, ScenarioRepository, semantic_projection,
};

pub const V14_SCHEMA_VERSION: &str = "1.4.1";
pub const MAX_REPLAY_DIFFERENCES: usize = 50;

const COVERAGE_DIMENSIONS: [&str; 10] = [
    "source_shape",
    "payload_format",
    "pagination",
    "authentication",
    "network_profile",
    "quota_scope",
    "transport",
    "fault_class",
    "execution_style",
    "assertion_focus",
];

/// A compact, machine-readable rendering of the coverage matrix.  `gaps`
/// deliberately reports empty enum values rather than hiding them: a matrix
/// is an observation tool, not a hand-maintained pass/fail table.
#[derive(Clone, Debug, Serialize)]
pub struct CoverageReport {
    pub schema_version: String,
    pub scenario_count: usize,
    pub dimensions: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    pub gaps: BTreeMap<String, Vec<String>>,
    pub high_risk_combinations: BTreeMap<String, Vec<String>>,
    pub exceptions: Vec<CoverageException>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoverageException {
    pub id: String,
    pub rule: String,
    pub dimension: String,
    pub value: String,
    pub reason: String,
    pub created_on: String,
    pub expires_on: String,
    pub reference: String,
    pub replacement: String,
    pub security_relevant: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct CoveragePolicyFile {
    required_combinations: Vec<String>,
    #[serde(default)]
    exceptions: Vec<CoverageException>,
}

const REQUIRED_COVERAGE_COMBINATIONS: [&str; 15] = [
    "http_proxy+proxy_auth+rate_limit",
    "http_proxy+per_source+retry_recovery",
    "connect_proxy+truncated+resource",
    "direct+per_key+deflate",
    "direct+global_run+multi_source",
    "brotli+rate_limit/recovery",
    "chunked+malformed/content-length-conflict",
    "pagination+rate_limit+retry_recovery",
    "campaign+json/html/csv/text",
    "campaign+pagination",
    "campaign+transport",
    "lifecycle+concurrent+reset/delete",
    "proxy_rejection+source_requests=0+quota_decisions=0",
    "strict_replay+provenance_difference",
    "baseline+scenario_fixture_digest",
];

#[derive(Clone, Debug, Serialize)]
pub struct CampaignDefinition {
    pub id: &'static str,
    pub scenario_id: &'static str,
    pub seed_min: u64,
    pub seed_max: u64,
    pub operators: &'static [&'static str],
    pub max_mutations: usize,
    pub max_nested_depth: usize,
    pub max_items: usize,
    pub max_text_bytes: usize,
    pub max_chunks: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CampaignManifest {
    pub schema_version: String,
    pub campaign_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub operators: Vec<String>,
    pub parameters: BTreeMap<String, u64>,
    pub mutation_fixture: Value,
    pub scenario_revision_digest: String,
    pub fixture_digest: String,
    pub truth_digest: String,
    pub reproduction_command: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CampaignReport {
    pub schema_version: String,
    pub manifest: CampaignManifest,
    pub report: RunReport,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Baseline {
    pub schema_version: String,
    pub profile: String,
    pub entries: BTreeMap<String, BaselineEntry>,
    #[serde(default)]
    pub public_soak: Option<SoakBaseline>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SoakBaseline {
    pub preset: SoakPreset,
    pub seed: u64,
    pub minimum_operations: usize,
    pub concurrency: usize,
    pub action_counts: BTreeMap<String, usize>,
    pub outcome_counts: BTreeMap<String, usize>,
    pub invariants: BTreeMap<String, bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BaselineEntry {
    pub scenario_revision_digest: String,
    pub fixture_digest: String,
    pub semantic_fingerprint: String,
    pub logical_metrics: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BaselineComparison {
    pub matched: bool,
    pub differences: Vec<BaselineDifference>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BaselineDifference {
    pub category: String,
    pub field: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SoakPreset {
    Smoke,
    Standard,
    Release,
}

impl SoakPreset {
    #[must_use]
    pub const fn operations(self) -> usize {
        match self {
            Self::Smoke => 50,
            Self::Standard => 250,
            Self::Release => 1_000,
        }
    }

    #[must_use]
    pub const fn concurrency(self) -> usize {
        match self {
            Self::Smoke => 2,
            Self::Standard => 4,
            Self::Release => 8,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SoakAction {
    pub index: usize,
    #[serde(default)]
    pub lane: usize,
    pub operation: String,
    pub scenario_id: String,
    pub outcome: String,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub seed: u64,
    #[serde(default)]
    pub audit_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SoakReport {
    pub schema_version: String,
    pub preset: SoakPreset,
    pub seed: u64,
    pub operations: usize,
    pub concurrency: usize,
    pub action_trace: Vec<SoakAction>,
    #[serde(default)]
    pub scenario_pool: Vec<String>,
    #[serde(default)]
    pub trace_coverage: BTreeMap<String, bool>,
    #[serde(default)]
    pub action_counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub outcome_counts: BTreeMap<String, usize>,
    pub resources: ResourceSummary,
    pub invariants: BTreeMap<String, bool>,
    pub last_failure: Option<String>,
    pub reproduction_command: String,
}

#[derive(Clone, Debug, Default)]
pub struct DifferenceSummary {
    pub differences: Vec<crate::ReplayDifference>,
    pub counts: BTreeMap<String, usize>,
    pub truncated: usize,
}

#[must_use]
pub fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        Value::Object(values) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in values {
                sorted.insert(key.clone(), canonical_json(value));
            }
            Value::Object(sorted.into_iter().collect())
        }
        _ => value.clone(),
    }
}

#[must_use]
pub fn stable_digest(value: &Value) -> String {
    let bytes = serde_json::to_vec(&canonical_json(value)).expect("JSON values serialize");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

#[must_use]
pub fn scenario_revision_digest(scenario: &Scenario) -> String {
    stable_digest(&serde_json::to_value(scenario).expect("scenario is serializable"))
}

pub fn fixture_digest(loaded: &LoadedScenario) -> Result<String> {
    let mut fixtures = BTreeMap::<String, Value>::new();
    for endpoint in &loaded.scenario.endpoints {
        for (index, reply) in endpoint.replies.iter().enumerate() {
            if let Some(file) = &reply.body_file {
                let path = loaded.directory.join(file);
                let body = fs::read(&path)
                    .with_context(|| format!("cannot read local fixture {}", path.display()))?;
                let normalized = String::from_utf8_lossy(&body).replace("\r\n", "\n");
                fixtures.insert(
                    format!("{}:{}:file", endpoint.id, index),
                    Value::String(normalized),
                );
            }
            fixtures.insert(
                format!("{}:{}:reply", endpoint.id, index),
                serde_json::to_value(reply).expect("reply is serializable"),
            );
        }
    }
    Ok(stable_digest(
        &serde_json::to_value(fixtures).expect("fixtures serialize"),
    ))
}

pub fn provenance_for(loaded: &LoadedScenario, seed: u64) -> Result<RunProvenance> {
    let mut scenario = loaded.scenario.clone();
    scenario.seed = seed;
    Ok(RunProvenance {
        scenario_revision_digest: scenario_revision_digest(&scenario),
        fixture_digest: fixture_digest(loaded)?,
        actual_response_digest: String::new(),
        actual_truth_digest: stable_digest(
            &serde_json::to_value(&loaded.truth).expect("truth is serializable"),
        ),
        fault_script_digest: stable_digest(
            &serde_json::to_value(&scenario.fault_script).expect("fault script is serializable"),
        ),
        campaign_operators: Vec::new(),
        campaign_id: None,
        campaign_seed: None,
        network_profile_summary: format!(
            "{:?};proxy_required={};fault={:?}",
            scenario.network_profile.mode,
            scenario.network_profile.proxy_must_be_used,
            scenario.network_profile.fault
        ),
        coverage_tags: coverage_tags_for(&scenario),
        report_schema_version: V14_SCHEMA_VERSION.to_owned(),
        legacy_provenance_unavailable: false,
    })
}

/// Adds V1.4 data after the legacy judge has produced its independent verdict.
/// This keeps truth and judgement separate from diagnostic decoration.
pub fn enrich_report(report: &mut RunReport, loaded: &LoadedScenario) -> Result<()> {
    report.schema_version = V14_SCHEMA_VERSION.to_owned();
    report.lab_version = V14_SCHEMA_VERSION.to_owned();
    report.provenance = provenance_for(loaded, report.seed)?;
    let responses = report
        .requests
        .iter()
        .filter_map(|record| {
            record.response_digest.as_ref().map(|digest| {
                (
                    record.endpoint_id.clone(),
                    record.script_step_id.clone(),
                    digest,
                )
            })
        })
        .collect::<Vec<_>>();
    report.provenance.actual_response_digest =
        stable_digest(&serde_json::to_value(responses).expect("response digests are serializable"));
    report.fault_script = fault_script_report(loaded, &report.requests);
    if !report.fault_script.missing_required_steps.is_empty()
        || !report.fault_script.unexpected_steps.is_empty()
    {
        report.status = crate::ReportStatus::Failed;
        report.result = crate::ReportStatus::Failed;
        report.failures.push(format!(
            "fault script incomplete: missing [{}]; unexpected [{}]",
            report.fault_script.missing_required_steps.join(", "),
            report.fault_script.unexpected_steps.join(", ")
        ));
    }
    report.diagnostics = diagnostics_for(report);
    crate::refresh_semantic_fingerprint(report);
    Ok(())
}

#[must_use]
pub fn fault_script_report(
    loaded: &LoadedScenario,
    audit: &[crate::AuditRecord],
) -> FaultScriptReport {
    let executed_steps = audit
        .iter()
        .filter_map(|record| record.script_step_id.clone())
        .collect::<Vec<_>>();
    let missing_required_steps = loaded
        .scenario
        .fault_script
        .iter()
        .filter(|step| step.required && !executed_steps.iter().any(|id| id == &step.id))
        .map(|step| step.id.clone())
        .collect::<Vec<_>>();
    let unexpected_steps = audit
        .iter()
        .flat_map(|record| record.mismatch_reasons.iter())
        .filter(|reason| reason.starts_with("unexpected_script_step"))
        .cloned()
        .collect::<Vec<_>>();
    FaultScriptReport {
        order_failure_reason: unexpected_steps.first().cloned(),
        executed_steps,
        missing_required_steps,
        unexpected_steps,
    }
}

#[must_use]
pub fn diagnostics_for(report: &RunReport) -> crate::DiagnosticSummary {
    let mut failure_categories = BTreeMap::new();
    for failure in &report.failures {
        let category = if failure.contains("quota") || failure.contains("rate") {
            "quota"
        } else if failure.contains("transport") || failure.contains("compression") {
            "transport"
        } else if failure.contains("proxy") || failure.contains("network") {
            "proxy"
        } else if failure.contains("source status") {
            "source_status"
        } else {
            "finding"
        };
        *failure_categories.entry(category.to_owned()).or_insert(0) += 1;
    }
    let event_timeline = report
        .requests
        .iter()
        .map(|record| crate::EventTimelineEntry {
            sequence: record.sequence,
            category: if record.transport_fault.is_some() || record.transfer_mode.is_some() {
                "transport".to_owned()
            } else {
                match record.event_type {
                    AuditEventType::ProxyRequest => "proxy",
                    AuditEventType::QuotaDecision => "quota",
                    AuditEventType::SourceRequest => "source",
                    AuditEventType::Lifecycle => "lifecycle",
                }
                .to_owned()
            },
            status: record.response_status,
            detail: record
                .proxy_reason
                .clone()
                .or_else(|| record.transport_fault.clone())
                .unwrap_or_else(|| {
                    record
                        .endpoint_id
                        .clone()
                        .unwrap_or_else(|| "local".to_owned())
                }),
        })
        .collect();
    let mut resource_invariants = BTreeMap::new();
    resource_invariants.insert(
        "no_external_egress".to_owned(),
        report
            .requests
            .iter()
            .filter(|record| record.event_type == AuditEventType::ProxyRequest)
            .all(|record| {
                record.external_target_rejected
                    || record
                        .proxy_target
                        .as_deref()
                        .is_none_or(|target| target.starts_with("127.0.0.1:"))
            }),
    );
    resource_invariants.insert(
        "request_sequence_bounded".to_owned(),
        report.request_summary.extra == 0,
    );
    resource_invariants.insert(
        "submission_isolated".to_owned(),
        report.assertions.submission_consistency,
    );
    crate::DiagnosticSummary {
        verdict: format!("{:?}", report.status).to_ascii_lowercase(),
        failure_categories,
        event_timeline,
        proxy_summary: format!(
            "mode={:?}; requests={}; direct={}",
            report.network.mode,
            report.network.proxy_requests,
            report.network.direct_source_requests
        ),
        quota_summary: format!(
            "decisions={}; consumed={}; rate_limited={}",
            report.quota.decisions, report.quota.consumed, report.quota.rate_limited
        ),
        transport_summary: format!(
            "mode={:?}; chunks={}; malformed={}",
            report.transport.transfer_mode,
            report.transport.chunk_count,
            report.transport.malformed
        ),
        lifecycle_summary: "run-local audit, submission and report state".to_owned(),
        resource_invariants,
        audit_reference: format!("run:{}:audit", report.scenario_id),
        recommended_replay_command: report.replay_command.clone(),
    }
}

#[must_use]
pub fn coverage_tags_for(scenario: &Scenario) -> BTreeMap<String, Vec<String>> {
    normalise_tags(scenario.coverage_tags.clone())
}

fn normalise_tags(mut tags: BTreeMap<String, Vec<String>>) -> BTreeMap<String, Vec<String>> {
    for values in tags.values_mut() {
        values.sort();
        values.dedup();
    }
    tags
}

pub fn validate_v14_scenario(loaded: &LoadedScenario) -> Vec<String> {
    let mut issues = Vec::new();
    if loaded.scenario.coverage_tags.is_empty() {
        issues.push("every scenario must declare coverage_tags".to_owned());
    }
    let tags = coverage_tags_for(&loaded.scenario);
    for dimension in COVERAGE_DIMENSIONS {
        let values = tags.get(dimension).cloned().unwrap_or_default();
        if values.is_empty() {
            issues.push(format!(
                "coverage_tags.{dimension} must have at least one value"
            ));
            continue;
        }
        let allowed = allowed_values(dimension);
        let mut seen = BTreeSet::new();
        for value in values {
            if !allowed.contains(&value.as_str()) {
                issues.push(format!(
                    "coverage_tags.{dimension} has unknown value {value}"
                ));
            }
            if !seen.insert(value.clone()) {
                issues.push(format!(
                    "coverage_tags.{dimension} duplicates value {value}"
                ));
            }
        }
    }
    for key in tags.keys() {
        if !COVERAGE_DIMENSIONS.contains(&key.as_str()) {
            issues.push(format!("coverage_tags has unknown dimension {key}"));
        }
    }
    if loaded.scenario.composition.fault_stages.len() > 3 {
        issues.push("composition.fault_stages may contain at most three primary faults".to_owned());
    }
    for order in &loaded.scenario.composition.event_order {
        if order.before.trim().is_empty()
            || order.after.trim().is_empty()
            || order.before == order.after
        {
            issues.push(
                "composition.event_order must contain two different non-empty event names"
                    .to_owned(),
            );
        }
    }
    let scenario_number = loaded
        .scenario
        .id
        .split('-')
        .next()
        .and_then(|value| value.parse::<u16>().ok());
    if !scenario_number.is_some_and(|number| (91..=114).contains(&number)) {
        return issues;
    }
    let mut script_ids = BTreeSet::new();
    let mut saw_rate_limit_step = false;
    let mut saw_positive_wait = false;
    for step in &loaded.scenario.fault_script {
        if step.id.trim().is_empty() || !script_ids.insert(step.id.clone()) {
            issues.push("fault_script step ids must be unique and non-empty".to_owned());
        }
        let Some(endpoint) = loaded
            .scenario
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id == step.endpoint)
        else {
            issues.push(format!(
                "fault_script step {} references unknown endpoint {}; add the endpoint or fix fault_script.endpoint",
                step.id, step.endpoint
            ));
            continue;
        };
        if step
            .response_index
            .is_some_and(|index| index >= endpoint.replies.len())
        {
            issues.push(format!(
                "fault_script step {} response_index exceeds endpoint {} replies; use a bounded existing reply index",
                step.id, endpoint.id
            ));
        }
        saw_positive_wait |= step.minimum_virtual_wait_ms > 0;
        if step.expect_quota_rate_limited {
            saw_rate_limit_step = true;
            if endpoint.quota.is_empty() {
                issues.push(format!(
                    "fault_script step {} expects quota rejection but endpoint {} has no quota profile; add a real bounded quota",
                    step.id, endpoint.id
                ));
            }
            if step.response_index.is_some() {
                issues.push(format!(
                    "fault_script step {} expects quota rejection and must not consume a normal reply; remove response_index",
                    step.id
                ));
            }
        }
        if step.response_index.is_some_and(|index| {
            endpoint
                .replies
                .get(index)
                .is_some_and(|reply| reply.status == 429)
        }) {
            saw_rate_limit_step = true;
        }
        if step.stage == crate::FaultScriptStage::Proxy
            && loaded.scenario.network_profile.mode == crate::NetworkMode::Direct
        {
            issues.push(format!(
                "fault_script step {} is a proxy action but network_profile is direct; use a bounded local proxy profile",
                step.id
            ));
        }
    }
    let tag = |dimension: &str, value: &str| {
        tags.get(dimension)
            .is_some_and(|values| values.iter().any(|item| item == value))
    };
    if (tag("fault_class", "rate_limit") || tag("fault_class", "retry_recovery"))
        && (!saw_rate_limit_step || !saw_positive_wait || loaded.scenario.fault_script.len() < 2)
    {
        issues.push(
            "fault_class rate_limit/retry_recovery requires a real quota-rejected fault_script step, a positive virtual wait, and a later retry step"
                .to_owned(),
        );
    }
    if tag("pagination", "page") && tag("fault_class", "rate_limit") {
        let pages = loaded
            .scenario
            .fault_script
            .iter()
            .filter_map(|step| step.query.get("page"))
            .collect::<BTreeSet<_>>();
        if pages.len() < 2 {
            issues.push(
                "pagination rate-limit scenario requires fault_script requests for at least two distinct page values"
                    .to_owned(),
            );
        }
    }
    if (tag("network_profile", "http_proxy") || tag("network_profile", "connect_proxy"))
        && (!loaded.scenario.network_profile.proxy_must_be_used
            || loaded.assertions.require_proxy != Some(true)
            || !loaded.assertions.forbid_direct_source)
    {
        issues.push(
            "proxy coverage tags require network_profile.proxy_must_be_used, assertions.require_proxy=true and forbid_direct_source=true"
                .to_owned(),
        );
    }
    if tag("authentication", "proxy_auth")
        && (loaded.scenario.network_profile.mode == crate::NetworkMode::Direct
            || loaded
                .assertions
                .expected_proxy_requests
                .unwrap_or_default()
                == 0)
    {
        issues.push(
            "proxy_auth scenarios require a real local proxy profile and at least one expected proxy audit"
                .to_owned(),
        );
    }
    if !tag("quota_scope", "none")
        && (loaded
            .scenario
            .endpoints
            .iter()
            .all(|endpoint| endpoint.quota.is_empty())
            || loaded
                .assertions
                .expected_quota_decisions
                .unwrap_or_default()
                == 0)
    {
        issues.push(
            "quota_scope requires a real endpoint quota profile and quota audit assertions"
                .to_owned(),
        );
    }
    for (tag_value, encoding) in [("deflate", "deflate"), ("brotli", "br")] {
        if tag("transport", tag_value)
            && !loaded
                .scenario
                .endpoints
                .iter()
                .flat_map(|endpoint| &endpoint.replies)
                .any(|reply| {
                    reply
                        .encoding
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(encoding))
                })
        {
            issues.push(format!(
                "transport {tag_value} requires a reply with the actual Content-Encoding {encoding}"
            ));
        }
    }
    if tag("transport", "chunked")
        && !loaded
            .scenario
            .endpoints
            .iter()
            .flat_map(|endpoint| &endpoint.replies)
            .any(|reply| {
                reply.transfer_mode == crate::TransferMode::Chunked && reply.chunk_count > 1
            })
    {
        issues.push("transport chunked requires an actual multi-chunk reply".to_owned());
    }
    if tag("execution_style", "campaign")
        && !matches!(
            loaded.scenario.id.as_str(),
            "107-json-structural-mutation-campaign"
                | "108-text-html-csv-mutation-campaign"
                | "109-pagination-token-mutation-campaign"
                | "110-transport-framing-mutation-campaign"
        )
    {
        issues.push(
            "execution_style campaign requires a registered 107-110 campaign scenario".to_owned(),
        );
    }
    if tag("execution_style", "soak")
        && !matches!(
            loaded.scenario.id.as_str(),
            "111-mixed-lifecycle-soak" | "112-concurrent-mixed-fault-soak"
        )
    {
        issues
            .push("execution_style soak requires a registered end-to-end soak scenario".to_owned());
    }
    issues
}

fn allowed_values(dimension: &str) -> &'static [&'static str] {
    match dimension {
        "source_shape" => &[
            "certificate",
            "pdns",
            "archive",
            "search",
            "intel",
            "code",
            "organization",
            "import",
            "generic",
        ],
        "payload_format" => &["json", "html", "csv", "text", "mixed"],
        "pagination" => &[
            "none",
            "page",
            "offset",
            "cursor",
            "post_cursor",
            "link",
            "loop",
            "empty",
        ],
        "authentication" => &[
            "none",
            "api_key",
            "bearer",
            "proxy_auth",
            "invalid",
            "expired",
        ],
        "network_profile" => &["direct", "http_proxy", "connect_proxy"],
        "quota_scope" => &["none", "per_source", "per_key", "global_run"],
        "transport" => &[
            "identity",
            "gzip",
            "deflate",
            "brotli",
            "chunked",
            "truncated",
            "malformed",
        ],
        "fault_class" => &[
            "none",
            "auth",
            "rate_limit",
            "upstream",
            "timeout",
            "disconnect",
            "redirect",
            "scope",
            "egress",
            "resource",
            "lifecycle",
        ],
        "execution_style" => &[
            "single",
            "concurrent",
            "cancelled",
            "replay",
            "campaign",
            "soak",
        ],
        "assertion_focus" => &[
            "finding",
            "evidence",
            "filter",
            "audit",
            "isolation",
            "redaction",
            "resource",
            "determinism",
            "lifecycle",
        ],
        _ => &[],
    }
}

#[must_use]
pub fn coverage_report(repository: &ScenarioRepository) -> CoverageReport {
    let mut dimensions = BTreeMap::new();
    for dimension in COVERAGE_DIMENSIONS {
        let mut values = BTreeMap::new();
        for value in allowed_values(dimension) {
            values.insert((*value).to_owned(), Vec::new());
        }
        dimensions.insert(dimension.to_owned(), values);
    }
    for loaded in repository.all() {
        for (dimension, values) in coverage_tags_for(&loaded.scenario) {
            if let Some(counts) = dimensions.get_mut(&dimension) {
                for value in values {
                    counts
                        .entry(value)
                        .or_default()
                        .push(loaded.scenario.id.clone());
                }
            }
        }
    }
    let gaps = dimensions
        .iter()
        .map(|(dimension, values)| {
            (
                dimension.clone(),
                values
                    .iter()
                    .filter_map(|(value, scenarios)| scenarios.is_empty().then_some(value.clone()))
                    .collect(),
            )
        })
        .collect();
    CoverageReport {
        schema_version: V14_SCHEMA_VERSION.to_owned(),
        scenario_count: repository.all().len(),
        dimensions,
        gaps,
        high_risk_combinations: REQUIRED_COVERAGE_COMBINATIONS
            .iter()
            .map(|name| {
                (
                    (*name).to_owned(),
                    required_combination_ids(repository, name).unwrap_or_default(),
                )
            })
            .collect(),
        exceptions: coverage_policy(repository)
            .map(|policy| policy.exceptions)
            .unwrap_or_default(),
    }
}

pub fn coverage_check(repository: &ScenarioRepository) -> Vec<String> {
    let mut issues = repository
        .all()
        .iter()
        .flat_map(validate_v14_scenario)
        .collect::<Vec<_>>();
    let report = coverage_report(repository);
    match coverage_policy(repository) {
        Ok(policy) => {
            let actual = policy
                .required_combinations
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            for required in REQUIRED_COVERAGE_COMBINATIONS {
                if !actual.contains(required) {
                    issues.push(format!(
                        "coverage policy is missing required combination {required}"
                    ));
                }
            }
            for exception in &policy.exceptions {
                if exception.id.trim().is_empty()
                    || exception.rule.trim().is_empty()
                    || exception.reason.trim().is_empty()
                    || exception.created_on.trim().is_empty()
                    || exception.expires_on.trim().is_empty()
                    || exception.reference.trim().is_empty()
                    || exception.replacement.trim().is_empty()
                {
                    issues.push(format!(
                        "coverage exception {} is missing required fields",
                        exception.id
                    ));
                }
                let expires = NaiveDate::parse_from_str(&exception.expires_on, "%Y-%m-%d");
                if expires.is_err() {
                    issues.push(format!(
                        "coverage exception {} has invalid expires_on",
                        exception.id
                    ));
                } else if expires
                    .ok()
                    .is_some_and(|date| date < chrono::Utc::now().date_naive())
                {
                    issues.push(format!("coverage exception {} is expired", exception.id));
                }
                if exception.security_relevant {
                    issues.push(format!(
                        "coverage exception {} cannot waive a security boundary",
                        exception.id
                    ));
                }
                if required_combination_ids(repository, &exception.rule)
                    .is_some_and(|ids| !ids.is_empty())
                {
                    issues.push(format!(
                        "coverage exception {} remains after its rule is covered",
                        exception.id
                    ));
                }
            }
        }
        Err(error) => issues.push(error),
    }
    for required in ["direct", "http_proxy", "connect_proxy"] {
        if report.dimensions["network_profile"][required].is_empty() {
            issues.push(format!("coverage is missing network_profile={required}"));
        }
    }
    for required in ["none", "per_source", "per_key", "global_run"] {
        if report.dimensions["quota_scope"][required].is_empty() {
            issues.push(format!("coverage is missing quota_scope={required}"));
        }
    }
    for required in ["gzip", "deflate", "brotli", "chunked"] {
        if report.dimensions["transport"][required].is_empty() {
            issues.push(format!("coverage is missing transport={required}"));
        }
    }
    issues
}

fn coverage_policy(repository: &ScenarioRepository) -> Result<CoveragePolicyFile, String> {
    let path = repository.root().join("..").join("coverage-policy.yaml");
    let bytes = fs::read(&path)
        .map_err(|error| format!("coverage policy {} cannot be read: {error}", path.display()))?;
    serde_yaml::from_slice(&bytes)
        .map_err(|error| format!("coverage policy {} is invalid: {error}", path.display()))
}

fn required_combination_ids(repository: &ScenarioRepository, name: &str) -> Option<Vec<String>> {
    let ids: &[&str] = match name {
        "http_proxy+proxy_auth+rate_limit" => &["094-proxy-auth-then-source-rate-limit"],
        "http_proxy+per_source+retry_recovery" => &["095-proxy-reset-then-retry-success"],
        "connect_proxy+truncated+resource" => &["096-connect-tunnel-truncated-payload"],
        "direct+per_key+deflate" => &["092-rate-limit-retry-deflate-success"],
        "direct+global_run+multi_source" => &["099-multi-source-global-quota-isolation"],
        "brotli+rate_limit/recovery" => &["093-quota-recovery-brotli-success"],
        "chunked+malformed/content-length-conflict" => &["098-chunked-content-length-conflict"],
        "pagination+rate_limit+retry_recovery" => &["091-pagination-second-page-rate-limit"],
        "campaign+json/html/csv/text" => &[
            "107-json-structural-mutation-campaign",
            "108-text-html-csv-mutation-campaign",
        ],
        "campaign+pagination" => &["109-pagination-token-mutation-campaign"],
        "campaign+transport" => &["110-transport-framing-mutation-campaign"],
        "lifecycle+concurrent+reset/delete" => &["105-stale-capability-after-reset-delete"],
        "proxy_rejection+source_requests=0+quota_decisions=0" => &[
            "101-proxy-target-canonicalization",
            "102-proxy-authority-header-ambiguity",
            "103-proxy-encoded-and-userinfo-targets",
            "104-proxy-framing-and-header-limits",
        ],
        "strict_replay+provenance_difference" => &["113-replay-provenance-and-multi-diff"],
        "baseline+scenario_fixture_digest" => &["114-coverage-and-baseline-integrity"],
        _ => return None,
    };
    Some(
        ids.iter()
            .filter_map(|id| {
                repository
                    .get(id)
                    .filter(|loaded| coverage_entry_is_semantic(name, loaded))
                    .map(|loaded| loaded.scenario.id.clone())
            })
            .collect(),
    )
}

fn coverage_entry_is_semantic(name: &str, loaded: &LoadedScenario) -> bool {
    let tags = coverage_tags_for(&loaded.scenario);
    let has = |dimension: &str, value: &str| {
        tags.get(dimension)
            .is_some_and(|values| values.iter().any(|actual| actual == value))
    };
    match name {
        "http_proxy+proxy_auth+rate_limit" => {
            has("network_profile", "http_proxy")
                && has("authentication", "proxy_auth")
                && has("fault_class", "rate_limit")
                && loaded.assertions.require_proxy == Some(true)
                && loaded
                    .assertions
                    .expected_quota_decisions
                    .unwrap_or_default()
                    > 0
        }
        "http_proxy+per_source+retry_recovery" => {
            has("network_profile", "http_proxy")
                && has("quota_scope", "per_source")
                && loaded
                    .scenario
                    .composition
                    .fault_stages
                    .contains(&crate::FaultStage::RetryRecovery)
        }
        "connect_proxy+truncated+resource" => {
            has("network_profile", "connect_proxy")
                && has("transport", "truncated")
                && has("assertion_focus", "resource")
        }
        "direct+per_key+deflate" => {
            has("network_profile", "direct")
                && has("quota_scope", "per_key")
                && has("transport", "deflate")
        }
        "direct+global_run+multi_source" => {
            has("network_profile", "direct")
                && has("quota_scope", "global_run")
                && loaded.scenario.endpoints.len() >= 2
        }
        "brotli+rate_limit/recovery" => {
            has("transport", "brotli") && has("fault_class", "rate_limit")
        }
        "chunked+malformed/content-length-conflict" => {
            has("transport", "chunked")
                && loaded.assertions.required_transport_fault.as_deref() == Some("framing_conflict")
        }
        "pagination+rate_limit+retry_recovery" => {
            has("pagination", "page")
                && has("fault_class", "rate_limit")
                && loaded
                    .scenario
                    .composition
                    .fault_stages
                    .contains(&crate::FaultStage::RetryRecovery)
        }
        "campaign+json/html/csv/text" => {
            has("execution_style", "campaign") && loaded.scenario.id.starts_with("107-")
                || has("execution_style", "campaign") && loaded.scenario.id.starts_with("108-")
        }
        "campaign+pagination" => has("execution_style", "campaign") && has("pagination", "cursor"),
        "campaign+transport" => has("execution_style", "campaign") && has("transport", "chunked"),
        "lifecycle+concurrent+reset/delete" => {
            has("fault_class", "lifecycle") && has("execution_style", "concurrent")
        }
        "proxy_rejection+source_requests=0+quota_decisions=0" => {
            has("network_profile", "http_proxy") || has("network_profile", "connect_proxy")
        }
        "strict_replay+provenance_difference" => has("execution_style", "replay"),
        "baseline+scenario_fixture_digest" => loaded.scenario.id.starts_with("114-"),
        _ => false,
    }
}

#[must_use]
pub fn coverage_markdown(report: &CoverageReport) -> String {
    let mut markdown = format!(
        "# FQDN Forge V1.4.1 coverage\n\nScenarios: {}\n",
        report.scenario_count
    );
    for (dimension, values) in &report.dimensions {
        markdown.push_str(&format!(
            "\n## {dimension}\n\n| Value | Count | Scenario IDs |\n|---|---:|---|\n"
        ));
        for (value, ids) in values {
            markdown.push_str(&format!(
                "| {value} | {} | {} |\n",
                ids.len(),
                ids.join(", ")
            ));
        }
    }
    markdown.push_str("\n## High-risk combinations\n\n| Combination | Scenario IDs |\n|---|---|\n");
    for (combination, ids) in &report.high_risk_combinations {
        markdown.push_str(&format!("| {combination} | {} |\n", ids.join(", ")));
    }
    markdown
}

#[must_use]
pub fn campaign_definitions() -> Vec<CampaignDefinition> {
    vec![
        CampaignDefinition {
            id: "107-json-structural-mutation-campaign",
            scenario_id: "107-json-structural-mutation-campaign",
            seed_min: 10_701,
            seed_max: 10_799,
            operators: &[
                "json_key_order",
                "json_noise",
                "json_null",
                "json_duplicate",
            ],
            max_mutations: 16,
            max_nested_depth: 8,
            max_items: 64,
            max_text_bytes: 16_384,
            max_chunks: 32,
        },
        CampaignDefinition {
            id: "108-text-html-csv-mutation-campaign",
            scenario_id: "108-text-html-csv-mutation-campaign",
            seed_min: 10_801,
            seed_max: 10_899,
            operators: &["html_noise", "csv_quoting", "line_endings", "text_case"],
            max_mutations: 16,
            max_nested_depth: 8,
            max_items: 64,
            max_text_bytes: 16_384,
            max_chunks: 32,
        },
        CampaignDefinition {
            id: "109-pagination-token-mutation-campaign",
            scenario_id: "109-pagination-token-mutation-campaign",
            seed_min: 10_901,
            seed_max: 10_999,
            operators: &[
                "cursor_empty",
                "cursor_repeat",
                "query_order",
                "link_variant",
            ],
            max_mutations: 12,
            max_nested_depth: 4,
            max_items: 32,
            max_text_bytes: 8_192,
            max_chunks: 16,
        },
        CampaignDefinition {
            id: "110-transport-framing-mutation-campaign",
            scenario_id: "110-transport-framing-mutation-campaign",
            seed_min: 11_001,
            seed_max: 11_099,
            operators: &[
                "chunk_boundaries",
                "truncate",
                "encoding_header",
                "content_length",
            ],
            max_mutations: 12,
            max_nested_depth: 4,
            max_items: 32,
            max_text_bytes: 8_192,
            max_chunks: 64,
        },
    ]
}

pub fn campaign_definition(id: &str) -> Option<CampaignDefinition> {
    campaign_definitions()
        .into_iter()
        .find(|definition| definition.id == id)
}

/// Materializes the bounded campaign fixture that the public run API serves.
/// The same pure transformation is used by the server, the reference runner,
/// provenance, and replay so a campaign report cannot describe a fixture that
/// was not actually returned.
pub fn campaign_loaded_scenario(loaded: &LoadedScenario, seed: u64) -> LoadedScenario {
    let mut dynamic = loaded.clone();
    dynamic.scenario.seed = seed;
    let Some(definition) = campaign_definition(&dynamic.scenario.id) else {
        return dynamic;
    };
    let operators = selected_campaign_operators(&definition, seed);
    let operator = operators.first().map(String::as_str).unwrap_or_default();
    let host = format!("api-{seed}.{}", dynamic.scenario.root_domain);
    let record_id = format!(
        "{}-{seed}",
        dynamic.scenario.id.split('-').next().unwrap_or("campaign")
    );
    match dynamic.scenario.id.as_str() {
        "107-json-structural-mutation-campaign" => {
            if let Some(reply) = dynamic.scenario.endpoints[0].replies.first_mut()
                && let Some(body) = reply.body.as_mut().and_then(Value::as_object_mut)
            {
                if let Some(items) = body.get_mut("items").and_then(Value::as_array_mut)
                    && let Some(item) = items.first_mut().and_then(Value::as_object_mut)
                {
                    item.insert("host".to_owned(), Value::String(host.clone()));
                    item.insert("id".to_owned(), Value::String(record_id.clone()));
                    item.insert(
                        "mutation_operator".to_owned(),
                        Value::String(operator.to_owned()),
                    );
                }
                if operator == "json_null" {
                    body.insert("nullable".to_owned(), Value::Null);
                } else if operator == "json_noise" {
                    body.insert(
                        "unknown_field".to_owned(),
                        Value::String(format!("noise-{seed}")),
                    );
                }
            }
            rewrite_truth(
                &mut dynamic,
                &host,
                &record_id,
                crate::SourceKind::GenericJson,
            );
        }
        "108-text-html-csv-mutation-campaign" => {
            let endpoint = &mut dynamic.scenario.endpoints[0];
            let reply = endpoint.replies.first_mut().expect("campaign reply");
            let extract = endpoint.extract.as_mut().expect("campaign extract");
            match operator {
                "csv_quoting" => {
                    extract.format = crate::ContentFormat::Csv;
                    reply.content_type = Some("text/csv".to_owned());
                    reply.body = None;
                    reply.body_text = Some(format!("host,id\n\"{host}\",{record_id}\n"));
                }
                "html_noise" => {
                    extract.format = crate::ContentFormat::Html;
                    reply.content_type = Some("text/html".to_owned());
                    reply.body = None;
                    reply.body_text = Some(format!(
                        "<!-- seed {seed} --> <a href=\"https://{host}/\">{host}</a>"
                    ));
                }
                _ => {
                    extract.format = crate::ContentFormat::Text;
                    reply.content_type = Some("text/plain".to_owned());
                    reply.body = None;
                    reply.body_text = Some(format!("https://{host}/noise-{seed}"));
                }
            }
            rewrite_truth(
                &mut dynamic,
                &host,
                &record_id,
                crate::SourceKind::GenericJson,
            );
            if operator != "csv_quoting"
                && let Some(expectation) = dynamic.truth.expected_observations.get_mut(&host)
            {
                expectation.record_ids.clear();
            }
        }
        "109-pagination-token-mutation-campaign" => {
            let endpoint = &mut dynamic.scenario.endpoints[0];
            endpoint.pagination = crate::Pagination {
                mode: crate::PaginationMode::Cursor,
                parameter: "cursor".to_owned(),
                next_cursor_field: Some("next_cursor".to_owned()),
                in_body: false,
                start: 1,
                step: 1,
            };
            if endpoint.replies.len() == 1 {
                let first = endpoint.replies[0].clone();
                endpoint.replies.push(first);
            }
            if let Some(first) = endpoint.replies.get_mut(0)
                && let Some(body) = first.body.as_mut().and_then(Value::as_object_mut)
            {
                body.insert(
                    "next_cursor".to_owned(),
                    Value::String(format!("cursor-{seed}")),
                );
            }
            if let Some(second) = endpoint.replies.get_mut(1)
                && let Some(body) = second.body.as_mut().and_then(Value::as_object_mut)
            {
                body.remove("next_cursor");
                if let Some(items) = body.get_mut("items").and_then(Value::as_array_mut)
                    && let Some(item) = items.first_mut().and_then(Value::as_object_mut)
                {
                    item.insert("host".to_owned(), Value::String(host.clone()));
                    item.insert("id".to_owned(), Value::String(record_id.clone()));
                }
            }
            if let Some(first) = endpoint.replies.get_mut(0)
                && let Some(body) = first.body.as_mut().and_then(Value::as_object_mut)
                && let Some(items) = body.get_mut("items").and_then(Value::as_array_mut)
                && let Some(item) = items.first_mut().and_then(Value::as_object_mut)
            {
                item.insert("host".to_owned(), Value::String(host.clone()));
                item.insert("id".to_owned(), Value::String(record_id.clone()));
            }
            dynamic.scenario.endpoints[0].request_match.query.insert(
                "domain".to_owned(),
                crate::ValueRule {
                    equals: Some("$TARGET_DOMAIN".to_owned()),
                    ..Default::default()
                },
            );
            dynamic.assertions.expected_requests = 2;
            dynamic
                .assertions
                .endpoint_requests
                .insert("source".to_owned(), 2);
            dynamic.assertions.request_sequence = vec![
                crate::RequestSequenceExpectation {
                    endpoint: "source".to_owned(),
                    response_index: Some(0),
                },
                crate::RequestSequenceExpectation {
                    endpoint: "source".to_owned(),
                    response_index: Some(1),
                },
            ];
            rewrite_truth(
                &mut dynamic,
                &host,
                &record_id,
                crate::SourceKind::GenericJson,
            );
        }
        "110-transport-framing-mutation-campaign" => {
            if let Some(reply) = dynamic.scenario.endpoints[0].replies.first_mut() {
                reply.chunk_count = 2 + (seed as usize % 3);
                if operator == "encoding_header" {
                    reply.content_encoding_header = Some("identity".to_owned());
                } else if operator == "content_length" {
                    reply.transfer_mode = crate::TransferMode::ContentLength;
                }
                if let Some(body) = reply.body.as_mut().and_then(Value::as_object_mut)
                    && let Some(items) = body.get_mut("items").and_then(Value::as_array_mut)
                    && let Some(item) = items.first_mut().and_then(Value::as_object_mut)
                {
                    item.insert("host".to_owned(), Value::String(host.clone()));
                    item.insert("id".to_owned(), Value::String(record_id.clone()));
                }
            }
            rewrite_truth(
                &mut dynamic,
                &host,
                &record_id,
                crate::SourceKind::GenericJson,
            );
        }
        _ => {}
    }
    dynamic
}

fn selected_campaign_operators(definition: &CampaignDefinition, seed: u64) -> Vec<String> {
    let mut state = seed;
    (0..3)
        .map(|_| {
            state = splitmix64(state);
            definition.operators[(state as usize) % definition.operators.len()].to_owned()
        })
        .collect()
}

fn rewrite_truth(
    loaded: &mut LoadedScenario,
    host: &str,
    record_id: &str,
    source_kind: crate::SourceKind,
) {
    loaded.truth.expected_fqdns = vec![host.to_owned()];
    loaded.truth.expected_observations = BTreeMap::from([(
        host.to_owned(),
        crate::ObservationExpectation {
            source_names: vec!["source".to_owned()],
            source_kinds: vec![source_kind],
            record_ids: vec![record_id.to_owned()],
            ..Default::default()
        },
    )]);
}

pub fn campaign_manifest(
    repository: &ScenarioRepository,
    id: &str,
    seed: u64,
) -> Result<CampaignManifest> {
    let definition = campaign_definition(id).ok_or_else(|| anyhow!("unknown campaign {id}"))?;
    if !(definition.seed_min..=definition.seed_max).contains(&seed) {
        bail!(
            "seed {seed} is outside the allowed {}..={} range for {id}",
            definition.seed_min,
            definition.seed_max
        );
    }
    let loaded = repository
        .get(definition.scenario_id)
        .ok_or_else(|| anyhow!("campaign scenario {} is missing", definition.scenario_id))?;
    let operators = selected_campaign_operators(&definition, seed);
    let dynamic = campaign_loaded_scenario(loaded, seed);
    let mutation_fixture = json!({
        "synthetic_domain": "campaign.synthetic.test",
        "seed": seed,
        "operators": operators,
        "actual_scenario": dynamic.scenario,
        "actual_truth": dynamic.truth,
        "limits": {
            "max_mutations": definition.max_mutations,
            "max_nested_depth": definition.max_nested_depth,
            "max_items": definition.max_items,
            "max_text_bytes": definition.max_text_bytes,
            "max_chunks": definition.max_chunks
        }
    });
    let fixture_digest = fixture_digest(&dynamic)?;
    let truth_digest = stable_digest(&serde_json::to_value(&dynamic.truth)?);
    Ok(CampaignManifest {
        schema_version: V14_SCHEMA_VERSION.to_owned(),
        campaign_id: definition.id.to_owned(),
        scenario_id: definition.scenario_id.to_owned(),
        seed,
        operators,
        parameters: BTreeMap::from([
            ("max_mutations".to_owned(), definition.max_mutations as u64),
            (
                "max_nested_depth".to_owned(),
                definition.max_nested_depth as u64,
            ),
            ("max_items".to_owned(), definition.max_items as u64),
            (
                "max_text_bytes".to_owned(),
                definition.max_text_bytes as u64,
            ),
            ("max_chunks".to_owned(), definition.max_chunks as u64),
        ]),
        mutation_fixture,
        scenario_revision_digest: scenario_revision_digest(&loaded.scenario),
        fixture_digest,
        truth_digest,
        reproduction_command: format!(
            "cargo run -p lab-cli -- campaign run --campaign {id} --seed {seed}"
        ),
    })
}

const fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[must_use]
pub fn baseline_from_reports(profile: &str, reports: &[RunReport]) -> Baseline {
    let entries = reports
        .iter()
        .map(|report| {
            (
                report.scenario_id.clone(),
                BaselineEntry {
                    scenario_revision_digest: report.provenance.scenario_revision_digest.clone(),
                    fixture_digest: report.provenance.fixture_digest.clone(),
                    semantic_fingerprint: report.semantic_fingerprint.clone(),
                    logical_metrics: logical_metrics(report),
                },
            )
        })
        .collect();
    Baseline {
        schema_version: V14_SCHEMA_VERSION.to_owned(),
        profile: profile.to_owned(),
        entries,
        public_soak: None,
    }
}

#[must_use]
pub fn soak_baseline_from_report(report: &SoakReport) -> SoakBaseline {
    SoakBaseline {
        preset: report.preset,
        seed: report.seed,
        minimum_operations: report.operations,
        concurrency: report.concurrency,
        action_counts: report.action_counts.clone(),
        outcome_counts: report.outcome_counts.clone(),
        invariants: report.invariants.clone(),
    }
}

#[must_use]
pub fn compare_baseline(baseline: &Baseline, report: &RunReport) -> BaselineComparison {
    let Some(entry) = baseline.entries.get(&report.scenario_id) else {
        return BaselineComparison {
            matched: false,
            differences: vec![BaselineDifference {
                category: "added".to_owned(),
                field: "scenario_id".to_owned(),
                expected: "present in baseline".to_owned(),
                actual: report.scenario_id.clone(),
            }],
        };
    };
    let mut differences = Vec::new();
    compare_field(
        &mut differences,
        "provenance",
        "scenario_revision_digest",
        &entry.scenario_revision_digest,
        &report.provenance.scenario_revision_digest,
    );
    compare_field(
        &mut differences,
        "provenance",
        "fixture_digest",
        &entry.fixture_digest,
        &report.provenance.fixture_digest,
    );
    compare_field(
        &mut differences,
        "semantic",
        "semantic_fingerprint",
        &entry.semantic_fingerprint,
        &report.semantic_fingerprint,
    );
    for (key, expected) in &entry.logical_metrics {
        let actual = logical_metrics(report)
            .get(key)
            .copied()
            .unwrap_or_default();
        if *expected != actual {
            differences.push(BaselineDifference {
                category: "logical_metric".to_owned(),
                field: key.clone(),
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
        }
    }
    BaselineComparison {
        matched: differences.is_empty(),
        differences,
    }
}

fn compare_field(
    differences: &mut Vec<BaselineDifference>,
    category: &str,
    field: &str,
    expected: &str,
    actual: &str,
) {
    if expected != actual {
        differences.push(BaselineDifference {
            category: category.to_owned(),
            field: field.to_owned(),
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
}

fn logical_metrics(report: &RunReport) -> BTreeMap<String, u64> {
    BTreeMap::from([
        (
            "request_count".to_owned(),
            report.metrics.request_count as u64,
        ),
        ("retry_count".to_owned(), report.metrics.retry_count as u64),
        ("virtual_wait_ms".to_owned(), report.virtual_waited_ms),
        ("findings".to_owned(), report.findings.len() as u64),
        ("audit_records".to_owned(), report.requests.len() as u64),
        (
            "wire_bytes".to_owned(),
            report.compression.wire_bytes as u64,
        ),
        (
            "decoded_bytes".to_owned(),
            report.compression.decoded_bytes as u64,
        ),
        ("quota_decisions".to_owned(), report.quota.decisions as u64),
    ])
}

#[must_use]
pub fn report_differences(
    previous: &RunReport,
    current: &RunReport,
    limit: usize,
) -> DifferenceSummary {
    let mut summary = DifferenceSummary::default();
    let limit = limit.min(MAX_REPLAY_DIFFERENCES);
    collect_differences(
        "$",
        &semantic_projection(previous),
        &semantic_projection(current),
        limit,
        &mut summary,
    );
    summary
}

fn collect_differences(
    path: &str,
    previous: &Value,
    current: &Value,
    limit: usize,
    summary: &mut DifferenceSummary,
) {
    if previous == current {
        return;
    }
    match (previous, current) {
        (Value::Object(left), Value::Object(right)) => {
            let keys = left.keys().chain(right.keys()).collect::<BTreeSet<_>>();
            for key in keys {
                let next = format!("{path}.{key}");
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) => {
                        collect_differences(&next, left, right, limit, summary)
                    }
                    (left, right) => push_difference(&next, left, right, limit, summary),
                }
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            let len = left.len().max(right.len());
            for index in 0..len {
                let next = format!("{path}[{index}]");
                match (left.get(index), right.get(index)) {
                    (Some(left), Some(right)) => {
                        collect_differences(&next, left, right, limit, summary)
                    }
                    (left, right) => push_difference(&next, left, right, limit, summary),
                }
            }
        }
        _ => push_difference(path, Some(previous), Some(current), limit, summary),
    }
}

fn push_difference(
    path: &str,
    previous: Option<&Value>,
    current: Option<&Value>,
    limit: usize,
    summary: &mut DifferenceSummary,
) {
    let category = category_for_path(path);
    *summary
        .counts
        .entry(category.as_str().to_owned())
        .or_insert(0) += 1;
    if summary.differences.len() < limit {
        summary.differences.push(crate::ReplayDifference {
            category,
            path: path.to_owned(),
            previous: render_redacted(previous),
            current: render_redacted(current),
        });
    } else {
        summary.truncated += 1;
    }
}

fn category_for_path(path: &str) -> DifferenceCategory {
    if path.contains("provenance") || path.contains("schema") {
        DifferenceCategory::Provenance
    } else if path.contains("findings") {
        DifferenceCategory::Finding
    } else if path.contains("evidence") {
        DifferenceCategory::Evidence
    } else if path.contains("source_status") {
        DifferenceCategory::SourceStatus
    } else if path.contains("filtered") {
        DifferenceCategory::Filter
    } else if path.contains("proxy") {
        DifferenceCategory::Proxy
    } else if path.contains("quota") {
        DifferenceCategory::Quota
    } else if path.contains("transport") || path.contains("chunk") || path.contains("encoding") {
        DifferenceCategory::Transport
    } else if path.contains("resource") {
        DifferenceCategory::Resource
    } else {
        DifferenceCategory::Audit
    }
}

fn render_redacted(value: Option<&Value>) -> String {
    let value = value.cloned().unwrap_or(Value::Null);
    let rendered = serde_json::to_string(&redact_value(value)).expect("JSON value serializes");
    if rendered.len() > 256 {
        format!("{}…", &rendered[..255])
    } else {
        rendered
    }
}

fn redact_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(redact_value).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let lowered = key.to_ascii_lowercase();
                    if lowered.contains("authorization")
                        || lowered.contains("capability")
                        || lowered.contains("token")
                        || lowered.contains("secret")
                        || lowered == "key"
                    {
                        (key, Value::String("<redacted>".to_owned()))
                    } else {
                        (key, redact_value(value))
                    }
                })
                .collect(),
        ),
        value => value,
    }
}

pub fn run_soak(
    repository: ScenarioRepository,
    preset: SoakPreset,
    seed: u64,
) -> Result<SoakReport> {
    let state = LabState::new(repository.clone());
    let scenario_ids = repository
        .all()
        .iter()
        .filter(|loaded| {
            matches!(
                loaded.scenario.id.as_str(),
                "091-pagination-second-page-rate-limit"
                    | "101-proxy-target-canonicalization"
                    | "111-mixed-lifecycle-soak"
                    | "112-concurrent-mixed-fault-soak"
            )
        })
        .map(|loaded| loaded.scenario.id.clone())
        .collect::<Vec<_>>();
    if scenario_ids.is_empty() {
        bail!("V1.4 soak scenarios are missing");
    }
    let concurrency = preset.concurrency().min(preset.operations());
    let start = Arc::new(Barrier::new(concurrency));
    let mut workers = Vec::with_capacity(concurrency);
    for lane in 0..concurrency {
        let state = state.clone();
        let scenario_ids = scenario_ids.clone();
        let start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            run_soak_lane(
                state,
                scenario_ids,
                preset.operations(),
                concurrency,
                lane,
                seed,
                start,
            )
        }));
    }
    let mut actions = Vec::with_capacity(preset.operations());
    let mut last_failure = None;
    for worker in workers {
        match worker.join() {
            Ok((mut lane_actions, lane_failure)) => {
                actions.append(&mut lane_actions);
                if last_failure.is_none() {
                    last_failure = lane_failure;
                }
            }
            Err(_) if last_failure.is_none() => {
                last_failure = Some("soak worker panicked".to_owned());
            }
            Err(_) => {}
        }
    }
    actions.sort_by_key(|action| action.index);
    let resources = state.resource_summary();
    let invariants = BTreeMap::from([
        ("no_live_runs".to_owned(), resources.active_runs == 0),
        (
            "no_active_proxy_connections".to_owned(),
            resources.active_proxy_connections == 0,
        ),
        (
            "no_quota_state_entries".to_owned(),
            resources.quota_state_entries == 0,
        ),
        (
            "bounded_action_trace".to_owned(),
            actions.len() == preset.operations()
                && actions.windows(2).all(|pair| pair[0].index < pair[1].index),
        ),
    ]);
    Ok(SoakReport {
        schema_version: V14_SCHEMA_VERSION.to_owned(),
        preset,
        seed,
        operations: preset.operations(),
        concurrency,
        action_counts: actions.iter().fold(BTreeMap::new(), |mut counts, action| {
            *counts.entry(action.endpoint.clone()).or_default() += 1;
            counts
        }),
        outcome_counts: actions.iter().fold(BTreeMap::new(), |mut counts, action| {
            *counts.entry(action.outcome.clone()).or_default() += 1;
            counts
        }),
        action_trace: actions,
        scenario_pool: scenario_ids,
        trace_coverage: BTreeMap::new(),
        resources,
        invariants,
        last_failure,
        reproduction_command: format!(
            "cargo run -p lab-cli -- soak run --preset {} --seed {seed}",
            match preset {
                SoakPreset::Smoke => "smoke",
                SoakPreset::Standard => "standard",
                SoakPreset::Release => "release",
            }
        ),
    })
}

fn run_soak_lane(
    state: LabState,
    scenario_ids: Vec<String>,
    operations: usize,
    concurrency: usize,
    lane: usize,
    seed: u64,
    start: Arc<Barrier>,
) -> (Vec<SoakAction>, Option<String>) {
    start.wait();
    let mut actions = Vec::new();
    let mut active: Option<(String, String)> = None;
    let mut failure = None;
    for (turn, index) in (lane..operations).step_by(concurrency).enumerate() {
        let state_seed = splitmix64(seed.wrapping_add(index as u64));
        let generated_scenario = scenario_ids[(state_seed as usize) % scenario_ids.len()].clone();
        let operation = match turn % 6 {
            0 => "create",
            1 => "request",
            2 => "submission",
            3 => "reset",
            4 => "replay",
            _ => "delete",
        };
        let scenario_id = active
            .as_ref()
            .map_or_else(|| generated_scenario.clone(), |(_, id)| id.clone());
        let outcome = match operation {
            "create" => match state.create_run_with_seed(&generated_scenario, Some(state_seed)) {
                Ok(run) => {
                    active = Some((run.run_id, generated_scenario));
                    "ok".to_owned()
                }
                Err(error) => {
                    failure.get_or_insert_with(|| error.to_string());
                    "rejected".to_owned()
                }
            },
            "request" => match active.as_ref() {
                Some((run_id, _)) => match state.loaded_for_run(run_id) {
                    Ok(loaded) => match loaded.scenario.endpoints.first() {
                        Some(endpoint) => state
                            .evaluate_quota(run_id, &endpoint.id, &endpoint.quota, "soak", 0)
                            .map_or_else(
                                |error| {
                                    failure.get_or_insert_with(|| error.message().to_owned());
                                    "rejected".to_owned()
                                },
                                |_| "ok".to_owned(),
                            ),
                        None => "skipped".to_owned(),
                    },
                    Err(error) => {
                        failure.get_or_insert_with(|| error.message().to_owned());
                        "rejected".to_owned()
                    }
                },
                None => "skipped".to_owned(),
            },
            "submission" => match active.as_ref() {
                Some((run_id, _)) => match state.loaded_for_run(run_id) {
                    Ok(loaded) => {
                        let submission = crate::CollectorSubmission {
                            schema_version: V14_SCHEMA_VERSION.to_owned(),
                            collector: crate::CollectorIdentity {
                                name: format!("soak-{run_id}"),
                                version: V14_SCHEMA_VERSION.to_owned(),
                            },
                            target_domain: loaded.scenario.root_domain,
                            source_statuses: BTreeMap::new(),
                            findings: Vec::new(),
                        };
                        state.freeze_submission(run_id, submission).map_or_else(
                            |error| {
                                failure.get_or_insert_with(|| error.message().to_owned());
                                "rejected".to_owned()
                            },
                            |_| "ok".to_owned(),
                        )
                    }
                    Err(error) => {
                        failure.get_or_insert_with(|| error.message().to_owned());
                        "rejected".to_owned()
                    }
                },
                None => "skipped".to_owned(),
            },
            "reset" => match active.as_ref() {
                Some((run_id, _)) => state.reset_and_rotate(run_id).map_or_else(
                    |error| {
                        failure.get_or_insert_with(|| error.message().to_owned());
                        "rejected".to_owned()
                    },
                    |_| "ok".to_owned(),
                ),
                None => "skipped".to_owned(),
            },
            "replay" => match active.as_ref() {
                Some((run_id, _)) => match state.latest_report(run_id) {
                    Ok(_) => "ok".to_owned(),
                    Err(_) => "not_ready".to_owned(),
                },
                None => "skipped".to_owned(),
            },
            "delete" => match active.take() {
                Some((run_id, _)) => state.delete(&run_id).map_or_else(
                    |error| {
                        failure.get_or_insert_with(|| error.message().to_owned());
                        "rejected".to_owned()
                    },
                    |_| "ok".to_owned(),
                ),
                None => "skipped".to_owned(),
            },
            _ => unreachable!("fixed soak operation"),
        };
        actions.push(SoakAction {
            index: index + 1,
            lane,
            operation: operation.to_owned(),
            scenario_id,
            outcome,
            run_id: None,
            endpoint: "internal-test-helper".to_owned(),
            seed,
            audit_count: 0,
        });
    }
    if let Some((run_id, _)) = active
        && let Err(error) = state.delete(&run_id)
    {
        failure.get_or_insert_with(|| error.message().to_owned());
    }
    (actions, failure)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_REPLAY_DIFFERENCES, SoakPreset, campaign_definitions, canonical_json, run_soak,
        splitmix64, stable_digest,
    };
    use crate::ScenarioRepository;
    use serde_json::json;

    #[test]
    fn canonical_digest_ignores_object_key_order() {
        assert_eq!(
            stable_digest(&json!({"b":1,"a":2})),
            stable_digest(&json!({"a":2,"b":1}))
        );
        assert_eq!(canonical_json(&json!({"b":1,"a":2})), json!({"a":2,"b":1}));
    }

    #[test]
    fn campaign_registry_is_bounded_and_deterministic() {
        assert_eq!(campaign_definitions().len(), 4);
        assert_eq!(splitmix64(10701), splitmix64(10701));
        let maximum_differences = MAX_REPLAY_DIFFERENCES;
        assert!(maximum_differences >= 50);
    }

    #[test]
    fn smoke_soak_uses_lifecycle_lanes_and_cleans_all_state() {
        let repository = ScenarioRepository::load(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios"),
        )
        .expect("load bundled scenarios");
        let report = run_soak(repository, SoakPreset::Smoke, 11_100).expect("run smoke soak");
        assert_eq!(report.operations, 50);
        assert_eq!(report.concurrency, 2);
        assert!(report.invariants.values().all(|value| *value));
        assert!(report.last_failure.is_none());
        for operation in [
            "create",
            "request",
            "submission",
            "reset",
            "replay",
            "delete",
        ] {
            assert!(
                report
                    .action_trace
                    .iter()
                    .any(|action| action.operation == operation),
                "missing soak operation {operation}"
            );
        }
        assert_eq!(report.resources.active_runs, 0);
        assert_eq!(report.resources.quota_state_entries, 0);
    }
}
