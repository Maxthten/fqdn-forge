use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A wholly local, declarative test scenario.  Scenario data describes a test
/// station; it is deliberately not a production collector configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub root_domain: String,
    pub seed: u64,
    #[serde(default)]
    pub include_root: bool,
    pub allow_duplicates: bool,
    pub allow_concurrent: bool,
    #[serde(default)]
    pub runner: RunnerConfig,
    /// Limits for the public collector-submission contract.  They are part of
    /// the local scenario, never part of a collector supplied payload.
    #[serde(default)]
    pub submission: SubmissionLimits,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    #[serde(default = "default_retry_after_cap_ms")]
    pub retry_after_cap_ms: u64,
    #[serde(default = "default_max_wire_response_bytes")]
    pub max_wire_response_bytes: usize,
    #[serde(default = "default_max_decoded_response_bytes")]
    pub max_decoded_response_bytes: usize,
    #[serde(default = "default_max_expansion_ratio")]
    pub max_expansion_ratio: usize,
    #[serde(default = "default_max_decompression_time_ms")]
    pub max_decompression_time_ms: u64,
    pub cancel_after_requests: Option<usize>,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            max_response_bytes: default_max_response_bytes(),
            max_retries: default_max_retries(),
            retry_after_cap_ms: default_retry_after_cap_ms(),
            max_wire_response_bytes: default_max_wire_response_bytes(),
            max_decoded_response_bytes: default_max_decoded_response_bytes(),
            max_expansion_ratio: default_max_expansion_ratio(),
            max_decompression_time_ms: default_max_decompression_time_ms(),
            cancel_after_requests: None,
        }
    }
}

impl RunnerConfig {
    /// Preserve the V1.2.0 `max_response_bytes` contract for scenarios that
    /// predate the distinct wire/decoded gzip limits. New scenarios can set
    /// the V1.2.1 fields explicitly for tighter independent bounds.
    #[must_use]
    pub const fn effective_max_wire_response_bytes(&self) -> usize {
        if self.max_wire_response_bytes == default_max_wire_response_bytes()
            && self.max_response_bytes != default_max_response_bytes()
        {
            self.max_response_bytes
        } else {
            self.max_wire_response_bytes
        }
    }

    #[must_use]
    pub const fn effective_max_decoded_response_bytes(&self) -> usize {
        if self.max_decoded_response_bytes == default_max_decoded_response_bytes()
            && self.max_response_bytes != default_max_response_bytes()
        {
            self.max_response_bytes
        } else {
            self.max_decoded_response_bytes
        }
    }
}

const fn default_timeout_ms() -> u64 {
    250
}

const fn default_max_response_bytes() -> usize {
    2 * 1024 * 1024
}

const fn default_max_retries() -> usize {
    3
}

const fn default_retry_after_cap_ms() -> u64 {
    30_000
}

const fn default_max_wire_response_bytes() -> usize {
    2 * 1024 * 1024
}

const fn default_max_decoded_response_bytes() -> usize {
    4 * 1024 * 1024
}

const fn default_max_expansion_ratio() -> usize {
    32
}

const fn default_max_decompression_time_ms() -> u64 {
    1_000
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionLimits {
    #[serde(default = "default_submission_max_bytes")]
    pub max_bytes: usize,
    #[serde(default = "default_submission_max_findings")]
    pub max_findings: usize,
    #[serde(default = "default_submission_max_evidence")]
    pub max_evidence_per_finding: usize,
    #[serde(default = "default_submission_max_string")]
    pub max_string_bytes: usize,
    #[serde(default = "default_submission_max_tags")]
    pub max_tags: usize,
    #[serde(default = "default_submission_max_depth")]
    pub max_depth: usize,
    #[serde(default = "default_submission_max_time_ms")]
    pub max_submission_time_ms: u64,
    #[serde(default)]
    pub allow_evidence_free_findings: bool,
}

impl Default for SubmissionLimits {
    fn default() -> Self {
        Self {
            max_bytes: default_submission_max_bytes(),
            max_findings: default_submission_max_findings(),
            max_evidence_per_finding: default_submission_max_evidence(),
            max_string_bytes: default_submission_max_string(),
            max_tags: default_submission_max_tags(),
            max_depth: default_submission_max_depth(),
            max_submission_time_ms: default_submission_max_time_ms(),
            allow_evidence_free_findings: false,
        }
    }
}

const fn default_submission_max_bytes() -> usize {
    8 * 1024 * 1024
}

const fn default_submission_max_findings() -> usize {
    10_000
}

const fn default_submission_max_evidence() -> usize {
    32
}

const fn default_submission_max_string() -> usize {
    4_096
}

const fn default_submission_max_tags() -> usize {
    32
}

const fn default_submission_max_depth() -> usize {
    8
}

const fn default_submission_max_time_ms() -> u64 {
    1_000
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub id: String,
    pub source_kind: SourceKind,
    #[serde(default)]
    pub source_label: Option<String>,
    #[serde(rename = "match")]
    pub request_match: RequestMatch,
    #[serde(default)]
    pub pagination: Pagination,
    #[serde(default)]
    pub allow_retry: bool,
    #[serde(default = "default_mismatch_status")]
    pub mismatch_status: u16,
    #[serde(default)]
    pub request_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub omit_headers: Vec<String>,
    pub request_body: Option<Value>,
    pub extract: Option<ExtractSpec>,
    pub replies: Vec<Reply>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Certificate,
    PassiveDns,
    Archive,
    InternetSearch,
    ThreatIntel,
    CodeSearch,
    SearchEngine,
    Organization,
    UserImport,
    KeyApi,
    GenericJson,
    GenericHtml,
    Custom,
}

const fn default_mismatch_status() -> u16 {
    400
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestMatch {
    pub method: HttpMethod,
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, ValueRule>,
    #[serde(default)]
    pub headers: BTreeMap<String, ValueRule>,
    pub json_body: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValueRule {
    pub equals: Option<String>,
    #[serde(default)]
    pub present: bool,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub forbidden: bool,
}

impl ValueRule {
    #[must_use]
    pub fn requires_value(&self) -> bool {
        self.equals.is_some() || self.present
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl HttpMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pagination {
    #[serde(default)]
    pub mode: PaginationMode,
    #[serde(default = "default_cursor_parameter")]
    pub parameter: String,
    pub next_cursor_field: Option<String>,
    #[serde(default)]
    pub in_body: bool,
    #[serde(default = "default_page_start")]
    pub start: u64,
    #[serde(default = "default_page_step")]
    pub step: u64,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            mode: PaginationMode::None,
            parameter: default_cursor_parameter(),
            next_cursor_field: None,
            in_body: false,
            start: default_page_start(),
            step: default_page_step(),
        }
    }
}

fn default_cursor_parameter() -> String {
    "cursor".to_owned()
}

const fn default_page_start() -> u64 {
    1
}

const fn default_page_step() -> u64 {
    1
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaginationMode {
    #[default]
    None,
    Cursor,
    Page,
    Offset,
    Link,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractSpec {
    /// A dot-separated JSON path.  The legacy field name is retained so all
    /// 1.1.1 scenario files remain valid.
    pub items_field: String,
    /// A dot-separated path relative to each item, or a CSV header name.
    pub candidate_field: String,
    #[serde(default = "default_record_id_field")]
    pub record_id_field: String,
    pub timestamp_field: Option<String>,
    #[serde(default)]
    pub kind: ExtractKind,
    #[serde(default)]
    pub format: ContentFormat,
    #[serde(default)]
    pub tags_field: Option<String>,
    #[serde(default)]
    pub confidence_field: Option<String>,
    #[serde(default)]
    pub evidence_fields: Vec<String>,
}

fn default_record_id_field() -> String {
    "id".to_owned()
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentFormat {
    #[default]
    Auto,
    Json,
    Html,
    Csv,
    Text,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractKind {
    #[default]
    Direct,
    Url,
    Tokens,
    Html,
    Csv,
    Text,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub body_file: Option<String>,
    pub body: Option<Value>,
    pub body_text: Option<String>,
    pub generator: Option<Generator>,
    pub content_type: Option<String>,
    pub encoding: Option<String>,
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub first_byte_delay_ms: u64,
    #[serde(default, alias = "virtual_wait")]
    pub virtual_wait_ms: u64,
    #[serde(default)]
    pub disconnect: bool,
    #[serde(default)]
    pub connection_reset: bool,
    #[serde(default)]
    pub close_before_body: bool,
    #[serde(default)]
    pub truncated_body: bool,
    #[serde(default)]
    pub malformed_body: bool,
    #[serde(default)]
    pub gzip_corrupt: bool,
    #[serde(default)]
    pub gzip_truncated: bool,
    #[serde(default)]
    pub invalid_content_type: bool,
    pub redirect: Option<String>,
    pub retry_after: Option<String>,
    #[serde(alias = "oversized_body")]
    pub oversized_bytes: Option<usize>,
    #[serde(default)]
    pub wrong_cursor: bool,
    #[serde(default)]
    pub duplicate_page: bool,
    pub malformed_content_length: Option<usize>,
}

impl Reply {
    #[must_use]
    pub fn content_type(&self) -> &str {
        if self.invalid_content_type {
            "application/x-fqdn-forge-invalid"
        } else {
            self.content_type.as_deref().unwrap_or("application/json")
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Generator {
    pub kind: GeneratorKind,
    pub count: usize,
    pub stress_count: Option<usize>,
    #[serde(default = "default_generator_field")]
    pub field: String,
    #[serde(default = "default_generator_unique")]
    pub unique: usize,
    #[serde(default)]
    pub seeded: bool,
}

fn default_generator_field() -> String {
    "host".to_owned()
}

const fn default_generator_unique() -> usize {
    5
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorKind {
    DomainRecords,
    UrlRecords,
    NestedDomainRecords,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Truth {
    #[serde(default)]
    pub expected_fqdns: Vec<String>,
    #[serde(default)]
    pub forbidden_fqdns: Vec<String>,
    #[serde(default)]
    pub allow_additional_fqdns: bool,
    pub minimum_unique_fqdns: Option<usize>,
    #[serde(default)]
    pub expected_observations: BTreeMap<String, ObservationExpectation>,
    #[serde(default)]
    pub expected_filter_reasons: Vec<FilterExpectation>,
    #[serde(default)]
    pub expected_run_status: RunStatus,
    #[serde(default)]
    pub expected_source_status: BTreeMap<String, SourceStatus>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationExpectation {
    #[serde(default = "default_min_count")]
    pub min_count: usize,
    #[serde(default)]
    pub source_kinds: Vec<SourceKind>,
    #[serde(default)]
    pub source_names: Vec<String>,
    #[serde(default)]
    pub record_ids: Vec<String>,
    #[serde(default)]
    pub requires_time: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    pub minimum_confidence: Option<f64>,
}

const fn default_min_count() -> usize {
    1
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilterExpectation {
    pub value: String,
    pub reason: FilterReason,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Assertions {
    pub expected_requests: usize,
    #[serde(default)]
    pub expected_unmatched_requests: usize,
    #[serde(default)]
    pub endpoint_requests: BTreeMap<String, usize>,
    #[serde(default)]
    pub required_paths: Vec<String>,
    #[serde(default)]
    pub forbidden_paths: Vec<String>,
    #[serde(default)]
    pub request_sequence: Vec<RequestSequenceExpectation>,
    #[serde(default)]
    pub timing: TimingExpectation,
    #[serde(default)]
    pub expected_rejected_egress_attempts: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSequenceExpectation {
    pub endpoint: String,
    pub response_index: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimingExpectation {
    pub min_virtual_wait_ms: Option<u64>,
    pub max_virtual_wait_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CollectorRun {
    pub observations: Vec<Observation>,
    pub filtered: Vec<FilteredCandidate>,
    pub source_statuses: BTreeMap<String, SourceStatus>,
    pub virtual_waited_ms: u64,
    #[serde(default)]
    pub metrics: RunMetrics,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Observation {
    pub fqdn: String,
    pub source_kind: SourceKind,
    pub source_name: String,
    pub record_id: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub confidence: Option<f64>,
    #[serde(default)]
    pub evidence: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FilteredCandidate {
    pub value: String,
    pub reason: FilterReason,
    pub source_name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RunMetrics {
    pub response_bytes: usize,
    pub raw_records: usize,
    pub parsed_candidates: usize,
    pub unique_fqdns: usize,
    pub duplicate_candidates: usize,
    pub filtered_candidates: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub request_count: usize,
    pub retry_count: usize,
    pub virtual_wait_ms: u64,
    pub elapsed_ms: u64,
    pub estimated_buffer_bytes: usize,
    pub peak_estimated_buffer_bytes: usize,
    pub cancelled: bool,
    pub cancellation_reason: Option<String>,
    pub blocked_egress: bool,
    #[serde(default)]
    pub wire_response_bytes: usize,
    #[serde(default)]
    pub decoded_response_bytes: usize,
    #[serde(default)]
    pub compression_limit_violation: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterReason {
    Wildcard,
    RootExcluded,
    OutOfScope,
    InvalidDomain,
    InvalidUrl,
    PaginationLoop,
    Duplicate,
    ResponseTooLarge,
    Malformed,
    EvidenceMissing,
    EvidenceMismatch,
    BlockedEgress,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Pending,
    Running,
    Success,
    Succeeded,
    Partial,
    Failed,
    TimedOut,
    AuthFailed,
    Unauthorized,
    RateLimited,
    Cancelled,
    Blocked,
    Completed,
}

/// The only payload an external collector is allowed to submit. It contains
/// discovered data and source evidence, never a report, assertions, audit or
/// a client-side pass/fail decision.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorSubmission {
    pub schema_version: String,
    pub collector: CollectorIdentity,
    pub target_domain: String,
    #[serde(default)]
    pub source_statuses: BTreeMap<String, SourceStatus>,
    #[serde(default)]
    pub findings: Vec<SubmissionFinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorIdentity {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionFinding {
    pub fqdn: String,
    #[serde(default)]
    pub evidence: Vec<SubmissionEvidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionEvidence {
    pub source_id: String,
    pub source_kind: SourceKind,
    pub record_id: Option<String>,
    pub url: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub confidence: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunManifest {
    pub schema_version: String,
    pub run_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub target_domain: String,
    pub network: ManifestNetwork,
    pub sources: Vec<ManifestSource>,
    pub submission: ManifestSubmission,
}

#[derive(Clone, Debug, Serialize)]
pub struct ManifestNetwork {
    pub allowed_hosts: Vec<String>,
    pub external_network_allowed: bool,
    pub required_header: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ManifestSource {
    pub source_id: String,
    pub source_kind: SourceKind,
    pub source_label: String,
    pub base_url: String,
    pub method: HttpMethod,
    pub path_template: String,
    pub required_query: BTreeMap<String, String>,
    pub required_headers: Vec<String>,
    pub authentication_field_names: Vec<String>,
    pub pagination_mode: PaginationMode,
    pub run_header_name: String,
    pub allow_retry: bool,
    pub allow_redirect: bool,
    pub local_test_only: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ManifestSubmission {
    pub url: String,
    pub max_bytes: usize,
    pub max_submission_time_ms: u64,
    pub finalizes_run: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SubmissionReport {
    pub received: bool,
    pub collector_name: Option<String>,
    pub collector_version: Option<String>,
    pub finding_count: usize,
    pub accepted: bool,
    #[serde(default)]
    pub rejected_fields: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ReplayReport {
    pub strict: bool,
    pub matched: Option<bool>,
    pub comparison_report: Option<String>,
    pub first_difference: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CompressionReport {
    pub wire_bytes: usize,
    pub decoded_bytes: usize,
    pub encoding: Option<String>,
    pub limit_violation: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    #[default]
    Success,
    PartialSuccess,
    Failure,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditRecord {
    #[serde(default)]
    pub sequence: usize,
    pub run_id: Option<String>,
    pub scenario_id: String,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub redacted_headers: BTreeMap<String, String>,
    pub body: Option<Value>,
    pub body_summary: Option<Value>,
    pub endpoint_id: Option<String>,
    pub response_index: Option<usize>,
    pub response_sequence: Option<usize>,
    pub response_status: u16,
    #[serde(default)]
    pub before_submission: bool,
    #[serde(default)]
    pub virtual_wait_ms: u64,
    pub retry_after: Option<String>,
    #[serde(default)]
    pub consumed: bool,
    #[serde(default)]
    pub blocked: bool,
    #[serde(default)]
    pub external_target_rejected: bool,
    pub matched: bool,
    pub extra: bool,
    pub mismatch_reasons: Vec<String>,
    #[serde(default)]
    pub wire_bytes: usize,
    #[serde(default)]
    pub decoded_bytes: usize,
    #[serde(default)]
    pub content_encoding: Option<String>,
    #[serde(default)]
    pub compression_limit_violation: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RunReport {
    pub schema_version: String,
    pub lab_version: String,
    /// Kept for 1.1.1 JSON consumers.
    pub version: String,
    pub run_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub target_domain: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub status: ReportStatus,
    pub result: ReportStatus,
    pub actual_run_status: RunStatus,
    pub expected_run_status: RunStatus,
    pub source_statuses: BTreeMap<String, SourceStatus>,
    #[serde(default)]
    pub findings: Vec<SubmissionFinding>,
    #[serde(default)]
    pub filtered: Vec<FilteredCandidate>,
    #[serde(skip_serializing, default)]
    pub truth: Truth,
    pub assertions: AssertionResults,
    pub requests: Vec<AuditRecord>,
    pub request_summary: RequestSummary,
    pub virtual_waited_ms: u64,
    #[serde(default)]
    pub metrics: RunMetrics,
    pub failures: Vec<String>,
    pub violations: Vec<String>,
    pub replay_command: String,
    pub reproducible: bool,
    #[serde(default)]
    pub submission: SubmissionReport,
    #[serde(default)]
    pub semantic_fingerprint: String,
    #[serde(default)]
    pub replay: ReplayReport,
    #[serde(default)]
    pub compression: CompressionReport,
    /// Kept for older GUI/MCP prototypes that read `audit`.
    pub audit: Vec<AuditRecord>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssertionResults {
    pub expected_fqdns: bool,
    pub forbidden_fqdns: bool,
    pub evidence: bool,
    pub filter_reasons: bool,
    pub source_status: bool,
    pub request_contract: bool,
    pub egress_guard: bool,
    #[serde(default = "default_submission_consistency")]
    pub submission_consistency: bool,
}

const fn default_submission_consistency() -> bool {
    true
}

impl AssertionResults {
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.expected_fqdns
            && self.forbidden_fqdns
            && self.evidence
            && self.filter_reasons
            && self.source_status
            && self.request_contract
            && self.egress_guard
            && self.submission_consistency
    }

    #[must_use]
    pub const fn passed_count(&self) -> usize {
        self.expected_fqdns as usize
            + self.forbidden_fqdns as usize
            + self.evidence as usize
            + self.filter_reasons as usize
            + self.source_status as usize
            + self.request_contract as usize
            + self.egress_guard as usize
            + self.submission_consistency as usize
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestSummary {
    pub total: usize,
    pub unmatched: usize,
    pub extra: usize,
    pub rejected_egress_attempts: usize,
}

#[cfg(test)]
mod tests {
    use super::SourceKind;

    #[test]
    fn source_kind_registry_rejects_unknown_values() {
        assert!(serde_yaml::from_str::<SourceKind>("passsive_dns").is_err());
        assert_eq!(
            serde_yaml::from_str::<SourceKind>("generic_json").expect("known source kind"),
            SourceKind::GenericJson
        );
    }
}
