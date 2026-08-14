use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub name: String,
    pub description: String,
    pub root_domain: String,
    pub seed: u64,
    #[serde(default)]
    pub include_root: bool,
    #[serde(default)]
    pub runner: RunnerConfig,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    pub cancel_after_requests: Option<usize>,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            max_response_bytes: default_max_response_bytes(),
            cancel_after_requests: None,
        }
    }
}

const fn default_timeout_ms() -> u64 {
    250
}

const fn default_max_response_bytes() -> usize {
    2 * 1024 * 1024
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
}

impl HttpMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
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
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            mode: PaginationMode::None,
            parameter: default_cursor_parameter(),
            next_cursor_field: None,
        }
    }
}

fn default_cursor_parameter() -> String {
    "cursor".to_owned()
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaginationMode {
    #[default]
    None,
    Cursor,
    Page,
    Offset,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractSpec {
    pub items_field: String,
    pub candidate_field: String,
    #[serde(default = "default_record_id_field")]
    pub record_id_field: String,
    pub timestamp_field: Option<String>,
    #[serde(default)]
    pub kind: ExtractKind,
}

fn default_record_id_field() -> String {
    "id".to_owned()
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractKind {
    #[default]
    Direct,
    Url,
    Tokens,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub body_file: Option<String>,
    pub body: Option<Value>,
    pub generator: Option<Generator>,
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub first_byte_delay_ms: u64,
    #[serde(default)]
    pub disconnect: bool,
    pub malformed_content_length: Option<usize>,
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Truth {
    #[serde(default)]
    pub expected_fqdns: Vec<String>,
    #[serde(default)]
    pub forbidden_fqdns: Vec<String>,
    #[serde(default)]
    pub expected_observations: BTreeMap<String, ObservationExpectation>,
    #[serde(default)]
    pub expected_filter_reasons: Vec<FilterExpectation>,
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
    pub elapsed_ms: u64,
    pub estimated_buffer_bytes: usize,
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Success,
    Failed,
    TimedOut,
    AuthFailed,
    RateLimited,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Success,
    PartialSuccess,
    Failure,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditRecord {
    pub run_id: Option<String>,
    pub scenario_id: String,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Value>,
    pub endpoint_id: Option<String>,
    pub response_index: Option<usize>,
    pub response_status: u16,
    pub matched: bool,
    pub extra: bool,
    pub mismatch_reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RunReport {
    pub version: String,
    pub run_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub status: ReportStatus,
    pub actual_run_status: RunStatus,
    pub expected_run_status: RunStatus,
    pub source_statuses: BTreeMap<String, SourceStatus>,
    pub assertions: AssertionResults,
    pub requests: RequestSummary,
    pub virtual_waited_ms: u64,
    #[serde(default)]
    pub metrics: RunMetrics,
    pub failures: Vec<String>,
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
