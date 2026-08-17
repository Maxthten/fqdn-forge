//! Versioned, declarative experiment plans for the local FQDN Forge lab.
//!
//! Plans deliberately describe only bounded local behaviour.  They contain no
//! URLs, executable expressions, proxy addresses, or long-lived credentials.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{normalize_domain, stable_digest};

pub const PLAN_SCHEMA_VERSION: &str = "0.2";
const MAX_PLAN_BYTES: u64 = 1024 * 1024;
const MAX_SOURCES: usize = 32;
const MAX_FAULTS_PER_SOURCE: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentPlan {
    pub schema_version: String,
    pub plan_id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_target_domain")]
    pub target_domain: String,
    #[serde(default = "default_seed")]
    pub seed: u64,
    #[serde(default)]
    pub sources: Vec<PlanSource>,
    #[serde(default)]
    pub authentication: PlanAuthentication,
    #[serde(default)]
    pub quota: PlanQuota,
    #[serde(default)]
    pub pagination: PlanPagination,
    #[serde(default)]
    pub network_path: PlanNetworkPath,
    #[serde(default)]
    pub faults: Vec<PlanFault>,
    #[serde(default)]
    pub dataset: PlanDataset,
    #[serde(default)]
    pub expected_behaviour: PlanExpectedBehaviour,
    #[serde(default)]
    pub status: PlanStatus,
    #[serde(default)]
    pub revision: u64,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub plan_digest: String,
}

impl ExperimentPlan {
    #[must_use]
    pub fn example() -> Self {
        let now = Utc::now();
        Self {
            schema_version: PLAN_SCHEMA_VERSION.to_owned(),
            plan_id: "plan_basic_001".to_owned(),
            name: "分页与限流基础实验".to_owned(),
            description: "验证本地多来源、分页、重复数据和 429 重试。".to_owned(),
            target_domain: default_target_domain(),
            seed: default_seed(),
            sources: vec![PlanSource {
                id: "certificate".to_owned(),
                template: PlanSourceTemplate::Certificate,
                enabled: true,
                authentication: None,
                quota: None,
                pagination: None,
                faults: Vec::new(),
            }],
            authentication: PlanAuthentication::default(),
            quota: PlanQuota::default(),
            pagination: PlanPagination::default(),
            network_path: PlanNetworkPath::default(),
            faults: Vec::new(),
            dataset: PlanDataset::default(),
            expected_behaviour: PlanExpectedBehaviour::default(),
            status: PlanStatus::Runnable,
            revision: 0,
            created_at: now,
            updated_at: now,
            plan_digest: String::new(),
        }
    }
}

fn default_target_domain() -> String {
    "acme.test".to_owned()
}

const fn default_seed() -> u64 {
    20_260_816
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSource {
    pub id: String,
    pub template: PlanSourceTemplate,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub authentication: Option<PlanAuthentication>,
    #[serde(default)]
    pub quota: Option<PlanQuota>,
    #[serde(default)]
    pub pagination: Option<PlanPagination>,
    #[serde(default)]
    pub faults: Vec<PlanFault>,
}

const fn default_enabled() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanSourceTemplate {
    Certificate,
    PassiveDns,
    Archive,
    UrlSearch,
    ThreatIntel,
    CodeSearch,
    SearchEngine,
    Organization,
    UserImport,
    GenericJson,
    GenericHtml,
    GenericCsv,
    GenericText,
    CustomRest,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMode {
    #[default]
    None,
    FakeApiKey,
    MissingKey,
    WrongKey,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationLocation {
    #[default]
    Header,
    Query,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanAuthentication {
    #[serde(default)]
    pub mode: AuthenticationMode,
    #[serde(default)]
    pub location: AuthenticationLocation,
    #[serde(default = "default_auth_failure_status")]
    pub failure_status: u16,
}

impl Default for PlanAuthentication {
    fn default() -> Self {
        Self {
            mode: AuthenticationMode::None,
            location: AuthenticationLocation::Header,
            failure_status: default_auth_failure_status(),
        }
    }
}

const fn default_auth_failure_status() -> u16 {
    401
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryAfterFormat {
    #[default]
    Seconds,
    HttpDate,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaExhaustedBehaviour {
    #[default]
    RateLimited,
    Forbidden,
    EmptyResult,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanQuota {
    #[serde(default = "default_request_budget")]
    pub request_budget: usize,
    #[serde(default = "default_consume_per_page")]
    pub consume_per_page: bool,
    #[serde(default)]
    pub allow_burst: bool,
    #[serde(default)]
    pub rate_limit_on_request: Option<usize>,
    #[serde(default = "default_retry_after_seconds")]
    pub retry_after_seconds: u64,
    #[serde(default)]
    pub retry_after_format: RetryAfterFormat,
    #[serde(default)]
    pub cooldown_seconds: u64,
    #[serde(default)]
    pub exhausted_behaviour: QuotaExhaustedBehaviour,
}

impl Default for PlanQuota {
    fn default() -> Self {
        Self {
            request_budget: default_request_budget(),
            consume_per_page: default_consume_per_page(),
            allow_burst: false,
            rate_limit_on_request: None,
            retry_after_seconds: default_retry_after_seconds(),
            retry_after_format: RetryAfterFormat::Seconds,
            cooldown_seconds: 0,
            exhausted_behaviour: QuotaExhaustedBehaviour::RateLimited,
        }
    }
}

const fn default_request_budget() -> usize {
    100
}

const fn default_consume_per_page() -> bool {
    true
}

const fn default_retry_after_seconds() -> u64 {
    1
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanPaginationMode {
    #[default]
    None,
    Page,
    Offset,
    Cursor,
    Link,
    PostBody,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanPagination {
    #[serde(default)]
    pub mode: PlanPaginationMode,
    #[serde(default = "default_page_size")]
    pub page_size: usize,
    #[serde(default = "default_total_pages")]
    pub total_pages: usize,
    #[serde(default = "default_next_page")]
    pub next_page_exists: bool,
    #[serde(default)]
    pub repeat_from_page: Option<usize>,
    #[serde(default)]
    pub duplicate_ratio_percent: u8,
    #[serde(default)]
    pub cursor_loop: bool,
    #[serde(default)]
    pub invalid_page: Option<usize>,
    #[serde(default)]
    pub empty_final_page_with_next: bool,
}

impl Default for PlanPagination {
    fn default() -> Self {
        Self {
            mode: PlanPaginationMode::None,
            page_size: default_page_size(),
            total_pages: default_total_pages(),
            next_page_exists: default_next_page(),
            repeat_from_page: None,
            duplicate_ratio_percent: 0,
            cursor_loop: false,
            invalid_page: None,
            empty_final_page_with_next: false,
        }
    }
}

const fn default_page_size() -> usize {
    25
}

const fn default_total_pages() -> usize {
    1
}

const fn default_next_page() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanNetworkMode {
    #[default]
    Direct,
    HttpProxy,
    Connect,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanNetworkPath {
    #[serde(default)]
    pub mode: PlanNetworkMode,
    #[serde(default)]
    pub proxy_authentication: ProxyAuthentication,
    #[serde(default)]
    pub proxy_fault: ProxySimulationFault,
    #[serde(default)]
    pub allowlisted_sources: Vec<String>,
}

impl Default for PlanNetworkPath {
    fn default() -> Self {
        Self {
            mode: PlanNetworkMode::Direct,
            proxy_authentication: ProxyAuthentication::NotRequired,
            proxy_fault: ProxySimulationFault::None,
            allowlisted_sources: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyAuthentication {
    #[default]
    NotRequired,
    Succeeds,
    Fails,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxySimulationFault {
    #[default]
    None,
    RejectRequest,
    ConnectFailure,
    SlowResponse,
    Disconnect,
    NotAllowlisted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanFault {
    pub kind: PlanFaultKind,
    #[serde(default = "default_fault_page")]
    pub trigger_page: usize,
    #[serde(default = "default_fault_occurrences")]
    pub occurrences: usize,
}

const fn default_fault_page() -> usize {
    1
}

const fn default_fault_occurrences() -> usize {
    1
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanFaultKind {
    SlowResponse,
    Timeout,
    Disconnect,
    Status500,
    Status502,
    Status503,
    Status401,
    Status403,
    Status404,
    Status429,
    EmptyResponse,
    NoContent,
    InvalidJson,
    TruncatedJson,
    HtmlInsteadOfJson,
    WrongContentType,
    WrongContentLength,
    MalformedChunked,
    Gzip,
    Deflate,
    Brotli,
    CorruptCompression,
    ResponseTooLarge,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetSize {
    #[default]
    Small,
    Medium,
    Large,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDataset {
    #[serde(default)]
    pub size: DatasetSize,
}

impl Default for PlanDataset {
    fn default() -> Self {
        Self {
            size: DatasetSize::Small,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanExpectedBehaviour {
    #[serde(default)]
    pub expected_fqdns: Vec<String>,
    #[serde(default)]
    pub forbidden_fqdns: Vec<String>,
    #[serde(default)]
    pub filtered_candidates: Vec<String>,
    #[serde(default)]
    pub expected_requests_per_source: BTreeMap<String, usize>,
    #[serde(default)]
    pub allow_partial_success: bool,
    #[serde(default)]
    pub require_evidence: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    #[default]
    Draft,
    Runnable,
    Invalid,
    Archived,
}

/// Identifies whether a run is the built-in deterministic self-check or an
/// externally driven integration session. Both modes use the same immutable
/// plan snapshot and server-side validation; only the caller changes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanExecutionMode {
    #[default]
    LocalSimulation,
    ExternalIntegration,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlanValidationIssue {
    pub code: String,
    pub field: String,
    pub message: String,
}

impl PlanValidationIssue {
    fn new(code: &str, field: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            field: field.to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PlanValidationResult {
    pub schema_version: String,
    pub valid: bool,
    pub issues: Vec<PlanValidationIssue>,
    pub plan_digest: Option<String>,
    pub normalized_plan: Option<ExperimentPlan>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlanRunAuditEntry {
    pub source_id: String,
    pub request_count: usize,
    pub retry_count: usize,
    pub virtual_wait_ms: u64,
    pub quota_consumed: usize,
    pub rate_limited: bool,
    pub status: String,
    pub failure: Option<String>,
    /// The deterministic sequence the server resolved from the plan. It is
    /// deliberately separate from `actual_requests`, which is populated only
    /// when a client uses the temporary loopback source capability.
    #[serde(default)]
    pub expected_requests: Vec<PlanRequestAuditStep>,
    /// Bounded, redacted observations from the real local source/proxy
    /// endpoint. No capability or fake key is ever stored here.
    #[serde(default)]
    pub actual_requests: Vec<PlanRequestAuditStep>,
    #[serde(default)]
    pub authentication: String,
    #[serde(default)]
    pub rate_limit_reason: Option<String>,
    #[serde(default)]
    pub retry_after: Option<String>,
    #[serde(default)]
    pub network_mode: PlanNetworkMode,
    #[serde(default)]
    pub proxy_authentication: ProxyAuthentication,
    #[serde(default)]
    pub proxy_fault: ProxySimulationFault,
}

/// A single, capability-redacted plan-source request. This is intentionally
/// data-only so reports remain safe to export and deterministic to compare.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PlanRequestAuditStep {
    pub request_number: usize,
    pub page: Option<usize>,
    pub pagination_token: Option<String>,
    pub response_status: u16,
    pub quota_consumed: bool,
    pub rate_limit_reason: Option<String>,
    pub retry_after: Option<String>,
    pub virtual_wait_ms: u64,
    pub authentication: String,
    pub network_mode: PlanNetworkMode,
    pub proxy_authentication: ProxyAuthentication,
    pub proxy_fault: ProxySimulationFault,
    pub triggered_fault: Option<PlanFaultKind>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlanRunReport {
    pub schema_version: String,
    pub run_id: String,
    pub plan_id: String,
    pub plan_digest: String,
    #[serde(default)]
    pub execution_mode: PlanExecutionMode,
    pub status: String,
    pub correct_findings: usize,
    pub missed_findings: usize,
    pub unexpected_findings: usize,
    pub filtered: usize,
    pub source_statuses: BTreeMap<String, String>,
    pub requests: usize,
    pub retries: usize,
    pub rate_limited_sources: usize,
    pub virtual_wait_ms: u64,
    pub fixture_digest: String,
    pub truth_digest: String,
    pub expected_behaviour_digest: String,
    pub manifest_digest: String,
    pub egress_attempted: bool,
    pub failures: Vec<String>,
    /// Number of requests received by the exposed local plan source endpoint;
    /// this does not include the server's deterministic reference simulation.
    #[serde(default)]
    pub actual_requests: usize,
    #[serde(default)]
    pub source_access_status: String,
    #[serde(default)]
    pub source_access_expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct PlanSourceContract {
    pub route_template: String,
    pub run_header_name: String,
    pub source_capability_header: String,
    pub fake_api_key_header: String,
    pub proxy_capability_header: String,
    pub runtime_capability_ttl_seconds: u64,
    pub network_mode: PlanNetworkMode,
}

impl Default for PlanSourceContract {
    fn default() -> Self {
        Self {
            route_template: "/api/plan-runs/{run_id}/sources/{source_id}".to_owned(),
            run_header_name: "x-lab-run-id".to_owned(),
            source_capability_header: "x-lab-source-capability".to_owned(),
            fake_api_key_header: "x-lab-plan-api-key".to_owned(),
            proxy_capability_header: "x-lab-proxy-capability".to_owned(),
            runtime_capability_ttl_seconds: 300,
            network_mode: PlanNetworkMode::Direct,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlanRunManifest {
    pub schema_version: String,
    pub run_id: String,
    pub plan_id: String,
    pub plan_revision: u64,
    #[serde(default)]
    pub execution_mode: PlanExecutionMode,
    pub seed: u64,
    pub resolved_configuration: Value,
    pub fixture_digest: String,
    pub truth_digest: String,
    pub expected_behaviour_digest: String,
    pub manifest_digest: String,
    pub created_at: DateTime<Utc>,
    pub replayed_from: Option<String>,
    #[serde(default)]
    pub source_contract: PlanSourceContract,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlanRun {
    pub manifest: PlanRunManifest,
    pub report: PlanRunReport,
    pub audit: Vec<PlanRunAuditEntry>,
    pub plan_snapshot: ExperimentPlan,
}

/// Read-only, bounded storage information intended for diagnostics. It never
/// removes files and exposes only local directories managed by `PlanStore`.
#[derive(Clone, Debug, Serialize)]
pub struct PlanStorageStats {
    pub schema_version: String,
    pub plan_count: usize,
    pub run_count: usize,
    pub total_bytes: u64,
    pub plans_directory: String,
    pub runs_directory: String,
}

#[derive(Clone, Debug)]
pub struct PlanStore {
    root: PathBuf,
    runs_root: PathBuf,
    plans: Arc<Mutex<BTreeMap<String, ExperimentPlan>>>,
}

impl PlanStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let runs_root = root
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("plan-runs");
        fs::create_dir_all(&root)
            .with_context(|| format!("cannot create plan directory {}", root.display()))?;
        fs::create_dir_all(&runs_root)
            .with_context(|| format!("cannot create plan run directory {}", runs_root.display()))?;
        let mut plans = BTreeMap::new();
        for entry in fs::read_dir(&root)
            .with_context(|| format!("cannot read plan directory {}", root.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let file_plan_id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    anyhow!("PLAN_FILE_ID_INVALID: plan file has no UTF-8 identifier")
                })?;
            if !safe_identifier(file_plan_id) {
                bail!("PLAN_FILE_ID_INVALID: plan file identifier is unsafe");
            }
            if entry.metadata()?.len() > MAX_PLAN_BYTES {
                bail!(
                    "PLAN_TOO_LARGE: plan file {} exceeds the 1 MiB safety limit",
                    path.display()
                );
            }
            let contents = fs::read(&path)?;
            let plan: ExperimentPlan = serde_json::from_slice(&contents).map_err(|error| {
                anyhow!(
                    "PLAN_JSON_CORRUPT: cannot parse plan file {}: {error}",
                    path.display()
                )
            })?;
            let canonical = canonicalize_plan(plan, true)
                .map_err(|issues| anyhow!(format_plan_issues(&issues)))?;
            if canonical.plan_id != file_plan_id {
                bail!(
                    "PLAN_FILE_ID_MISMATCH: plan file {file_plan_id} contains plan_id {}",
                    canonical.plan_id
                );
            }
            plans.insert(canonical.plan_id.clone(), canonical);
        }
        Ok(Self {
            root,
            runs_root,
            plans: Arc::new(Mutex::new(plans)),
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn list(&self) -> Vec<ExperimentPlan> {
        self.plans
            .lock()
            .expect("plan store lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn get(&self, plan_id: &str) -> Option<ExperimentPlan> {
        self.plans
            .lock()
            .expect("plan store lock poisoned")
            .get(plan_id)
            .cloned()
    }

    pub fn create(&self, plan: ExperimentPlan) -> Result<ExperimentPlan> {
        let canonical = canonicalize_plan(plan, false)
            .map_err(|issues| anyhow!(format_plan_issues(&issues)))?;
        let mut plans = self.plans.lock().expect("plan store lock poisoned");
        if plans.contains_key(&canonical.plan_id) {
            bail!(
                "PLAN_ALREADY_EXISTS: plan {} already exists",
                canonical.plan_id
            );
        }
        write_plan_file(&self.root, &canonical)?;
        plans.insert(canonical.plan_id.clone(), canonical.clone());
        Ok(canonical)
    }

    pub fn update(&self, plan_id: &str, mut plan: ExperimentPlan) -> Result<ExperimentPlan> {
        let mut plans = self.plans.lock().expect("plan store lock poisoned");
        let prior = plans
            .get(plan_id)
            .cloned()
            .ok_or_else(|| anyhow!("PLAN_NOT_FOUND: plan {plan_id} does not exist"))?;
        plan.plan_id = plan_id.to_owned();
        plan.created_at = prior.created_at;
        plan.revision = prior.revision.saturating_add(1);
        plan.updated_at = Utc::now();
        let canonical = canonicalize_plan(plan, false)
            .map_err(|issues| anyhow!(format_plan_issues(&issues)))?;
        write_plan_file(&self.root, &canonical)?;
        plans.insert(plan_id.to_owned(), canonical.clone());
        Ok(canonical)
    }

    pub fn archive(&self, plan_id: &str) -> Result<ExperimentPlan> {
        let mut plans = self.plans.lock().expect("plan store lock poisoned");
        let mut plan = plans
            .get(plan_id)
            .cloned()
            .ok_or_else(|| anyhow!("PLAN_NOT_FOUND: plan {plan_id} does not exist"))?;
        plan.status = PlanStatus::Archived;
        plan.revision = plan.revision.saturating_add(1);
        plan.updated_at = Utc::now();
        let canonical = canonicalize_plan(plan, false)
            .map_err(|issues| anyhow!(format_plan_issues(&issues)))?;
        write_plan_file(&self.root, &canonical)?;
        plans.insert(plan_id.to_owned(), canonical.clone());
        Ok(canonical)
    }

    pub fn import(&self, plan: ExperimentPlan) -> Result<ExperimentPlan> {
        let canonical =
            canonicalize_plan(plan, true).map_err(|issues| anyhow!(format_plan_issues(&issues)))?;
        let mut plans = self.plans.lock().expect("plan store lock poisoned");
        if plans.contains_key(&canonical.plan_id) {
            bail!(
                "PLAN_ALREADY_EXISTS: plan {} already exists",
                canonical.plan_id
            );
        }
        write_plan_file(&self.root, &canonical)?;
        plans.insert(canonical.plan_id.clone(), canonical.clone());
        Ok(canonical)
    }

    pub fn delete(&self, plan_id: &str) -> Result<()> {
        let mut plans = self.plans.lock().expect("plan store lock poisoned");
        if plans.remove(plan_id).is_none() {
            bail!("PLAN_NOT_FOUND: plan {plan_id} does not exist");
        }
        let path = plan_file(&self.root, plan_id)?;
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("cannot delete plan file {}", path.display()))?;
        }
        Ok(())
    }

    pub fn save_run(&self, run: &PlanRun) -> Result<()> {
        let target = plan_run_file(&self.runs_root, &run.manifest.run_id)?;
        let temporary = target.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(run)?;
        if bytes.len() as u64 > MAX_PLAN_BYTES {
            bail!("PLAN_RUN_TOO_LARGE: run snapshot exceeds the 1 MiB safety limit");
        }
        fs::write(&temporary, bytes)
            .with_context(|| format!("cannot write plan run {}", temporary.display()))?;
        fs::rename(&temporary, &target)
            .with_context(|| format!("cannot save plan run {}", target.display()))?;
        Ok(())
    }

    pub fn load_run(&self, run_id: &str) -> Result<PlanRun> {
        let path = plan_run_file(&self.runs_root, run_id)?;
        if !path.exists() {
            bail!("PLAN_RUN_NOT_FOUND: run {run_id} does not exist");
        }
        if fs::metadata(&path)?.len() > MAX_PLAN_BYTES {
            bail!("PLAN_RUN_TOO_LARGE: run snapshot exceeds the 1 MiB safety limit");
        }
        let run: PlanRun = serde_json::from_slice(&fs::read(&path)?).map_err(|error| {
            anyhow!(
                "PLAN_RUN_JSON_CORRUPT: cannot parse plan run {}: {error}",
                path.display()
            )
        })?;
        if run.manifest.run_id != run_id {
            bail!("PLAN_RUN_INVALID: run snapshot identifier does not match its file name");
        }
        Ok(run)
    }

    pub fn list_runs(&self) -> Result<Vec<PlanRun>> {
        let mut runs = Vec::new();
        for entry in fs::read_dir(&self.runs_root)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let run_id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            runs.push(self.load_run(run_id)?);
        }
        runs.sort_by_key(|run| run.manifest.created_at);
        Ok(runs)
    }

    pub fn storage_stats(&self) -> Result<PlanStorageStats> {
        Ok(PlanStorageStats {
            schema_version: PLAN_SCHEMA_VERSION.to_owned(),
            plan_count: self.list().len(),
            run_count: self.list_runs()?.len(),
            total_bytes: directory_file_bytes(&self.root)?
                .saturating_add(directory_file_bytes(&self.runs_root)?),
            plans_directory: self.root.display().to_string(),
            runs_directory: self.runs_root.display().to_string(),
        })
    }
}

pub fn validate_plan(plan: ExperimentPlan, verify_digest: bool) -> PlanValidationResult {
    match canonicalize_plan(plan, verify_digest) {
        Ok(plan) => PlanValidationResult {
            schema_version: PLAN_SCHEMA_VERSION.to_owned(),
            valid: true,
            issues: Vec::new(),
            plan_digest: Some(plan.plan_digest.clone()),
            normalized_plan: Some(plan),
        },
        Err(issues) => PlanValidationResult {
            schema_version: PLAN_SCHEMA_VERSION.to_owned(),
            valid: false,
            issues,
            plan_digest: None,
            normalized_plan: None,
        },
    }
}

pub fn canonicalize_plan(
    mut plan: ExperimentPlan,
    verify_digest: bool,
) -> std::result::Result<ExperimentPlan, Vec<PlanValidationIssue>> {
    let mut issues = validate_plan_fields(&plan);
    if !issues.is_empty() {
        return Err(issues);
    }
    plan.schema_version = PLAN_SCHEMA_VERSION.to_owned();
    plan.target_domain = normalize_domain(&plan.target_domain).map_err(|_| {
        vec![PlanValidationIssue::new(
            "PLAN_TARGET_DOMAIN_INVALID",
            "target_domain",
            "target_domain must be a valid synthetic .test domain",
        )]
    })?;
    for fqdn in &mut plan.expected_behaviour.expected_fqdns {
        *fqdn = normalize_domain(fqdn).map_err(|_| {
            vec![PlanValidationIssue::new(
                "PLAN_EXPECTED_FQDN_INVALID",
                "expected_behaviour.expected_fqdns",
                "expected FQDN must be a valid domain",
            )]
        })?;
    }
    for fqdn in &mut plan.expected_behaviour.forbidden_fqdns {
        *fqdn = normalize_domain(fqdn).map_err(|_| {
            vec![PlanValidationIssue::new(
                "PLAN_FORBIDDEN_FQDN_INVALID",
                "expected_behaviour.forbidden_fqdns",
                "forbidden FQDN must be a valid domain",
            )]
        })?;
    }
    plan.expected_behaviour.expected_fqdns.sort();
    plan.expected_behaviour.expected_fqdns.dedup();
    plan.expected_behaviour.forbidden_fqdns.sort();
    plan.expected_behaviour.forbidden_fqdns.dedup();
    let digest = plan_digest(&plan);
    if verify_digest && !plan.plan_digest.is_empty() && plan.plan_digest != digest {
        issues.push(PlanValidationIssue::new(
            "PLAN_DIGEST_MISMATCH",
            "plan_digest",
            "plan_digest does not match the normalized plan content",
        ));
        return Err(issues);
    }
    // Draft is a meaningful user-visible state. A valid draft keeps its
    // draft status until the caller explicitly marks it runnable; an archived
    // plan is likewise preserved. `Invalid` is an internal display state and
    // becomes a draft once the supplied fields validate successfully.
    if plan.status == PlanStatus::Invalid {
        plan.status = PlanStatus::Draft;
    }
    plan.plan_digest = digest;
    Ok(plan)
}

fn validate_plan_fields(plan: &ExperimentPlan) -> Vec<PlanValidationIssue> {
    let mut issues = Vec::new();
    if plan.schema_version != PLAN_SCHEMA_VERSION {
        issues.push(PlanValidationIssue::new(
            "PLAN_SCHEMA_VERSION_UNSUPPORTED",
            "schema_version",
            format!("schema_version must be {PLAN_SCHEMA_VERSION}"),
        ));
    }
    if !safe_identifier(&plan.plan_id) {
        issues.push(PlanValidationIssue::new(
            "PLAN_ID_INVALID",
            "plan_id",
            "plan_id must be 3-64 lowercase letters, digits, '-' or '_'",
        ));
    }
    if plan.name.trim().is_empty() || plan.name.chars().count() > 120 {
        issues.push(PlanValidationIssue::new(
            "PLAN_NAME_INVALID",
            "name",
            "name must contain 1-120 characters",
        ));
    }
    if plan.description.chars().count() > 2_000 {
        issues.push(PlanValidationIssue::new(
            "PLAN_DESCRIPTION_TOO_LONG",
            "description",
            "description must not exceed 2000 characters",
        ));
    }
    let target = normalize_domain(&plan.target_domain);
    if target
        .as_deref()
        .map_or(true, |domain| !domain.ends_with(".test"))
    {
        issues.push(PlanValidationIssue::new(
            "PLAN_TARGET_DOMAIN_INVALID",
            "target_domain",
            "target_domain must be a valid local synthetic .test domain",
        ));
    }
    if plan.sources.is_empty() || plan.sources.len() > MAX_SOURCES {
        issues.push(PlanValidationIssue::new(
            "PLAN_SOURCES_INVALID",
            "sources",
            format!("a plan must contain 1-{MAX_SOURCES} sources"),
        ));
    }
    let mut ids = BTreeSet::new();
    for (index, source) in plan.sources.iter().enumerate() {
        let field = format!("sources[{index}]");
        if !safe_identifier(&source.id) || !ids.insert(source.id.clone()) {
            issues.push(PlanValidationIssue::new(
                "PLAN_SOURCE_ID_INVALID",
                &format!("{field}.id"),
                "source id must be unique and use only lowercase letters, digits, '-' or '_'",
            ));
        }
        if source.faults.len() > MAX_FAULTS_PER_SOURCE {
            issues.push(PlanValidationIssue::new(
                "PLAN_FAULTS_TOO_MANY",
                &format!("{field}.faults"),
                format!("a source may contain at most {MAX_FAULTS_PER_SOURCE} faults"),
            ));
        }
        validate_source_settings(source, &field, &mut issues);
    }
    if !plan.sources.iter().any(|source| source.enabled) {
        issues.push(PlanValidationIssue::new(
            "PLAN_NO_ENABLED_SOURCES",
            "sources",
            "at least one source must be enabled",
        ));
    }
    validate_authentication(&plan.authentication, "authentication", &mut issues);
    validate_quota(&plan.quota, "quota", &mut issues);
    validate_pagination(&plan.pagination, "pagination", &mut issues);
    if plan.faults.len() > MAX_FAULTS_PER_SOURCE {
        issues.push(PlanValidationIssue::new(
            "PLAN_FAULTS_TOO_MANY",
            "faults",
            format!("a plan may contain at most {MAX_FAULTS_PER_SOURCE} shared faults"),
        ));
    }
    for (index, fault) in plan.faults.iter().enumerate() {
        validate_fault(fault, &format!("faults[{index}]"), &mut issues);
    }
    for (source, requests) in &plan.expected_behaviour.expected_requests_per_source {
        if !ids.contains(source) || *requests == 0 {
            issues.push(PlanValidationIssue::new(
                "PLAN_EXPECTED_REQUESTS_INVALID",
                "expected_behaviour.expected_requests_per_source",
                "expected request counts require a known source and a positive value",
            ));
            break;
        }
    }
    let serialised = serde_json::to_string(plan).unwrap_or_default();
    for prohibited in [
        "http://",
        "https://",
        "javascript:",
        "powershell",
        "function(",
        "=>",
    ] {
        if serialised.to_ascii_lowercase().contains(prohibited) {
            issues.push(PlanValidationIssue::new(
                "PLAN_UNSAFE_CONTENT",
                "plan",
                "plans cannot contain URLs, scripts, dynamic expressions, or external network targets",
            ));
            break;
        }
    }
    if contains_ip_literal(&serialised) {
        issues.push(PlanValidationIssue::new(
            "PLAN_EXTERNAL_ADDRESS_FORBIDDEN",
            "plan",
            "plans cannot contain IP addresses or external network addresses",
        ));
    }
    for suspicious in [
        "authorization",
        "cookie",
        "password",
        "bearer ",
        "sk-",
        "ghp_",
    ] {
        if serialised.to_ascii_lowercase().contains(suspicious) {
            issues.push(PlanValidationIssue::new(
                "PLAN_REAL_CREDENTIAL_FORBIDDEN",
                "plan",
                "plans store only authentication modes and redacted placeholders, never credentials",
            ));
            break;
        }
    }
    issues
}

fn validate_source_settings(
    source: &PlanSource,
    field: &str,
    issues: &mut Vec<PlanValidationIssue>,
) {
    if let Some(authentication) = &source.authentication {
        validate_authentication(authentication, &format!("{field}.authentication"), issues);
    }
    if let Some(quota) = &source.quota {
        validate_quota(quota, &format!("{field}.quota"), issues);
    }
    if let Some(pagination) = &source.pagination {
        validate_pagination(pagination, &format!("{field}.pagination"), issues);
    }
    for (index, fault) in source.faults.iter().enumerate() {
        validate_fault(fault, &format!("{field}.faults[{index}]"), issues);
    }
}

fn validate_authentication(
    authentication: &PlanAuthentication,
    field: &str,
    issues: &mut Vec<PlanValidationIssue>,
) {
    if !matches!(authentication.failure_status, 401 | 403) {
        issues.push(PlanValidationIssue::new(
            "PLAN_AUTH_STATUS_INVALID",
            &format!("{field}.failure_status"),
            "authentication failure_status must be 401 or 403",
        ));
    }
}

fn validate_quota(quota: &PlanQuota, field: &str, issues: &mut Vec<PlanValidationIssue>) {
    if quota.request_budget == 0 || quota.request_budget > 10_000 {
        issues.push(PlanValidationIssue::new(
            "PLAN_QUOTA_INVALID",
            &format!("{field}.request_budget"),
            "request_budget must be between 1 and 10000",
        ));
    }
    if quota
        .rate_limit_on_request
        .is_some_and(|value| value == 0 || value > 10_000)
    {
        issues.push(PlanValidationIssue::new(
            "PLAN_RATE_LIMIT_INVALID",
            &format!("{field}.rate_limit_on_request"),
            "rate_limit_on_request must be between 1 and 10000",
        ));
    }
    if quota.retry_after_seconds > 86_400 || quota.cooldown_seconds > 86_400 {
        issues.push(PlanValidationIssue::new(
            "PLAN_COOLDOWN_INVALID",
            field,
            "Retry-After and cooldown must not exceed one virtual day",
        ));
    }
}

fn validate_pagination(
    pagination: &PlanPagination,
    field: &str,
    issues: &mut Vec<PlanValidationIssue>,
) {
    if pagination.page_size == 0 || pagination.page_size > 10_000 {
        issues.push(PlanValidationIssue::new(
            "PLAN_PAGE_SIZE_INVALID",
            &format!("{field}.page_size"),
            "page_size must be between 1 and 10000",
        ));
    }
    if pagination.total_pages == 0 || pagination.total_pages > 1_000 {
        issues.push(PlanValidationIssue::new(
            "PLAN_TOTAL_PAGES_INVALID",
            &format!("{field}.total_pages"),
            "total_pages must be between 1 and 1000",
        ));
    }
    if pagination.duplicate_ratio_percent > 100 {
        issues.push(PlanValidationIssue::new(
            "PLAN_DUPLICATE_RATIO_INVALID",
            &format!("{field}.duplicate_ratio_percent"),
            "duplicate_ratio_percent must be 0-100",
        ));
    }
    if pagination
        .repeat_from_page
        .is_some_and(|page| page == 0 || page > pagination.total_pages)
        || pagination
            .invalid_page
            .is_some_and(|page| page == 0 || page > pagination.total_pages)
    {
        issues.push(PlanValidationIssue::new(
            "PLAN_PAGINATION_PAGE_INVALID",
            field,
            "repeat_from_page and invalid_page must refer to an existing page",
        ));
    }
}

fn validate_fault(fault: &PlanFault, field: &str, issues: &mut Vec<PlanValidationIssue>) {
    if fault.trigger_page == 0 || fault.occurrences == 0 || fault.occurrences > 100 {
        issues.push(PlanValidationIssue::new(
            "PLAN_FAULT_TRIGGER_INVALID",
            field,
            "fault trigger_page must be positive and occurrences must be 1-100",
        ));
    }
}

fn safe_identifier(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn contains_ip_literal(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .any(|part| {
            let octets = part.split('.').collect::<Vec<_>>();
            octets.len() == 4
                && octets
                    .iter()
                    .all(|octet| !octet.is_empty() && octet.parse::<u8>().is_ok())
        })
}

#[must_use]
pub fn plan_digest(plan: &ExperimentPlan) -> String {
    stable_digest(&json!({
        "schema_version": PLAN_SCHEMA_VERSION,
        "target_domain": plan.target_domain,
        "seed": plan.seed,
        "sources": plan.sources,
        "authentication": plan.authentication,
        "quota": plan.quota,
        "pagination": plan.pagination,
        "network_path": plan.network_path,
        "faults": plan.faults,
        "dataset": plan.dataset,
        "expected_behaviour": plan.expected_behaviour,
    }))
}

pub fn execute_plan(plan: ExperimentPlan, replayed_from: Option<String>) -> PlanRun {
    execute_plan_with_mode(plan, replayed_from, PlanExecutionMode::LocalSimulation)
}

pub fn execute_plan_with_mode(
    plan: ExperimentPlan,
    replayed_from: Option<String>,
    execution_mode: PlanExecutionMode,
) -> PlanRun {
    let run_id = Uuid::new_v4().to_string();
    let resolved_configuration = json!({
        "schema_version": PLAN_SCHEMA_VERSION,
        "plan_digest": plan.plan_digest,
        "target_domain": plan.target_domain,
        "seed": plan.seed,
        "sources": plan.sources,
        "authentication": plan.authentication,
        "quota": plan.quota,
        "pagination": plan.pagination,
        "network_path": plan.network_path,
        "faults": plan.faults,
        "dataset": plan.dataset,
        "expected_behaviour": plan.expected_behaviour,
        "execution_mode": execution_mode,
        "local_only": true,
        "external_network_allowed": false,
    });
    let fixture_digest = stable_digest(&json!({
        "seed": plan.seed,
        "target_domain": plan.target_domain,
        "sources": plan.sources,
        "dataset": plan.dataset,
        "pagination": plan.pagination,
    }));
    let expected_behaviour_digest = stable_digest(
        &serde_json::to_value(&plan.expected_behaviour).expect("expected behaviour serializes"),
    );
    let truth = plan_truth(&plan);
    let truth_digest = stable_digest(&truth);
    let (audit, source_statuses, failures, correct_findings, missed_findings, filtered) =
        simulate_sources(&plan, &truth);
    let requests = audit.iter().map(|entry| entry.request_count).sum();
    let retries = audit.iter().map(|entry| entry.retry_count).sum();
    let virtual_wait_ms = audit.iter().map(|entry| entry.virtual_wait_ms).sum();
    let rate_limited_sources = audit.iter().filter(|entry| entry.rate_limited).count();
    let expected_request_failures = plan
        .expected_behaviour
        .expected_requests_per_source
        .iter()
        .filter_map(|(source, expected)| {
            audit
                .iter()
                .find(|entry| &entry.source_id == source)
                .filter(|entry| entry.request_count != *expected)
                .map(|entry| {
                    format!(
                        "{source}: expected {expected} requests, observed {}",
                        entry.request_count
                    )
                })
        })
        .collect::<Vec<_>>();
    let mut failures = failures;
    failures.extend(expected_request_failures);
    if !plan.expected_behaviour.allow_partial_success
        && source_statuses.values().any(|status| status != "succeeded")
    {
        failures
            .push("one or more sources did not succeed and partial success is disabled".to_owned());
    }
    let status = if failures.is_empty() {
        "passed"
    } else {
        "failed"
    }
    .to_owned();
    let source_contract = PlanSourceContract {
        network_mode: plan.network_path.mode,
        ..PlanSourceContract::default()
    };
    let manifest_seed = json!({
        "schema_version": PLAN_SCHEMA_VERSION,
        "run_id": run_id,
        "plan_id": plan.plan_id,
        "plan_revision": plan.revision,
        "execution_mode": execution_mode,
        "seed": plan.seed,
        "resolved_configuration": resolved_configuration,
        "fixture_digest": fixture_digest,
        "truth_digest": truth_digest,
        "expected_behaviour_digest": expected_behaviour_digest,
        "source_contract": source_contract,
        "replayed_from": replayed_from,
    });
    let manifest_digest = stable_digest(&manifest_seed);
    let manifest = PlanRunManifest {
        schema_version: PLAN_SCHEMA_VERSION.to_owned(),
        run_id: run_id.clone(),
        plan_id: plan.plan_id.clone(),
        plan_revision: plan.revision,
        execution_mode,
        seed: plan.seed,
        resolved_configuration,
        fixture_digest: fixture_digest.clone(),
        truth_digest: truth_digest.clone(),
        expected_behaviour_digest: expected_behaviour_digest.clone(),
        manifest_digest: manifest_digest.clone(),
        created_at: Utc::now(),
        replayed_from,
        source_contract,
    };
    let report = PlanRunReport {
        schema_version: PLAN_SCHEMA_VERSION.to_owned(),
        run_id,
        plan_id: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        execution_mode,
        status,
        correct_findings,
        missed_findings,
        unexpected_findings: 0,
        filtered,
        source_statuses,
        requests,
        retries,
        rate_limited_sources,
        virtual_wait_ms,
        fixture_digest,
        truth_digest,
        expected_behaviour_digest,
        manifest_digest,
        egress_attempted: false,
        failures,
        actual_requests: 0,
        // Stable across CLI and API runs. The active/expired/cancelled state
        // belongs to the ephemeral runtime, not the deterministic result.
        source_access_status: "local_contract".to_owned(),
        source_access_expires_at: None,
    };
    PlanRun {
        manifest,
        report,
        audit,
        plan_snapshot: plan,
    }
}

fn plan_truth(plan: &ExperimentPlan) -> Value {
    let generated = plan
        .sources
        .iter()
        .filter(|source| source.enabled)
        .map(|source| generated_fqdn(plan, source, 1))
        .collect::<Vec<_>>();
    let expected = if plan.expected_behaviour.expected_fqdns.is_empty() {
        generated
    } else {
        plan.expected_behaviour.expected_fqdns.clone()
    };
    json!({
        "expected_fqdns": expected,
        "forbidden_fqdns": plan.expected_behaviour.forbidden_fqdns,
        "minimum_unique_fqdns": dataset_record_count(plan.dataset.size),
        "filtered_candidates": plan.expected_behaviour.filtered_candidates,
    })
}

fn simulate_sources(
    plan: &ExperimentPlan,
    truth: &Value,
) -> (
    Vec<PlanRunAuditEntry>,
    BTreeMap<String, String>,
    Vec<String>,
    usize,
    usize,
    usize,
) {
    let expected = truth
        .get("expected_fqdns")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut audit = Vec::new();
    let mut statuses = BTreeMap::new();
    let mut failures = Vec::new();
    let mut discovered = 0usize;
    let mut filtered = plan.expected_behaviour.filtered_candidates.len();
    for source in plan.sources.iter().filter(|source| source.enabled) {
        let authentication = source
            .authentication
            .as_ref()
            .unwrap_or(&plan.authentication);
        let quota = source.quota.as_ref().unwrap_or(&plan.quota);
        let pagination = source.pagination.as_ref().unwrap_or(&plan.pagination);
        let faults = source
            .faults
            .iter()
            .chain(plan.faults.iter())
            .collect::<Vec<_>>();
        let pages = if pagination.mode == PlanPaginationMode::None {
            1
        } else {
            pagination.total_pages
        };
        let mut request_count = 0usize;
        let mut retries = 0usize;
        let mut virtual_wait_ms = 0u64;
        let mut quota_consumed = 0usize;
        let mut rate_limited = false;
        let mut failure = None;
        let mut status = "succeeded".to_owned();
        match authentication.mode {
            AuthenticationMode::MissingKey | AuthenticationMode::WrongKey => {
                status = "auth_failed".to_owned();
                request_count = 1;
                failure = Some(format!(
                    "simulated authentication rejected with {}",
                    authentication.failure_status
                ));
            }
            _ => {
                for page in 1..=pages {
                    request_count = request_count.saturating_add(1);
                    if quota.consume_per_page {
                        quota_consumed = quota_consumed.saturating_add(1);
                    }
                    if quota.rate_limit_on_request == Some(page) {
                        rate_limited = true;
                        retries = retries.saturating_add(1);
                        virtual_wait_ms = virtual_wait_ms.saturating_add(
                            quota
                                .retry_after_seconds
                                .saturating_add(quota.cooldown_seconds)
                                .saturating_mul(1_000),
                        );
                    }
                    if quota_consumed > quota.request_budget {
                        rate_limited = true;
                        match quota.exhausted_behaviour {
                            QuotaExhaustedBehaviour::EmptyResult => break,
                            QuotaExhaustedBehaviour::RateLimited => {
                                status = "rate_limited".to_owned();
                                failure = Some("request budget exhausted with 429".to_owned());
                            }
                            QuotaExhaustedBehaviour::Forbidden => {
                                status = "failed".to_owned();
                                failure = Some("request budget exhausted with 403".to_owned());
                            }
                        }
                        break;
                    }
                    if let Some(fault) = faults.iter().find(|fault| fault.trigger_page == page) {
                        let outcome = fault_outcome(fault.kind);
                        if let Some((fault_status, fault_message)) = outcome {
                            status = fault_status.to_owned();
                            failure = Some(fault_message.to_owned());
                            if fault.kind == PlanFaultKind::Status429 {
                                rate_limited = true;
                                retries = retries.saturating_add(1);
                                virtual_wait_ms = virtual_wait_ms.saturating_add(
                                    quota.retry_after_seconds.saturating_mul(1_000),
                                );
                                status = "succeeded".to_owned();
                                failure = None;
                                continue;
                            }
                            break;
                        }
                    }
                    if pagination.cursor_loop {
                        status = "failed".to_owned();
                        failure = Some("cursor loop detected by server-side judge".to_owned());
                        filtered = filtered.saturating_add(1);
                        break;
                    }
                    if pagination.invalid_page == Some(page) {
                        status = "failed".to_owned();
                        failure = Some("invalid pagination token returned".to_owned());
                        break;
                    }
                    if pagination.empty_final_page_with_next && page == pages {
                        status = "failed".to_owned();
                        failure = Some("empty final page advertised another page".to_owned());
                        break;
                    }
                }
                if status == "succeeded" {
                    let records = dataset_record_count(plan.dataset.size);
                    let duplicates =
                        records.saturating_mul(pagination.duplicate_ratio_percent as usize) / 100;
                    discovered = discovered.saturating_add(records.saturating_sub(duplicates));
                    if pagination.repeat_from_page.is_some() {
                        filtered = filtered.saturating_add(1);
                    }
                }
            }
        }
        if status != "succeeded" {
            failures.push(format!(
                "{}: {}",
                source.id,
                failure.as_deref().unwrap_or("source failed")
            ));
        }
        statuses.insert(source.id.clone(), status.clone());
        let expected_requests = (1..=request_count)
            .map(|request_number| {
                let page = (pagination.mode != PlanPaginationMode::None)
                    .then_some(request_number.min(pages));
                let rate_limited_request = quota.rate_limit_on_request == Some(request_number)
                    || (quota.consume_per_page && request_number > quota.request_budget);
                let triggered_fault = page.and_then(|page| {
                    faults
                        .iter()
                        .find(|fault| fault.trigger_page == page)
                        .map(|fault| fault.kind)
                });
                let response_status = match authentication.mode {
                    AuthenticationMode::MissingKey | AuthenticationMode::WrongKey => {
                        authentication.failure_status
                    }
                    _ if rate_limited_request => match quota.exhausted_behaviour {
                        QuotaExhaustedBehaviour::Forbidden => 403,
                        QuotaExhaustedBehaviour::EmptyResult => 200,
                        QuotaExhaustedBehaviour::RateLimited => 429,
                    },
                    _ => match triggered_fault {
                        Some(PlanFaultKind::Status401) => 401,
                        Some(PlanFaultKind::Status403) => 403,
                        Some(PlanFaultKind::Status404) => 404,
                        Some(PlanFaultKind::Status429) => 429,
                        Some(PlanFaultKind::Status500) => 500,
                        Some(PlanFaultKind::Status502) => 502,
                        Some(PlanFaultKind::Status503) => 503,
                        Some(PlanFaultKind::NoContent) => 204,
                        _ => 200,
                    },
                };
                PlanRequestAuditStep {
                    request_number,
                    page,
                    pagination_token: page.map(|page| pagination_token(pagination, page)),
                    response_status,
                    quota_consumed: quota.consume_per_page,
                    rate_limit_reason: rate_limited_request
                        .then_some("configured rate limit or exhausted request budget".to_owned()),
                    retry_after: (response_status == 429).then(|| retry_after_value(quota)),
                    virtual_wait_ms: if response_status == 429 {
                        quota
                            .retry_after_seconds
                            .saturating_add(quota.cooldown_seconds)
                            .saturating_mul(1_000)
                    } else {
                        0
                    },
                    authentication: authentication_outcome(authentication).to_owned(),
                    network_mode: plan.network_path.mode,
                    proxy_authentication: plan.network_path.proxy_authentication,
                    proxy_fault: plan.network_path.proxy_fault,
                    triggered_fault,
                }
            })
            .collect();
        audit.push(PlanRunAuditEntry {
            source_id: source.id.clone(),
            request_count,
            retry_count: retries,
            virtual_wait_ms,
            quota_consumed,
            rate_limited,
            status,
            failure,
            expected_requests,
            actual_requests: Vec::new(),
            authentication: authentication_outcome(authentication).to_owned(),
            rate_limit_reason: rate_limited
                .then_some("configured quota or 429 response".to_owned()),
            retry_after: rate_limited.then(|| retry_after_value(quota)),
            network_mode: plan.network_path.mode,
            proxy_authentication: plan.network_path.proxy_authentication,
            proxy_fault: plan.network_path.proxy_fault,
        });
    }
    let generated = plan
        .sources
        .iter()
        .filter(|source| source.enabled)
        .map(|source| generated_fqdn(plan, source, 1))
        .collect::<BTreeSet<_>>();
    let correct_findings = expected.intersection(&generated).count().min(discovered);
    let missed_findings = expected.len().saturating_sub(correct_findings);
    if missed_findings > 0 {
        failures.push(format!(
            "server-side judge found {missed_findings} missing expected FQDN(s)"
        ));
    }
    (
        audit,
        statuses,
        failures,
        correct_findings,
        missed_findings,
        filtered,
    )
}

fn fault_outcome(kind: PlanFaultKind) -> Option<(&'static str, &'static str)> {
    match kind {
        PlanFaultKind::Gzip | PlanFaultKind::Deflate | PlanFaultKind::Brotli => None,
        PlanFaultKind::Status429 => Some(("rate_limited", "simulated 429 rate limit")),
        PlanFaultKind::Status401 | PlanFaultKind::Status403 => {
            Some(("auth_failed", "simulated authentication failure"))
        }
        PlanFaultKind::Timeout | PlanFaultKind::SlowResponse => {
            Some(("timed_out", "simulated timeout"))
        }
        PlanFaultKind::Disconnect => Some(("failed", "simulated connection disconnect")),
        PlanFaultKind::EmptyResponse | PlanFaultKind::NoContent => None,
        PlanFaultKind::Status500
        | PlanFaultKind::Status502
        | PlanFaultKind::Status503
        | PlanFaultKind::Status404
        | PlanFaultKind::InvalidJson
        | PlanFaultKind::TruncatedJson
        | PlanFaultKind::HtmlInsteadOfJson
        | PlanFaultKind::WrongContentType
        | PlanFaultKind::WrongContentLength
        | PlanFaultKind::MalformedChunked
        | PlanFaultKind::CorruptCompression
        | PlanFaultKind::ResponseTooLarge => {
            Some(("failed", "simulated controlled response fault"))
        }
    }
}

fn generated_fqdn(plan: &ExperimentPlan, source: &PlanSource, index: usize) -> String {
    format!(
        "{}-{}-{}.{}",
        source.id, plan.seed, index, plan.target_domain
    )
}

/// Produces bounded deterministic records for the public loopback plan-source
/// contract. The full large fixture remains represented by its digest; a
/// single response is capped by the plan page size so the GUI never materializes
/// a 100k-record data set at once.
#[must_use]
pub fn plan_source_page_records(
    plan: &ExperimentPlan,
    source: &PlanSource,
    page: usize,
    page_size: usize,
) -> Vec<String> {
    let total = dataset_record_count(plan.dataset.size);
    let start = page.saturating_sub(1).saturating_mul(page_size);
    let end = start.saturating_add(page_size).min(total);
    (start..end)
        .map(|index| generated_fqdn(plan, source, index.saturating_add(1)))
        .collect()
}

#[must_use]
pub fn pagination_token(pagination: &PlanPagination, page: usize) -> String {
    match pagination.mode {
        PlanPaginationMode::None => "single".to_owned(),
        PlanPaginationMode::Page => page.to_string(),
        PlanPaginationMode::Offset => page
            .saturating_sub(1)
            .saturating_mul(pagination.page_size)
            .to_string(),
        PlanPaginationMode::Cursor => format!("cursor-{page}"),
        PlanPaginationMode::Link => format!("page-{page}"),
        PlanPaginationMode::PostBody => format!("body-{page}"),
    }
}

#[must_use]
pub fn retry_after_value(quota: &PlanQuota) -> String {
    match quota.retry_after_format {
        RetryAfterFormat::Seconds => quota.retry_after_seconds.to_string(),
        RetryAfterFormat::HttpDate => virtual_http_date_after(
            quota
                .retry_after_seconds
                .saturating_add(quota.cooldown_seconds)
                .saturating_mul(1_000),
        ),
    }
}

/// Formats an HTTP-date relative to the fixed virtual clock shared by local
/// plans and scenario clients. It never consults wall-clock time.
#[must_use]
pub fn virtual_http_date_after(wait_ms: u64) -> String {
    let base = Utc
        .with_ymd_and_hms(2026, 8, 17, 0, 0, 0)
        .single()
        .expect("fixed virtual clock timestamp is valid");
    let offset_seconds = i64::try_from(wait_ms.div_ceil(1_000)).unwrap_or(i64::MAX);
    (base + ChronoDuration::seconds(offset_seconds))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

#[must_use]
pub const fn authentication_outcome(authentication: &PlanAuthentication) -> &'static str {
    match authentication.mode {
        AuthenticationMode::None => "not_required",
        AuthenticationMode::FakeApiKey => "accepted_with_fake_key",
        AuthenticationMode::MissingKey => "missing_key_rejected",
        AuthenticationMode::WrongKey => "wrong_key_rejected",
    }
}

const fn dataset_record_count(size: DatasetSize) -> usize {
    match size {
        DatasetSize::Small => 24,
        DatasetSize::Medium => 3_000,
        DatasetSize::Large => 100_000,
    }
}

fn plan_file(root: &Path, plan_id: &str) -> Result<PathBuf> {
    if !safe_identifier(plan_id) {
        bail!("PLAN_ID_INVALID: unsafe plan id");
    }
    Ok(root.join(format!("{plan_id}.json")))
}

fn plan_run_file(root: &Path, run_id: &str) -> Result<PathBuf> {
    Uuid::parse_str(run_id).map_err(|_| anyhow!("PLAN_RUN_ID_INVALID: invalid run id"))?;
    Ok(root.join(format!("{run_id}.json")))
}

fn directory_file_bytes(root: &Path) -> Result<u64> {
    fs::read_dir(root)
        .with_context(|| format!("cannot read managed directory {}", root.display()))?
        .try_fold(0_u64, |total, entry| {
            let entry = entry?;
            let metadata = entry.metadata()?;
            Ok(if metadata.is_file() {
                total.saturating_add(metadata.len())
            } else {
                total
            })
        })
}

fn write_plan_file(root: &Path, plan: &ExperimentPlan) -> Result<()> {
    let target = plan_file(root, &plan.plan_id)?;
    let temporary = target.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(plan)?;
    if bytes.len() as u64 > MAX_PLAN_BYTES {
        bail!("PLAN_TOO_LARGE: plan exceeds the 1 MiB safety limit");
    }
    fs::write(&temporary, bytes)
        .with_context(|| format!("cannot write temporary plan {}", temporary.display()))?;
    fs::rename(&temporary, &target)
        .with_context(|| format!("cannot save plan {}", target.display()))?;
    Ok(())
}

fn format_plan_issues(issues: &[PlanValidationIssue]) -> String {
    issues
        .iter()
        .map(|issue| format!("{} {}: {}", issue.code, issue.field, issue.message))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_plan_store(label: &str) -> PlanStore {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-artifacts")
            .join(format!("lab-core-{label}-{}", Uuid::new_v4().simple()))
            .join("plans");
        PlanStore::open(root).expect("open isolated test plan store")
    }

    #[test]
    fn behavior_digest_ignores_presentation_and_timestamps() {
        let first = canonicalize_plan(ExperimentPlan::example(), false).expect("canonical plan");
        let mut second = first.clone();
        second.name = "different label".to_owned();
        second.description = "different note".to_owned();
        second.updated_at = Utc::now();
        assert_eq!(plan_digest(&first), plan_digest(&second));
    }

    #[test]
    fn behavior_digest_changes_for_each_major_behavioral_group_and_preserves_draft() {
        let baseline = canonicalize_plan(ExperimentPlan::example(), false).expect("canonical plan");
        let digest = plan_digest(&baseline);
        let mut draft = baseline.clone();
        draft.status = PlanStatus::Draft;
        assert_eq!(
            canonicalize_plan(draft, false).expect("valid draft").status,
            PlanStatus::Draft
        );
        let mut source = baseline.clone();
        source.sources[0].template = PlanSourceTemplate::Archive;
        assert_ne!(digest, plan_digest(&source));
        let mut authentication = baseline.clone();
        authentication.authentication.mode = AuthenticationMode::FakeApiKey;
        assert_ne!(digest, plan_digest(&authentication));
        let mut quota = baseline.clone();
        quota.quota.request_budget = 99;
        assert_ne!(digest, plan_digest(&quota));
        let mut pagination = baseline.clone();
        pagination.pagination.total_pages = 2;
        assert_ne!(digest, plan_digest(&pagination));
        let mut network = baseline.clone();
        network.network_path.mode = PlanNetworkMode::HttpProxy;
        assert_ne!(digest, plan_digest(&network));
        let mut faults = baseline.clone();
        faults.faults.push(PlanFault {
            kind: PlanFaultKind::Status503,
            trigger_page: 1,
            occurrences: 1,
        });
        assert_ne!(digest, plan_digest(&faults));
        let mut dataset = baseline.clone();
        dataset.dataset.size = DatasetSize::Large;
        assert_ne!(digest, plan_digest(&dataset));
        let mut expected = baseline.clone();
        expected
            .expected_behaviour
            .forbidden_fqdns
            .push("outside.acme.test".to_owned());
        assert_ne!(digest, plan_digest(&expected));
    }

    #[test]
    fn import_rejects_tampered_digest_and_external_address() {
        let mut plan = canonicalize_plan(ExperimentPlan::example(), false).expect("canonical plan");
        plan.plan_digest = "sha256:wrong".to_owned();
        assert_eq!(
            validate_plan(plan, true)
                .issues
                .first()
                .map(|issue| issue.code.as_str()),
            Some("PLAN_DIGEST_MISMATCH")
        );
        let mut unsafe_plan = ExperimentPlan::example();
        unsafe_plan.description = "https://public.example".to_owned();
        assert!(
            validate_plan(unsafe_plan, false)
                .issues
                .iter()
                .any(|issue| issue.code == "PLAN_UNSAFE_CONTENT")
        );
    }

    #[test]
    fn run_and_replay_are_deterministic_except_for_run_identity() {
        let plan = canonicalize_plan(ExperimentPlan::example(), false).expect("canonical plan");
        let first = execute_plan(plan.clone(), None);
        let replay = execute_plan(plan, Some(first.manifest.run_id.clone()));
        assert_eq!(first.report.fixture_digest, replay.report.fixture_digest);
        assert_eq!(first.report.truth_digest, replay.report.truth_digest);
        assert_eq!(
            first.report.expected_behaviour_digest,
            replay.report.expected_behaviour_digest
        );
        assert_eq!(first.report.source_statuses, replay.report.source_statuses);
        assert!(!first.report.egress_attempted);
    }

    #[test]
    fn http_date_retry_after_uses_the_fixed_virtual_clock() {
        assert_eq!(
            virtual_http_date_after(2_000),
            "Mon, 17 Aug 2026 00:00:02 GMT"
        );
        let mut plan = ExperimentPlan::example();
        plan.quota.retry_after_format = RetryAfterFormat::HttpDate;
        plan.quota.retry_after_seconds = 2;
        assert_eq!(
            retry_after_value(&plan.quota),
            "Mon, 17 Aug 2026 00:00:02 GMT"
        );
    }

    #[test]
    fn plan_store_preserves_runs_across_update_archive_and_delete() {
        let store = test_plan_store("lifecycle");
        let mut plan = ExperimentPlan::example();
        plan.plan_id = format!("plan-store-{}", Uuid::new_v4().simple());
        let created = store.create(plan).expect("create plan");
        let first_run =
            execute_plan_with_mode(created.clone(), None, PlanExecutionMode::LocalSimulation);
        store.save_run(&first_run).expect("persist run snapshot");

        let mut replacement = created.clone();
        replacement.name = "Updated lifecycle plan".to_owned();
        let updated = store
            .update(&created.plan_id, replacement)
            .expect("update plan");
        assert_eq!(updated.revision, created.revision + 1);
        assert_eq!(updated.plan_digest, created.plan_digest);

        let archived = store.archive(&created.plan_id).expect("archive plan");
        assert_eq!(archived.status, PlanStatus::Archived);
        assert_eq!(archived.revision, updated.revision + 1);
        let retained = store
            .load_run(&first_run.manifest.run_id)
            .expect("run snapshot survives archive");
        assert_eq!(retained.plan_snapshot.revision, created.revision);
        assert_eq!(
            retained.manifest.execution_mode,
            PlanExecutionMode::LocalSimulation
        );

        let stats = store.storage_stats().expect("storage statistics");
        assert_eq!(stats.plan_count, 1);
        assert_eq!(stats.run_count, 1);
        assert!(stats.total_bytes > 0);
        assert!(stats.plans_directory.contains("target"));

        store
            .delete(&created.plan_id)
            .expect("delete plan definition");
        assert!(store.list().is_empty());
        assert!(store.load_run(&first_run.manifest.run_id).is_ok());
        let error = store
            .delete(&created.plan_id)
            .expect_err("missing plan is stable");
        assert!(error.to_string().contains("PLAN_NOT_FOUND"));
    }

    #[test]
    fn plan_store_rejects_mismatched_filename_and_plan_id() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-artifacts")
            .join(format!("lab-core-corrupt-{}", Uuid::new_v4().simple()))
            .join("plans");
        fs::create_dir_all(&root).expect("create isolated corrupt plan root");
        let plan = canonicalize_plan(ExperimentPlan::example(), false).expect("canonical plan");
        fs::write(
            root.join("different-safe-id.json"),
            serde_json::to_vec_pretty(&plan).expect("serialize plan"),
        )
        .expect("write mismatched plan fixture");
        let error = PlanStore::open(root).expect_err("mismatched plan filename must fail");
        assert!(error.to_string().contains("PLAN_FILE_ID_MISMATCH"));
    }

    #[test]
    fn plan_store_loads_legacy_partial_source_contracts_without_masking_bad_json() {
        let store = test_plan_store("legacy-run");
        let run = execute_plan(ExperimentPlan::example(), None);
        store.save_run(&run).expect("persist current run snapshot");
        let run_path = plan_run_file(&store.runs_root, &run.manifest.run_id).expect("run path");
        let mut legacy: Value =
            serde_json::from_slice(&fs::read(&run_path).expect("read run snapshot"))
                .expect("current run JSON");
        let contract = legacy["manifest"]["source_contract"]
            .as_object_mut()
            .expect("source contract object");
        contract.remove("run_header_name");
        contract.remove("source_capability_header");
        contract.remove("fake_api_key_header");
        contract.remove("proxy_capability_header");
        contract.remove("runtime_capability_ttl_seconds");
        fs::write(
            &run_path,
            serde_json::to_vec_pretty(&legacy).expect("serialize legacy run"),
        )
        .expect("write legacy run snapshot");

        let loaded = store
            .load_run(&run.manifest.run_id)
            .expect("load legacy run");
        assert_eq!(
            loaded.manifest.source_contract,
            PlanSourceContract::default()
        );

        let corrupt_run_id = Uuid::new_v4().to_string();
        let corrupt_path = plan_run_file(&store.runs_root, &corrupt_run_id).expect("corrupt path");
        fs::write(corrupt_path, b"{").expect("write corrupt run snapshot");
        let error = store
            .load_run(&corrupt_run_id)
            .expect_err("malformed run JSON must stay an error");
        assert!(error.to_string().contains("PLAN_RUN_JSON_CORRUPT"));
    }
}
