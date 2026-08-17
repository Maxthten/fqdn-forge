use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    AuditEventType, AuditRecord, CollectorSubmission, ExperimentPlan, FaultScriptStage,
    FaultScriptStep, LoadedScenario, PlanExecutionMode, PlanRequestAuditStep, PlanRun, PlanSource,
    PlanStore, QuotaProfile, QuotaScope, ResourceSummary, RunReport, ScenarioRepository,
    execute_plan_with_mode,
};

#[derive(Clone, Debug)]
pub struct LabState {
    repository: Arc<ScenarioRepository>,
    plan_store: PlanStore,
    inner: Arc<Mutex<MutableLabState>>,
}

#[derive(Debug, Default)]
struct MutableLabState {
    runs: BTreeMap<String, RunSession>,
    control_audit: BTreeMap<String, Vec<ControlAuditRecord>>,
    unscoped_audit: Vec<RejectedRequestAudit>,
    developer_run_id: Option<String>,
    base_url: Option<String>,
    proxy_url: Option<String>,
    submitted_payloads: BTreeMap<String, String>,
    deleted_runs: usize,
    deleted_run_history: Vec<DeletedRunSummary>,
    plan_runs: BTreeMap<String, PlanRun>,
    plan_runtimes: BTreeMap<String, PlanRunRuntime>,
}

const PLAN_RUNTIME_CAPABILITY_TTL_SECONDS: i64 = 300;
const MAX_PLAN_RUNTIME_AUDIT_REQUESTS: usize = 512;

/// Secrets are intentionally only held in memory for a current local plan
/// run. They are never part of `PlanRun`, exports, reports, or logs.
#[derive(Clone, Debug)]
struct PlanRunRuntime {
    source_capability: String,
    fake_api_key: Option<String>,
    expires_at: DateTime<Utc>,
    active: bool,
    request_counts: BTreeMap<String, usize>,
    fault_occurrences: BTreeMap<String, usize>,
}

#[derive(Clone, Debug)]
pub struct PlanRunAccess {
    pub run_id: String,
    pub source_capability: String,
    pub fake_api_key: Option<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct PlanSourceRequest {
    pub plan: ExperimentPlan,
    pub source: PlanSource,
    pub request_number: usize,
    pub fake_api_key: Option<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunSession {
    pub run_id: String,
    #[serde(skip_serializing)]
    pub access_token: String,
    pub scenario_id: String,
    pub seed: u64,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub status: RunSessionStatus,
    #[serde(skip_serializing)]
    pub response_counts: BTreeMap<String, usize>,
    #[serde(skip_serializing)]
    pub quota_counts: BTreeMap<String, usize>,
    #[serde(skip_serializing)]
    pub audit: Vec<AuditRecord>,
    #[serde(skip_serializing)]
    pub latest_report: Option<RunReport>,
    #[serde(skip_serializing)]
    pub submission: Option<CollectorSubmission>,
    #[serde(skip_serializing)]
    pub fault_script_cursor: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunSessionStatus {
    Active,
    Submitted,
    Completed,
    Cancelled,
    Reset,
    Expired,
}

#[derive(Clone, Debug, Serialize)]
pub struct RejectedRequestAudit {
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub reason: String,
}

/// A non-sensitive control-plane event, intentionally separate from the
/// immutable source audit consumed by the independent judge.
#[derive(Clone, Debug, Serialize)]
pub struct ControlAuditRecord {
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub operation: String,
    pub path: String,
    pub outcome: String,
}

/// A local-console tombstone. It retains no capability, report, submission,
/// source audit, or fixture data after a run is deleted.
#[derive(Clone, Debug, Serialize)]
pub struct DeletedRunSummary {
    pub run_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub created_at: DateTime<Utc>,
    pub deleted_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ResponseMetrics {
    pub endpoint_id: String,
    pub response_index: usize,
    pub wire_bytes: usize,
    pub decoded_bytes: usize,
    pub response_digest: Option<String>,
    pub content_encoding: Option<String>,
    pub compression_limit_violation: Option<String>,
    pub transfer_mode: Option<crate::TransferMode>,
    pub chunk_count: usize,
    pub transport_fault: Option<String>,
}

#[derive(Clone, Debug)]
pub enum FaultScriptClaim {
    Unscripted,
    Matched(FaultScriptStep),
    Unexpected(String),
}

#[derive(Clone, Debug)]
pub struct QuotaDecision {
    pub profile: QuotaProfile,
    pub remaining_before: usize,
    pub remaining_after: usize,
    pub consumed: bool,
    pub rate_limited: bool,
}

#[derive(Clone, Debug)]
pub enum RunStateError {
    InvalidRunId,
    UnknownRun,
    AlreadySubmitted,
    CrossRunSubmission,
    RunNotAcceptingSubmission,
    RunNotAcceptingSourceRequests,
}

impl RunStateError {
    #[must_use]
    pub const fn message(&self) -> &'static str {
        match self {
            Self::InvalidRunId => "invalid run id",
            Self::UnknownRun => "unknown run id",
            Self::AlreadySubmitted => "submission has already been accepted for this run",
            Self::CrossRunSubmission => "submission payload was already accepted by another run",
            Self::RunNotAcceptingSubmission => "run is not accepting a submission",
            Self::RunNotAcceptingSourceRequests => "run is not accepting source requests",
        }
    }
}

impl LabState {
    #[must_use]
    pub fn new(repository: ScenarioRepository) -> Self {
        let plan_root = repository
            .root()
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("artifacts")
            .join("plans");
        Self::new_with_plan_root(repository, plan_root)
    }

    #[must_use]
    pub fn new_with_plan_root(repository: ScenarioRepository, plan_root: impl AsRef<Path>) -> Self {
        let plan_root = plan_root.as_ref().to_path_buf();
        let plan_store = PlanStore::open(plan_root).expect("plan store must be available");
        Self {
            repository: Arc::new(repository),
            plan_store,
            inner: Arc::new(Mutex::new(MutableLabState::default())),
        }
    }

    #[must_use]
    pub fn repository(&self) -> &ScenarioRepository {
        &self.repository
    }

    #[must_use]
    pub fn plan_store(&self) -> &PlanStore {
        &self.plan_store
    }

    pub fn create_plan(&self, plan: ExperimentPlan) -> Result<ExperimentPlan> {
        self.plan_store.create(plan)
    }

    pub fn update_plan(&self, plan_id: &str, plan: ExperimentPlan) -> Result<ExperimentPlan> {
        self.plan_store.update(plan_id, plan)
    }

    pub fn archive_plan(&self, plan_id: &str) -> Result<ExperimentPlan> {
        self.plan_store.archive(plan_id)
    }

    pub fn import_plan(&self, plan: ExperimentPlan) -> Result<ExperimentPlan> {
        self.plan_store.import(plan)
    }

    pub fn delete_plan(&self, plan_id: &str) -> Result<()> {
        self.plan_store.delete(plan_id)?;
        self.invalidate_plan_runtimes(plan_id, "plan definition deleted")
    }

    pub fn run_plan(&self, plan_id: &str) -> Result<PlanRun> {
        self.run_plan_with_mode(plan_id, PlanExecutionMode::ExternalIntegration)
    }

    pub fn simulate_plan(&self, plan_id: &str) -> Result<PlanRun> {
        self.run_plan_with_mode(plan_id, PlanExecutionMode::LocalSimulation)
    }

    pub fn run_plan_with_mode(
        &self,
        plan_id: &str,
        execution_mode: PlanExecutionMode,
    ) -> Result<PlanRun> {
        let plan = self
            .plan_store
            .get(plan_id)
            .ok_or_else(|| anyhow!("PLAN_NOT_FOUND: plan {plan_id} does not exist"))?;
        if plan.status == crate::PlanStatus::Archived {
            bail!("PLAN_ARCHIVED: archived plans cannot be run");
        }
        if plan.status != crate::PlanStatus::Runnable {
            bail!("PLAN_NOT_RUNNABLE: only plans marked runnable can be run");
        }
        self.register_plan_run(execute_plan_with_mode(plan, None, execution_mode))
    }

    pub fn replay_plan_run(&self, run_id: &str) -> Result<PlanRun> {
        let prior = self
            .inner
            .lock()
            .expect("lab state lock poisoned")
            .plan_runs
            .get(run_id)
            .cloned()
            .or_else(|| self.plan_store.load_run(run_id).ok())
            .ok_or_else(|| anyhow!("PLAN_RUN_NOT_FOUND: run {run_id} does not exist"))?;
        self.register_plan_run(execute_plan_with_mode(
            prior.plan_snapshot,
            Some(run_id.to_owned()),
            prior.manifest.execution_mode,
        ))
    }

    #[must_use]
    pub fn list_plan_runs(&self) -> Vec<PlanRun> {
        let mut runs = self.plan_store.list_runs().unwrap_or_default();
        for run in self
            .inner
            .lock()
            .expect("lab state lock poisoned")
            .plan_runs
            .values()
            .cloned()
        {
            if !runs
                .iter()
                .any(|saved| saved.manifest.run_id == run.manifest.run_id)
            {
                runs.push(run);
            }
        }
        runs.sort_by_key(|run| run.manifest.created_at);
        runs
    }

    pub fn plan_run(&self, run_id: &str) -> Result<PlanRun> {
        self.inner
            .lock()
            .expect("lab state lock poisoned")
            .plan_runs
            .get(run_id)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| self.plan_store.load_run(run_id))
    }

    /// Returns the one short-lived secret bundle which is sent only in the
    /// create/replay response. Callers must keep it in memory and never export
    /// it. A cancelled, expired, deleted, or historical run has no bundle.
    pub fn plan_run_access(&self, run_id: &str) -> Result<PlanRunAccess> {
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let runtime = inner.plan_runtimes.get_mut(run_id).ok_or_else(|| {
            anyhow!("PLAN_SOURCE_CAPABILITY_UNAVAILABLE: no active local source capability")
        })?;
        if Utc::now() >= runtime.expires_at {
            runtime.active = false;
        }
        if !runtime.active {
            bail!(
                "PLAN_SOURCE_CAPABILITY_UNAVAILABLE: local source capability is expired or cancelled"
            );
        }
        Ok(PlanRunAccess {
            run_id: run_id.to_owned(),
            source_capability: runtime.source_capability.clone(),
            fake_api_key: runtime.fake_api_key.clone(),
            expires_at: runtime.expires_at,
        })
    }

    /// Authorizes one direct or proxied plan-source request and reserves its
    /// request sequence number. Authentication mode-specific validation is
    /// performed by the server after it receives this non-persistent context.
    pub fn authorize_plan_source(
        &self,
        run_id: &str,
        source_id: &str,
        source_capability: Option<&str>,
    ) -> Result<PlanSourceRequest> {
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        {
            let runtime = inner.plan_runtimes.get_mut(run_id).ok_or_else(|| {
                anyhow!("PLAN_SOURCE_CAPABILITY_UNAVAILABLE: no active local source capability")
            })?;
            if Utc::now() >= runtime.expires_at {
                runtime.active = false;
            }
            if !runtime.active {
                bail!(
                    "PLAN_SOURCE_CAPABILITY_UNAVAILABLE: local source capability is expired or cancelled"
                );
            }
            if source_capability != Some(runtime.source_capability.as_str()) {
                bail!(
                    "PLAN_SOURCE_CAPABILITY_INVALID: source capability is missing, stale, or invalid"
                );
            }
        }
        let run = inner
            .plan_runs
            .get(run_id)
            .cloned()
            .ok_or_else(|| anyhow!("PLAN_RUN_NOT_FOUND: plan run {run_id} does not exist"))?;
        let source = run
            .plan_snapshot
            .sources
            .iter()
            .find(|source| source.id == source_id && source.enabled)
            .cloned()
            .ok_or_else(|| {
                anyhow!("PLAN_SOURCE_NOT_FOUND: enabled source {source_id} does not exist")
            })?;
        let runtime = inner
            .plan_runtimes
            .get_mut(run_id)
            .expect("validated plan runtime must remain present");
        let request_number = runtime
            .request_counts
            .entry(source_id.to_owned())
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        Ok(PlanSourceRequest {
            plan: run.plan_snapshot,
            source,
            request_number: *request_number,
            fake_api_key: runtime.fake_api_key.clone(),
            expires_at: runtime.expires_at,
        })
    }

    pub fn record_plan_source_request(
        &self,
        run_id: &str,
        source_id: &str,
        step: PlanRequestAuditStep,
    ) -> Result<()> {
        let updated = {
            let mut inner = self.inner.lock().expect("lab state lock poisoned");
            let run = inner
                .plan_runs
                .get_mut(run_id)
                .ok_or_else(|| anyhow!("PLAN_RUN_NOT_FOUND: plan run {run_id} does not exist"))?;
            let entry = run
                .audit
                .iter_mut()
                .find(|entry| entry.source_id == source_id)
                .ok_or_else(|| {
                    anyhow!("PLAN_SOURCE_NOT_FOUND: source {source_id} does not exist")
                })?;
            if entry.actual_requests.len() < MAX_PLAN_RUNTIME_AUDIT_REQUESTS {
                entry.actual_requests.push(step);
            }
            run.report.actual_requests = run.report.actual_requests.saturating_add(1);
            run.report.source_access_status = "active".to_owned();
            run.clone()
        };
        self.plan_store.save_run(&updated)
    }

    /// Consumes one deterministic occurrence of a configured source fault.
    /// This state is strictly runtime-only so a retry can observe a one-shot
    /// failure without making the plan snapshot or manifest stateful.
    pub fn consume_plan_fault(
        &self,
        run_id: &str,
        source_id: &str,
        fault: &crate::PlanFault,
    ) -> Result<bool> {
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let runtime = inner.plan_runtimes.get_mut(run_id).ok_or_else(|| {
            anyhow!("PLAN_SOURCE_CAPABILITY_UNAVAILABLE: no active local source capability")
        })?;
        if Utc::now() >= runtime.expires_at {
            runtime.active = false;
        }
        if !runtime.active {
            bail!(
                "PLAN_SOURCE_CAPABILITY_UNAVAILABLE: local source capability is expired or cancelled"
            );
        }
        let key = format!("{source_id}:{}:{:?}", fault.trigger_page, fault.kind);
        let consumed = runtime.fault_occurrences.entry(key).or_default();
        if *consumed >= fault.occurrences {
            return Ok(false);
        }
        *consumed = consumed.saturating_add(1);
        Ok(true)
    }

    pub fn cancel_plan_run(&self, run_id: &str) -> Result<PlanRun> {
        let updated = {
            let mut inner = self.inner.lock().expect("lab state lock poisoned");
            let runtime = inner.plan_runtimes.get_mut(run_id).ok_or_else(|| {
                anyhow!("PLAN_SOURCE_CAPABILITY_UNAVAILABLE: no active local source capability")
            })?;
            runtime.active = false;
            let run = inner
                .plan_runs
                .get_mut(run_id)
                .ok_or_else(|| anyhow!("PLAN_RUN_NOT_FOUND: plan run {run_id} does not exist"))?;
            run.report.source_access_status = "cancelled".to_owned();
            run.report.source_access_expires_at = None;
            if !run
                .report
                .failures
                .iter()
                .any(|failure| failure == "local source capability cancelled")
            {
                run.report
                    .failures
                    .push("local source capability cancelled".to_owned());
            }
            run.clone()
        };
        self.plan_store.save_run(&updated)?;
        Ok(updated)
    }

    fn register_plan_run(&self, run: PlanRun) -> Result<PlanRun> {
        let expires_at = Utc::now() + ChronoDuration::seconds(PLAN_RUNTIME_CAPABILITY_TTL_SECONDS);
        let needs_fake_key = run.plan_snapshot.sources.iter().any(|source| {
            source
                .authentication
                .as_ref()
                .unwrap_or(&run.plan_snapshot.authentication)
                .mode
                == crate::AuthenticationMode::FakeApiKey
        });
        let runtime = PlanRunRuntime {
            source_capability: format!("plan-src-{}", Uuid::new_v4()),
            fake_api_key: needs_fake_key.then(|| format!("fake-plan-{}", Uuid::new_v4().simple())),
            expires_at,
            active: true,
            request_counts: BTreeMap::new(),
            fault_occurrences: BTreeMap::new(),
        };
        self.plan_store.save_run(&run)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        inner
            .plan_runtimes
            .insert(run.manifest.run_id.clone(), runtime);
        inner
            .plan_runs
            .insert(run.manifest.run_id.clone(), run.clone());
        Ok(run)
    }

    fn invalidate_plan_runtimes(&self, plan_id: &str, reason: &str) -> Result<()> {
        let updated = {
            let mut inner = self.inner.lock().expect("lab state lock poisoned");
            let mut updated = Vec::new();
            let run_ids = inner
                .plan_runs
                .iter()
                .filter(|(run_id, run)| {
                    run.manifest.plan_id == plan_id
                        && inner
                            .plan_runtimes
                            .get(*run_id)
                            .is_some_and(|runtime| runtime.active)
                })
                .map(|(run_id, _)| run_id.clone())
                .collect::<Vec<_>>();
            for run_id in run_ids {
                if let Some(runtime) = inner.plan_runtimes.get_mut(&run_id) {
                    runtime.active = false;
                }
                if let Some(run) = inner.plan_runs.get_mut(&run_id) {
                    run.report.source_access_status = "invalidated".to_owned();
                    run.report.source_access_expires_at = None;
                    run.report.failures.push(reason.to_owned());
                    updated.push(run.clone());
                }
            }
            updated
        };
        for run in updated {
            self.plan_store.save_run(&run)?;
        }
        Ok(())
    }

    pub fn set_base_url(&self, base_url: String) {
        self.inner.lock().expect("lab state lock poisoned").base_url = Some(base_url);
    }

    pub fn set_proxy_url(&self, proxy_url: String) {
        self.inner
            .lock()
            .expect("lab state lock poisoned")
            .proxy_url = Some(proxy_url);
    }

    #[must_use]
    pub fn proxy_url(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("lab state lock poisoned")
            .proxy_url
            .clone()
    }

    #[must_use]
    pub fn base_url(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("lab state lock poisoned")
            .base_url
            .clone()
    }

    pub fn create_run(&self, scenario_id: &str) -> Result<RunSession> {
        self.create_run_with_seed(scenario_id, None)
    }

    pub fn create_run_with_seed(&self, scenario_id: &str, seed: Option<u64>) -> Result<RunSession> {
        let scenario = self
            .repository
            .get(scenario_id)
            .ok_or_else(|| anyhow!("unknown scenario {scenario_id}"))?;
        let now = Utc::now();
        let run = RunSession {
            run_id: Uuid::new_v4().to_string(),
            access_token: Uuid::new_v4().to_string(),
            scenario_id: scenario_id.to_owned(),
            seed: seed.unwrap_or(scenario.scenario.seed),
            created_at: now,
            last_activity_at: now,
            status: RunSessionStatus::Active,
            response_counts: BTreeMap::new(),
            quota_counts: BTreeMap::new(),
            audit: Vec::new(),
            latest_report: None,
            submission: None,
            fault_script_cursor: 0,
        };
        self.inner
            .lock()
            .expect("lab state lock poisoned")
            .runs
            .insert(run.run_id.clone(), run.clone());
        Ok(run)
    }

    /// Creates the one explicitly named legacy developer session. Source requests
    /// still require `x-lab-run-id`; this only backs deprecated control routes.
    pub fn activate(&self, scenario_id: &str) -> Result<RunSession> {
        let run = self.create_run(scenario_id)?;
        self.inner
            .lock()
            .expect("lab state lock poisoned")
            .developer_run_id = Some(run.run_id.clone());
        Ok(run)
    }

    #[must_use]
    pub fn list_runs(&self) -> Vec<RunSession> {
        self.inner
            .lock()
            .expect("lab state lock poisoned")
            .runs
            .values()
            .filter(|run| run.status != RunSessionStatus::Expired)
            .cloned()
            .collect()
    }

    pub fn session(&self, run_id: &str) -> std::result::Result<RunSession, RunStateError> {
        validate_run_id(run_id)?;
        self.inner
            .lock()
            .expect("lab state lock poisoned")
            .runs
            .get(run_id)
            .cloned()
            .ok_or(RunStateError::UnknownRun)
    }

    pub fn loaded_for_run(
        &self,
        run_id: &str,
    ) -> std::result::Result<LoadedScenario, RunStateError> {
        let run = self.session(run_id)?;
        let mut loaded = self
            .repository
            .get(&run.scenario_id)
            .cloned()
            .ok_or(RunStateError::UnknownRun)?;
        loaded.scenario.seed = run.seed;
        loaded.scenario.root_domain = loaded
            .scenario
            .root_domain
            .replace("$SEED", &run.seed.to_string());
        Ok(crate::campaign_loaded_scenario(&loaded, run.seed))
    }

    pub fn claim_response_index(
        &self,
        run_id: &str,
        endpoint_id: &str,
        reply_count: usize,
    ) -> std::result::Result<Option<usize>, RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let run = inner
            .runs
            .get_mut(run_id)
            .ok_or(RunStateError::UnknownRun)?;
        if !matches!(
            run.status,
            RunSessionStatus::Active | RunSessionStatus::Reset
        ) {
            return Err(RunStateError::RunNotAcceptingSourceRequests);
        }
        let count = run
            .response_counts
            .entry(endpoint_id.to_owned())
            .or_default();
        if *count >= reply_count {
            return Ok(None);
        }
        let index = *count;
        *count += 1;
        run.last_activity_at = Utc::now();
        run.status = RunSessionStatus::Active;
        Ok(Some(index))
    }

    /// Claims exactly the next declarative fault-script step for this run.
    /// A mismatch never advances the cursor or the endpoint reply sequence.
    pub fn claim_fault_script_step(
        &self,
        run_id: &str,
        script: &[FaultScriptStep],
        stage: FaultScriptStage,
        endpoint_id: &str,
        query: &BTreeMap<String, String>,
        client_virtual_wait_ms: u64,
    ) -> std::result::Result<FaultScriptClaim, RunStateError> {
        if script.is_empty() {
            return Ok(FaultScriptClaim::Unscripted);
        }
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let run = inner
            .runs
            .get_mut(run_id)
            .ok_or(RunStateError::UnknownRun)?;
        if !matches!(
            run.status,
            RunSessionStatus::Active | RunSessionStatus::Reset
        ) {
            return Err(RunStateError::RunNotAcceptingSourceRequests);
        }
        let Some(step) = script.get(run.fault_script_cursor).cloned() else {
            return Ok(FaultScriptClaim::Unexpected(
                "fault script exhausted".to_owned(),
            ));
        };
        if step.stage != stage {
            // A proxy step is consumed at the proxy boundary and its paired
            // source step is consumed only after forwarding.  Seeing the
            // other boundary while that transition is in progress is normal.
            return Ok(FaultScriptClaim::Unscripted);
        }
        if step.endpoint != endpoint_id {
            return Ok(FaultScriptClaim::Unexpected(format!(
                "expected endpoint {} for step {}",
                step.endpoint, step.id
            )));
        }
        if step
            .query
            .iter()
            .any(|(key, value)| query.get(key) != Some(value))
        {
            return Ok(FaultScriptClaim::Unexpected(format!(
                "request query does not match step {}",
                step.id
            )));
        }
        if client_virtual_wait_ms < step.minimum_virtual_wait_ms {
            return Ok(FaultScriptClaim::Unexpected(format!(
                "step {} requires at least {}ms virtual wait",
                step.id, step.minimum_virtual_wait_ms
            )));
        }
        run.fault_script_cursor += 1;
        run.last_activity_at = Utc::now();
        Ok(FaultScriptClaim::Matched(step))
    }

    pub fn matched_request_count(
        &self,
        run_id: &str,
        endpoint_id: &str,
    ) -> std::result::Result<usize, RunStateError> {
        validate_run_id(run_id)?;
        let inner = self.inner.lock().expect("lab state lock poisoned");
        let run = inner.runs.get(run_id).ok_or(RunStateError::UnknownRun)?;
        Ok(run
            .audit
            .iter()
            .filter(|record| {
                record.endpoint_id.as_deref() == Some(endpoint_id)
                    && record.matched
                    && record.event_type == crate::AuditEventType::SourceRequest
                    && record.response_index.is_some()
            })
            .count())
    }

    pub fn record_request(
        &self,
        run_id: &str,
        mut audit: AuditRecord,
    ) -> std::result::Result<(), RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let run = inner
            .runs
            .get_mut(run_id)
            .ok_or(RunStateError::UnknownRun)?;
        if run.submission.is_some()
            || !matches!(
                run.status,
                RunSessionStatus::Active | RunSessionStatus::Reset
            )
        {
            return Err(RunStateError::RunNotAcceptingSourceRequests);
        }
        audit.sequence = run.audit.len() + 1;
        audit.before_submission = true;
        run.audit.push(audit);
        run.last_activity_at = Utc::now();
        Ok(())
    }

    pub fn set_response_metrics(
        &self,
        run_id: &str,
        metrics: ResponseMetrics,
    ) -> std::result::Result<(), RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let run = inner
            .runs
            .get_mut(run_id)
            .ok_or(RunStateError::UnknownRun)?;
        let Some(record) = run.audit.iter_mut().rev().find(|record| {
            record.endpoint_id.as_deref() == Some(&metrics.endpoint_id)
                && record.response_index == Some(metrics.response_index)
        }) else {
            return Ok(());
        };
        record.wire_bytes = metrics.wire_bytes;
        record.decoded_bytes = metrics.decoded_bytes;
        record.response_digest = metrics.response_digest;
        record.content_encoding = metrics.content_encoding;
        record.compression_limit_violation = metrics.compression_limit_violation;
        record.transfer_mode = metrics.transfer_mode;
        record.chunk_count = metrics.chunk_count;
        record.transport_fault = metrics.transport_fault;
        Ok(())
    }

    /// Atomically evaluates all quota scopes configured for one source request.
    /// A denied scope leaves every counter unchanged, so a rejected proxy or a
    /// later quota scope can never accidentally consume an earlier budget.
    pub fn evaluate_quota(
        &self,
        run_id: &str,
        endpoint_id: &str,
        profiles: &[QuotaProfile],
        credential_identity: &str,
        client_virtual_wait_ms: u64,
    ) -> std::result::Result<Vec<QuotaDecision>, RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let run = inner
            .runs
            .get_mut(run_id)
            .ok_or(RunStateError::UnknownRun)?;
        if !matches!(
            run.status,
            RunSessionStatus::Active | RunSessionStatus::Reset
        ) {
            return Err(RunStateError::RunNotAcceptingSourceRequests);
        }
        let mut decisions = Vec::with_capacity(profiles.len());
        let mut permitted = true;
        for profile in profiles {
            let key = quota_key(profile.scope, endpoint_id, credential_identity);
            let mut used = run.quota_counts.get(&key).copied().unwrap_or_default();
            let recovered = used >= profile.success_limit
                && profile
                    .recover_after_virtual_ms
                    .is_some_and(|minimum| client_virtual_wait_ms >= minimum);
            if recovered {
                used = 0;
            }
            let remaining_before = profile.success_limit.saturating_sub(used);
            let rate_limited = used >= profile.success_limit && !recovered;
            permitted &= !rate_limited;
            decisions.push(QuotaDecision {
                profile: profile.clone(),
                remaining_before,
                remaining_after: remaining_before.saturating_sub(usize::from(!rate_limited)),
                consumed: !rate_limited,
                rate_limited,
            });
        }
        if permitted {
            for (profile, decision) in profiles.iter().zip(&decisions) {
                let key = quota_key(profile.scope, endpoint_id, credential_identity);
                let before = profile
                    .success_limit
                    .saturating_sub(decision.remaining_before);
                run.quota_counts.insert(key, before.saturating_add(1));
            }
        } else {
            for decision in &mut decisions {
                decision.consumed = false;
                decision.remaining_after = decision.remaining_before;
            }
        }
        Ok(decisions)
    }

    pub fn audit(&self, run_id: &str) -> std::result::Result<Vec<AuditRecord>, RunStateError> {
        Ok(self.session(run_id)?.audit)
    }

    /// Records a safe control action without changing the source/proxy audit
    /// that determines the judge's report.
    pub fn record_control_audit(
        &self,
        run_id: &str,
        method: &str,
        operation: &str,
        path: &str,
        outcome: &str,
    ) -> std::result::Result<(), RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        if !inner.runs.contains_key(run_id) {
            return Err(RunStateError::UnknownRun);
        }
        inner
            .control_audit
            .entry(run_id.to_owned())
            .or_default()
            .push(ControlAuditRecord {
                timestamp: Utc::now(),
                method: method.to_owned(),
                operation: operation.to_owned(),
                path: path.to_owned(),
                outcome: outcome.to_owned(),
            });
        Ok(())
    }

    pub fn control_audit(
        &self,
        run_id: &str,
    ) -> std::result::Result<Vec<ControlAuditRecord>, RunStateError> {
        validate_run_id(run_id)?;
        let inner = self.inner.lock().expect("lab state lock poisoned");
        if !inner.runs.contains_key(run_id) {
            return Err(RunStateError::UnknownRun);
        }
        Ok(inner.control_audit.get(run_id).cloned().unwrap_or_default())
    }

    pub fn reset(&self, run_id: &str) -> std::result::Result<(), RunStateError> {
        self.reset_and_rotate(run_id).map(|_| ())
    }

    /// Stops future source/proxy work for a run while retaining the immutable
    /// audit so the external client can submit a terminal cancelled status.
    pub fn cancel(
        &self,
        run_id: &str,
        virtual_wait_ms: u64,
    ) -> std::result::Result<(), RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let run = inner
            .runs
            .get_mut(run_id)
            .ok_or(RunStateError::UnknownRun)?;
        if !matches!(
            run.status,
            RunSessionStatus::Active | RunSessionStatus::Reset
        ) {
            return Err(RunStateError::RunNotAcceptingSourceRequests);
        }
        run.audit.push(AuditRecord {
            sequence: run.audit.len() + 1,
            run_id: Some(run.run_id.clone()),
            scenario_id: run.scenario_id.clone(),
            timestamp: Utc::now(),
            method: "CANCEL".to_owned(),
            path: "<lifecycle:cancel>".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            redacted_headers: BTreeMap::new(),
            body: None,
            body_summary: None,
            endpoint_id: None,
            response_index: None,
            script_step_id: None,
            response_sequence: None,
            response_status: 200,
            before_submission: true,
            virtual_wait_ms,
            retry_after: None,
            consumed: false,
            blocked: false,
            external_target_rejected: false,
            matched: true,
            extra: false,
            mismatch_reasons: Vec::new(),
            wire_bytes: 0,
            response_digest: None,
            decoded_bytes: 0,
            content_encoding: None,
            compression_limit_violation: None,
            event_type: AuditEventType::Lifecycle,
            proxy_mode: None,
            proxy_target: None,
            proxy_authentication: crate::ProxyAuthenticationState::NotApplicable,
            proxy_reason: Some("cancelled".to_owned()),
            correlation_id: None,
            quota_scope: None,
            quota_remaining_before: None,
            quota_remaining_after: None,
            quota_consumed: false,
            quota_rate_limited: false,
            quota_recovery_virtual_wait_ms: None,
            transfer_mode: None,
            chunk_count: 0,
            transport_fault: None,
        });
        run.status = RunSessionStatus::Cancelled;
        run.last_activity_at = Utc::now();
        Ok(())
    }

    /// A reset creates a fresh capability epoch.  Callers that need to continue
    /// through the public control API can use the returned token; stale run and
    /// proxy capabilities are deliberately no longer accepted.
    pub fn reset_and_rotate(&self, run_id: &str) -> std::result::Result<RunSession, RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let (digest, updated) = {
            let run = inner
                .runs
                .get_mut(run_id)
                .ok_or(RunStateError::UnknownRun)?;
            let digest = run
                .submission
                .as_ref()
                .and_then(|submission| serde_json::to_string(submission).ok());
            run.audit.clear();
            run.response_counts.clear();
            run.quota_counts.clear();
            run.latest_report = None;
            run.submission = None;
            run.fault_script_cursor = 0;
            run.access_token = Uuid::new_v4().to_string();
            run.last_activity_at = Utc::now();
            run.status = RunSessionStatus::Reset;
            (digest, run.clone())
        };
        if let Some(digest) = digest {
            inner.submitted_payloads.remove(&digest);
        }
        Ok(updated)
    }

    pub fn set_report(
        &self,
        run_id: &str,
        report: RunReport,
    ) -> std::result::Result<(), RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let run = inner
            .runs
            .get_mut(run_id)
            .ok_or(RunStateError::UnknownRun)?;
        run.latest_report = Some(report);
        run.last_activity_at = Utc::now();
        run.status = RunSessionStatus::Completed;
        Ok(())
    }

    /// Atomically freezes the first valid collector payload for a run. The
    /// server judges this immutable payload immediately afterwards; a caller
    /// can never replace it with a different report or submission.
    pub fn freeze_submission(
        &self,
        run_id: &str,
        submission: CollectorSubmission,
    ) -> std::result::Result<(), RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let digest = serde_json::to_string(&submission)
            .map_err(|_| RunStateError::RunNotAcceptingSubmission)?;
        if !inner.runs.contains_key(run_id) {
            return Err(RunStateError::UnknownRun);
        }
        if inner
            .submitted_payloads
            .get(&digest)
            .is_some_and(|owner| owner != run_id)
        {
            return Err(RunStateError::CrossRunSubmission);
        }
        {
            let run = inner
                .runs
                .get_mut(run_id)
                .ok_or(RunStateError::UnknownRun)?;
            if run.submission.is_some() {
                return Err(RunStateError::AlreadySubmitted);
            }
            if !matches!(
                run.status,
                RunSessionStatus::Active | RunSessionStatus::Reset | RunSessionStatus::Cancelled
            ) {
                return Err(RunStateError::RunNotAcceptingSubmission);
            }
            run.submission = Some(submission);
            run.status = RunSessionStatus::Submitted;
            run.last_activity_at = Utc::now();
        }
        inner.submitted_payloads.insert(digest, run_id.to_owned());
        Ok(())
    }

    pub fn submission(
        &self,
        run_id: &str,
    ) -> std::result::Result<Option<CollectorSubmission>, RunStateError> {
        Ok(self.session(run_id)?.submission)
    }

    pub fn latest_report(
        &self,
        run_id: &str,
    ) -> std::result::Result<Option<RunReport>, RunStateError> {
        Ok(self.session(run_id)?.latest_report)
    }

    pub fn delete(&self, run_id: &str) -> std::result::Result<(), RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let run = inner.runs.remove(run_id).ok_or(RunStateError::UnknownRun)?;
        inner.control_audit.remove(run_id);
        if let Some(digest) = run
            .submission
            .as_ref()
            .and_then(|submission| serde_json::to_string(submission).ok())
            && inner.submitted_payloads.get(&digest) == Some(&run.run_id)
        {
            inner.submitted_payloads.remove(&digest);
        }
        if inner.developer_run_id.as_deref() == Some(run_id) {
            inner.developer_run_id = None;
        }
        inner.deleted_runs += 1;
        inner.deleted_run_history.push(DeletedRunSummary {
            run_id: run.run_id,
            scenario_id: run.scenario_id,
            seed: run.seed,
            created_at: run.created_at,
            deleted_at: Utc::now(),
        });
        Ok(())
    }

    #[must_use]
    pub fn deleted_run_history(&self) -> Vec<DeletedRunSummary> {
        self.inner
            .lock()
            .expect("lab state lock poisoned")
            .deleted_run_history
            .clone()
    }

    #[must_use]
    pub fn developer_run(&self) -> Option<RunSession> {
        let inner = self.inner.lock().expect("lab state lock poisoned");
        inner
            .developer_run_id
            .as_ref()
            .and_then(|run_id| inner.runs.get(run_id))
            .cloned()
    }

    pub fn record_unscoped_request(&self, method: &str, path: &str, reason: &str) {
        self.inner
            .lock()
            .expect("lab state lock poisoned")
            .unscoped_audit
            .push(RejectedRequestAudit {
                timestamp: Utc::now(),
                method: method.to_owned(),
                path: path.to_owned(),
                reason: reason.to_owned(),
            });
    }

    #[must_use]
    pub fn unscoped_audit(&self) -> Vec<RejectedRequestAudit> {
        self.inner
            .lock()
            .expect("lab state lock poisoned")
            .unscoped_audit
            .clone()
    }

    #[must_use]
    pub fn resource_summary(&self) -> ResourceSummary {
        let inner = self.inner.lock().expect("lab state lock poisoned");
        let active_runs = inner
            .runs
            .values()
            .filter(|run| {
                matches!(
                    run.status,
                    RunSessionStatus::Active
                        | RunSessionStatus::Submitted
                        | RunSessionStatus::Completed
                )
            })
            .count();
        ResourceSummary {
            active_runs,
            reset_runs: inner
                .runs
                .values()
                .filter(|run| run.status == RunSessionStatus::Reset)
                .count(),
            deleted_runs: inner.deleted_runs,
            active_proxy_connections: 0,
            audit_records: inner.runs.values().map(|run| run.audit.len()).sum(),
            quota_state_entries: inner.runs.values().map(|run| run.quota_counts.len()).sum(),
            report_count: inner
                .runs
                .values()
                .filter(|run| run.latest_report.is_some())
                .count(),
            fixture_bytes: 0,
            rejection_count: inner.unscoped_audit.len(),
        }
    }
}

fn validate_run_id(run_id: &str) -> std::result::Result<(), RunStateError> {
    Uuid::parse_str(run_id)
        .map(|_| ())
        .map_err(|_| RunStateError::InvalidRunId)
}

fn quota_key(scope: QuotaScope, endpoint_id: &str, credential_identity: &str) -> String {
    match scope {
        QuotaScope::PerSource => format!("source:{endpoint_id}"),
        QuotaScope::PerKey => format!("key:{endpoint_id}:{credential_identity}"),
        QuotaScope::GlobalRun => "global".to_owned(),
    }
}
