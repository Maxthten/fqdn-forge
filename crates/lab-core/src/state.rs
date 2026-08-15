use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{AuditRecord, CollectorSubmission, LoadedScenario, RunReport, ScenarioRepository};

#[derive(Clone, Debug)]
pub struct LabState {
    repository: Arc<ScenarioRepository>,
    inner: Arc<Mutex<MutableLabState>>,
}

#[derive(Debug, Default)]
struct MutableLabState {
    runs: BTreeMap<String, RunSession>,
    unscoped_audit: Vec<RejectedRequestAudit>,
    developer_run_id: Option<String>,
    base_url: Option<String>,
    submitted_payloads: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunSession {
    pub run_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub status: RunSessionStatus,
    #[serde(skip_serializing)]
    pub response_counts: BTreeMap<String, usize>,
    #[serde(skip_serializing)]
    pub audit: Vec<AuditRecord>,
    #[serde(skip_serializing)]
    pub latest_report: Option<RunReport>,
    #[serde(skip_serializing)]
    pub submission: Option<CollectorSubmission>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunSessionStatus {
    Active,
    Submitted,
    Completed,
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

#[derive(Clone, Debug)]
pub struct ResponseMetrics {
    pub endpoint_id: String,
    pub response_index: usize,
    pub wire_bytes: usize,
    pub decoded_bytes: usize,
    pub content_encoding: Option<String>,
    pub compression_limit_violation: Option<String>,
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
        Self {
            repository: Arc::new(repository),
            inner: Arc::new(Mutex::new(MutableLabState::default())),
        }
    }

    #[must_use]
    pub fn repository(&self) -> &ScenarioRepository {
        &self.repository
    }

    pub fn set_base_url(&self, base_url: String) {
        self.inner.lock().expect("lab state lock poisoned").base_url = Some(base_url);
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
            scenario_id: scenario_id.to_owned(),
            seed: seed.unwrap_or(scenario.scenario.seed),
            created_at: now,
            last_activity_at: now,
            status: RunSessionStatus::Active,
            response_counts: BTreeMap::new(),
            audit: Vec::new(),
            latest_report: None,
            submission: None,
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
        Ok(loaded)
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
            .filter(|record| record.endpoint_id.as_deref() == Some(endpoint_id) && record.matched)
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
        record.content_encoding = metrics.content_encoding;
        record.compression_limit_violation = metrics.compression_limit_violation;
        Ok(())
    }

    pub fn audit(&self, run_id: &str) -> std::result::Result<Vec<AuditRecord>, RunStateError> {
        Ok(self.session(run_id)?.audit)
    }

    pub fn reset(&self, run_id: &str) -> std::result::Result<(), RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let digest = {
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
            run.latest_report = None;
            run.submission = None;
            run.last_activity_at = Utc::now();
            run.status = RunSessionStatus::Reset;
            digest
        };
        if let Some(digest) = digest {
            inner.submitted_payloads.remove(&digest);
        }
        Ok(())
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
                RunSessionStatus::Active | RunSessionStatus::Reset
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
        Ok(())
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
}

fn validate_run_id(run_id: &str) -> std::result::Result<(), RunStateError> {
    Uuid::parse_str(run_id)
        .map(|_| ())
        .map_err(|_| RunStateError::InvalidRunId)
}
