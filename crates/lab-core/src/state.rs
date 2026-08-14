use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{AuditRecord, LoadedScenario, RunReport, ScenarioRepository};

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
}

#[derive(Clone, Debug, Serialize)]
pub struct RunSession {
    pub run_id: String,
    pub scenario_id: String,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub status: RunSessionStatus,
    #[serde(skip_serializing)]
    pub response_counts: BTreeMap<String, usize>,
    #[serde(skip_serializing)]
    pub audit: Vec<AuditRecord>,
    #[serde(skip_serializing)]
    pub latest_report: Option<RunReport>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunSessionStatus {
    Active,
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
pub enum RunStateError {
    InvalidRunId,
    UnknownRun,
}

impl RunStateError {
    #[must_use]
    pub const fn message(&self) -> &'static str {
        match self {
            Self::InvalidRunId => "invalid run id",
            Self::UnknownRun => "unknown run id",
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

    pub fn create_run(&self, scenario_id: &str) -> Result<RunSession> {
        if self.repository.get(scenario_id).is_none() {
            return Err(anyhow!("unknown scenario {scenario_id}"));
        }
        let now = Utc::now();
        let run = RunSession {
            run_id: Uuid::new_v4().to_string(),
            scenario_id: scenario_id.to_owned(),
            created_at: now,
            last_activity_at: now,
            status: RunSessionStatus::Active,
            response_counts: BTreeMap::new(),
            audit: Vec::new(),
            latest_report: None,
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
        self.repository
            .get(&run.scenario_id)
            .cloned()
            .ok_or(RunStateError::UnknownRun)
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
        audit: AuditRecord,
    ) -> std::result::Result<(), RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let run = inner
            .runs
            .get_mut(run_id)
            .ok_or(RunStateError::UnknownRun)?;
        run.audit.push(audit);
        run.last_activity_at = Utc::now();
        Ok(())
    }

    pub fn audit(&self, run_id: &str) -> std::result::Result<Vec<AuditRecord>, RunStateError> {
        Ok(self.session(run_id)?.audit)
    }

    pub fn reset(&self, run_id: &str) -> std::result::Result<(), RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        let run = inner
            .runs
            .get_mut(run_id)
            .ok_or(RunStateError::UnknownRun)?;
        run.audit.clear();
        run.response_counts.clear();
        run.latest_report = None;
        run.last_activity_at = Utc::now();
        run.status = RunSessionStatus::Reset;
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

    pub fn latest_report(
        &self,
        run_id: &str,
    ) -> std::result::Result<Option<RunReport>, RunStateError> {
        Ok(self.session(run_id)?.latest_report)
    }

    pub fn delete(&self, run_id: &str) -> std::result::Result<(), RunStateError> {
        validate_run_id(run_id)?;
        let mut inner = self.inner.lock().expect("lab state lock poisoned");
        if inner.runs.remove(run_id).is_none() {
            return Err(RunStateError::UnknownRun);
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
