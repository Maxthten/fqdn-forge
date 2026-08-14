//! Shared, data-driven contracts for the offline JNSEC laboratory.

mod domain;
mod egress;
mod judge;
mod model;
mod repository;
mod runner;
mod state;

pub use domain::{
    CandidateError, accept_candidate, domainish_tokens, host_from_url, normalize_domain,
};
pub use egress::{EgressGuard, EgressViolation};
pub use judge::{JudgeInput, judge_run};
pub use model::*;
pub use repository::{LoadedScenario, ScenarioRepository, ValidationIssue};
pub use runner::{ReferenceRunner, RunnerError};
pub use state::{LabState, RejectedRequestAudit, RunSession, RunSessionStatus, RunStateError};

pub fn report_json(report: &RunReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}
