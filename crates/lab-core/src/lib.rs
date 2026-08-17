//! Shared, data-driven contracts for the offline JNSEC laboratory.

mod analysis;
mod domain;
mod egress;
mod judge;
mod model;
mod plan;
mod repository;
mod runner;
mod state;
mod v14;

pub use analysis::{
    ANALYSIS_SCHEMA_VERSION, AnalysisError, AnalysisIndex, AnalysisRequest, AnalysisView,
    analysis_artifacts_root, analysis_markdown, analysis_value, parse_analysis_request,
    redact_analysis_value,
};
pub use domain::{
    CandidateError, accept_candidate, domainish_tokens, host_from_url, normalize_domain,
};
pub use egress::{EgressGuard, EgressViolation};
pub use judge::{
    JudgeInput, compression_from_audit, findings_from_collector, judge_run,
    refresh_semantic_fingerprint, semantic_difference, semantic_fingerprint, semantic_projection,
};
pub use model::*;
pub use plan::*;
pub use repository::{LoadedScenario, ScenarioRepository, ValidationIssue};
pub use runner::{ReferenceRunner, RunnerError};
pub use state::{
    ControlAuditRecord, DeletedRunSummary, FaultScriptClaim, LabState, QuotaDecision,
    RejectedRequestAudit, ResponseMetrics, RunSession, RunSessionStatus, RunStateError,
};
pub use v14::{
    Baseline, BaselineComparison, CampaignDefinition, CampaignManifest, CampaignReport,
    CoverageException, CoverageReport, DifferenceSummary, SoakAction, SoakBaseline, SoakPreset,
    SoakReport, V14_SCHEMA_VERSION, baseline_from_reports, campaign_definition,
    campaign_definitions, campaign_loaded_scenario, campaign_manifest, compare_baseline,
    coverage_check, coverage_combination_expected_ids, coverage_markdown, coverage_report,
    diagnostics_for, enrich_report, fault_script_report, fixture_digest, provenance_for,
    report_differences, run_soak, scenario_revision_digest, soak_baseline_from_report,
    stable_digest, validate_v14_scenario,
};

pub fn report_json(report: &RunReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}
