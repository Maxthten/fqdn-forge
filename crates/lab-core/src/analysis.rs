//! Versioned, read-only analysis models for local FQDN Forge artifacts.
//!
//! This module deliberately builds a compact, redacted view instead of
//! returning raw artifact JSON to a browser or command-line consumer.  It is
//! shared by the loopback API and the CLI so neither caller can reimplement a
//! verdict, coverage decision, or replay comparison.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use chrono::{NaiveDate, Utc};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    CampaignReport, CoverageReport, PlanRun, ReportStatus, RunReport, ScenarioRepository,
    SoakReport, campaign_definitions, coverage_combination_expected_ids, coverage_report,
};

pub const ANALYSIS_SCHEMA_VERSION: &str = "1.0";
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024;
const MAX_ARTIFACT_FILES: usize = 2_000;
const MAX_LIST_LIMIT: usize = 200;
const MAX_GRAPH_NODES: usize = 500;
const MAX_GRAPH_EDGES: usize = 2_000;
const MAX_TIMELINE_EVENTS: usize = 1_000;
const MAX_TREND_POINTS: usize = 300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisView {
    Overview,
    Coverage,
    Replays,
    Campaigns,
    Soak,
    EvidenceGraph,
    Timeline,
    Trends,
}

impl AnalysisView {
    #[must_use]
    pub const fn max_limit(self) -> usize {
        match self {
            Self::EvidenceGraph => MAX_GRAPH_NODES,
            Self::Timeline => MAX_TIMELINE_EVENTS,
            Self::Trends => MAX_TREND_POINTS,
            _ => MAX_LIST_LIMIT,
        }
    }

    #[must_use]
    pub const fn default_limit(self) -> usize {
        match self {
            Self::Overview => 20,
            Self::EvidenceGraph => MAX_GRAPH_NODES,
            Self::Timeline => 200,
            Self::Trends => MAX_TREND_POINTS,
            _ => MAX_LIST_LIMIT,
        }
    }

    #[must_use]
    pub const fn allowed_filters(self) -> &'static [&'static str] {
        match self {
            Self::Overview => &[],
            Self::Coverage => &["dimension", "status", "q"],
            Self::Replays => &["status", "scenario", "category", "id", "from", "to"],
            Self::Campaigns => &["status", "campaign", "id"],
            Self::Soak => &["preset", "status", "id"],
            Self::EvidenceGraph => &[
                "run",
                "scenario",
                "source",
                "fqdn",
                "verdict",
                "evidence_type",
            ],
            Self::Timeline => &[
                "run", "scenario", "source", "status", "proxy", "retry", "quota", "expected",
                "failure",
            ],
            Self::Trends => &["from", "to", "object_type", "scenario"],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisRequest {
    pub limit: usize,
    pub cursor: usize,
    pub filters: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("{code}: {message}")]
    InvalidRequest { code: &'static str, message: String },
}

impl AnalysisError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest { code, .. } => code,
        }
    }
}

pub fn parse_analysis_request(
    view: AnalysisView,
    parameters: &BTreeMap<String, String>,
) -> Result<AnalysisRequest, AnalysisError> {
    let mut filters = BTreeMap::new();
    for (name, value) in parameters {
        if name == "limit" || name == "cursor" {
            continue;
        }
        if !view.allowed_filters().contains(&name.as_str()) {
            return Err(AnalysisError::InvalidRequest {
                code: "ANALYSIS_FILTER_INVALID",
                message: format!("filter {name} is not supported for this analysis view"),
            });
        }
        if value.len() > 256 || value.contains('\0') {
            return Err(AnalysisError::InvalidRequest {
                code: "ANALYSIS_FILTER_INVALID",
                message: format!("filter {name} has an invalid value"),
            });
        }
        if !value.is_empty() {
            filters.insert(name.clone(), value.clone());
        }
    }
    let limit = match parameters.get("limit") {
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|value| *value > 0 && *value <= view.max_limit())
            .ok_or_else(|| AnalysisError::InvalidRequest {
                code: "ANALYSIS_LIMIT_INVALID",
                message: format!(
                    "limit must be an integer from 1 to {} for this analysis view",
                    view.max_limit()
                ),
            })?,
        None => view.default_limit(),
    };
    let cursor = match parameters.get("cursor") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| AnalysisError::InvalidRequest {
                code: "ANALYSIS_CURSOR_INVALID",
                message: "cursor must be a non-negative numeric offset".to_owned(),
            })?,
        None => 0,
    };
    Ok(AnalysisRequest {
        limit,
        cursor,
        filters,
    })
}

#[must_use]
pub fn analysis_artifacts_root(repository: &ScenarioRepository) -> PathBuf {
    repository
        .root()
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("artifacts")
}

pub fn analysis_value(
    repository: &ScenarioRepository,
    artifacts_root: &Path,
    view: AnalysisView,
    request: &AnalysisRequest,
) -> Value {
    let corpus = ArtifactCorpus::load(artifacts_root);
    analysis_value_from_corpus(repository, &corpus, view, request)
}

/// A small, invalidatable in-memory index. It stores only parsed, redacted
/// analysis inputs and is rebuilt when the managed artifact metadata changes;
/// it never writes beside user artifacts and therefore preserves read-only
/// analysis semantics.
#[derive(Debug, Default)]
pub struct AnalysisIndex {
    root: Option<PathBuf>,
    fingerprint: BTreeMap<PathBuf, (u64, u128)>,
    corpus: ArtifactCorpus,
}

impl AnalysisIndex {
    pub fn value(
        &mut self,
        repository: &ScenarioRepository,
        artifacts_root: &Path,
        view: AnalysisView,
        request: &AnalysisRequest,
    ) -> Value {
        let fingerprint = artifact_fingerprint(artifacts_root);
        if self.root.as_deref() != Some(artifacts_root) || self.fingerprint != fingerprint {
            self.corpus = ArtifactCorpus::load(artifacts_root);
            self.root = Some(artifacts_root.to_path_buf());
            self.fingerprint = fingerprint;
        }
        analysis_value_from_corpus(repository, &self.corpus, view, request)
    }

    pub fn rebuild(&mut self, artifacts_root: &Path) {
        self.corpus = ArtifactCorpus::load(artifacts_root);
        self.root = Some(artifacts_root.to_path_buf());
        self.fingerprint = artifact_fingerprint(artifacts_root);
    }
}

fn analysis_value_from_corpus(
    repository: &ScenarioRepository,
    corpus: &ArtifactCorpus,
    view: AnalysisView,
    request: &AnalysisRequest,
) -> Value {
    let generated_at = Utc::now().to_rfc3339();
    match view {
        AnalysisView::Overview => overview_value(repository, corpus, request, &generated_at),
        AnalysisView::Coverage => coverage_value(repository, corpus, request, &generated_at),
        AnalysisView::Replays => replays_value(corpus, request, &generated_at),
        AnalysisView::Campaigns => campaigns_value(corpus, request, &generated_at),
        AnalysisView::Soak => soak_value(corpus, request, &generated_at),
        AnalysisView::EvidenceGraph => evidence_value(corpus, request, &generated_at),
        AnalysisView::Timeline => timeline_value(corpus, request, &generated_at),
        AnalysisView::Trends => trends_value(repository, corpus, request, &generated_at),
    }
}

/// Produces a portable, human-readable export from the same redacted model as
/// the API.  Markdown intentionally embeds the stable envelope so an issue or
/// PR attachment retains its schema, filters, and truncation state.
#[must_use]
pub fn analysis_markdown(value: &Value) -> String {
    let schema_version = value
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or(ANALYSIS_SCHEMA_VERSION);
    let generated_at = value
        .get("generated_at")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    let filters = value.get("filters").cloned().unwrap_or_else(|| json!({}));
    let truncated = value
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let body = serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_owned());
    format!(
        "# FQDN Forge analysis export\n\n- Schema: `{schema_version}`\n- Generated: `{generated_at}`\n- Filters: `{filters}`\n- Truncated: `{truncated}`\n\nThe following is a server-generated, redacted local analysis model.\n\n```json\n{body}\n```\n"
    )
}

#[derive(Clone, Debug, Default)]
struct ArtifactCorpus {
    reports: Vec<RunReport>,
    campaigns: Vec<CampaignReport>,
    soaks: Vec<SoakReport>,
    plans: Vec<PlanRun>,
    diagnostics: Vec<Value>,
}

impl ArtifactCorpus {
    fn load(artifacts_root: &Path) -> Self {
        let mut corpus = Self::default();
        corpus.reports = load_documents(
            &artifacts_root.join("reports"),
            "report",
            &mut corpus.diagnostics,
        );
        corpus.campaigns = load_documents(
            &artifacts_root.join("campaigns"),
            "campaign",
            &mut corpus.diagnostics,
        );
        corpus.soaks = load_documents(
            &artifacts_root.join("soak"),
            "soak",
            &mut corpus.diagnostics,
        );
        corpus.plans = load_documents(
            &artifacts_root.join("plan-runs"),
            "plan_run",
            &mut corpus.diagnostics,
        );
        corpus.reports.sort_by_key(|report| report.finished_at);
        corpus
            .campaigns
            .sort_by_key(|report| report.report.finished_at);
        corpus.plans.sort_by_key(|run| run.manifest.created_at);
        corpus.soaks.sort_by(|left, right| {
            left.reproduction_command
                .cmp(&right.reproduction_command)
                .then(left.seed.cmp(&right.seed))
        });
        corpus
    }
}

fn load_documents<T: DeserializeOwned>(
    root: &Path,
    kind: &str,
    diagnostics: &mut Vec<Value>,
) -> Vec<T> {
    let mut documents = Vec::new();
    let files = json_files(root, diagnostics, kind);
    for path in files {
        let object_id = artifact_id(&path);
        match fs::metadata(&path) {
            Ok(metadata) if metadata.len() > MAX_ARTIFACT_BYTES => diagnostics.push(json!({
                "code": "ARTIFACT_TOO_LARGE",
                "object_type": kind,
                "object_id": object_id,
                "message": format!("artifact exceeds the {} byte analysis safety limit", MAX_ARTIFACT_BYTES),
            })),
            Ok(_) => match fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<T>(&bytes).ok())
            {
                Some(document) => documents.push(document),
                None => diagnostics.push(json!({
                    "code": "ARTIFACT_UNREADABLE",
                    "object_type": kind,
                    "object_id": object_id,
                    "message": "artifact is not a compatible JSON analysis input; it was skipped",
                })),
            },
            Err(_) => diagnostics.push(json!({
                "code": "ARTIFACT_UNREADABLE",
                "object_type": kind,
                "object_id": object_id,
                "message": "artifact metadata could not be read; it was skipped",
            })),
        }
    }
    documents
}

fn json_files(root: &Path, diagnostics: &mut Vec<Value>, kind: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    collect_json_files(root, &mut paths, diagnostics, kind);
    paths.sort();
    paths
}

fn collect_json_files(
    root: &Path,
    paths: &mut Vec<PathBuf>,
    diagnostics: &mut Vec<Value>,
    kind: &str,
) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut entries = entries.flatten().collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if paths.len() >= MAX_ARTIFACT_FILES {
            diagnostics.push(json!({
                "code": "ARTIFACT_INDEX_TRUNCATED",
                "object_type": kind,
                "object_id": "index",
                "message": format!("analysis indexed at most {MAX_ARTIFACT_FILES} local artifacts"),
            }));
            return;
        }
        let path = entry.path();
        if entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
            collect_json_files(&path, paths, diagnostics, kind);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
}

fn artifact_id(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("artifact")
        .to_owned()
}

fn artifact_fingerprint(artifacts_root: &Path) -> BTreeMap<PathBuf, (u64, u128)> {
    let mut fingerprint = BTreeMap::new();
    for directory in ["reports", "campaigns", "soak", "plan-runs"] {
        collect_artifact_fingerprint(&artifacts_root.join(directory), &mut fingerprint);
    }
    fingerprint
}

fn collect_artifact_fingerprint(root: &Path, fingerprint: &mut BTreeMap<PathBuf, (u64, u128)>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            collect_artifact_fingerprint(&path, fingerprint);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
            && let Ok(metadata) = entry.metadata()
        {
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_nanos());
            fingerprint.insert(path, (metadata.len(), modified));
        }
    }
}

fn envelope(
    generated_at: &str,
    request: &AnalysisRequest,
    truncated: bool,
    next_cursor: Option<String>,
    data: Value,
    diagnostics: &[Value],
) -> Value {
    json!({
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "generated_at": generated_at,
        "filters": request.filters,
        "truncated": truncated,
        "next_cursor": next_cursor,
        "limits": {"requested": request.limit},
        "diagnostics": diagnostics,
        "data": redact_analysis_value(data),
    })
}

fn paged(mut items: Vec<Value>, request: &AnalysisRequest) -> (Vec<Value>, bool, Option<String>) {
    let total = items.len();
    let start = request.cursor.min(total);
    let end = start.saturating_add(request.limit).min(total);
    let next_cursor = (end < total).then(|| end.to_string());
    items.drain(..start);
    items.truncate(end.saturating_sub(start));
    (items, end < total, next_cursor)
}

fn overview_value(
    repository: &ScenarioRepository,
    corpus: &ArtifactCorpus,
    request: &AnalysisRequest,
    generated_at: &str,
) -> Value {
    let coverage = coverage_summary(&coverage_report(repository));
    let mut recent = corpus.reports.iter().collect::<Vec<_>>();
    recent.sort_by(|left, right| {
        right
            .finished_at
            .cmp(&left.finished_at)
            .then_with(|| right.run_id.cmp(&left.run_id))
    });
    let mut recent = recent.into_iter().map(report_summary).collect::<Vec<_>>();
    recent.truncate(request.limit.min(20));
    let replay_count = replay_rows(corpus).len();
    let mismatch_count = replay_rows(corpus)
        .iter()
        .filter(|row| row.get("status") == Some(&Value::String("mismatch".to_owned())))
        .count();
    let mut failure_categories = BTreeMap::<String, usize>::new();
    for report in &corpus.reports {
        for (category, count) in &report.diagnostics.failure_categories {
            *failure_categories.entry(category.clone()).or_default() += count;
        }
    }
    envelope(
        generated_at,
        request,
        false,
        None,
        json!({
            "local_only": true,
            "simulation_notice_code": "offline_artifacts_not_public_network_assets",
            "simulation_notice": "All values describe saved offline test-station artifacts, not public-network assets.",
            "reports": {"count": corpus.reports.len(), "recent": recent},
            "campaigns": {"count": corpus.campaigns.len(), "recent": campaign_rows(corpus).into_iter().rev().take(5).collect::<Vec<_>>()},
            "soak": {"count": corpus.soaks.len(), "recent": soak_rows(corpus).into_iter().rev().take(5).collect::<Vec<_>>()},
            "coverage": coverage,
            "replays": {"count": replay_count, "mismatch_count": mismatch_count},
            "failure_categories": failure_categories,
            "plan_run_count": corpus.plans.len(),
        }),
        &corpus.diagnostics,
    )
}

fn coverage_value(
    repository: &ScenarioRepository,
    corpus: &ArtifactCorpus,
    request: &AnalysisRequest,
    generated_at: &str,
) -> Value {
    let report = coverage_report(repository);
    let now = Utc::now().date_naive();
    let campaign_by_scenario = campaign_definitions()
        .into_iter()
        .map(|definition| (definition.scenario_id.to_owned(), definition.id.to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut cells = Vec::new();
    for (dimension, values) in &report.dimensions {
        for (value, scenario_ids) in values {
            let exception = report
                .exceptions
                .iter()
                .find(|exception| exception.dimension == *dimension && exception.value == *value);
            let status = coverage_status(scenario_ids.len(), 1, exception, now);
            let matches_dimension = request
                .filters
                .get("dimension")
                .is_none_or(|filter| filter == dimension);
            let matches_status = request
                .filters
                .get("status")
                .is_none_or(|filter| filter == status);
            let search = request
                .filters
                .get("q")
                .map(|value| value.to_ascii_lowercase());
            let matches_search = search.as_ref().is_none_or(|needle| {
                dimension.to_ascii_lowercase().contains(needle)
                    || value.to_ascii_lowercase().contains(needle)
                    || scenario_ids
                        .iter()
                        .any(|scenario| scenario.to_ascii_lowercase().contains(needle))
            });
            if matches_dimension && matches_status && matches_search {
                let campaign_ids = scenario_ids
                    .iter()
                    .filter_map(|scenario| campaign_by_scenario.get(scenario).cloned())
                    .collect::<Vec<_>>();
                cells.push(json!({
                    "dimension": dimension,
                    "value": value,
                    "status": status,
                    "scenario_ids": scenario_ids,
                    "campaign_ids": campaign_ids,
                    "exception_ids": exception.map(|item| vec![item.id.clone()]).unwrap_or_default(),
                    "description": coverage_description(status, exception, &[], false),
                }));
            }
        }
    }
    for (combination, scenario_ids) in &report.high_risk_combinations {
        let expected_scenario_ids = coverage_combination_expected_ids(combination)
            .unwrap_or_default()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let missing_scenario_ids = expected_scenario_ids
            .iter()
            .filter(|id| !scenario_ids.contains(*id))
            .cloned()
            .collect::<Vec<_>>();
        let exception = report.exceptions.iter().find(|exception| {
            exception.dimension == "high_risk_combination" && exception.value == *combination
        });
        let status = coverage_status(
            scenario_ids.len(),
            expected_scenario_ids.len().max(1),
            exception,
            now,
        );
        let matches_dimension = request
            .filters
            .get("dimension")
            .is_none_or(|filter| filter == "high_risk_combination");
        let matches_status = request
            .filters
            .get("status")
            .is_none_or(|filter| filter == status);
        let search = request
            .filters
            .get("q")
            .map(|value| value.to_ascii_lowercase());
        let matches_search = search.as_ref().is_none_or(|needle| {
            combination.to_ascii_lowercase().contains(needle)
                || scenario_ids
                    .iter()
                    .any(|scenario| scenario.to_ascii_lowercase().contains(needle))
        });
        if matches_dimension && matches_status && matches_search {
            let campaign_ids = scenario_ids
                .iter()
                .filter_map(|scenario| campaign_by_scenario.get(scenario).cloned())
                .collect::<Vec<_>>();
            cells.push(json!({
                "dimension": "high_risk_combination",
                "value": combination,
                "status": status,
                "scenario_ids": scenario_ids,
                "campaign_ids": campaign_ids,
                "exception_ids": exception.map(|item| vec![item.id.clone()]).unwrap_or_default(),
                "required_scenario_ids": expected_scenario_ids,
                "missing_scenario_ids": missing_scenario_ids,
                "description": coverage_description(status, exception, &missing_scenario_ids, true),
            }));
        }
    }
    let summary = coverage_summary(&report);
    let (cells, truncated, next_cursor) = paged(cells, request);
    envelope(
        generated_at,
        request,
        truncated,
        next_cursor,
        json!({"summary": summary, "cells": cells, "policy_exceptions": report.exceptions}),
        &corpus.diagnostics,
    )
}

fn coverage_status(
    scenario_count: usize,
    required_scenario_count: usize,
    exception: Option<&crate::CoverageException>,
    now: NaiveDate,
) -> &'static str {
    if scenario_count >= required_scenario_count {
        "covered"
    } else if scenario_count > 0 {
        "partial"
    } else if exception.is_some_and(|exception| exception_expired(exception, now)) {
        "expired_exception"
    } else if exception.is_some() {
        "excepted"
    } else {
        "missing"
    }
}

fn coverage_description(
    status: &str,
    exception: Option<&crate::CoverageException>,
    missing_scenario_ids: &[String],
    high_risk_combination: bool,
) -> String {
    match (status, exception) {
        ("covered", _) => "One or more scenario definitions provide this coverage.".to_owned(),
        ("partial", _) => format!(
            "Basic coverage exists, but the high-risk combination still needs: {}.",
            missing_scenario_ids.join(", ")
        ),
        ("excepted", Some(exception)) => format!(
            "Approved exception {}: {}",
            exception.id,
            safe_text(&exception.reason)
        ),
        ("expired_exception", Some(exception)) => format!(
            "Exception {} is expired and blocks complete acceptance.",
            exception.id
        ),
        (_, _) if high_risk_combination => {
            "This required high-risk combination has no currently valid scenario or exception."
                .to_owned()
        }
        _ => "This policy value has no currently valid scenario or exception.".to_owned(),
    }
}

fn exception_expired(exception: &crate::CoverageException, now: NaiveDate) -> bool {
    NaiveDate::parse_from_str(&exception.expires_on, "%Y-%m-%d")
        .is_ok_and(|expires_on| expires_on < now)
}

fn coverage_summary(report: &CoverageReport) -> Value {
    let now = Utc::now().date_naive();
    let mut counts = BTreeMap::<String, usize>::new();
    for (dimension, values) in &report.dimensions {
        for (value, scenario_ids) in values {
            let exception = report
                .exceptions
                .iter()
                .find(|exception| exception.dimension == *dimension && exception.value == *value);
            let status = coverage_status(scenario_ids.len(), 1, exception, now);
            *counts.entry(status.to_owned()).or_default() += 1;
        }
    }
    for (combination, scenario_ids) in &report.high_risk_combinations {
        let exception = report.exceptions.iter().find(|exception| {
            exception.dimension == "high_risk_combination" && exception.value == *combination
        });
        let required_scenario_count =
            coverage_combination_expected_ids(combination).map_or(1, |ids| ids.len());
        let status = coverage_status(scenario_ids.len(), required_scenario_count, exception, now);
        *counts.entry(status.to_owned()).or_default() += 1;
    }
    json!({"scenario_count": report.scenario_count, "status_counts": counts, "high_risk_combinations": report.high_risk_combinations})
}

fn replays_value(corpus: &ArtifactCorpus, request: &AnalysisRequest, generated_at: &str) -> Value {
    let rows = replay_rows(corpus)
        .into_iter()
        .filter(|row| matches_replay_filter(row, request))
        .collect::<Vec<_>>();
    let (rows, truncated, next_cursor) = paged(rows, request);
    envelope(
        generated_at,
        request,
        truncated,
        next_cursor,
        json!({"comparisons": rows}),
        &corpus.diagnostics,
    )
}

fn replay_rows(corpus: &ArtifactCorpus) -> Vec<Value> {
    let mut rows = Vec::new();
    for (index, report) in corpus.reports.iter().enumerate() {
        if !(report.replay.strict
            || report.replay.matched.is_some()
            || report.replay.comparison_report.is_some())
        {
            continue;
        }
        let source_run_id = corpus.reports[..index]
            .iter()
            .rev()
            .find(|prior| prior.scenario_id == report.scenario_id && prior.seed == report.seed)
            .map(|prior| prior.run_id.clone())
            .unwrap_or_else(|| "unavailable".to_owned());
        let status = match report.replay.matched {
            Some(true) => "matched",
            Some(false) => "mismatch",
            None => "unavailable",
        };
        let differences = report
            .replay
            .differences
            .iter()
            .map(|difference| {
                json!({
                    "path": difference.path,
                    "category": difference.category.as_str(),
                    "previous": safe_text(&difference.previous),
                    "current": safe_text(&difference.current),
                    "truncated": false,
                    "explanation": format!("{} changed at {}", difference.category.as_str(), difference.path),
                })
            })
            .collect::<Vec<_>>();
        rows.push(json!({
            "comparison_id": format!("replay:{}", report.run_id),
            "source_run_id": source_run_id,
            "replay_run_id": report.run_id,
            "scenario_or_plan_id": report.scenario_id,
            "seed": report.seed,
            "status": status,
            "provenance_status": report.replay.provenance_status.clone().unwrap_or_else(|| "unavailable".to_owned()),
            "difference_count": report.replay.differences.len() + report.replay.truncated_difference_count,
            "first_difference_path": report.replay.first_difference,
            "differences": differences,
            "created_at": report.finished_at.to_rfc3339(),
            "timeline_run_id": report.run_id,
        }));
    }
    for plan in &corpus.plans {
        let Some(source_run_id) = &plan.manifest.replayed_from else {
            continue;
        };
        let source = corpus
            .plans
            .iter()
            .find(|candidate| candidate.manifest.run_id == *source_run_id);
        let matched = source.is_some_and(|source| {
            source.report.status == plan.report.status
                && source.report.fixture_digest == plan.report.fixture_digest
                && source.report.truth_digest == plan.report.truth_digest
                && source.report.expected_behaviour_digest == plan.report.expected_behaviour_digest
        });
        rows.push(json!({
            "comparison_id": format!("plan-replay:{}", plan.manifest.run_id),
            "source_run_id": source_run_id,
            "replay_run_id": plan.manifest.run_id,
            "scenario_or_plan_id": plan.manifest.plan_id,
            "seed": plan.manifest.seed,
            "status": if matched { "matched" } else { "mismatch" },
            "provenance_status": if matched { "matched" } else { "plan_or_fixture_changed" },
            "difference_count": usize::from(!matched),
            "first_difference_path": (!matched).then_some("$.report"),
            "differences": if matched { Vec::<Value>::new() } else { vec![json!({"path":"$.report", "category":"provenance", "previous":"source plan report", "current":"replay plan report", "truncated":false, "explanation":"The replay plan report no longer matches its source run."})] },
            "created_at": plan.manifest.created_at.to_rfc3339(),
            "timeline_run_id": plan.manifest.run_id,
        }));
    }
    rows.sort_by_key(|row| {
        row.get("created_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    });
    rows.reverse();
    rows
}

fn matches_replay_filter(row: &Value, request: &AnalysisRequest) -> bool {
    matches_filter(row, "status", request)
        && matches_filter(row, "scenario", request)
        && matches_filter(row, "id", request)
        && matches_time_filter(row, "created_at", "from", request, true)
        && matches_time_filter(row, "created_at", "to", request, false)
        && request.filters.get("category").is_none_or(|category| {
            row.get("differences")
                .and_then(Value::as_array)
                .is_some_and(|items| {
                    items
                        .iter()
                        .any(|item| item.get("category").and_then(Value::as_str) == Some(category))
                })
        })
}

fn campaigns_value(
    corpus: &ArtifactCorpus,
    request: &AnalysisRequest,
    generated_at: &str,
) -> Value {
    let rows = campaign_rows(corpus)
        .into_iter()
        .filter(|row| {
            matches_filter(row, "status", request)
                && matches_filter(row, "campaign", request)
                && matches_filter(row, "id", request)
        })
        .collect::<Vec<_>>();
    let (rows, truncated, next_cursor) = paged(rows, request);
    envelope(
        generated_at,
        request,
        truncated,
        next_cursor,
        json!({"campaigns": rows}),
        &corpus.diagnostics,
    )
}

fn campaign_rows(corpus: &ArtifactCorpus) -> Vec<Value> {
    let mut rows = corpus
        .campaigns
        .iter()
        .map(|campaign| {
            let report = &campaign.report;
            json!({
                "campaign_id": campaign.manifest.campaign_id,
                "scenario_id": campaign.manifest.scenario_id,
                "seed": campaign.manifest.seed,
                "started_at": report.started_at.to_rfc3339(),
                "finished_at": report.finished_at.to_rfc3339(),
                "status": report_status(report.status),
                "mutation_types": campaign.manifest.operators,
                "mutation_count": campaign.manifest.operators.len(),
                "total_runs": 1,
                "passed_runs": usize::from(report.status == ReportStatus::Passed),
                "failed_runs": usize::from(report.status == ReportStatus::Failed),
                "cancelled_runs": usize::from(report.metrics.cancelled),
                "first_failure": report.failures.first().map(|value| safe_text(value)),
                "failure_categories": report.diagnostics.failure_categories,
                "run_id": report.run_id,
                "replay_available": report.reproducible,
                "provenance_status": report.replay.provenance_status,
                "artifact_id": format!("campaign:{}:{}", campaign.manifest.campaign_id, campaign.manifest.seed),
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| {
        row.get("finished_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    });
    rows
}

fn soak_value(corpus: &ArtifactCorpus, request: &AnalysisRequest, generated_at: &str) -> Value {
    let rows = soak_rows(corpus)
        .into_iter()
        .filter(|row| {
            matches_filter(row, "preset", request)
                && matches_filter(row, "status", request)
                && matches_filter(row, "id", request)
        })
        .collect::<Vec<_>>();
    let (rows, truncated, next_cursor) = paged(rows, request);
    envelope(
        generated_at,
        request,
        truncated,
        next_cursor,
        json!({"soaks": rows}),
        &corpus.diagnostics,
    )
}

fn soak_rows(corpus: &ArtifactCorpus) -> Vec<Value> {
    corpus
        .soaks
        .iter()
        .map(|soak| {
            let passed = soak.last_failure.is_none() && soak.invariants.values().all(|value| *value);
            let retry_count = soak.action_counts.get("retry").copied().unwrap_or_default();
            let rate_limited = soak
                .outcome_counts
                .get("rate_limited")
                .copied()
                .unwrap_or_default();
            json!({
                "soak_id": format!("{:?}-{}", soak.preset, soak.seed).to_ascii_lowercase(),
                "preset": format!("{:?}", soak.preset).to_ascii_lowercase(),
                "seed": soak.seed,
                "concurrency": soak.concurrency,
                "operations": soak.operations,
                "status": if passed { "passed" } else { "failed" },
                "passed": passed,
                "cancelled": soak.outcome_counts.get("cancelled").copied().unwrap_or_default(),
                "retries": retry_count,
                "rate_limited": rate_limited,
                "blocked_egress": soak.outcome_counts.get("blocked_egress").copied().unwrap_or_default(),
                "action_counts": soak.action_counts,
                "outcome_counts": soak.outcome_counts,
                "resources": soak.resources,
                "resource_invariants": soak.invariants,
                "last_failure": soak.last_failure.as_deref().map(safe_text),
                "reproduction_command": soak.reproduction_command,
                "virtual_wait_note": "Soak reports record operation outcomes; virtual wait is reported separately from real elapsed time.",
            })
        })
        .collect()
}

fn evidence_value(corpus: &ArtifactCorpus, request: &AnalysisRequest, generated_at: &str) -> Value {
    let scoped = request.filters.contains_key("run") || request.filters.contains_key("scenario");
    if !scoped {
        return envelope(
            generated_at,
            request,
            false,
            None,
            json!({
                "simulation_notice": "Evidence graph nodes describe offline simulated test data only.",
                "scope_required": true,
                "message": "Choose a run or scenario before loading an evidence graph.",
                "nodes": Vec::<Value>::new(),
                "edges": Vec::<Value>::new(),
            }),
            &corpus.diagnostics,
        );
    }
    let mut nodes = BTreeMap::<String, Value>::new();
    let mut edges = BTreeMap::<String, Value>::new();
    for report in corpus
        .reports
        .iter()
        .filter(|report| matches_report_scope(report, request))
    {
        let run_node = format!("run:{}", report.run_id);
        nodes.insert(
            run_node.clone(),
            graph_node(&run_node, "run", &report.run_id, "saved offline run", 1),
        );
        for (source_id, status) in &report.source_statuses {
            if !matches_optional(request, "source", source_id) {
                continue;
            }
            let source_node = format!("source:{}:{}", report.run_id, source_id);
            nodes.insert(
                source_node.clone(),
                graph_node(
                    &source_node,
                    "source",
                    source_id,
                    &format!("source status {status:?}"),
                    1,
                ),
            );
            insert_edge(&mut edges, &run_node, &source_node, "run_source");
        }
        for finding in &report.findings {
            if !matches_optional(request, "fqdn", &finding.fqdn) {
                continue;
            }
            let fqdn_node = format!("fqdn:{}:{}", report.run_id, finding.fqdn);
            nodes.insert(
                fqdn_node.clone(),
                graph_node(
                    &fqdn_node,
                    "fqdn",
                    &finding.fqdn,
                    "reported simulated finding",
                    1,
                ),
            );
            let verdict = if report.status == ReportStatus::Passed {
                "correct"
            } else {
                "review"
            };
            if !matches_optional(request, "verdict", verdict) {
                continue;
            }
            let verdict_node = format!("verdict:{}:{}", report.run_id, verdict);
            nodes.insert(
                verdict_node.clone(),
                graph_node(
                    &verdict_node,
                    "verdict",
                    verdict,
                    "server judgment summary",
                    1,
                ),
            );
            insert_edge(&mut edges, &fqdn_node, &verdict_node, "fqdn_verdict");
            for (index, evidence) in finding.evidence.iter().enumerate() {
                if !matches_optional(request, "source", &evidence.source_id) {
                    continue;
                }
                let evidence_type = format!("{:?}", evidence.source_kind).to_ascii_lowercase();
                if !matches_optional(request, "evidence_type", &evidence_type) {
                    continue;
                }
                let source_node = format!("source:{}:{}", report.run_id, evidence.source_id);
                nodes.insert(
                    source_node.clone(),
                    graph_node(
                        &source_node,
                        "source",
                        &evidence.source_id,
                        &format!("simulated {evidence_type} source"),
                        1,
                    ),
                );
                insert_edge(&mut edges, &run_node, &source_node, "run_source");
                let evidence_node = format!("evidence:{}:{}:{index}", report.run_id, finding.fqdn);
                nodes.insert(
                    evidence_node.clone(),
                    graph_node(
                        &evidence_node,
                        "evidence",
                        &evidence_type,
                        "redacted evidence summary",
                        1,
                    ),
                );
                insert_edge(&mut edges, &source_node, &evidence_node, "source_evidence");
                insert_edge(&mut edges, &evidence_node, &fqdn_node, "evidence_fqdn");
            }
        }
    }
    let original_node_count = nodes.len();
    let original_edge_count = edges.len();
    let mut node_values = nodes.into_values().collect::<Vec<_>>();
    node_values.sort_by_key(|node| {
        node.get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    });
    node_values.truncate(request.limit.min(MAX_GRAPH_NODES));
    let allowed = node_values
        .iter()
        .filter_map(|node| node.get("id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let mut edge_values = edges
        .into_values()
        .filter(|edge| {
            edge.get("from")
                .and_then(Value::as_str)
                .is_some_and(|from| allowed.contains(from))
                && edge
                    .get("to")
                    .and_then(Value::as_str)
                    .is_some_and(|to| allowed.contains(to))
        })
        .collect::<Vec<_>>();
    edge_values.sort_by_key(|edge| {
        edge.get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    });
    edge_values.truncate(MAX_GRAPH_EDGES);
    let truncated =
        original_node_count > node_values.len() || original_edge_count > edge_values.len();
    envelope(
        generated_at,
        request,
        truncated,
        None,
        json!({
            "simulation_notice": "Evidence graph nodes describe offline simulated test data only.",
            "scope_required": false,
            "nodes": node_values,
            "edges": edge_values,
            "total_nodes": original_node_count,
            "total_edges": original_edge_count,
            "truncation_hint": truncated.then_some("Narrow the run, scenario, source, FQDN, verdict, or evidence-type filter."),
        }),
        &corpus.diagnostics,
    )
}

fn graph_node(id: &str, kind: &str, label: &str, reason: &str, count: usize) -> Value {
    json!({"id": id, "type": kind, "label": safe_text(label), "visibility_reason": safe_text(reason), "count": count, "redacted": true})
}

fn insert_edge(edges: &mut BTreeMap<String, Value>, from: &str, to: &str, kind: &str) {
    let id = format!("{kind}:{from}:{to}");
    edges.entry(id.clone()).or_insert_with(
        || json!({"id": id, "from": from, "to": to, "type": kind, "count": 1, "redacted": true}),
    );
}

fn timeline_value(corpus: &ArtifactCorpus, request: &AnalysisRequest, generated_at: &str) -> Value {
    let mut events = Vec::new();
    for report in corpus
        .reports
        .iter()
        .filter(|report| matches_report_scope(report, request))
    {
        let records = if report.audit.is_empty() {
            &report.requests
        } else {
            &report.audit
        };
        let mut virtual_time_ms = 0_u64;
        for (index, record) in records.iter().enumerate() {
            virtual_time_ms = virtual_time_ms.saturating_add(record.virtual_wait_ms);
            let source_id = record.endpoint_id.clone().unwrap_or_default();
            let retry = record.retry_after.is_some() || record.virtual_wait_ms > 0;
            let quota = record.quota_consumed || record.consumed || record.quota_rate_limited;
            let expected =
                record.blocked || record.external_target_rejected || record.quota_rate_limited;
            let failure = !record.mismatch_reasons.is_empty() || record.transport_fault.is_some();
            if !matches_optional(request, "source", &source_id)
                || !matches_optional(request, "status", &record.response_status.to_string())
                || !matches_bool_filter(request, "proxy", record.proxy_mode.is_some())
                || !matches_bool_filter(request, "retry", retry)
                || !matches_bool_filter(request, "quota", quota)
                || !matches_bool_filter(request, "expected", expected)
                || !matches_bool_filter(request, "failure", failure)
            {
                continue;
            }
            events.push(json!({
                "event_id": format!("{}:{}:{index}", report.run_id, record.sequence),
                "run_id": report.run_id,
                "scenario_id": report.scenario_id,
                "source_id": source_id,
                "operation": format!("{:?}", record.event_type).to_ascii_lowercase(),
                "method": record.method,
                "status": record.response_status,
                "request_sequence": record.sequence,
                "timestamp": record.timestamp.to_rfc3339(),
                "virtual_time_ms": virtual_time_ms,
                "virtual_wait_ms": record.virtual_wait_ms,
                "through_proxy": record.proxy_mode.is_some(),
                "quota_consumed": quota,
                "expected_rejection": expected,
                "retry_after": record.retry_after,
                "retry": retry,
                "failure_type": record.transport_fault.as_deref().or_else(|| record.mismatch_reasons.first().map(String::as_str)).map(safe_text),
                "cancelled": report.metrics.cancelled,
                "path_summary": safe_path(&record.path),
            }));
        }
    }
    events.sort_by_key(|event| {
        (
            event
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            event
                .get("request_sequence")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        )
    });
    let (events, truncated, next_cursor) = paged(events, request);
    envelope(
        generated_at,
        request,
        truncated,
        next_cursor,
        json!({
            "time_note": "Timestamp is real wall-clock artifact metadata. virtual_time_ms is deterministic simulated wait and is not elapsed wall time.",
            "events": events,
        }),
        &corpus.diagnostics,
    )
}

fn trends_value(
    repository: &ScenarioRepository,
    corpus: &ArtifactCorpus,
    request: &AnalysisRequest,
    generated_at: &str,
) -> Value {
    let mut points = corpus
        .reports
        .iter()
        .filter(|report| {
            matches_optional(request, "scenario", &report.scenario_id)
                && matches_optional(request, "object_type", "run")
                && matches_time_filter_value(
                    report.finished_at.to_rfc3339().as_str(),
                    "from",
                    request,
                    true,
                )
                && matches_time_filter_value(
                    report.finished_at.to_rfc3339().as_str(),
                    "to",
                    request,
                    false,
                )
        })
        .map(|report| {
            json!({
                "timestamp": report.finished_at.to_rfc3339(),
                "object_type": "run",
                "object_id": report.run_id,
                "scenario_id": report.scenario_id,
                "passed": report.status == ReportStatus::Passed,
                "requests": report.metrics.request_count,
                "retries": report.metrics.retry_count,
                "rate_limited": report.quota.rate_limited,
                "virtual_wait_ms": report.metrics.virtual_wait_ms,
                "failure_categories": report.diagnostics.failure_categories,
            })
        })
        .collect::<Vec<_>>();
    for campaign in &corpus.campaigns {
        let report = &campaign.report;
        if matches_optional(request, "scenario", &report.scenario_id)
            && matches_optional(request, "object_type", "campaign")
            && matches_time_filter_value(
                report.finished_at.to_rfc3339().as_str(),
                "from",
                request,
                true,
            )
            && matches_time_filter_value(
                report.finished_at.to_rfc3339().as_str(),
                "to",
                request,
                false,
            )
        {
            points.push(json!({
                "timestamp": report.finished_at.to_rfc3339(), "object_type":"campaign", "object_id":campaign.manifest.campaign_id,
                "scenario_id":report.scenario_id, "passed":report.status == ReportStatus::Passed,
                "requests":report.metrics.request_count, "retries":report.metrics.retry_count,
                "rate_limited":report.quota.rate_limited, "virtual_wait_ms":report.metrics.virtual_wait_ms,
                "failure_categories":report.diagnostics.failure_categories,
            }));
        }
    }
    points.sort_by_key(|point| {
        point
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    });
    let original_count = points.len();
    let sampled = downsample(&points, request.limit.min(MAX_TREND_POINTS));
    let coverage = coverage_summary(&coverage_report(repository));
    envelope(
        generated_at,
        request,
        original_count > sampled.len(),
        None,
        json!({
            "points": sampled,
            "source_point_count": original_count,
            "coverage_current": coverage,
            "unavailable": {"coverage_gap_history": "No historical coverage-summary artifacts are available; the current server-computed coverage summary is shown instead."},
        }),
        &corpus.diagnostics,
    )
}

fn downsample(points: &[Value], limit: usize) -> Vec<Value> {
    if points.len() <= limit || limit < 2 {
        return points.iter().take(limit).cloned().collect();
    }
    let mut sampled = Vec::with_capacity(limit);
    let last = points.len() - 1;
    for index in 0..limit {
        let position = index * last / (limit - 1);
        sampled.push(points[position].clone());
    }
    sampled
}

fn report_summary(report: &RunReport) -> Value {
    json!({
        "run_id": report.run_id,
        "scenario_id": report.scenario_id,
        "seed": report.seed,
        "status": report_status(report.status),
        "started_at": report.started_at.to_rfc3339(),
        "finished_at": report.finished_at.to_rfc3339(),
        "request_count": report.metrics.request_count,
        "retry_count": report.metrics.retry_count,
        "virtual_wait_ms": report.metrics.virtual_wait_ms,
        "failure_categories": report.diagnostics.failure_categories,
    })
}

fn report_status(status: ReportStatus) -> &'static str {
    match status {
        ReportStatus::Passed => "passed",
        ReportStatus::Failed => "failed",
    }
}

fn matches_report_scope(report: &RunReport, request: &AnalysisRequest) -> bool {
    matches_optional(request, "run", &report.run_id)
        && matches_optional(request, "scenario", &report.scenario_id)
}

fn matches_filter(row: &Value, filter: &str, request: &AnalysisRequest) -> bool {
    request.filters.get(filter).is_none_or(|needle| {
        let fields: &[&str] = match filter {
            "scenario" => &["scenario_or_plan_id"],
            "campaign" => &["campaign_id"],
            "id" => &[
                "id",
                "comparison_id",
                "campaign_id",
                "soak_id",
                "artifact_id",
            ],
            _ => &[filter],
        };
        fields.iter().any(|field| {
            row.get(*field)
                .and_then(Value::as_str)
                .is_some_and(|value| value == needle || value.contains(needle))
        })
    })
}

fn matches_optional(request: &AnalysisRequest, filter: &str, value: &str) -> bool {
    request
        .filters
        .get(filter)
        .is_none_or(|needle| value == needle || value.contains(needle))
}

fn matches_bool_filter(request: &AnalysisRequest, filter: &str, value: bool) -> bool {
    request
        .filters
        .get(filter)
        .is_none_or(|needle| match needle.as_str() {
            "true" | "1" | "yes" => value,
            "false" | "0" | "no" => !value,
            _ => false,
        })
}

fn matches_time_filter(
    row: &Value,
    field: &str,
    filter: &str,
    request: &AnalysisRequest,
    minimum: bool,
) -> bool {
    row.get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| matches_time_filter_value(value, filter, request, minimum))
}

fn matches_time_filter_value(
    value: &str,
    filter: &str,
    request: &AnalysisRequest,
    minimum: bool,
) -> bool {
    request.filters.get(filter).is_none_or(|boundary| {
        if minimum {
            value >= boundary.as_str()
        } else {
            value <= boundary.as_str()
        }
    })
}

fn safe_path(path: &str) -> String {
    if path.starts_with('/') && !path.contains("//") {
        path.split('?').next().unwrap_or("/").to_owned()
    } else {
        "[redacted path]".to_owned()
    }
}

fn safe_text(value: &str) -> String {
    let normalized = value.to_ascii_lowercase();
    let named_secret = normalized.contains("authorization:")
        || normalized.contains("api_key=")
        || normalized.contains("api key=")
        || normalized.contains("access_token=")
        || normalized.contains("cookie:")
        || normalized.contains("password=")
        || ((normalized.contains("capability=") || normalized.contains("capability:"))
            && normalized.len() > "capability".len() + 8);
    if named_secret
        || ((normalized.contains("http://") || normalized.contains("https://"))
            && !normalized.contains("127.0.0.1")
            && !normalized.contains(".test"))
    {
        "[redacted]".to_owned()
    } else {
        value.chars().take(512).collect()
    }
}

/// Structural final defense for any value included in an analysis envelope.
/// The GUI never receives raw audit headers, request bodies, credentials, or
/// external URLs even if a future model adds them to a summary by mistake.
#[must_use]
pub fn redact_analysis_value(value: Value) -> Value {
    match value {
        Value::Array(values) => {
            Value::Array(values.into_iter().map(redact_analysis_value).collect())
        }
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .filter_map(|(key, value)| {
                    let key_lower = key.to_ascii_lowercase();
                    if key_lower == "truth" {
                        return None;
                    }
                    let sensitive = [
                        "capability",
                        "authorization",
                        "credential",
                        "access_token",
                        "api_key",
                        "cookie",
                        "password",
                        "headers",
                        "body",
                        "query",
                    ]
                    .iter()
                    .any(|needle| key_lower.contains(needle));
                    Some((
                        key,
                        if sensitive {
                            Value::String("[redacted]".to_owned())
                        } else {
                            redact_analysis_value(value)
                        },
                    ))
                })
                .collect(),
        ),
        Value::String(value) => Value::String(safe_text(&value)),
        value => value,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use serde_json::json;
    use uuid::Uuid;

    use super::{
        ANALYSIS_SCHEMA_VERSION, AnalysisView, analysis_artifacts_root, analysis_value,
        coverage_status, parse_analysis_request, redact_analysis_value,
    };
    use crate::ScenarioRepository;

    fn repository() -> ScenarioRepository {
        ScenarioRepository::load(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios"))
            .expect("repository")
    }

    use std::path::PathBuf;

    #[test]
    fn empty_artifacts_produce_a_stable_coverage_envelope() {
        let repository = repository();
        let temporary =
            std::env::temp_dir().join(format!("fqdn-forge-analysis-{}", Uuid::new_v4()));
        fs::create_dir_all(&temporary).expect("temporary artifacts");
        let request =
            parse_analysis_request(AnalysisView::Coverage, &BTreeMap::new()).expect("request");
        let value = analysis_value(&repository, &temporary, AnalysisView::Coverage, &request);
        assert_eq!(value["schema_version"], ANALYSIS_SCHEMA_VERSION);
        assert!(value["data"]["cells"].as_array().is_some());
        fs::remove_dir_all(&temporary).expect("remove temporary artifacts");
        let _ = analysis_artifacts_root(&repository);
    }

    #[test]
    fn invalid_filter_and_limit_are_rejected() {
        let mut invalid_filter = BTreeMap::new();
        invalid_filter.insert("path".to_owned(), "../../anything".to_owned());
        assert!(parse_analysis_request(AnalysisView::Coverage, &invalid_filter).is_err());
        let mut invalid_limit = BTreeMap::new();
        invalid_limit.insert("limit".to_owned(), "201".to_owned());
        assert!(parse_analysis_request(AnalysisView::Coverage, &invalid_limit).is_err());
    }

    #[test]
    fn redaction_removes_sensitive_fields_and_external_urls() {
        let value = redact_analysis_value(json!({
            "capability": "not-exported",
            "headers": {"Authorization":"no"},
            "nested": {"url":"https://example.invalid/private", "safe":"fixture.test"},
        }));
        assert_eq!(value["capability"], "[redacted]");
        assert_eq!(value["headers"], "[redacted]");
        assert_eq!(value["nested"]["url"], "[redacted]");
        assert_eq!(value["nested"]["safe"], "fixture.test");
    }

    #[test]
    fn high_risk_combination_with_some_required_scenarios_is_partial() {
        assert_eq!(
            coverage_status(1, 2, None, chrono::Utc::now().date_naive()),
            "partial"
        );
    }
}
