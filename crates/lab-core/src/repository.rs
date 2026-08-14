use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;

use crate::{Assertions, PaginationMode, Scenario, SourceKind, Truth, normalize_domain};

#[derive(Clone, Debug)]
pub struct LoadedScenario {
    pub directory: PathBuf,
    pub scenario: Scenario,
    pub truth: Truth,
    pub assertions: Assertions,
}

#[derive(Clone, Debug)]
pub struct ScenarioRepository {
    root: PathBuf,
    scenarios: Vec<LoadedScenario>,
}

#[derive(Clone, Debug)]
pub struct ValidationIssue {
    pub scenario_id: String,
    pub message: String,
}

impl ScenarioRepository {
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let mut entries = fs::read_dir(&root)
            .with_context(|| format!("cannot read scenarios directory {}", root.display()))?
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        let scenarios = entries
            .into_iter()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .map(|entry| Self::load_one(entry.path()))
            .collect::<Result<Vec<_>>>()?;
        if scenarios.is_empty() {
            bail!("no scenario directories found in {}", root.display());
        }
        Ok(Self { root, scenarios })
    }

    fn load_one(directory: PathBuf) -> Result<LoadedScenario> {
        let scenario: Scenario = read_yaml(&directory.join("scenario.yaml"))?;
        let truth: Truth = read_yaml(&directory.join("truth.yaml"))?;
        let assertions: Assertions = read_yaml(&directory.join("assertions.yaml"))?;
        let directory_id = directory
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if scenario.id != directory_id {
            bail!(
                "scenario id {} does not match directory {directory_id}",
                scenario.id
            );
        }
        Ok(LoadedScenario {
            directory,
            scenario,
            truth,
            assertions,
        })
    }

    #[must_use]
    pub fn all(&self) -> &[LoadedScenario] {
        &self.scenarios
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&LoadedScenario> {
        self.scenarios
            .iter()
            .find(|loaded| loaded.scenario.id == id)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn validate(&self) -> Vec<ValidationIssue> {
        self.scenarios.iter().flat_map(validate_loaded).collect()
    }
}

fn validate_loaded(loaded: &LoadedScenario) -> Vec<ValidationIssue> {
    let id = &loaded.scenario.id;
    let mut issues = Vec::new();
    if normalize_domain(&loaded.scenario.root_domain).is_err() {
        issues.push(issue(id, "root_domain is not a valid domain"));
    }
    if loaded.scenario.endpoints.is_empty() {
        issues.push(issue(id, "at least one endpoint is required"));
    }
    let mut endpoint_ids = BTreeSet::new();
    for endpoint in &loaded.scenario.endpoints {
        if !endpoint_ids.insert(&endpoint.id) {
            issues.push(issue(id, format!("duplicate endpoint id {}", endpoint.id)));
        }
        if endpoint.request_match.path.is_empty() || !endpoint.request_match.path.starts_with('/') {
            issues.push(issue(
                id,
                format!("endpoint {} path must start with /", endpoint.id),
            ));
        }
        if endpoint.replies.is_empty() {
            issues.push(issue(
                id,
                format!("endpoint {} has no replies", endpoint.id),
            ));
        }
        match endpoint.source_kind {
            SourceKind::GenericHtml
                if endpoint
                    .extract
                    .as_ref()
                    .is_some_and(|extract| extract.kind != crate::ExtractKind::Tokens) =>
            {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} generic_html requires a tokens extract rule",
                        endpoint.id
                    ),
                ));
            }
            _ => {}
        }
        if endpoint.source_kind != SourceKind::Custom && endpoint.source_label.is_some() {
            issues.push(issue(
                id,
                format!(
                    "endpoint {} source_label is only valid with source_kind custom",
                    endpoint.id
                ),
            ));
        }
        for reply in &endpoint.replies {
            let source_count = usize::from(reply.body_file.is_some())
                + usize::from(reply.body.is_some())
                + usize::from(reply.generator.is_some());
            if source_count != 1 {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} replies must have exactly one body source",
                        endpoint.id
                    ),
                ));
            }
            if let Some(body_file) = &reply.body_file
                && !safe_fixture(&loaded.directory, body_file)
            {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} references missing or unsafe fixture {body_file}",
                        endpoint.id
                    ),
                ));
            }
            if reply.status == 429
                && endpoint.allow_retry
                && !reply
                    .headers
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case("retry-after"))
            {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} retryable 429 reply is missing Retry-After",
                        endpoint.id
                    ),
                ));
            }
            if let Some(generator) = &reply.generator {
                if generator
                    .stress_count
                    .is_some_and(|count| count < generator.count)
                {
                    issues.push(issue(
                        id,
                        format!(
                            "endpoint {} generator stress_count must be at least count",
                            endpoint.id
                        ),
                    ));
                }
                if generator.unique == 0 {
                    issues.push(issue(
                        id,
                        format!(
                            "endpoint {} generator unique must be greater than zero",
                            endpoint.id
                        ),
                    ));
                }
            }
        }
        match endpoint.pagination.mode {
            PaginationMode::None if endpoint.pagination.next_cursor_field.is_some() => {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} has next_cursor_field without pagination",
                        endpoint.id
                    ),
                ));
            }
            PaginationMode::None => {}
            _ if endpoint.pagination.next_cursor_field.is_none()
                || endpoint.pagination.parameter.is_empty() =>
            {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} pagination requires parameter and next_cursor_field",
                        endpoint.id
                    ),
                ));
            }
            _ => {}
        }
    }
    for source in loaded.truth.expected_source_status.keys() {
        if !endpoint_ids.contains(source) {
            issues.push(issue(
                id,
                format!("truth references unknown endpoint {source}"),
            ));
        }
    }
    for observation in loaded.truth.expected_observations.values() {
        for source in &observation.source_names {
            if !endpoint_ids.contains(source) {
                issues.push(issue(
                    id,
                    format!("truth observation references unknown endpoint {source}"),
                ));
            }
        }
    }
    for endpoint in loaded.assertions.endpoint_requests.keys() {
        if !endpoint_ids.contains(endpoint) {
            issues.push(issue(
                id,
                format!("assertions reference unknown endpoint {endpoint}"),
            ));
        }
    }
    for expectation in &loaded.assertions.request_sequence {
        if !endpoint_ids.contains(&expectation.endpoint) {
            issues.push(issue(
                id,
                format!(
                    "request sequence references unknown endpoint {}",
                    expectation.endpoint
                ),
            ));
        }
        if let Some(endpoint) = loaded
            .scenario
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id == expectation.endpoint)
            && expectation
                .response_index
                .is_some_and(|index| index >= endpoint.replies.len())
        {
            issues.push(issue(
                id,
                format!(
                    "request sequence response_index exceeds reply sequence for {}",
                    expectation.endpoint
                ),
            ));
        }
    }
    if loaded.assertions.expected_requests < loaded.assertions.request_sequence.len() {
        issues.push(issue(
            id,
            "expected_requests must be at least request_sequence length",
        ));
    }
    if loaded.assertions.expected_unmatched_requests > loaded.assertions.expected_requests {
        issues.push(issue(
            id,
            "expected_unmatched_requests cannot exceed expected_requests",
        ));
    }
    issues
}

fn safe_fixture(directory: &Path, fixture: &str) -> bool {
    let Ok(root) = directory.canonicalize() else {
        return false;
    };
    let Ok(path) = directory.join(fixture).canonicalize() else {
        return false;
    };
    path.starts_with(root) && path.is_file()
}

fn issue(id: &str, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        scenario_id: id.to_owned(),
        message: message.into(),
    }
}

fn read_yaml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_yaml::from_str(&contents).with_context(|| format!("invalid YAML in {}", path.display()))
}
