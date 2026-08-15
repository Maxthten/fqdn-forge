use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::de::DeserializeOwned;

use crate::{
    Assertions, NetworkMode, PaginationMode, ProxyFault, Scenario, SourceKind, Truth,
    normalize_domain,
};

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
        let directory_id = directory
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let scenario: Scenario = read_yaml(&directory, directory_id, "scenario.yaml")?;
        let truth: Truth = read_yaml(&directory, directory_id, "truth.yaml")?;
        let assertions: Assertions = read_yaml(&directory, directory_id, "assertions.yaml")?;
        if scenario.id != directory_id {
            return Err(anyhow!(diagnostic(
                directory_id,
                "scenario.yaml",
                "id",
                format!(
                    "scenario id {} does not match directory {directory_id}",
                    scenario.id
                ),
                "set scenario.id to the directory name or rename the directory"
            )));
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
        let mut issues = self
            .scenarios
            .iter()
            .flat_map(validate_loaded)
            .collect::<Vec<_>>();
        if self.scenarios.len() != 90 {
            issues.push(issue_at(
                "repository",
                "scenarios",
                "count",
                format!("V1.3 requires exactly 90 scenarios; found {}", self.scenarios.len()),
                "add the 061-066 and 079-090 V1.3 scenario directories without removing baseline scenarios",
            ));
        }
        issues
    }
}

fn validate_loaded(loaded: &LoadedScenario) -> Vec<ValidationIssue> {
    let id = &loaded.scenario.id;
    let mut issues = Vec::new();
    if !matches!(loaded.scenario.version.as_str(), "1.2" | "1.2.1" | "1.3.0") {
        issues.push(issue_at(
            id,
            "scenario.yaml",
            "version",
            format!(
                "scenario version {} is unsupported for the V1.3 repository",
                loaded.scenario.version
            ),
            "set version to 1.2, 1.2.1 or 1.3.0",
        ));
    }
    let limits = &loaded.scenario.submission;
    if limits.max_bytes == 0
        || limits.max_findings == 0
        || limits.max_evidence_per_finding == 0
        || limits.max_string_bytes == 0
        || limits.max_tags == 0
        || limits.max_depth == 0
        || limits.max_submission_time_ms == 0
    {
        issues.push(issue_at(
            id,
            "scenario.yaml",
            "submission",
            "submission limits must all be greater than zero",
            "set bounded positive submission limits",
        ));
    }
    if loaded.scenario.runner.max_wire_response_bytes == 0
        || loaded.scenario.runner.max_decoded_response_bytes == 0
        || loaded.scenario.runner.max_expansion_ratio < 1
        || loaded.scenario.runner.max_decompression_time_ms == 0
        || loaded.scenario.runner.max_chunk_bytes == 0
        || loaded.scenario.runner.max_chunk_count == 0
    {
        issues.push(issue_at(
            id,
            "scenario.yaml",
            "runner",
            "compression and chunk limits must be positive and expansion ratio must be at least one",
            "set finite wire, decoded, chunk, ratio and decompression-time limits",
        ));
    }
    let network = &loaded.scenario.network_profile;
    if network.max_connections == 0 || network.virtual_timeout_ms == 0 {
        issues.push(issue_at(
            id,
            "scenario.yaml",
            "network_profile",
            "proxy connection and virtual timeout limits must be positive",
            "set finite max_connections and virtual_timeout_ms values",
        ));
    }
    if network.mode == NetworkMode::Direct
        && (network.proxy_must_be_used || network.fault != ProxyFault::None)
    {
        issues.push(issue_at(
            id,
            "scenario.yaml",
            "network_profile",
            "direct profile cannot require or fault a proxy",
            "use http_proxy/connect_proxy for proxy behavior or remove proxy fields",
        ));
    }
    let target_domain = loaded
        .scenario
        .root_domain
        .replace("$SEED", &loaded.scenario.seed.to_string());
    if normalize_domain(&target_domain).is_err() {
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
        for quota in &endpoint.quota {
            if quota.success_limit == 0
                || quota.retry_after_ms == 0
                || !(400..=599).contains(&quota.exhausted_status)
            {
                issues.push(issue_at(
                    id,
                    "scenario.yaml",
                    "endpoints.quota",
                    format!(
                        "endpoint {} has invalid bounded quota configuration",
                        endpoint.id
                    ),
                    "set a positive limit/retry time and an HTTP error status",
                ));
            }
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
                if endpoint.extract.as_ref().is_some_and(|extract| {
                    !matches!(
                        extract.kind,
                        crate::ExtractKind::Tokens
                            | crate::ExtractKind::Html
                            | crate::ExtractKind::Url
                    )
                }) =>
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
        for reply in &endpoint.replies {
            let source_count = usize::from(reply.body_file.is_some())
                + usize::from(reply.body.is_some())
                + usize::from(reply.body_text.is_some())
                + usize::from(reply.generator.is_some());
            if (reply.status == 204 && source_count != 0)
                || (reply.status != 204 && !reply.close_before_body && source_count != 1)
                || (reply.close_before_body && source_count != 0)
            {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} replies must have exactly one body source (or none for 204)",
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
            if reply.status == 204
                && (reply.body_file.is_some()
                    || reply.body.is_some()
                    || reply.body_text.is_some()
                    || reply.generator.is_some())
            {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} reply status 204 has contradictory body; fix by removing body source",
                        endpoint.id
                    ),
                ));
            }
            if (300..400).contains(&reply.status)
                && reply.redirect.is_none()
                && !reply
                    .headers
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case("location"))
            {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} redirect reply is missing Location; add redirect or Location",
                        endpoint.id
                    ),
                ));
            }
            if let Some(encoding) = &reply.encoding
                && !matches!(
                    encoding.to_ascii_lowercase().as_str(),
                    "identity" | "utf-8" | "utf8" | "gzip" | "deflate" | "br"
                )
            {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} reply encoding {encoding} is unsupported; use identity, gzip, deflate or br",
                        endpoint.id
                    ),
                ));
            }
            if reply.retry_after.is_some() && reply.status != 429 {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} Retry-After is only valid on 429; fix the status or remove retry_after",
                        endpoint.id
                    ),
                ));
            }
            if (reply.gzip_corrupt
                || reply.gzip_truncated
                || reply.encoding_corrupt
                || reply.encoding_truncated)
                && !reply.encoding.as_deref().is_some_and(|encoding| {
                    matches!(
                        encoding.to_ascii_lowercase().as_str(),
                        "gzip" | "deflate" | "br"
                    )
                })
            {
                issues.push(issue_at(
                    id,
                    "scenario.yaml",
                    "endpoints.replies.gzip",
                    format!(
                        "endpoint {} uses an encoding fault without a supported Content-Encoding",
                        endpoint.id
                    ),
                    "set encoding to gzip, deflate or br or remove the encoding fault",
                ));
            }
            if reply.transfer_mode == crate::TransferMode::Chunked && reply.chunk_count == 0 {
                issues.push(issue_at(
                    id,
                    "scenario.yaml",
                    "endpoints.replies.chunk_count",
                    format!(
                        "endpoint {} chunked reply needs at least one chunk",
                        endpoint.id
                    ),
                    "set chunk_count to a positive bounded value",
                ));
            }
            if reply.virtual_wait_ms > loaded.scenario.runner.retry_after_cap_ms {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} virtual_wait_ms exceeds retry_after_cap_ms; lower the virtual wait or raise the scenario cap",
                        endpoint.id
                    ),
                ));
            }
            if reply.wrong_cursor
                && (endpoint.pagination.mode == PaginationMode::None
                    || endpoint.pagination.mode == PaginationMode::Link
                    || endpoint.pagination.next_cursor_field.is_none())
            {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} wrong_cursor requires non-Link pagination with next_cursor_field",
                        endpoint.id
                    ),
                ));
            }
            if reply.duplicate_page && endpoint.extract.is_none() {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} duplicate_page requires an extract rule with an items field",
                        endpoint.id
                    ),
                ));
            }
            if reply.close_before_body && source_count != 0 {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} close_before_body conflicts with a configured body source; remove the body source",
                        endpoint.id
                    ),
                ));
            }
            if reply.oversized_bytes.is_some_and(|size| {
                size > loaded.scenario.runner.max_response_bytes.saturating_mul(16)
            }) {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} oversized_bytes is unreasonably large; keep the fixture bounded by the local response limit",
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
            PaginationMode::Link if endpoint.pagination.parameter.is_empty() => {
                issues.push(issue(
                    id,
                    format!(
                        "endpoint {} Link pagination requires a non-empty parameter",
                        endpoint.id
                    ),
                ));
            }
            PaginationMode::Link => {}
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
            issues.push(issue_at(
                id,
                "truth.yaml",
                "expected_source_status",
                format!("truth references unknown endpoint {source}"),
                "reference an endpoint declared in scenario.yaml",
            ));
        }
    }
    for observation in loaded.truth.expected_observations.values() {
        for source in &observation.source_names {
            if !endpoint_ids.contains(source) {
                issues.push(issue_at(
                    id,
                    "truth.yaml",
                    "expected_observations",
                    format!("truth observation references unknown endpoint {source}"),
                    "reference an endpoint declared in scenario.yaml",
                ));
            }
        }
    }
    for endpoint in loaded.assertions.endpoint_requests.keys() {
        if !endpoint_ids.contains(endpoint) {
            issues.push(issue_at(
                id,
                "assertions.yaml",
                "endpoint_requests",
                format!("assertions reference unknown endpoint {endpoint}"),
                "reference an endpoint declared in scenario.yaml",
            ));
        }
    }
    for expectation in &loaded.assertions.request_sequence {
        if !endpoint_ids.contains(&expectation.endpoint) {
            issues.push(issue_at(
                id,
                "assertions.yaml",
                "request_sequence",
                format!(
                    "request sequence references unknown endpoint {}",
                    expectation.endpoint
                ),
                "reference an endpoint declared in scenario.yaml",
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
            issues.push(issue_at(
                id,
                "assertions.yaml",
                "request_sequence.response_index",
                format!(
                    "request sequence response_index exceeds reply sequence for {}",
                    expectation.endpoint
                ),
                "use an index that exists in the endpoint reply sequence",
            ));
        }
    }
    if loaded.assertions.expected_requests < loaded.assertions.request_sequence.len() {
        issues.push(issue_at(
            id,
            "assertions.yaml",
            "expected_requests",
            "expected_requests must be at least request_sequence length",
            "increase expected_requests or shorten request_sequence",
        ));
    }
    if loaded.assertions.expected_unmatched_requests > loaded.assertions.expected_requests {
        issues.push(issue_at(
            id,
            "assertions.yaml",
            "expected_unmatched_requests",
            "expected_unmatched_requests cannot exceed expected_requests",
            "lower expected_unmatched_requests or raise expected_requests",
        ));
    }
    if let Some(number) = id
        .split('-')
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        && (67..=78).contains(&number)
    {
        if loaded.scenario.version != "1.2.1" {
            issues.push(issue_at(
                id,
                "scenario.yaml",
                "version",
                "V1.2.1 contract scenarios must use version 1.2.1",
                "set version to 1.2.1",
            ));
        }
        if loaded.scenario.endpoints.is_empty() {
            issues.push(issue_at(
                id,
                "scenario.yaml",
                "endpoints",
                "external contract scenarios need at least one manifest source",
                "add a local source endpoint",
            ));
        }
    }
    if let Some(number) = id
        .split('-')
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        && ((61..=66).contains(&number) || (79..=90).contains(&number))
    {
        if loaded.scenario.version != "1.3.0" {
            issues.push(issue_at(
                id,
                "scenario.yaml",
                "version",
                "V1.3 network, quota and transport scenarios must use version 1.3.0",
                "set version to 1.3.0",
            ));
        }
        let assertion_count = 1
            + usize::from(loaded.assertions.expected_unmatched_requests > 0)
            + loaded.assertions.endpoint_requests.len()
            + loaded.assertions.required_paths.len()
            + loaded.assertions.forbidden_paths.len()
            + loaded.assertions.request_sequence.len()
            + usize::from(loaded.assertions.timing.min_virtual_wait_ms.is_some())
            + usize::from(loaded.assertions.timing.max_virtual_wait_ms.is_some())
            + usize::from(loaded.assertions.expected_rejected_egress_attempts > 0)
            + usize::from(loaded.assertions.expected_proxy_requests.is_some())
            + usize::from(loaded.assertions.expected_quota_decisions.is_some())
            + usize::from(loaded.assertions.require_proxy.is_some())
            + usize::from(loaded.assertions.forbid_direct_source)
            + usize::from(loaded.assertions.require_quota_rate_limited)
            + usize::from(loaded.assertions.required_content_encoding.is_some())
            + usize::from(loaded.assertions.required_transfer_mode.is_some())
            + usize::from(loaded.assertions.required_transport_fault.is_some());
        if assertion_count < 8 {
            issues.push(issue_at(
                id,
                "assertions.yaml",
                "assertions",
                "each V1.3 scenario needs at least eight observable assertions",
                "add source, proxy, quota, transport, wait, egress or request assertions",
            ));
        }
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
    issue_at(
        id,
        "scenario.yaml",
        "scenario",
        message,
        "correct the reported scenario field and rerun `lab-cli validate`",
    )
}

fn issue_at(
    id: &str,
    file: &str,
    field: &str,
    reason: impl Into<String>,
    hint: impl AsRef<str>,
) -> ValidationIssue {
    ValidationIssue {
        scenario_id: id.to_owned(),
        message: diagnostic(id, file, field, reason, hint),
    }
}

fn diagnostic(
    id: &str,
    file: &str,
    field: &str,
    reason: impl Into<String>,
    hint: impl AsRef<str>,
) -> String {
    format!(
        "scenario: {id}; file: scenarios/{id}/{file}; field: {field}; reason: {}; hint: {}",
        reason.into(),
        hint.as_ref()
    )
}

fn read_yaml<T: DeserializeOwned>(directory: &Path, id: &str, file: &str) -> Result<T> {
    let path = directory.join(file);
    let contents = fs::read_to_string(&path).map_err(|error| {
        anyhow!(diagnostic(
            id,
            file,
            "document",
            format!("cannot read {}: {error}", path.display()),
            "create the required YAML file and ensure it is readable"
        ))
    })?;
    serde_yaml::from_str(&contents).map_err(|error| {
        anyhow!(diagnostic(
            id,
            file,
            "document",
            format!("invalid YAML: {error}"),
            "correct the YAML structure and field names"
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use uuid::Uuid;

    use super::ScenarioRepository;

    fn temporary_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("fqdn-forge-{label}-{}", Uuid::new_v4()))
    }

    #[test]
    fn validation_diagnostics_identify_the_referenced_source_file_and_field() {
        let root = temporary_root("validation-diagnostic");
        let scenario = root.join("bad-contract");
        fs::create_dir_all(&scenario).expect("scenario directory");
        fs::write(
            scenario.join("scenario.yaml"),
            r#"id: bad-contract
name: invalid truth reference
description: validates diagnostic metadata
version: "1.2"
root_domain: acme.test
seed: 1
allow_duplicates: false
allow_concurrent: true
endpoints:
  - id: source
    source_kind: generic_json
    match: { method: GET, path: /v1/source }
    extract: { items_field: items, candidate_field: host }
    replies: [{ status: 200, body: { items: [] } }]
"#,
        )
        .expect("scenario YAML");
        fs::write(
            scenario.join("truth.yaml"),
            "expected_source_status: { missing-source: success }\n",
        )
        .expect("truth YAML");
        fs::write(scenario.join("assertions.yaml"), "expected_requests: 0\n")
            .expect("assertions YAML");

        let repository = ScenarioRepository::load(&root).expect("load test repository");
        let issues = repository.validate();
        let message = &issues
            .iter()
            .find(|issue| issue.message.contains("missing-source"))
            .expect("truth issue")
            .message;
        assert!(message.contains("scenario: bad-contract"));
        assert!(message.contains("file: scenarios/bad-contract/truth.yaml"));
        assert!(message.contains("field: expected_source_status"));
        assert!(message.contains("reason:"));
        assert!(message.contains("hint:"));

        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn malformed_yaml_diagnostics_include_a_scenario_id_and_repair_hint() {
        let root = temporary_root("malformed-yaml");
        let scenario = root.join("bad-yaml");
        fs::create_dir_all(&scenario).expect("scenario directory");
        fs::write(scenario.join("scenario.yaml"), "id: [unterminated\n")
            .expect("invalid scenario YAML");

        let error = ScenarioRepository::load(&root)
            .expect_err("invalid YAML must be rejected")
            .to_string();
        assert!(error.contains("scenario: bad-yaml"));
        assert!(error.contains("file: scenarios/bad-yaml/scenario.yaml"));
        assert!(error.contains("field: document"));
        assert!(error.contains("reason: invalid YAML"));
        assert!(error.contains("hint: correct the YAML structure and field names"));

        fs::remove_dir_all(root).expect("remove test directory");
    }
}
