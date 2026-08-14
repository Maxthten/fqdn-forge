use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use chrono::{DateTime, Utc};
use reqwest::{
    Client, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use serde_json::Value;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{
    CandidateError, CollectorRun, EgressGuard, Endpoint, ExtractKind, FilterReason,
    FilteredCandidate, HttpMethod, Observation, PaginationMode, Scenario, SourceStatus,
    accept_candidate, domainish_tokens, host_from_url,
};

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("invalid local service base URL: {0}")]
    InvalidBaseUrl(String),
    #[error(transparent)]
    Egress(#[from] crate::EgressViolation),
}

pub struct ReferenceRunner {
    client: Client,
    guard: EgressGuard,
}

impl ReferenceRunner {
    pub fn new(guard: EgressGuard) -> Result<Self, RunnerError> {
        let client = Client::builder()
            .redirect(Policy::none())
            .build()
            .map_err(|error| RunnerError::InvalidBaseUrl(error.to_string()))?;
        Ok(Self { client, guard })
    }

    #[must_use]
    pub fn guard(&self) -> &EgressGuard {
        &self.guard
    }

    pub async fn run(
        &self,
        base_url: &str,
        scenario: &Scenario,
        run_id: Uuid,
        profile: &str,
    ) -> Result<CollectorRun, RunnerError> {
        let started = Instant::now();
        self.guard.validate(base_url)?;
        let base_url =
            Url::parse(base_url).map_err(|error| RunnerError::InvalidBaseUrl(error.to_string()))?;
        let root_domain = crate::normalize_domain(&scenario.root_domain)
            .map_err(|_| RunnerError::InvalidBaseUrl("invalid scenario root domain".to_owned()))?;
        let mut run = CollectorRun::default();
        let mut seen = BTreeSet::new();
        let mut sent = 0_usize;
        for endpoint in &scenario.endpoints {
            if scenario
                .runner
                .cancel_after_requests
                .is_some_and(|limit| sent >= limit)
            {
                run.source_statuses
                    .insert(endpoint.id.clone(), SourceStatus::Cancelled);
                continue;
            }
            let (status, requests) = self
                .run_endpoint(
                    &base_url,
                    scenario,
                    endpoint,
                    &root_domain,
                    run_id,
                    profile,
                    &mut run,
                    &mut seen,
                )
                .await;
            sent += requests;
            run.source_statuses.insert(endpoint.id.clone(), status);
        }
        run.metrics.unique_fqdns = seen.len();
        run.metrics.duplicate_candidates = run
            .filtered
            .iter()
            .filter(|candidate| candidate.reason == FilterReason::Duplicate)
            .count();
        run.metrics.filtered_candidates = run
            .filtered
            .iter()
            .filter(|candidate| candidate.reason != FilterReason::Duplicate)
            .count();
        run.metrics.elapsed_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        run.metrics.estimated_buffer_bytes = run
            .metrics
            .response_bytes
            .saturating_add(
                run.observations
                    .iter()
                    .map(|observation| observation.fqdn.len() + observation.source_name.len())
                    .sum::<usize>(),
            )
            .saturating_add(
                run.filtered
                    .iter()
                    .map(|candidate| candidate.value.len() + candidate.source_name.len())
                    .sum::<usize>(),
            );
        Ok(run)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_endpoint(
        &self,
        base_url: &Url,
        scenario: &Scenario,
        endpoint: &Endpoint,
        root_domain: &str,
        run_id: Uuid,
        profile: &str,
        run: &mut CollectorRun,
        seen: &mut BTreeSet<String>,
    ) -> (SourceStatus, usize) {
        let mut request_count = 0_usize;
        let mut cursor: Option<String> = None;
        let mut seen_cursors = BTreeSet::new();
        loop {
            let url = match endpoint_url(base_url, endpoint, scenario, run_id, cursor.as_deref()) {
                Ok(url) => url,
                Err(_) => return (SourceStatus::Failed, request_count),
            };
            if self.guard.validate(url.as_str()).is_err() {
                return (SourceStatus::Failed, request_count);
            }
            let headers = match headers_for(endpoint, scenario, run_id, profile) {
                Ok(headers) => headers,
                Err(_) => return (SourceStatus::Failed, request_count),
            };
            let request = match endpoint.request_match.method {
                HttpMethod::Get => self.client.get(url),
                HttpMethod::Post => self.client.post(url),
            }
            .headers(headers);
            let request = if let Some(body) = &endpoint.request_body {
                request.json(body)
            } else {
                request
            };
            request_count += 1;
            let response = match tokio::time::timeout(
                std::time::Duration::from_millis(scenario.runner.timeout_ms),
                request.send(),
            )
            .await
            {
                Ok(Ok(response)) => response,
                Ok(Err(_)) => return (SourceStatus::Failed, request_count),
                Err(_) => return (SourceStatus::TimedOut, request_count),
            };
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                if endpoint.allow_retry {
                    let retry_after = response
                        .headers()
                        .get("retry-after")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(0);
                    run.virtual_waited_ms += retry_after.saturating_mul(1_000);
                    continue;
                }
                return (SourceStatus::RateLimited, request_count);
            }
            if matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ) {
                return (SourceStatus::AuthFailed, request_count);
            }
            if !response.status().is_success() {
                return (SourceStatus::Failed, request_count);
            }
            if response
                .content_length()
                .is_some_and(|length| length > scenario.runner.max_response_bytes as u64)
            {
                run.filtered.push(FilteredCandidate {
                    value: endpoint.id.clone(),
                    reason: FilterReason::ResponseTooLarge,
                    source_name: endpoint.id.clone(),
                });
                return (SourceStatus::Failed, request_count);
            }
            let bytes = match tokio::time::timeout(
                std::time::Duration::from_millis(scenario.runner.timeout_ms),
                response.bytes(),
            )
            .await
            {
                Ok(Ok(bytes)) if bytes.len() <= scenario.runner.max_response_bytes => bytes,
                Ok(Ok(_)) => {
                    run.filtered.push(FilteredCandidate {
                        value: endpoint.id.clone(),
                        reason: FilterReason::ResponseTooLarge,
                        source_name: endpoint.id.clone(),
                    });
                    return (SourceStatus::Failed, request_count);
                }
                Ok(Err(_)) => return (SourceStatus::Failed, request_count),
                Err(_) => return (SourceStatus::TimedOut, request_count),
            };
            run.metrics.response_bytes = run.metrics.response_bytes.saturating_add(bytes.len());
            let (next_cursor, records, raw_records) = match extract_records(endpoint, &bytes) {
                Ok(result) => result,
                Err(_) => return (SourceStatus::Failed, request_count),
            };
            run.metrics.raw_records = run.metrics.raw_records.saturating_add(raw_records);
            let context = CandidateContext {
                endpoint,
                root_domain,
                include_root: scenario.include_root,
            };
            for record in records {
                record_candidate(record, &context, run, seen);
            }
            if endpoint.pagination.mode == PaginationMode::None || next_cursor.is_none() {
                return (SourceStatus::Success, request_count);
            }
            let next_cursor = next_cursor.expect("checked above");
            if !seen_cursors.insert(next_cursor.clone()) {
                run.filtered.push(FilteredCandidate {
                    value: next_cursor,
                    reason: FilterReason::PaginationLoop,
                    source_name: endpoint.id.clone(),
                });
                return (SourceStatus::Failed, request_count);
            }
            cursor = Some(next_cursor);
        }
    }
}

struct ExtractedRecord {
    candidate: String,
    record_id: Option<String>,
    observed_at: Option<DateTime<Utc>>,
}

fn endpoint_url(
    base_url: &Url,
    endpoint: &Endpoint,
    scenario: &Scenario,
    run_id: Uuid,
    cursor: Option<&str>,
) -> Result<Url, url::ParseError> {
    let mut url = base_url.join(&endpoint.request_match.path)?;
    let mut query = BTreeMap::new();
    for (name, rule) in &endpoint.request_match.query {
        if let Some(value) = &rule.equals {
            query.insert(name, resolve_variable(value, scenario, run_id, cursor));
        }
    }
    if endpoint.pagination.mode != PaginationMode::None
        && let Some(cursor) = cursor
    {
        query.insert(&endpoint.pagination.parameter, cursor.to_owned());
    }
    url.query_pairs_mut().extend_pairs(query);
    Ok(url)
}

fn headers_for(
    endpoint: &Endpoint,
    scenario: &Scenario,
    run_id: Uuid,
    profile: &str,
) -> Result<HeaderMap, ()> {
    let omitted = endpoint
        .omit_headers
        .iter()
        .map(|header| header.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut values = endpoint.request_headers.clone();
    for (name, rule) in &endpoint.request_match.headers {
        if !omitted.contains(&name.to_ascii_lowercase())
            && !values.contains_key(name)
            && let Some(value) = &rule.equals
        {
            values.insert(
                name.clone(),
                resolve_variable(value, scenario, run_id, None),
            );
        }
    }
    values.insert("x-lab-run-id".to_owned(), run_id.to_string());
    values.insert("x-lab-data-profile".to_owned(), profile.to_owned());
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?;
        let value = HeaderValue::from_str(&value).map_err(|_| ())?;
        headers.insert(name, value);
    }
    Ok(headers)
}

fn resolve_variable(
    value: &str,
    scenario: &Scenario,
    run_id: Uuid,
    cursor: Option<&str>,
) -> String {
    match value {
        "$ROOT_DOMAIN" => scenario.root_domain.clone(),
        "$RUN_ID" => run_id.to_string(),
        "$SEED" => scenario.seed.to_string(),
        "$CURSOR" => cursor.unwrap_or_default().to_owned(),
        _ => value.to_owned(),
    }
}

fn extract_records(
    endpoint: &Endpoint,
    bytes: &[u8],
) -> Result<(Option<String>, Vec<ExtractedRecord>, usize), serde_json::Error> {
    let value: Value = serde_json::from_slice(bytes)?;
    let Some(extract) = &endpoint.extract else {
        return Ok((None, Vec::new(), 0));
    };
    let items = value.get(&extract.items_field).and_then(Value::as_array);
    let raw_records = items.map_or(0, Vec::len);
    let records = items
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let object = item.as_object()?;
            let candidate = object.get(&extract.candidate_field)?.as_str()?.to_owned();
            let record_id = object
                .get(&extract.record_id_field)
                .and_then(Value::as_str)
                .map(str::to_owned);
            let observed_at = extract
                .timestamp_field
                .as_ref()
                .and_then(|field| object.get(field))
                .and_then(Value::as_str)
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&Utc));
            Some(ExtractedRecord {
                candidate,
                record_id,
                observed_at,
            })
        })
        .collect();
    let next_cursor = endpoint
        .pagination
        .next_cursor_field
        .as_ref()
        .and_then(|field| value.get(field))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok((next_cursor, records, raw_records))
}

struct CandidateContext<'a> {
    endpoint: &'a Endpoint,
    root_domain: &'a str,
    include_root: bool,
}

fn record_candidate(
    record: ExtractedRecord,
    context: &CandidateContext<'_>,
    run: &mut CollectorRun,
    seen: &mut BTreeSet<String>,
) {
    let ExtractedRecord {
        candidate,
        record_id,
        observed_at,
    } = record;
    let endpoint = context.endpoint;
    run.metrics.parsed_candidates = run.metrics.parsed_candidates.saturating_add(1);
    let candidates = match endpoint
        .extract
        .as_ref()
        .map(|extract| extract.kind)
        .unwrap_or(ExtractKind::Direct)
    {
        ExtractKind::Direct => vec![candidate],
        ExtractKind::Url => match host_from_url(&candidate) {
            Ok(host) => vec![host],
            Err(CandidateError::Filtered(reason)) => {
                run.filtered.push(FilteredCandidate {
                    value: candidate,
                    reason,
                    source_name: endpoint.id.clone(),
                });
                return;
            }
        },
        ExtractKind::Tokens => domainish_tokens(&candidate),
    };
    for value in candidates {
        match accept_candidate(&value, context.root_domain, context.include_root) {
            Ok(fqdn) => {
                if !seen.insert(fqdn.clone()) {
                    run.filtered.push(FilteredCandidate {
                        value: fqdn.clone(),
                        reason: FilterReason::Duplicate,
                        source_name: endpoint.id.clone(),
                    });
                }
                // Keep every provenance observation even after the FQDN output set has
                // deduplicated it: truth assertions need to verify multi-source evidence.
                run.observations.push(Observation {
                    fqdn,
                    source_kind: endpoint.source_kind,
                    source_name: endpoint.id.clone(),
                    record_id: record_id.clone(),
                    observed_at,
                });
            }
            Err(CandidateError::Filtered(reason)) => run.filtered.push(FilteredCandidate {
                value,
                reason,
                source_name: endpoint.id.clone(),
            }),
        }
    }
}
