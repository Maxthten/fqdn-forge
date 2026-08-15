use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    time::Instant,
};

use brotli::Decompressor;
use chrono::{DateTime, Utc};
use csv::ReaderBuilder;
use flate2::read::{GzDecoder, ZlibDecoder};
use futures_util::StreamExt;
use reqwest::{
    Client, Proxy, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use scraper::{Html, Selector};
use serde_json::Value;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use url::Url;
use uuid::Uuid;

use crate::{
    CandidateError, CollectorRun, ContentFormat, EgressGuard, Endpoint, ExtractKind, FilterReason,
    FilteredCandidate, HttpMethod, NetworkMode, Observation, PaginationMode, Scenario,
    SourceStatus, accept_candidate, domainish_tokens, host_from_url,
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
            .no_proxy()
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
        self.run_with_proxy(base_url, None, scenario, run_id, profile)
            .await
    }

    pub async fn run_with_proxy(
        &self,
        base_url: &str,
        proxy_url: Option<&str>,
        scenario: &Scenario,
        run_id: Uuid,
        profile: &str,
    ) -> Result<CollectorRun, RunnerError> {
        let started = Instant::now();
        self.guard.validate(base_url)?;
        let base_url =
            Url::parse(base_url).map_err(|error| RunnerError::InvalidBaseUrl(error.to_string()))?;
        let root_domain = materialize(&scenario.root_domain, scenario, run_id, None);
        let root_domain = crate::normalize_domain(&root_domain)
            .map_err(|_| RunnerError::InvalidBaseUrl("invalid scenario root domain".to_owned()))?;
        let mut run = CollectorRun::default();
        if scenario.network_profile.mode == NetworkMode::ConnectProxy {
            let status = match proxy_url {
                Some(proxy_url) => {
                    connect_proxy_probe(proxy_url, &base_url, run_id, scenario).await
                }
                None => SourceStatus::Failed,
            };
            for endpoint in &scenario.endpoints {
                run.source_statuses.insert(endpoint.id.clone(), status);
            }
            run.metrics.request_count = usize::from(!scenario.endpoints.is_empty());
            run.metrics.elapsed_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
            return Ok(run);
        }
        let client = if scenario.network_profile.mode == NetworkMode::HttpProxy {
            let proxy_url = proxy_url
                .ok_or_else(|| RunnerError::InvalidBaseUrl("missing local proxy URL".to_owned()))?;
            self.guard.validate(proxy_url)?;
            Client::builder()
                .redirect(Policy::none())
                .no_proxy()
                .proxy(
                    Proxy::http(proxy_url)
                        .map_err(|error| RunnerError::InvalidBaseUrl(error.to_string()))?,
                )
                .build()
                .map_err(|error| RunnerError::InvalidBaseUrl(error.to_string()))?
        } else {
            self.client.clone()
        };
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
                run.metrics.cancelled = true;
                run.metrics.cancellation_reason = Some("cancel_after_requests".to_owned());
                continue;
            }
            let (status, _) = self
                .run_endpoint(
                    &client,
                    &base_url,
                    scenario,
                    endpoint,
                    &root_domain,
                    run_id,
                    profile,
                    &mut run,
                    &mut seen,
                    &mut sent,
                )
                .await;
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
        run.metrics.request_count = sent;
        run.metrics.virtual_wait_ms = run.virtual_waited_ms;
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
        run.metrics.peak_estimated_buffer_bytes = run.metrics.estimated_buffer_bytes;
        Ok(run)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_endpoint(
        &self,
        client: &Client,
        base_url: &Url,
        scenario: &Scenario,
        endpoint: &Endpoint,
        root_domain: &str,
        run_id: Uuid,
        profile: &str,
        run: &mut CollectorRun,
        seen: &mut BTreeSet<String>,
        sent: &mut usize,
    ) -> (SourceStatus, usize) {
        let mut request_count = 0_usize;
        let mut cursor: Option<String> = None;
        let mut current_url: Option<Url> = None;
        let mut seen_cursors = BTreeSet::new();
        let mut retries = 0_usize;
        let mut client_virtual_wait_ms = 0_u64;
        loop {
            if scenario
                .runner
                .cancel_after_requests
                .is_some_and(|limit| *sent >= limit)
            {
                run.metrics.cancelled = true;
                run.metrics.cancellation_reason = Some("cancel_after_requests".to_owned());
                return (SourceStatus::Cancelled, request_count);
            }
            let url = match current_url.take() {
                Some(url) => url,
                None => match endpoint_url(base_url, endpoint, scenario, run_id, cursor.as_deref())
                {
                    Ok(url) => url,
                    Err(_) => return (SourceStatus::Failed, request_count),
                },
            };
            if self.guard.validate(url.as_str()).is_err() {
                run.metrics.blocked_egress = true;
                run.filtered.push(FilteredCandidate {
                    value: url.to_string(),
                    reason: FilterReason::BlockedEgress,
                    source_name: endpoint.id.clone(),
                });
                return (SourceStatus::Blocked, request_count);
            }
            let headers = match headers_for(
                endpoint,
                scenario,
                run_id,
                profile,
                cursor.as_deref(),
                client_virtual_wait_ms,
            ) {
                Ok(headers) => headers,
                Err(_) => return (SourceStatus::Failed, request_count),
            };
            let method = endpoint.request_match.method;
            let request = match method {
                HttpMethod::Get => client.get(url.clone()),
                HttpMethod::Post => client.post(url.clone()),
                HttpMethod::Put => client.put(url.clone()),
                HttpMethod::Delete => client.delete(url.clone()),
            }
            .headers(headers);
            let request = request_body(request, endpoint, scenario, run_id, cursor.as_deref());
            *sent += 1;
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
            let status = response.status();
            let virtual_wait = response
                .headers()
                .get("x-lab-virtual-wait-ms")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
                .min(scenario.runner.retry_after_cap_ms);
            run.virtual_waited_ms = run.virtual_waited_ms.saturating_add(virtual_wait);
            client_virtual_wait_ms = client_virtual_wait_ms.saturating_add(virtual_wait);
            if status.is_redirection() {
                let Some(location) = response
                    .headers()
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                else {
                    return (SourceStatus::Failed, request_count);
                };
                let target = match url.join(location) {
                    Ok(target) => target,
                    Err(_) => return (SourceStatus::Failed, request_count),
                };
                if self.guard.validate(target.as_str()).is_err() {
                    run.metrics.blocked_egress = true;
                    run.filtered.push(FilteredCandidate {
                        value: target.to_string(),
                        reason: FilterReason::BlockedEgress,
                        source_name: endpoint.id.clone(),
                    });
                    return (SourceStatus::Blocked, request_count);
                }
                return (SourceStatus::Failed, request_count);
            }
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                if endpoint.allow_retry && retries < scenario.runner.max_retries {
                    retries += 1;
                    run.metrics.retry_count = run.metrics.retry_count.saturating_add(1);
                    let wait = response
                        .headers()
                        .get("retry-after")
                        .and_then(|value| value.to_str().ok())
                        .map(parse_retry_after_ms)
                        .unwrap_or(0)
                        .min(scenario.runner.retry_after_cap_ms);
                    run.virtual_waited_ms = run.virtual_waited_ms.saturating_add(wait);
                    client_virtual_wait_ms = client_virtual_wait_ms.saturating_add(wait);
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
            if response.status() == StatusCode::NO_CONTENT {
                return (SourceStatus::Success, request_count);
            }
            if response.content_length().is_some_and(|length| {
                length > scenario.runner.effective_max_wire_response_bytes() as u64
            }) {
                run.filtered.push(FilteredCandidate {
                    value: endpoint.id.clone(),
                    reason: FilterReason::ResponseTooLarge,
                    source_name: endpoint.id.clone(),
                });
                return (SourceStatus::Failed, request_count);
            }
            let response_headers = response.headers().clone();
            let bytes = match read_limited_response(
                response,
                scenario.runner.effective_max_wire_response_bytes(),
                scenario.runner.timeout_ms,
                scenario.runner.max_chunk_bytes,
                scenario.runner.max_chunk_count,
            )
            .await
            {
                Ok(bytes) => bytes,
                Err(ReadResponseError::TooLarge) => {
                    run.filtered.push(FilteredCandidate {
                        value: endpoint.id.clone(),
                        reason: FilterReason::ResponseTooLarge,
                        source_name: endpoint.id.clone(),
                    });
                    return (SourceStatus::Failed, request_count);
                }
                Err(ReadResponseError::ChunkTooLarge | ReadResponseError::TooManyChunks) => {
                    run.metrics.compression_limit_violation =
                        Some("chunk resource limit exceeded".to_owned());
                    run.filtered.push(FilteredCandidate {
                        value: endpoint.id.clone(),
                        reason: FilterReason::ResponseTooLarge,
                        source_name: endpoint.id.clone(),
                    });
                    return (SourceStatus::Failed, request_count);
                }
                Err(ReadResponseError::TimedOut) => return (SourceStatus::TimedOut, request_count),
                Err(ReadResponseError::Body) => return (SourceStatus::Failed, request_count),
            };
            run.metrics.wire_response_bytes =
                run.metrics.wire_response_bytes.saturating_add(bytes.len());
            let decoded = match decode_response(&response_headers, &bytes, scenario) {
                Ok(decoded) => decoded,
                Err(DecodeResponseError::Limit(reason)) => {
                    run.metrics.compression_limit_violation = Some(reason.to_owned());
                    run.filtered.push(FilteredCandidate {
                        value: endpoint.id.clone(),
                        reason: FilterReason::ResponseTooLarge,
                        source_name: endpoint.id.clone(),
                    });
                    return (SourceStatus::Failed, request_count);
                }
                Err(DecodeResponseError::Invalid) => {
                    run.filtered.push(FilteredCandidate {
                        value: endpoint.id.clone(),
                        reason: FilterReason::Malformed,
                        source_name: endpoint.id.clone(),
                    });
                    return (SourceStatus::Failed, request_count);
                }
            };
            run.metrics.response_bytes = run.metrics.response_bytes.saturating_add(decoded.len());
            run.metrics.decoded_response_bytes = run
                .metrics
                .decoded_response_bytes
                .saturating_add(decoded.len());
            let extracted = match extract_records(endpoint, &response_headers, &decoded) {
                Ok(result) => result,
                Err(_) => {
                    run.filtered.push(FilteredCandidate {
                        value: endpoint.id.clone(),
                        reason: FilterReason::Malformed,
                        source_name: endpoint.id.clone(),
                    });
                    return (SourceStatus::Failed, request_count);
                }
            };
            run.metrics.raw_records = run
                .metrics
                .raw_records
                .saturating_add(extracted.raw_records);
            let context = CandidateContext {
                endpoint,
                root_domain,
                include_root: scenario.include_root,
            };
            for record in extracted.records {
                record_candidate(record, &context, run, seen);
            }
            let (next_cursor, next_url) = if endpoint.pagination.mode == PaginationMode::Link {
                (None, extracted.next_link)
            } else {
                (extracted.next_cursor, None)
            };
            if next_cursor.is_none() && next_url.is_none() {
                return (SourceStatus::Success, request_count);
            }
            let token = next_cursor
                .clone()
                .or(next_url.clone())
                .expect("checked above");
            if !seen_cursors.insert(token.clone()) {
                run.filtered.push(FilteredCandidate {
                    value: token,
                    reason: FilterReason::PaginationLoop,
                    source_name: endpoint.id.clone(),
                });
                return (SourceStatus::Failed, request_count);
            }
            cursor = next_cursor;
            if let Some(link) = next_url {
                current_url = Some(match base_url.join(&link) {
                    Ok(url) => url,
                    Err(_) => return (SourceStatus::Failed, request_count),
                });
            }
        }
    }
}

struct ExtractedRecord {
    candidate: String,
    record_id: Option<String>,
    observed_at: Option<DateTime<Utc>>,
    tags: Vec<String>,
    confidence: Option<f64>,
    evidence: BTreeMap<String, String>,
}

struct Extraction {
    next_cursor: Option<String>,
    next_link: Option<String>,
    records: Vec<ExtractedRecord>,
    raw_records: usize,
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
            query.insert(name.clone(), materialize(value, scenario, run_id, cursor));
        }
    }
    match endpoint.pagination.mode {
        PaginationMode::Cursor if cursor.is_some() && !endpoint.pagination.in_body => {
            query.insert(
                endpoint.pagination.parameter.clone(),
                cursor.unwrap_or_default().to_owned(),
            );
        }
        PaginationMode::Page | PaginationMode::Offset
            if cursor.is_none() && !endpoint.pagination.in_body =>
        {
            query.insert(
                endpoint.pagination.parameter.clone(),
                endpoint.pagination.start.to_string(),
            );
        }
        PaginationMode::Page | PaginationMode::Offset
            if cursor.is_some() && !endpoint.pagination.in_body =>
        {
            query.insert(
                endpoint.pagination.parameter.clone(),
                cursor.unwrap_or_default().to_owned(),
            );
        }
        _ => {}
    }
    url.query_pairs_mut().extend_pairs(query);
    Ok(url)
}

fn request_body(
    request: reqwest::RequestBuilder,
    endpoint: &Endpoint,
    scenario: &Scenario,
    run_id: Uuid,
    cursor: Option<&str>,
) -> reqwest::RequestBuilder {
    let Some(body) = &endpoint.request_body else {
        return request;
    };
    let mut body = materialize_value(body, scenario, run_id, cursor);
    if endpoint.pagination.in_body
        && endpoint.pagination.mode != PaginationMode::None
        && let Value::Object(map) = &mut body
    {
        let value = cursor
            .map(str::to_owned)
            .unwrap_or_else(|| endpoint.pagination.start.to_string());
        map.insert(endpoint.pagination.parameter.clone(), Value::String(value));
    }
    request.json(&body)
}

fn headers_for(
    endpoint: &Endpoint,
    scenario: &Scenario,
    run_id: Uuid,
    profile: &str,
    cursor: Option<&str>,
    client_virtual_wait_ms: u64,
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
            values.insert(name.clone(), materialize(value, scenario, run_id, cursor));
        }
    }
    values.insert("x-lab-run-id".to_owned(), run_id.to_string());
    values.insert("x-lab-data-profile".to_owned(), profile.to_owned());
    values.insert(
        "x-lab-client-virtual-wait-ms".to_owned(),
        client_virtual_wait_ms.to_string(),
    );
    if scenario.network_profile.mode == NetworkMode::HttpProxy {
        let capability = format!("cap-{run_id}");
        values.insert(
            "proxy-authorization".to_owned(),
            format!("Lab {capability}"),
        );
        values.insert("x-lab-proxy-capability".to_owned(), capability);
    }
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?;
        let value = HeaderValue::from_str(&materialize(&value, scenario, run_id, cursor))
            .map_err(|_| ())?;
        headers.insert(name, value);
    }
    Ok(headers)
}

async fn connect_proxy_probe(
    proxy_url: &str,
    source_url: &Url,
    run_id: Uuid,
    scenario: &Scenario,
) -> SourceStatus {
    let Ok(proxy) = Url::parse(proxy_url) else {
        return SourceStatus::Failed;
    };
    if proxy.scheme() != "http" || proxy.host_str() != Some("127.0.0.1") {
        return SourceStatus::Blocked;
    }
    let Some(proxy_port) = proxy.port_or_known_default() else {
        return SourceStatus::Failed;
    };
    let Some(target_port) = source_url.port_or_known_default() else {
        return SourceStatus::Failed;
    };
    let mut stream = match TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, proxy_port)).await {
        Ok(stream) => stream,
        Err(_) => return SourceStatus::Failed,
    };
    let capability = format!("cap-{run_id}");
    let request = format!(
        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nx-lab-run-id: {run_id}\r\nProxy-Authorization: Lab {capability}\r\nx-lab-proxy-capability: {capability}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).await.is_err() {
        return SourceStatus::Failed;
    }
    let mut response = [0_u8; 512];
    let Ok(Ok(count)) = tokio::time::timeout(
        std::time::Duration::from_millis(scenario.network_profile.virtual_timeout_ms.max(50)),
        stream.read(&mut response),
    )
    .await
    else {
        return SourceStatus::TimedOut;
    };
    let response = String::from_utf8_lossy(&response[..count]);
    if response.starts_with("HTTP/1.1 200") {
        SourceStatus::Success
    } else if response.starts_with("HTTP/1.1 407") || response.starts_with("HTTP/1.1 403") {
        SourceStatus::AuthFailed
    } else {
        SourceStatus::Failed
    }
}

fn materialize(value: &str, scenario: &Scenario, run_id: Uuid, cursor: Option<&str>) -> String {
    let target_domain = scenario
        .root_domain
        .replace("$SEED", &scenario.seed.to_string());
    let continuation = cursor.unwrap_or_default();
    let page = if continuation.is_empty() {
        "1"
    } else {
        continuation
    };
    let offset = if continuation.is_empty() {
        "0"
    } else {
        continuation
    };
    let synthetic_record_id = format!("synthetic-{}-{}", scenario.seed, page);
    let observation_time = format!("2025-01-{:02}T00:00:00Z", scenario.seed % 28 + 1);
    value
        .replace("$TARGET_DOMAIN", &target_domain)
        .replace("$ROOT_DOMAIN", &target_domain)
        .replace("$SEED", &scenario.seed.to_string())
        .replace("$RUN_ID", &run_id.to_string())
        .replace("$PAGE", page)
        .replace("$OFFSET", offset)
        .replace("$CURSOR", continuation)
        .replace("$SYNTHETIC_RECORD_ID", &synthetic_record_id)
        .replace("$OBSERVATION_TIME", &observation_time)
}

fn materialize_value(
    value: &Value,
    scenario: &Scenario,
    run_id: Uuid,
    cursor: Option<&str>,
) -> Value {
    match value {
        Value::String(value) => Value::String(materialize(value, scenario, run_id, cursor)),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| materialize_value(value, scenario, run_id, cursor))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        materialize_value(value, scenario, run_id, cursor),
                    )
                })
                .collect(),
        ),
        value => value.clone(),
    }
}

fn parse_retry_after_ms(value: &str) -> u64 {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return seconds.saturating_mul(1_000);
    }
    DateTime::parse_from_rfc2822(value.trim())
        .ok()
        .and_then(|date| {
            let delta = date.with_timezone(&Utc) - Utc::now();
            u64::try_from(delta.num_milliseconds()).ok()
        })
        .unwrap_or(0)
}

enum ReadResponseError {
    TooLarge,
    ChunkTooLarge,
    TooManyChunks,
    TimedOut,
    Body,
}

async fn read_limited_response(
    response: reqwest::Response,
    limit: usize,
    timeout_ms: u64,
    max_chunk_bytes: usize,
    max_chunk_count: usize,
) -> Result<Vec<u8>, ReadResponseError> {
    let read = async move {
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        let mut chunk_count = 0_usize;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ReadResponseError::Body)?;
            chunk_count = chunk_count.saturating_add(1);
            if chunk.len() > max_chunk_bytes {
                return Err(ReadResponseError::ChunkTooLarge);
            }
            if chunk_count > max_chunk_count {
                return Err(ReadResponseError::TooManyChunks);
            }
            if bytes.len().saturating_add(chunk.len()) > limit {
                return Err(ReadResponseError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    };
    tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), read)
        .await
        .map_err(|_| ReadResponseError::TimedOut)?
}

enum DecodeResponseError {
    Invalid,
    Limit(&'static str),
}

fn decode_response(
    headers: &HeaderMap,
    wire: &[u8],
    scenario: &Scenario,
) -> Result<Vec<u8>, DecodeResponseError> {
    let encoding = headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("identity");
    if encoding.contains(',') {
        return Err(DecodeResponseError::Invalid);
    }
    if encoding.eq_ignore_ascii_case("identity")
        || encoding.eq_ignore_ascii_case("utf-8")
        || encoding.eq_ignore_ascii_case("utf8")
    {
        return Ok(wire.to_vec());
    }
    let started = Instant::now();
    let mut decoder: Box<dyn Read> = if encoding.eq_ignore_ascii_case("gzip") {
        Box::new(GzDecoder::new(wire))
    } else if encoding.eq_ignore_ascii_case("deflate") {
        Box::new(ZlibDecoder::new(wire))
    } else if encoding.eq_ignore_ascii_case("br") {
        Box::new(Decompressor::new(wire, 8 * 1024))
    } else {
        return Err(DecodeResponseError::Invalid);
    };
    let mut decoded = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        if started.elapsed().as_millis() > u128::from(scenario.runner.max_decompression_time_ms) {
            return Err(DecodeResponseError::Limit(
                "max_decompression_time exceeded",
            ));
        }
        let count = decoder
            .read(&mut buffer)
            .map_err(|_| DecodeResponseError::Invalid)?;
        if count == 0 {
            break;
        }
        let next = decoded.len().saturating_add(count);
        if next > scenario.runner.effective_max_decoded_response_bytes() {
            return Err(DecodeResponseError::Limit(
                "max_decoded_response_bytes exceeded",
            ));
        }
        if wire.is_empty()
            || next
                > wire
                    .len()
                    .saturating_mul(scenario.runner.max_expansion_ratio)
        {
            return Err(DecodeResponseError::Limit("max_expansion_ratio exceeded"));
        }
        decoded.extend_from_slice(&buffer[..count]);
    }
    Ok(decoded)
}

fn extract_records(
    endpoint: &Endpoint,
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<Extraction, String> {
    let Some(extract) = &endpoint.extract else {
        return Ok(Extraction {
            next_cursor: None,
            next_link: None,
            records: Vec::new(),
            raw_records: 0,
        });
    };
    let format = match extract.format {
        ContentFormat::Auto => infer_format(headers, bytes),
        format => format,
    };
    match format {
        ContentFormat::Json => extract_json(extract, endpoint, bytes),
        ContentFormat::Html => extract_html(extract, bytes),
        ContentFormat::Csv => extract_csv(extract, bytes),
        ContentFormat::Text | ContentFormat::Auto => extract_text(extract, bytes),
    }
    .map(|mut extraction| {
        if endpoint.pagination.mode == PaginationMode::Link {
            extraction.next_link = headers
                .get("link")
                .and_then(|value| value.to_str().ok())
                .and_then(parse_next_link);
        }
        extraction
    })
}

fn infer_format(headers: &HeaderMap, bytes: &[u8]) -> ContentFormat {
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if content_type.contains("html") {
        ContentFormat::Html
    } else if content_type.contains("csv") {
        ContentFormat::Csv
    } else if content_type.contains("json")
        || bytes
            .first()
            .is_some_and(|byte| *byte == b'{' || *byte == b'[')
    {
        ContentFormat::Json
    } else {
        ContentFormat::Text
    }
}

fn extract_json(
    extract: &crate::ExtractSpec,
    endpoint: &Endpoint,
    bytes: &[u8],
) -> Result<Extraction, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let mut items = values_at_path(&value, &extract.items_field);
    if items.len() == 1 && items[0].is_array() {
        items = items[0]
            .as_array()
            .map(|values| values.iter().collect())
            .unwrap_or_default();
    }
    let raw_records = items.len();
    let records = items
        .iter()
        .filter_map(|item| record_from_json(item, extract))
        .collect::<Vec<_>>();
    let next_cursor = endpoint
        .pagination
        .next_cursor_field
        .as_ref()
        .and_then(|field| values_at_path(&value, field).into_iter().next())
        .and_then(value_as_string);
    Ok(Extraction {
        next_cursor,
        next_link: None,
        records,
        raw_records,
    })
}

fn record_from_json(item: &Value, extract: &crate::ExtractSpec) -> Option<ExtractedRecord> {
    let candidate = values_at_path(item, &extract.candidate_field)
        .into_iter()
        .next()
        .and_then(value_as_string)?;
    let record_id = values_at_path(item, &extract.record_id_field)
        .into_iter()
        .next()
        .and_then(value_as_string);
    let observed_at = extract
        .timestamp_field
        .as_ref()
        .and_then(|field| values_at_path(item, field).into_iter().next())
        .and_then(value_as_string)
        .and_then(|value| DateTime::parse_from_rfc3339(&value).ok())
        .map(|value| value.with_timezone(&Utc));
    let tags = extract
        .tags_field
        .as_ref()
        .map(|field| {
            values_at_path(item, field)
                .into_iter()
                .flat_map(value_to_strings)
                .collect()
        })
        .unwrap_or_default();
    let confidence = extract
        .confidence_field
        .as_ref()
        .and_then(|field| values_at_path(item, field).into_iter().next())
        .and_then(|value| value.as_f64());
    let evidence = extract
        .evidence_fields
        .iter()
        .filter_map(|field| {
            values_at_path(item, field)
                .into_iter()
                .next()
                .and_then(value_as_string)
                .map(|value| (field.clone(), value))
        })
        .collect();
    Some(ExtractedRecord {
        candidate,
        record_id,
        observed_at,
        tags,
        confidence,
        evidence,
    })
}

fn values_at_path<'a>(value: &'a Value, path: &str) -> Vec<&'a Value> {
    if path.is_empty() || path == "$" {
        return vec![value];
    }
    let mut values = vec![value];
    for segment in path.split('.') {
        let mut next = Vec::new();
        for value in values {
            match value {
                Value::Object(map) if segment == "*" => next.extend(map.values()),
                Value::Object(map) => {
                    if let Some(value) = map.get(segment) {
                        next.push(value);
                    }
                }
                Value::Array(values) if segment == "*" => next.extend(values),
                Value::Array(values) => {
                    if let Ok(index) = segment.parse::<usize>()
                        && let Some(value) = values.get(index)
                    {
                        next.push(value);
                    }
                }
                _ => {}
            }
        }
        values = next;
    }
    values
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn value_to_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Array(values) => values.iter().filter_map(value_as_string).collect(),
        value => value_as_string(value).into_iter().collect(),
    }
}

fn extract_html(_extract: &crate::ExtractSpec, bytes: &[u8]) -> Result<Extraction, String> {
    let text = String::from_utf8_lossy(bytes);
    let document = Html::parse_document(&text);
    let mut candidates = Vec::new();
    let document_text = document.root_element().text().collect::<Vec<_>>().join(" ");
    for token in domainish_tokens(&document_text) {
        candidates.push(ExtractedRecord {
            candidate: token,
            record_id: None,
            observed_at: None,
            tags: Vec::new(),
            confidence: None,
            evidence: BTreeMap::new(),
        });
    }
    let selector = Selector::parse("[href]").map_err(|error| error.to_string())?;
    for element in document.select(&selector) {
        if let Some(href) = element.value().attr("href")
            && let Ok(host) = host_from_url(href)
        {
            candidates.push(ExtractedRecord {
                candidate: host,
                record_id: None,
                observed_at: None,
                tags: Vec::new(),
                confidence: None,
                evidence: BTreeMap::new(),
            });
        }
    }
    Ok(Extraction {
        next_cursor: None,
        next_link: None,
        raw_records: candidates.len(),
        records: candidates,
    })
}

fn extract_urls(value: &str) -> Vec<ExtractedRecord> {
    value
        .split_whitespace()
        .filter(|token| token.starts_with("http://") || token.starts_with("https://"))
        .map(|token| ExtractedRecord {
            candidate: token
                .trim_matches(|character: char| "\"'<>),;".contains(character))
                .to_owned(),
            record_id: None,
            observed_at: None,
            tags: Vec::new(),
            confidence: None,
            evidence: BTreeMap::new(),
        })
        .collect()
}

fn extract_csv(extract: &crate::ExtractSpec, bytes: &[u8]) -> Result<Extraction, String> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(bytes);
    let headers = reader.headers().map_err(|error| error.to_string())?.clone();
    let candidate_index = headers
        .iter()
        .position(|header| header.trim() == extract.candidate_field)
        .ok_or_else(|| "CSV is missing candidate column".to_owned())?;
    let id_index = headers
        .iter()
        .position(|header| header.trim() == extract.record_id_field);
    let timestamp_index = extract
        .timestamp_field
        .as_ref()
        .and_then(|field| headers.iter().position(|header| header.trim() == field));
    let mut records = Vec::new();
    for row in reader.records() {
        let row = row.map_err(|error| error.to_string())?;
        if row.len() <= candidate_index {
            continue;
        }
        let observed_at = timestamp_index
            .and_then(|index| row.get(index))
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc));
        records.push(ExtractedRecord {
            candidate: row.get(candidate_index).unwrap_or_default().to_owned(),
            record_id: id_index.and_then(|index| row.get(index).map(str::to_owned)),
            observed_at,
            tags: Vec::new(),
            confidence: None,
            evidence: BTreeMap::new(),
        });
    }
    Ok(Extraction {
        next_cursor: None,
        next_link: None,
        raw_records: records.len(),
        records,
    })
}

fn extract_text(extract: &crate::ExtractSpec, bytes: &[u8]) -> Result<Extraction, String> {
    let text = String::from_utf8_lossy(bytes);
    let records = if extract.kind == ExtractKind::Url {
        extract_urls(&text)
    } else {
        domainish_tokens(&text)
            .into_iter()
            .map(|candidate| ExtractedRecord {
                candidate,
                record_id: None,
                observed_at: None,
                tags: Vec::new(),
                confidence: None,
                evidence: BTreeMap::new(),
            })
            .collect()
    };
    Ok(Extraction {
        next_cursor: None,
        next_link: None,
        raw_records: records.len(),
        records,
    })
}

fn parse_next_link(value: &str) -> Option<String> {
    value.split(',').find_map(|part| {
        let is_next = part.split(';').skip(1).any(|attribute| {
            attribute.trim().eq_ignore_ascii_case("rel=\"next\"")
                || attribute.trim().eq_ignore_ascii_case("rel=next")
        });
        if !is_next {
            return None;
        }
        let start = part.find('<')? + 1;
        let end = part[start..].find('>')? + start;
        Some(part[start..end].to_owned())
    })
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
        tags,
        confidence,
        evidence,
    } = record;
    let endpoint = context.endpoint;
    run.metrics.parsed_candidates = run.metrics.parsed_candidates.saturating_add(1);
    let candidates = match endpoint
        .extract
        .as_ref()
        .map(|extract| extract.kind)
        .unwrap_or(ExtractKind::Direct)
    {
        ExtractKind::Direct | ExtractKind::Csv | ExtractKind::Html | ExtractKind::Text => {
            vec![candidate]
        }
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
                run.observations.push(Observation {
                    fqdn,
                    source_kind: endpoint.source_kind,
                    source_name: endpoint
                        .source_label
                        .clone()
                        .unwrap_or_else(|| endpoint.id.clone()),
                    record_id: record_id.clone(),
                    observed_at,
                    tags: tags.clone(),
                    confidence,
                    evidence: evidence.clone(),
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{parse_retry_after_ms, values_at_path};

    #[test]
    fn nested_json_path_and_csv_quotes_are_deterministic() {
        let value = json!({"outer":{"items":[{"host":"api.acme.test"}]}});
        assert_eq!(
            values_at_path(&value, "outer.items.0.host")
                .first()
                .and_then(|value| value.as_str()),
            Some("api.acme.test")
        );
        assert_eq!(
            csv::ReaderBuilder::new()
                .has_headers(false)
                .from_reader("a,\"quoted, value\",c\n".as_bytes())
                .records()
                .next()
                .expect("CSV record")
                .expect("valid CSV")
                .iter()
                .collect::<Vec<_>>(),
            vec!["a", "quoted, value", "c"]
        );
    }

    #[test]
    fn retry_after_parser_never_requires_real_sleep() {
        assert_eq!(parse_retry_after_ms("2"), 2_000);
        assert_eq!(parse_retry_after_ms("not-a-date"), 0);
    }
}
