//! A rule-driven HTTP simulator that only binds numeric IPv4 loopback.

use std::{
    collections::BTreeMap,
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::Response,
    routing::any,
};
use chrono::Utc;
use futures_util::stream;
use lab_core::{
    AuditRecord, Endpoint, GeneratorKind, LabState, LoadedScenario, Reply, RunReport, RunSession,
    RunStateError, Scenario, ScenarioRepository, ValueRule,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use url::Url;

pub struct LocalServer {
    address: SocketAddr,
    state: LabState,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl LocalServer {
    pub async fn spawn(
        repository: ScenarioRepository,
        active: Option<&str>,
    ) -> Result<Self, String> {
        Self::spawn_on(repository, active, None).await
    }

    pub async fn spawn_on(
        repository: ScenarioRepository,
        active: Option<&str>,
        port: Option<u16>,
    ) -> Result<Self, String> {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port.unwrap_or(0));
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err("refusing non-loopback listener".to_owned());
        }
        let state = LabState::new(repository);
        if let Some(id) = active {
            state.activate(id).map_err(|error| error.to_string())?;
        }
        let app = Router::new()
            .fallback(any(handle_request))
            .with_state(state.clone());
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = receiver.await;
                })
                .await;
        });
        Ok(Self {
            address,
            state,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.address.port())
    }

    pub fn activate(&self, id: &str) -> Result<(), String> {
        self.state
            .activate(id)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    #[must_use]
    pub fn developer_run_id(&self) -> Option<String> {
        self.state.developer_run().map(|run| run.run_id)
    }

    #[must_use]
    pub fn audit(&self) -> Vec<AuditRecord> {
        self.state
            .developer_run()
            .and_then(|run| self.state.audit(&run.run_id).ok())
            .unwrap_or_default()
    }

    pub fn set_report(&self, report: RunReport) {
        let run_id = report.run_id.clone();
        let _ = self.state.set_report(&run_id, report);
    }

    pub async fn shutdown(mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
    }
}

async fn handle_request(State(state): State<LabState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let method = parts.method.clone();
    let path = parts.uri.path().to_owned();
    let query = parse_query(parts.uri.query());
    let headers = parts.headers;
    let base_url = format!(
        "http://{}",
        headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("127.0.0.1")
    );
    let body = to_bytes(body, 16 * 1024 * 1024).await.unwrap_or_default();
    if let Some(response) = control_response(&state, &method, &path, &body, &base_url).await {
        return response;
    }
    scenario_response(
        state,
        method,
        path,
        query,
        headers,
        body.to_vec(),
        &base_url,
    )
    .await
}

async fn control_response(
    state: &LabState,
    method: &Method,
    path: &str,
    body: &[u8],
    base_url: &str,
) -> Option<Response> {
    if method == Method::POST && path == "/api/runs" {
        let request = match serde_json::from_slice::<CreateRunRequest>(body) {
            Ok(request) => request,
            Err(_) => {
                return Some(json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"body must be {\"scenario_id\": \"...\"}"}),
                ));
            }
        };
        return Some(
            match state.create_run_with_seed(&request.scenario_id, request.seed) {
                Ok(run) => json_response(
                    StatusCode::CREATED,
                    json!({
                        "run_id": run.run_id,
                        "scenario_id": run.scenario_id,
                        "seed": run.seed,
                        "base_url": base_url,
                        "required_request_header": {"x-lab-run-id": run.run_id},
                    }),
                ),
                Err(_) => {
                    json_response(StatusCode::BAD_REQUEST, json!({"error":"unknown scenario"}))
                }
            },
        );
    }
    if method == Method::GET && path == "/api/runs" {
        return Some(json_response(
            StatusCode::OK,
            json!({"runs":state.list_runs().iter().map(run_summary).collect::<Vec<_>>() }),
        ));
    }
    if let Some((run_id, action)) = run_route(path) {
        return Some(run_control_response(state, method, run_id, action, body));
    }
    let value = match (method, path) {
        (&Method::GET, "/health") => {
            let developer = state.developer_run();
            json!({
                "status":"ok",
                "developer_run_id":developer.as_ref().map(|run| &run.run_id),
                "active_scenario":developer.as_ref().map(|run| &run.scenario_id),
            })
        }
        (&Method::GET, "/api/scenarios") => {
            json!({"scenarios": state.repository().all().iter().map(|loaded| json!({"id":loaded.scenario.id,"name":loaded.scenario.name,"description":loaded.scenario.description})).collect::<Vec<_>>() })
        }
        (&Method::GET, "/api/diagnostics/unscoped-requests") => {
            json!({"unscoped_requests":state.unscoped_audit()})
        }
        (&Method::GET, "/api/requests") => match legacy_run(state) {
            Some(run) => json!({"deprecated":true,"run_id":run.run_id,"requests":run.audit}),
            None => return Some(no_developer_run_response()),
        },
        (&Method::GET, "/api/truth") => match legacy_run(state) {
            Some(run) => match state.loaded_for_run(&run.run_id) {
                Ok(loaded) => {
                    json!({"deprecated":true,"run_id":run.run_id,"scenario_id":loaded.scenario.id,"truth":loaded.truth})
                }
                Err(error) => return Some(run_error_response(error)),
            },
            None => return Some(no_developer_run_response()),
        },
        (&Method::GET, "/api/report") => match legacy_run(state) {
            Some(run) => match state.latest_report(&run.run_id) {
                Ok(report) => json!({"deprecated":true,"run_id":run.run_id,"report":report}),
                Err(error) => return Some(run_error_response(error)),
            },
            None => return Some(no_developer_run_response()),
        },
        (&Method::POST, "/api/reset") => match legacy_run(state) {
            Some(run) => match state.reset(&run.run_id) {
                Ok(()) => json!({"deprecated":true,"run_id":run.run_id,"reset":true}),
                Err(error) => return Some(run_error_response(error)),
            },
            None => return Some(no_developer_run_response()),
        },
        _ if method == Method::POST
            && path.starts_with("/api/scenarios/")
            && path.ends_with("/activate") =>
        {
            let id = path
                .trim_start_matches("/api/scenarios/")
                .trim_end_matches("/activate")
                .trim_end_matches('/');
            return Some(match state.activate(id) {
                Ok(run) => json_response(
                    StatusCode::OK,
                    json!({"deprecated":true,"active_scenario":id,"run_id":run.run_id}),
                ),
                Err(_) => {
                    json_response(StatusCode::BAD_REQUEST, json!({"error":"unknown scenario"}))
                }
            });
        }
        _ => return None,
    };
    Some(json_response(StatusCode::OK, value))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRunRequest {
    scenario_id: String,
    #[serde(default)]
    seed: Option<u64>,
}

fn run_route(path: &str) -> Option<(&str, Option<&str>)> {
    let mut segments = path.trim_start_matches('/').split('/');
    if segments.next()? != "api" || segments.next()? != "runs" {
        return None;
    }
    let run_id = segments.next()?;
    let action = segments.next();
    if segments.next().is_some() {
        return None;
    }
    Some((run_id, action))
}

fn run_control_response(
    state: &LabState,
    method: &Method,
    run_id: &str,
    action: Option<&str>,
    body: &[u8],
) -> Response {
    let run = match state.session(run_id) {
        Ok(run) => run,
        Err(error) => return run_error_response(error),
    };
    match (method, action) {
        (&Method::GET, None) => json_response(StatusCode::OK, run_summary(&run)),
        (&Method::GET, Some("requests")) => match state.audit(run_id) {
            Ok(requests) => {
                json_response(StatusCode::OK, json!({"run_id":run_id,"requests":requests}))
            }
            Err(error) => run_error_response(error),
        },
        (&Method::GET, Some("truth")) => match state.loaded_for_run(run_id) {
            Ok(loaded) => json_response(
                StatusCode::OK,
                json!({"run_id":run_id,"scenario_id":loaded.scenario.id,"truth":loaded.truth}),
            ),
            Err(error) => run_error_response(error),
        },
        (&Method::GET, Some("report")) => match state.latest_report(run_id) {
            Ok(report) => json_response(StatusCode::OK, json!({"run_id":run_id,"report":report})),
            Err(error) => run_error_response(error),
        },
        (&Method::POST, Some("reset")) => match state.reset(run_id) {
            Ok(()) => json_response(StatusCode::OK, json!({"run_id":run_id,"reset":true})),
            Err(error) => run_error_response(error),
        },
        (&Method::POST, Some("report")) => {
            let report = match serde_json::from_slice::<RunReport>(body) {
                Ok(report) => report,
                Err(_) => {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"invalid run report JSON"}),
                    );
                }
            };
            if report.run_id != run_id || report.scenario_id != run.scenario_id {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"report run_id or scenario_id does not match session"}),
                );
            }
            match state.set_report(run_id, report) {
                Ok(()) => json_response(StatusCode::OK, json!({"run_id":run_id,"stored":true})),
                Err(error) => run_error_response(error),
            }
        }
        (&Method::DELETE, None) => match state.delete(run_id) {
            Ok(()) => Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .expect("static response builder"),
            Err(error) => run_error_response(error),
        },
        _ => json_response(
            StatusCode::NOT_FOUND,
            json!({"error":"unknown run control route"}),
        ),
    }
}

fn run_summary(run: &RunSession) -> Value {
    json!({
        "run_id":run.run_id,
        "scenario_id":run.scenario_id,
        "seed":run.seed,
        "status":run.status,
        "created_at":run.created_at,
        "last_activity_at":run.last_activity_at,
        "request_count":run.audit.len(),
    })
}

fn legacy_run(state: &LabState) -> Option<RunSession> {
    state.developer_run()
}

fn no_developer_run_response() -> Response {
    json_response(
        StatusCode::CONFLICT,
        json!({"error":"no developer single-session run"}),
    )
}

fn run_error_response(error: RunStateError) -> Response {
    let status = match error {
        RunStateError::InvalidRunId => StatusCode::BAD_REQUEST,
        RunStateError::UnknownRun => StatusCode::NOT_FOUND,
    };
    json_response(status, json!({"error":error.message()}))
}

async fn scenario_response(
    state: LabState,
    method: Method,
    path: String,
    query: BTreeMap<String, String>,
    headers: HeaderMap,
    body: Vec<u8>,
    base_url: &str,
) -> Response {
    let run_id = match headers
        .get("x-lab-run-id")
        .and_then(|value| value.to_str().ok())
    {
        Some(run_id) => run_id,
        None => {
            state.record_unscoped_request(method.as_ref(), &path, "missing x-lab-run-id");
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"missing x-lab-run-id"}),
            );
        }
    };
    let loaded = match state.loaded_for_run(run_id) {
        Ok(loaded) => loaded,
        Err(error) => {
            state.record_unscoped_request(method.as_ref(), &path, error.message());
            let status = match error {
                RunStateError::InvalidRunId => StatusCode::BAD_REQUEST,
                RunStateError::UnknownRun => StatusCode::CONFLICT,
            };
            return json_response(status, json!({"error":error.message()}));
        }
    };
    let matching_path = loaded.scenario.endpoints.iter().find(|endpoint| {
        endpoint.request_match.path == path
            && endpoint.request_match.method.as_str() == method.as_str()
    });
    let Some(endpoint) = matching_path else {
        let record = audit_record(AuditInput {
            run_id,
            scenario: &loaded.scenario,
            endpoint: None,
            method: &method,
            path: &path,
            query,
            headers: &headers,
            body: &body,
            response_index: None,
            response_status: 404,
            matched: false,
            extra: true,
            mismatch_reasons: vec!["no endpoint matches method and path".to_owned()],
        });
        let _ = state.record_request(run_id, record);
        return json_response(
            StatusCode::NOT_FOUND,
            json!({"error":"no matching scenario rule"}),
        );
    };
    let reasons = match_request(endpoint, &loaded, &query, &headers, &body, &state, run_id);
    if !reasons.is_empty() {
        let status =
            StatusCode::from_u16(endpoint.mismatch_status).unwrap_or(StatusCode::BAD_REQUEST);
        let record = audit_record(AuditInput {
            run_id,
            scenario: &loaded.scenario,
            endpoint: Some(endpoint),
            method: &method,
            path: &path,
            query,
            headers: &headers,
            body: &body,
            response_index: None,
            response_status: status.as_u16(),
            matched: false,
            extra: true,
            mismatch_reasons: reasons,
        });
        let _ = state.record_request(run_id, record);
        return json_response(
            status,
            json!({"error":"request did not match scenario rule"}),
        );
    }
    let index = match state.claim_response_index(run_id, &endpoint.id, endpoint.replies.len()) {
        Ok(Some(index)) => index,
        Ok(None) => {
            let record = audit_record(AuditInput {
                run_id,
                scenario: &loaded.scenario,
                endpoint: Some(endpoint),
                method: &method,
                path: &path,
                query,
                headers: &headers,
                body: &body,
                response_index: None,
                response_status: 409,
                matched: false,
                extra: true,
                mismatch_reasons: vec!["response sequence exhausted".to_owned()],
            });
            let _ = state.record_request(run_id, record);
            return json_response(
                StatusCode::CONFLICT,
                json!({"error":"response sequence exhausted"}),
            );
        }
        Err(error) => return run_error_response(error),
    };
    let reply = &endpoint.replies[index];
    let template_context = TemplateContext::from_request(endpoint, &query, &body);
    let status = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut record = audit_record(AuditInput {
        run_id,
        scenario: &loaded.scenario,
        endpoint: Some(endpoint),
        method: &method,
        path: &path,
        query,
        headers: &headers,
        body: &body,
        response_index: Some(index),
        response_status: status.as_u16(),
        matched: true,
        extra: false,
        mismatch_reasons: Vec::new(),
    });
    record.retry_after = reply.retry_after.clone().or_else(|| {
        reply
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
            .map(|(_, value)| value.clone())
    });
    record.virtual_wait_ms = reply.virtual_wait_ms;
    if status.is_redirection()
        && response_location(reply)
            .is_some_and(|location| redirect_target_is_external(base_url, location))
    {
        record.blocked = true;
        record.external_target_rejected = true;
    }
    if state.record_request(run_id, record).is_err() {
        return json_response(StatusCode::CONFLICT, json!({"error":"run was deleted"}));
    }
    if reply.delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(reply.delay_ms)).await;
    }
    let profile = headers
        .get("x-lab-data-profile")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("default");
    if status == StatusCode::NO_CONTENT || reply.close_before_body {
        return reply_response(status, reply, Vec::new()).await;
    }
    match response_body(reply, endpoint, &loaded, profile, run_id, &template_context) {
        Ok(bytes) => reply_response(status, reply, bytes).await,
        Err(error) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":format!("fixture error: {error}")}),
        ),
    }
}

fn match_request(
    endpoint: &Endpoint,
    loaded: &LoadedScenario,
    query: &BTreeMap<String, String>,
    headers: &HeaderMap,
    body: &[u8],
    state: &LabState,
    run_id: &str,
) -> Vec<String> {
    let mut reasons = Vec::new();
    let template_context = TemplateContext::from_request(endpoint, query, body);
    for (name, rule) in &endpoint.request_match.query {
        check_rule(
            &mut reasons,
            &format!("query {name}"),
            query.get(name).map(String::as_str),
            rule,
            &loaded.scenario,
            &template_context,
        );
    }
    for name in query.keys() {
        if !endpoint.request_match.query.contains_key(name)
            && !(endpoint.pagination.mode != lab_core::PaginationMode::None
                && name == &endpoint.pagination.parameter)
        {
            reasons.push(format!("unexpected query parameter {name}"));
        }
    }
    if endpoint.pagination.mode != lab_core::PaginationMode::None
        && endpoint.pagination.mode != lab_core::PaginationMode::Link
    {
        let current = state
            .matched_request_count(run_id, &endpoint.id)
            .unwrap_or(0);
        if current > 0 {
            let expected = previous_cursor(endpoint, loaded, current - 1, state, run_id);
            let actual = if endpoint.pagination.in_body {
                serde_json::from_slice::<Value>(body).ok().and_then(|body| {
                    body.get(&endpoint.pagination.parameter)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
            } else {
                query.get(&endpoint.pagination.parameter).cloned()
            };
            if actual.as_ref() != expected.as_ref() {
                reasons.push("pagination cursor does not match previous reply".to_owned());
            }
        }
    }
    for (name, rule) in &endpoint.request_match.headers {
        check_rule(
            &mut reasons,
            &format!("header {name}"),
            headers.get(name).and_then(|value| value.to_str().ok()),
            rule,
            &loaded.scenario,
            &template_context,
        );
    }
    if let Some(expected_body) = &endpoint.request_match.json_body {
        match serde_json::from_slice::<Value>(body) {
            Ok(actual) if &actual == expected_body => {}
            Ok(_) => reasons.push("JSON body does not match".to_owned()),
            Err(_) => reasons.push("body is not valid JSON".to_owned()),
        }
    } else if !body.is_empty() && endpoint.request_body.is_none() {
        reasons.push("unexpected request body".to_owned());
    }
    reasons
}

fn check_rule(
    reasons: &mut Vec<String>,
    label: &str,
    actual: Option<&str>,
    rule: &ValueRule,
    scenario: &Scenario,
    template_context: &TemplateContext,
) {
    if rule.forbidden && actual.is_some() {
        reasons.push(format!("{label} is forbidden"));
        return;
    }
    if rule.requires_value() && actual.is_none() && !rule.optional {
        reasons.push(format!("{label} is missing"));
        return;
    }
    if let Some(expected) = &rule.equals {
        let expected = resolve(expected, scenario, template_context);
        if actual != Some(expected.as_str()) {
            reasons.push(format!("{label} has the wrong value"));
        }
    }
}

fn resolve(value: &str, scenario: &Scenario, template_context: &TemplateContext) -> String {
    match value {
        "$ROOT_DOMAIN" | "$TARGET_DOMAIN" => scenario.root_domain.clone(),
        "$SEED" => scenario.seed.to_string(),
        "$PAGE" => template_context.page.clone(),
        "$OFFSET" => template_context.offset.clone(),
        "$CURSOR" => template_context.cursor.clone(),
        "$SYNTHETIC_RECORD_ID" => {
            format!("synthetic-{}-{}", scenario.seed, template_context.page)
        }
        "$OBSERVATION_TIME" => format!("2025-01-{:02}T00:00:00Z", scenario.seed % 28 + 1),
        _ => value.to_owned(),
    }
}

fn previous_cursor(
    endpoint: &Endpoint,
    loaded: &LoadedScenario,
    previous_index: usize,
    state: &LabState,
    run_id: &str,
) -> Option<String> {
    let field = endpoint.pagination.next_cursor_field.as_ref()?;
    let reply = endpoint.replies.get(previous_index)?;
    let previous_request = state.audit(run_id).ok()?.into_iter().rev().find(|record| {
        record.matched && record.endpoint_id.as_deref() == Some(endpoint.id.as_str())
    })?;
    let template_context = TemplateContext::from_audit(endpoint, &previous_request);
    response_body(
        reply,
        endpoint,
        loaded,
        "default",
        run_id,
        &template_context,
    )
    .ok()
    .and_then(|body| serde_json::from_slice::<Value>(&body).ok())
    .and_then(|value| value.get(field).and_then(Value::as_str).map(str::to_owned))
}

fn response_body(
    reply: &Reply,
    endpoint: &Endpoint,
    loaded: &LoadedScenario,
    profile: &str,
    run_id: &str,
    template_context: &TemplateContext,
) -> Result<Vec<u8>, String> {
    if let Some(file) = &reply.body_file {
        let mut bytes = fs::read(loaded.directory.join(file)).map_err(|error| error.to_string())?;
        materialize_bytes(&mut bytes, loaded, run_id, template_context);
        return finalize_response_body(reply, endpoint, bytes, run_id);
    }
    if let Some(body) = &reply.body_text {
        let body = materialize_text(body, loaded, run_id, template_context);
        return finalize_response_body(reply, endpoint, body.into_bytes(), run_id);
    }
    if let Some(body) = &reply.body {
        let body = materialize_json(body, loaded, run_id, template_context);
        let mut bytes = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
        materialize_bytes(&mut bytes, loaded, run_id, template_context);
        return finalize_response_body(reply, endpoint, bytes, run_id);
    }
    if let Some(generator) = &reply.generator {
        let count = if profile == "stress" {
            generator.stress_count.unwrap_or(generator.count)
        } else {
            generator.count
        };
        let items = match generator.kind {
            GeneratorKind::DomainRecords => (0..count)
                .map(|index| {
                    let value = if generator.seeded {
                        format!(
                            "bulk-{}-{}.{}",
                            loaded.scenario.seed,
                            index % generator.unique + 1,
                            loaded.scenario.root_domain
                        )
                    } else {
                        format!(
                            "bulk-{}.{}",
                            index % generator.unique + 1,
                            loaded.scenario.root_domain
                        )
                    };
                    json!({"id":format!("generated-{index}"), generator.field.clone(): value})
                })
                .collect::<Vec<_>>(),
            GeneratorKind::UrlRecords => (0..count)
                .map(|index| {
                    let value = if generator.seeded {
                        format!(
                            "https://bulk-{}-{}.{}:8443/path?q={index}#fragment",
                            loaded.scenario.seed,
                            index % generator.unique + 1,
                            loaded.scenario.root_domain
                        )
                    } else {
                        format!(
                            "https://bulk-{}.{}:8443/path?q={index}#fragment",
                            index % generator.unique + 1,
                            loaded.scenario.root_domain
                        )
                    };
                    json!({"id":format!("generated-{index}"), generator.field.clone(): value})
                })
                .collect::<Vec<_>>(),
            GeneratorKind::NestedDomainRecords => (0..count)
                .map(|index| {
                    let value = if generator.seeded {
                        format!(
                            "nested-{}-{}.{}",
                            loaded.scenario.seed,
                            index % generator.unique + 1,
                            loaded.scenario.root_domain
                        )
                    } else {
                        format!(
                            "nested-{}.{}",
                            index % generator.unique + 1,
                            loaded.scenario.root_domain
                        )
                    };
                    json!({"meta":{"record":{"id":format!("generated-{index}"), "host":value}}})
                })
                .collect::<Vec<_>>(),
        };
        let mut bytes =
            serde_json::to_vec(&json!({"items":items})).map_err(|error| error.to_string())?;
        materialize_bytes(&mut bytes, loaded, run_id, template_context);
        return finalize_response_body(reply, endpoint, bytes, run_id);
    }
    Err("reply has no body source".to_owned())
}

fn finalize_response_body(
    reply: &Reply,
    endpoint: &Endpoint,
    bytes: Vec<u8>,
    run_id: &str,
) -> Result<Vec<u8>, String> {
    let bytes = with_oversize(reply, bytes);
    if !reply.wrong_cursor && !reply.duplicate_page {
        return Ok(bytes);
    }
    let mut body = serde_json::from_slice::<Value>(&bytes).map_err(|error| error.to_string())?;
    if reply.wrong_cursor
        && let Some(field) = &endpoint.pagination.next_cursor_field
    {
        set_json_string(&mut body, field, format!("wrong-cursor-{run_id}"));
    }
    if reply.duplicate_page
        && let Some(extract) = &endpoint.extract
    {
        duplicate_json_array(&mut body, &extract.items_field);
    }
    serde_json::to_vec(&body).map_err(|error| error.to_string())
}

fn set_json_string(value: &mut Value, path: &str, replacement: String) {
    let mut current = value;
    let mut segments = path.split('.').peekable();
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() {
            if let Value::Object(values) = current {
                values.insert(segment.to_owned(), Value::String(replacement));
            }
            return;
        }
        let Value::Object(values) = current else {
            return;
        };
        let Some(next) = values.get_mut(segment) else {
            return;
        };
        current = next;
    }
}

fn duplicate_json_array(value: &mut Value, path: &str) {
    let mut current = value;
    for segment in path.split('.') {
        let Value::Object(values) = current else {
            return;
        };
        let Some(next) = values.get_mut(segment) else {
            return;
        };
        current = next;
    }
    if let Value::Array(values) = current {
        let duplicate = values.clone();
        values.extend(duplicate);
    }
}

fn with_oversize(reply: &Reply, mut bytes: Vec<u8>) -> Vec<u8> {
    if let Some(size) = reply.oversized_bytes
        && bytes.len() < size
    {
        bytes.resize(size, b'x');
    }
    bytes
}

async fn reply_response(status: StatusCode, reply: &Reply, bytes: Vec<u8>) -> Response {
    if reply.first_byte_delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(reply.first_byte_delay_ms)).await;
    }
    let sent = if reply.disconnect
        || reply.connection_reset
        || reply.close_before_body
        || reply.truncated_body
    {
        bytes[..bytes.len() / 2].to_vec()
    } else if reply.malformed_body {
        b"{malformed-response".to_vec()
    } else {
        bytes.clone()
    };
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, reply.content_type())
        .header(header::CONNECTION, "close");
    let transport_fault = reply.disconnect
        || reply.connection_reset
        || reply.close_before_body
        || reply.truncated_body
        || reply.malformed_content_length.is_some();
    if let Some(location) = &reply.redirect {
        builder = builder.header(header::LOCATION, location);
    }
    if reply.virtual_wait_ms > 0 {
        builder = builder.header("x-lab-virtual-wait-ms", reply.virtual_wait_ms.to_string());
    }
    if let Some(retry_after) = &reply.retry_after {
        builder = builder.header("retry-after", retry_after);
    }
    if let Some(encoding) = &reply.encoding {
        builder = builder.header(header::CONTENT_ENCODING, encoding);
    }
    for (name, value) in &reply.headers {
        builder = builder.header(name, value);
    }
    let body = if transport_fault {
        let error = io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "synthetic transport fault",
        );
        Body::from_stream(stream::iter(vec![
            Ok::<Bytes, io::Error>(Bytes::from(sent)),
            Err(error),
        ]))
    } else {
        Body::from(sent)
    };
    builder.body(body).unwrap_or_else(|_| {
        json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":"invalid response headers"}),
        )
    })
}

fn response_location(reply: &Reply) -> Option<&str> {
    reply.redirect.as_deref().or_else(|| {
        reply
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value.as_str())
    })
}

fn redirect_target_is_external(base_url: &str, location: &str) -> bool {
    let Ok(base_url) = Url::parse(base_url) else {
        return true;
    };
    let Ok(target) = base_url.join(location) else {
        return true;
    };
    target.scheme() != "http"
        || target.host_str() != Some("127.0.0.1")
        || !target.username().is_empty()
        || target.password().is_some()
}

#[derive(Clone, Debug)]
struct TemplateContext {
    page: String,
    offset: String,
    cursor: String,
}

impl TemplateContext {
    fn from_request(endpoint: &Endpoint, query: &BTreeMap<String, String>, body: &[u8]) -> Self {
        let body = serde_json::from_slice::<Value>(body).ok();
        Self::from_values(endpoint, query, body.as_ref())
    }

    fn from_audit(endpoint: &Endpoint, record: &AuditRecord) -> Self {
        Self::from_values(endpoint, &record.query, record.body.as_ref())
    }

    fn from_values(
        endpoint: &Endpoint,
        query: &BTreeMap<String, String>,
        body: Option<&Value>,
    ) -> Self {
        let value = |name: &str| request_value(query, body, name);
        let pagination_value = value(&endpoint.pagination.parameter);
        let page = if endpoint.pagination.mode == lab_core::PaginationMode::Page {
            pagination_value
                .clone()
                .unwrap_or_else(|| endpoint.pagination.start.to_string())
        } else {
            value("page").unwrap_or_else(|| "1".to_owned())
        };
        let offset = if endpoint.pagination.mode == lab_core::PaginationMode::Offset {
            pagination_value
                .clone()
                .unwrap_or_else(|| endpoint.pagination.start.to_string())
        } else {
            value("offset").unwrap_or_else(|| "0".to_owned())
        };
        let cursor = if endpoint.pagination.mode == lab_core::PaginationMode::Cursor {
            pagination_value.unwrap_or_default()
        } else {
            value("cursor").unwrap_or_default()
        };
        Self {
            page,
            offset,
            cursor,
        }
    }
}

fn request_value(
    query: &BTreeMap<String, String>,
    body: Option<&Value>,
    name: &str,
) -> Option<String> {
    query.get(name).cloned().or_else(|| {
        body.and_then(|value| value.get(name))
            .and_then(|value| match value {
                Value::String(value) => Some(value.clone()),
                Value::Number(value) => Some(value.to_string()),
                _ => None,
            })
    })
}

fn materialize_bytes(
    bytes: &mut Vec<u8>,
    loaded: &LoadedScenario,
    run_id: &str,
    template_context: &TemplateContext,
) {
    let text = materialize_text(
        &String::from_utf8_lossy(bytes),
        loaded,
        run_id,
        template_context,
    );
    *bytes = text.into_bytes();
}

fn materialize_text(
    value: &str,
    loaded: &LoadedScenario,
    run_id: &str,
    template_context: &TemplateContext,
) -> String {
    value
        .replace("$TARGET_DOMAIN", &loaded.scenario.root_domain)
        .replace("$ROOT_DOMAIN", &loaded.scenario.root_domain)
        .replace("$SEED", &loaded.scenario.seed.to_string())
        .replace("$RUN_ID", run_id)
        .replace("$PAGE", &template_context.page)
        .replace("$OFFSET", &template_context.offset)
        .replace("$CURSOR", &template_context.cursor)
        .replace(
            "$SYNTHETIC_RECORD_ID",
            &format!(
                "synthetic-{}-{}",
                loaded.scenario.seed, template_context.page
            ),
        )
        .replace(
            "$OBSERVATION_TIME",
            &format!("2025-01-{:02}T00:00:00Z", loaded.scenario.seed % 28 + 1),
        )
}

fn materialize_json(
    value: &Value,
    loaded: &LoadedScenario,
    run_id: &str,
    template_context: &TemplateContext,
) -> Value {
    match value {
        Value::String(value) => {
            Value::String(materialize_text(value, loaded, run_id, template_context))
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| materialize_json(value, loaded, run_id, template_context))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        materialize_json(value, loaded, run_id, template_context),
                    )
                })
                .collect(),
        ),
        value => value.clone(),
    }
}

struct AuditInput<'a> {
    run_id: &'a str,
    scenario: &'a Scenario,
    endpoint: Option<&'a Endpoint>,
    method: &'a Method,
    path: &'a str,
    query: BTreeMap<String, String>,
    headers: &'a HeaderMap,
    body: &'a [u8],
    response_index: Option<usize>,
    response_status: u16,
    matched: bool,
    extra: bool,
    mismatch_reasons: Vec<String>,
}

fn audit_record(input: AuditInput<'_>) -> AuditRecord {
    let AuditInput {
        run_id,
        scenario,
        endpoint,
        method,
        path,
        query,
        headers,
        body,
        response_index,
        response_status,
        matched,
        extra,
        mismatch_reasons,
    } = input;
    let mut audit_headers = BTreeMap::new();
    for (name, value) in headers {
        let name = name.as_str().to_ascii_lowercase();
        let value = value.to_str().unwrap_or_default();
        let rule = endpoint.and_then(|endpoint| endpoint.request_match.headers.get(&name));
        audit_headers.insert(name.clone(), redact_header(&name, value, rule));
    }
    if let Some(endpoint) = endpoint {
        for (name, rule) in &endpoint.request_match.headers {
            if is_sensitive(name) && !audit_headers.contains_key(name) && rule.requires_value() {
                audit_headers.insert(name.clone(), "<missing>".to_owned());
            }
        }
    }
    let redacted_headers = audit_headers.clone();
    let redacted_body = redact_body(body);
    AuditRecord {
        sequence: 0,
        run_id: Some(run_id.to_owned()),
        scenario_id: scenario.id.clone(),
        timestamp: Utc::now(),
        method: method.to_string(),
        path: path.to_owned(),
        query: query
            .into_iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    if is_sensitive(&name) {
                        "<redacted>".to_owned()
                    } else {
                        value
                    },
                )
            })
            .collect(),
        headers: audit_headers,
        body: redacted_body.clone(),
        body_summary: redacted_body,
        endpoint_id: endpoint.map(|endpoint| endpoint.id.clone()),
        response_index,
        response_sequence: response_index,
        response_status,
        redacted_headers,
        virtual_wait_ms: 0,
        retry_after: None,
        consumed: matched,
        blocked: false,
        external_target_rejected: false,
        matched,
        extra,
        mismatch_reasons,
    }
}

fn is_sensitive(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "authorization",
        "cookie",
        "token",
        "secret",
        "password",
        "api-key",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

fn redact_header(name: &str, value: &str, rule: Option<&ValueRule>) -> String {
    if !is_sensitive(name) {
        return if value.is_empty() {
            "<empty>".to_owned()
        } else {
            "<present>".to_owned()
        };
    }
    match rule.and_then(|rule| rule.equals.as_deref()) {
        Some(expected) if expected == value => "<matched-secret>".to_owned(),
        Some(_) => "<wrong-secret>".to_owned(),
        None => "<redacted>".to_owned(),
    }
}

fn redact_body(body: &[u8]) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    let mut value = serde_json::from_slice(body).ok()?;
    redact_value(&mut value);
    Some(value)
}

fn redact_value(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (name, value) in object {
                if is_sensitive(name) {
                    *value = Value::String("<redacted>".to_owned());
                } else {
                    redact_value(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_value(value);
            }
        }
        _ => {}
    }
}

fn parse_query(value: Option<&str>) -> BTreeMap<String, String> {
    value
        .map(|value| {
            url::form_urlencoded::parse(value.as_bytes())
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn json_response(status: StatusCode, value: Value) -> Response {
    let bytes =
        serde_json::to_vec(&value).unwrap_or_else(|_| b"{\"error\":\"serialization\"}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(Body::from(bytes))
        .expect("static response builder")
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use lab_core::{
        AuditRecord, EgressGuard, JudgeInput, LoadedScenario, ReferenceRunner, ReportStatus,
        RunReport, ScenarioRepository, SourceStatus, judge_run,
    };
    use reqwest::{Client, StatusCode};
    use std::{collections::BTreeMap, fs, path::PathBuf};
    use uuid::Uuid;

    use super::{LocalServer, TemplateContext, materialize_text};

    fn repository() -> ScenarioRepository {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios");
        ScenarioRepository::load(root).expect("load scenarios")
    }

    fn temporary_contract_repository() -> (ScenarioRepository, PathBuf) {
        let root = std::env::temp_dir().join(format!("jnsec-lab-contract-{}", Uuid::new_v4()));
        let post = root.join("post-json");
        let redirect = root.join("redirect");
        fs::create_dir_all(&post).expect("post scenario directory");
        fs::create_dir_all(&redirect).expect("redirect scenario directory");
        fs::write(
            post.join("scenario.yaml"),
            r#"id: post-json
name: post JSON contract
description: synthetic POST JSON body matcher
version: "1.2"
root_domain: acme.test
seed: 1
allow_duplicates: false
allow_concurrent: true
endpoints:
  - id: post-source
    source_kind: generic_json
    match:
      method: POST
      path: /post/v1/search
      query: { domain: { equals: $ROOT_DOMAIN } }
      json_body: { query: subdomains }
    extract: { items_field: items, candidate_field: host }
    replies: [{ status: 200, body: { items: [{ id: p1, host: post.acme.test }] } }]
"#,
        )
        .expect("post scenario");
        fs::write(
            post.join("truth.yaml"),
            r#"expected_fqdns: [post.acme.test]
expected_observations: { post.acme.test: { source_names: [post-source] } }
expected_filter_reasons: []
expected_run_status: success
expected_source_status: { post-source: success }
"#,
        )
        .expect("post truth");
        fs::write(
            post.join("assertions.yaml"),
            r#"expected_requests: 1
expected_unmatched_requests: 0
endpoint_requests: { post-source: 1 }
required_paths: [/post/v1/search]
forbidden_paths: []
request_sequence: [{ endpoint: post-source, response_index: 0 }]
"#,
        )
        .expect("post assertions");
        fs::write(
            redirect.join("scenario.yaml"),
            r#"id: redirect
name: redirect contract
description: synthetic redirect that the runner must not follow
version: "1.2"
root_domain: acme.test
seed: 2
allow_duplicates: false
allow_concurrent: true
endpoints:
  - id: redirect-source
    source_kind: generic_json
    match: { method: GET, path: /redirect/v1/search, query: { domain: { equals: $ROOT_DOMAIN } } }
    extract: { items_field: items, candidate_field: host }
    replies: [{ status: 302, headers: { location: http://198.51.100.10/redirect }, body: { items: [{ id: r1, host: redirect.acme.test }] } }]
"#,
        )
        .expect("redirect scenario");
        fs::write(
            redirect.join("truth.yaml"),
            r#"expected_fqdns: []
expected_filter_reasons: [{ value: http://198.51.100.10/redirect, reason: blocked_egress }]
expected_run_status: failure
expected_source_status: { redirect-source: blocked }
"#,
        )
        .expect("redirect truth");
        fs::write(
            redirect.join("assertions.yaml"),
            r#"expected_requests: 1
expected_unmatched_requests: 0
endpoint_requests: { redirect-source: 1 }
required_paths: [/redirect/v1/search]
forbidden_paths: []
request_sequence: [{ endpoint: redirect-source, response_index: 0 }]
"#,
        )
        .expect("redirect assertions");
        (
            ScenarioRepository::load(&root).expect("contract repository"),
            root,
        )
    }

    async fn create_run(client: &Client, base_url: &str, scenario_id: &str) -> Uuid {
        let response = client
            .post(format!("{base_url}/api/runs"))
            .json(&serde_json::json!({"scenario_id":scenario_id}))
            .send()
            .await
            .expect("create run request");
        assert_eq!(response.status(), StatusCode::CREATED);
        let value: serde_json::Value = response.json().await.expect("create run JSON");
        Uuid::parse_str(
            value
                .get("run_id")
                .and_then(serde_json::Value::as_str)
                .expect("run id"),
        )
        .expect("UUID")
    }

    async fn requests(client: &Client, base_url: &str, run_id: Uuid) -> Vec<AuditRecord> {
        let value: serde_json::Value = client
            .get(format!("{base_url}/api/runs/{run_id}/requests"))
            .send()
            .await
            .expect("requests response")
            .error_for_status()
            .expect("requests status")
            .json()
            .await
            .expect("requests JSON");
        serde_json::from_value(value["requests"].clone()).expect("audit records")
    }

    async fn run_report(
        client: &Client,
        base_url: &str,
        loaded: &LoadedScenario,
        run_id: Uuid,
    ) -> RunReport {
        let guard = EgressGuard::default();
        let runner = ReferenceRunner::new(guard.clone()).expect("reference runner");
        let started = Utc::now();
        let collector = runner
            .run(base_url, &loaded.scenario, run_id, "default")
            .await
            .expect("reference run");
        let audit = requests(client, base_url, run_id).await;
        let report = judge_run(JudgeInput {
            run_id,
            scenario_id: &loaded.scenario.id,
            seed: loaded.scenario.seed,
            target_domain: &loaded.scenario.root_domain,
            started_at: started,
            finished_at: Utc::now(),
            collector_run: &collector,
            truth: &loaded.truth,
            assertions: &loaded.assertions,
            audit: &audit,
            rejected_egress_urls: &guard.rejected_urls(),
        });
        client
            .post(format!("{base_url}/api/runs/{run_id}/report"))
            .json(&report)
            .send()
            .await
            .expect("store report request")
            .error_for_status()
            .expect("store report status");
        report
    }

    fn response_indices(audit: &[AuditRecord]) -> Vec<usize> {
        audit
            .iter()
            .filter_map(|record| record.response_index)
            .collect()
    }

    #[test]
    fn response_templates_follow_the_current_pagination_request() {
        let repository = repository();

        let page = repository
            .get("037-page-pagination")
            .expect("page scenario");
        let mut page_query = BTreeMap::new();
        page_query.insert("page".to_owned(), "4".to_owned());
        let page_context =
            TemplateContext::from_request(&page.scenario.endpoints[0], &page_query, &[]);
        assert_eq!(
            materialize_text(
                "$PAGE|$OFFSET|$CURSOR|$SYNTHETIC_RECORD_ID",
                page,
                "run-page",
                &page_context,
            ),
            "4|0||synthetic-37-4"
        );

        let offset = repository
            .get("038-offset-pagination")
            .expect("offset scenario");
        let mut offset_query = BTreeMap::new();
        offset_query.insert("offset".to_owned(), "40".to_owned());
        let offset_context =
            TemplateContext::from_request(&offset.scenario.endpoints[0], &offset_query, &[]);
        assert_eq!(
            materialize_text(
                "$PAGE|$OFFSET|$CURSOR",
                offset,
                "run-offset",
                &offset_context
            ),
            "1|40|"
        );

        let cursor = repository
            .get("039-post-cursor-pagination")
            .expect("cursor scenario");
        let cursor_context = TemplateContext::from_request(
            &cursor.scenario.endpoints[0],
            &BTreeMap::new(),
            br#"{"cursor":"cursor-next"}"#,
        );
        assert_eq!(
            materialize_text(
                "$PAGE|$OFFSET|$CURSOR",
                cursor,
                "run-cursor",
                &cursor_context
            ),
            "1|0|cursor-next"
        );
    }

    #[tokio::test]
    async fn binds_loopback_and_exposes_control_api() {
        let repository = repository();
        let server = LocalServer::spawn(repository, Some("001-basic-certificate"))
            .await
            .expect("start server");
        let response = Client::new()
            .get(format!("{}/api/scenarios", server.base_url()))
            .send()
            .await
            .expect("control request")
            .text()
            .await
            .expect("body");
        assert!(response.contains("020-cancellation-and-egress-guard"));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn scoped_control_api_returns_empty_report_and_handles_unknown_or_deleted_runs() {
        let server = LocalServer::spawn(repository(), None)
            .await
            .expect("server");
        let client = Client::new();
        let base_url = server.base_url();
        let run_id = create_run(&client, &base_url, "012-pagination-success").await;
        let listed: serde_json::Value = client
            .get(format!("{base_url}/api/runs"))
            .send()
            .await
            .expect("list runs")
            .error_for_status()
            .expect("list status")
            .json()
            .await
            .expect("list JSON");
        assert!(
            listed["runs"]
                .as_array()
                .is_some_and(|runs| runs.iter().any(|run| run["run_id"] == run_id.to_string()))
        );
        let report: serde_json::Value = client
            .get(format!("{base_url}/api/runs/{run_id}/report"))
            .send()
            .await
            .expect("empty report")
            .error_for_status()
            .expect("empty report status")
            .json()
            .await
            .expect("empty report JSON");
        assert!(report["report"].is_null());
        assert_eq!(
            client
                .get(format!("{base_url}/api/runs/not-a-uuid"))
                .send()
                .await
                .expect("invalid run request")
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            client
                .get(format!("{base_url}/api/runs/{}", Uuid::new_v4()))
                .send()
                .await
                .expect("unknown run request")
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            client
                .delete(format!("{base_url}/api/runs/{run_id}"))
                .send()
                .await
                .expect("delete run")
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            client
                .get(format!("{base_url}/api/runs/{run_id}"))
                .send()
                .await
                .expect("deleted run request")
                .status(),
            StatusCode::NOT_FOUND
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn concurrent_pagination_runs_are_isolated() {
        let repository = repository();
        let loaded = repository
            .get("012-pagination-success")
            .expect("pagination scenario")
            .clone();
        let server = LocalServer::spawn(repository, None).await.expect("server");
        let client = Client::new();
        let base_url = server.base_url();
        let (first, second) = tokio::join!(
            create_run(&client, &base_url, &loaded.scenario.id),
            create_run(&client, &base_url, &loaded.scenario.id)
        );
        let (first_report, second_report) = tokio::join!(
            run_report(&client, &base_url, &loaded, first),
            run_report(&client, &base_url, &loaded, second)
        );
        assert_eq!(first_report.status, ReportStatus::Passed);
        assert_eq!(second_report.status, ReportStatus::Passed);
        let first_audit = requests(&client, &base_url, first).await;
        let second_audit = requests(&client, &base_url, second).await;
        assert_eq!(first_audit.len(), 2);
        assert_eq!(second_audit.len(), 2);
        assert_eq!(response_indices(&first_audit), vec![0, 1]);
        assert_eq!(response_indices(&second_audit), vec![0, 1]);
        assert!(
            first_audit
                .iter()
                .all(|record| record.run_id.as_deref() == Some(&first.to_string()))
        );
        assert!(
            second_audit
                .iter()
                .all(|record| record.run_id.as_deref() == Some(&second.to_string()))
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn resetting_one_run_does_not_affect_another() {
        let repository = repository();
        let loaded = repository
            .get("012-pagination-success")
            .expect("pagination scenario")
            .clone();
        let server = LocalServer::spawn(repository, None).await.expect("server");
        let client = Client::new();
        let base_url = server.base_url();
        let first = create_run(&client, &base_url, &loaded.scenario.id).await;
        let second = create_run(&client, &base_url, &loaded.scenario.id).await;
        let first_page = client
            .get(format!("{base_url}/pages/v1/search?domain=acme.test"))
            .header("x-lab-run-id", first.to_string())
            .send()
            .await
            .expect("first page");
        assert_eq!(first_page.status(), StatusCode::OK);
        let reset = client
            .post(format!("{base_url}/api/runs/{first}/reset"))
            .send()
            .await
            .expect("reset");
        assert_eq!(reset.status(), StatusCode::OK);
        let second_report = run_report(&client, &base_url, &loaded, second).await;
        assert_eq!(second_report.status, ReportStatus::Passed);
        assert!(requests(&client, &base_url, first).await.is_empty());
        assert_eq!(
            response_indices(&requests(&client, &base_url, second).await),
            vec![0, 1]
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn different_scenarios_run_concurrently_without_mixing() {
        let repository = repository();
        let pages = repository
            .get("012-pagination-success")
            .expect("pagination scenario")
            .clone();
        let rate_limit = repository
            .get("015-rate-limit-retry")
            .expect("rate scenario")
            .clone();
        let server = LocalServer::spawn(repository, None).await.expect("server");
        let client = Client::new();
        let base_url = server.base_url();
        let (pages_id, rate_id) = tokio::join!(
            create_run(&client, &base_url, &pages.scenario.id),
            create_run(&client, &base_url, &rate_limit.scenario.id)
        );
        let (pages_report, rate_report) = tokio::join!(
            run_report(&client, &base_url, &pages, pages_id),
            run_report(&client, &base_url, &rate_limit, rate_id)
        );
        assert_eq!(pages_report.status, ReportStatus::Passed);
        assert_eq!(rate_report.status, ReportStatus::Passed);
        assert_eq!(pages_report.virtual_waited_ms, 0);
        assert_eq!(rate_report.virtual_waited_ms, 1_000);
        assert_eq!(
            response_indices(&requests(&client, &base_url, pages_id).await),
            vec![0, 1]
        );
        assert_eq!(
            response_indices(&requests(&client, &base_url, rate_id).await),
            vec![0, 1]
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn missing_run_id_is_unscoped_and_does_not_consume_a_session() {
        let repository = repository();
        let loaded = repository
            .get("012-pagination-success")
            .expect("pagination scenario")
            .clone();
        let server = LocalServer::spawn(repository, None).await.expect("server");
        let client = Client::new();
        let base_url = server.base_url();
        let run_id = create_run(&client, &base_url, &loaded.scenario.id).await;
        let missing = client
            .get(format!("{base_url}/pages/v1/search?domain=acme.test"))
            .send()
            .await
            .expect("missing run header request");
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        assert!(requests(&client, &base_url, run_id).await.is_empty());
        let diagnostics = client
            .get(format!("{base_url}/api/diagnostics/unscoped-requests"))
            .send()
            .await
            .expect("diagnostics")
            .text()
            .await
            .expect("diagnostics body");
        assert!(diagnostics.contains("missing x-lab-run-id"));
        let report = run_report(&client, &base_url, &loaded, run_id).await;
        assert_eq!(report.status, ReportStatus::Passed);
        assert_eq!(
            response_indices(&requests(&client, &base_url, run_id).await),
            vec![0, 1]
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn request_mismatches_do_not_consume_the_first_reply_or_leak_keys() {
        let repository = repository();
        let pagination = repository
            .get("012-pagination-success")
            .expect("pagination scenario")
            .clone();
        let rate_limit = repository
            .get("015-rate-limit-retry")
            .expect("rate scenario")
            .clone();
        let server = LocalServer::spawn(repository, None).await.expect("server");
        let client = Client::new();
        let base_url = server.base_url();
        let page_id = create_run(&client, &base_url, &pagination.scenario.id).await;
        for request in [
            client
                .post(format!("{base_url}/pages/v1/search?domain=acme.test"))
                .header("x-lab-run-id", page_id.to_string()),
            client
                .get(format!("{base_url}/pages/v1/search"))
                .header("x-lab-run-id", page_id.to_string()),
            client
                .get(format!("{base_url}/pages/v1/search?domain=wrong.test"))
                .header("x-lab-run-id", page_id.to_string()),
        ] {
            assert!(
                request
                    .send()
                    .await
                    .expect("mismatch request")
                    .status()
                    .is_client_error()
            );
        }
        let first_page = client
            .get(format!("{base_url}/pages/v1/search?domain=acme.test"))
            .header("x-lab-run-id", page_id.to_string())
            .send()
            .await
            .expect("correct request");
        assert_eq!(first_page.status(), StatusCode::OK);
        let second_page = client
            .get(format!(
                "{base_url}/pages/v1/search?domain=acme.test&cursor=next"
            ))
            .header("x-lab-run-id", page_id.to_string())
            .send()
            .await
            .expect("second page");
        assert_eq!(second_page.status(), StatusCode::OK);
        let extra = client
            .get(format!("{base_url}/pages/v1/search?domain=acme.test"))
            .header("x-lab-run-id", page_id.to_string())
            .send()
            .await
            .expect("extra request");
        assert_eq!(extra.status(), StatusCode::CONFLICT);
        let audit = requests(&client, &base_url, page_id).await;
        assert_eq!(response_indices(&audit), vec![0, 1]);
        assert!(audit.last().is_some_and(|record| record.extra));

        let rate_id = create_run(&client, &base_url, &rate_limit.scenario.id).await;
        let wrong_key = client
            .get(format!("{base_url}/key/v1/search?domain=acme.test"))
            .header("x-lab-run-id", rate_id.to_string())
            .header("x-api-key", "wrong-key")
            .send()
            .await
            .expect("wrong key request");
        assert_eq!(wrong_key.status(), StatusCode::BAD_REQUEST);
        assert!(
            !serde_json::to_string(&requests(&client, &base_url, rate_id).await)
                .expect("audit JSON")
                .contains("wrong-key")
        );
        let good_rate_id = create_run(&client, &base_url, &rate_limit.scenario.id).await;
        let rate_report = run_report(&client, &base_url, &rate_limit, good_rate_id).await;
        assert_eq!(rate_report.status, ReportStatus::Passed);
        assert!(
            !serde_json::to_string(&requests(&client, &base_url, good_rate_id).await)
                .expect("audit JSON")
                .contains("lab-demo-key")
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn post_body_and_external_redirect_contracts_are_enforced() {
        let (repository, temporary_root) = temporary_contract_repository();
        let post = repository.get("post-json").expect("post scenario").clone();
        let redirect = repository
            .get("redirect")
            .expect("redirect scenario")
            .clone();
        let server = LocalServer::spawn(repository, None).await.expect("server");
        let client = Client::new();
        let base_url = server.base_url();

        let correct_run = create_run(&client, &base_url, &post.scenario.id).await;
        let correct = client
            .post(format!("{base_url}/post/v1/search?domain=acme.test"))
            .header("x-lab-run-id", correct_run.to_string())
            .json(&serde_json::json!({"query":"subdomains"}))
            .send()
            .await
            .expect("correct POST body");
        assert_eq!(correct.status(), StatusCode::OK);
        assert_eq!(
            response_indices(&requests(&client, &base_url, correct_run).await),
            vec![0]
        );

        let wrong_run = create_run(&client, &base_url, &post.scenario.id).await;
        let wrong = client
            .post(format!("{base_url}/post/v1/search?domain=acme.test"))
            .header("x-lab-run-id", wrong_run.to_string())
            .json(&serde_json::json!({"query":"wrong"}))
            .send()
            .await
            .expect("wrong POST body");
        assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
        assert!(response_indices(&requests(&client, &base_url, wrong_run).await).is_empty());

        let redirect_run = create_run(&client, &base_url, &redirect.scenario.id).await;
        let guard = EgressGuard::default();
        let collector = ReferenceRunner::new(guard.clone())
            .expect("reference runner")
            .run(&base_url, &redirect.scenario, redirect_run, "default")
            .await
            .expect("redirect run");
        assert_eq!(
            collector.source_statuses.get("redirect-source"),
            Some(&SourceStatus::Blocked)
        );
        assert!(collector.metrics.blocked_egress);
        assert_eq!(guard.rejected_urls(), vec!["http://198.51.100.10/redirect"]);
        let redirect_audit = requests(&client, &base_url, redirect_run).await;
        assert_eq!(redirect_audit.len(), 1);
        assert_eq!(redirect_audit[0].response_status, 302);
        assert!(redirect_audit[0].blocked);
        assert!(redirect_audit[0].external_target_rejected);
        server.shutdown().await;
        fs::remove_dir_all(temporary_root).expect("remove temporary scenarios");
    }
}
