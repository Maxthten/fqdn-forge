//! A rule-driven HTTP simulator that only binds numeric IPv4 loopback.

use std::{
    collections::BTreeMap,
    fs,
    hash::{Hash, Hasher},
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
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
use brotli::CompressorWriter;
use chrono::Utc;
use flate2::{
    Compression,
    write::{GzEncoder, ZlibEncoder},
};
use futures_util::stream;
use lab_core::{
    AnalysisView, AuditEventType, AuditRecord, AuthenticationLocation, AuthenticationMode,
    CollectorRun, CollectorSubmission, EgressGuard, Endpoint, ExperimentPlan, FaultScriptClaim,
    FaultScriptStage, FilterReason, FilteredCandidate, GeneratorKind, JudgeInput, LabState,
    LoadedScenario, ManifestNetwork, ManifestNetworkProfile, ManifestQuotaProfile, ManifestSource,
    ManifestSubmission, ManifestTransportProfile, NetworkMode, NetworkProfile, PLAN_SCHEMA_VERSION,
    PaginationMode, PlanFaultKind, PlanNetworkMode, PlanPagination, PlanPaginationMode, PlanQuota,
    PlanRequestAuditStep, PlanRun, PlanSourceTemplate, ProxyAuthenticationState, ProxyFault,
    QuotaExhaustedBehaviour, QuotaProfile, ReferenceRunner, Reply, ResponseMetrics, RetryAfterMode,
    RunManifest, RunReport, RunSession, RunStateError, Scenario, ScenarioRepository, SourceStatus,
    SubmissionLimits, SubmissionReport, TransferMode, ValueRule, accept_candidate,
    analysis_markdown, authentication_outcome, enrich_report, judge_run, parse_analysis_request,
    plan_source_page_records, refresh_semantic_fingerprint, retry_after_value, stable_digest,
    validate_plan, virtual_http_date_after,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
use url::Url;
use uuid::Uuid;

pub struct LocalServer {
    address: SocketAddr,
    proxy_address: SocketAddr,
    state: LabState,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    proxy_shutdown: Option<oneshot::Sender<()>>,
    proxy_task: Option<JoinHandle<()>>,
}

impl LocalServer {
    pub async fn spawn(
        repository: ScenarioRepository,
        active: Option<&str>,
    ) -> Result<Self, String> {
        Self::spawn_inner(repository, active, None, None).await
    }

    pub async fn spawn_on(
        repository: ScenarioRepository,
        active: Option<&str>,
        port: Option<u16>,
    ) -> Result<Self, String> {
        Self::spawn_inner(repository, active, port, None).await
    }

    pub async fn spawn_on_with_plan_root(
        repository: ScenarioRepository,
        active: Option<&str>,
        port: Option<u16>,
        plan_root: PathBuf,
    ) -> Result<Self, String> {
        let analysis_artifacts_root = repository
            .root()
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("artifacts");
        Self::spawn_inner(
            repository,
            active,
            port,
            Some((plan_root, analysis_artifacts_root)),
        )
        .await
    }

    pub async fn spawn_on_with_roots(
        repository: ScenarioRepository,
        active: Option<&str>,
        port: Option<u16>,
        plan_root: PathBuf,
        analysis_artifacts_root: PathBuf,
    ) -> Result<Self, String> {
        Self::spawn_inner(
            repository,
            active,
            port,
            Some((plan_root, analysis_artifacts_root)),
        )
        .await
    }

    #[cfg(test)]
    async fn spawn_with_plan_root(
        repository: ScenarioRepository,
        active: Option<&str>,
        plan_root: PathBuf,
    ) -> Result<Self, String> {
        Self::spawn_on_with_plan_root(repository, active, None, plan_root).await
    }

    async fn spawn_inner(
        repository: ScenarioRepository,
        active: Option<&str>,
        port: Option<u16>,
        roots: Option<(PathBuf, PathBuf)>,
    ) -> Result<Self, String> {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port.unwrap_or(0));
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err("refusing non-loopback listener".to_owned());
        }
        let state = match roots {
            Some((plan_root, analysis_artifacts_root)) => {
                LabState::new_with_plan_root_and_analysis_root(
                    repository,
                    plan_root,
                    analysis_artifacts_root,
                )
            }
            None => LabState::new(repository),
        };
        state.set_base_url(format!("http://127.0.0.1:{}", address.port()));
        let proxy_listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .map_err(|error| error.to_string())?;
        let proxy_address = proxy_listener
            .local_addr()
            .map_err(|error| error.to_string())?;
        if proxy_address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err("refusing non-loopback proxy listener".to_owned());
        }
        state.set_proxy_url(format!("http://127.0.0.1:{}", proxy_address.port()));
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
        let (proxy_shutdown, proxy_receiver) = oneshot::channel();
        let proxy_state = state.clone();
        let proxy_task = tokio::spawn(async move {
            proxy_loop(proxy_listener, proxy_state, proxy_receiver).await;
        });
        Ok(Self {
            address,
            proxy_address,
            state,
            shutdown: Some(shutdown),
            task: Some(task),
            proxy_shutdown: Some(proxy_shutdown),
            proxy_task: Some(proxy_task),
        })
    }

    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.address.port())
    }

    #[must_use]
    pub fn proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.proxy_address.port())
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

    /// Internal state is exposed only for the terminal leak/invariant check of
    /// a public loopback soak; test actions themselves use HTTP/proxy routes.
    #[must_use]
    pub fn resource_summary(&self) -> lab_core::ResourceSummary {
        self.state.resource_summary()
    }

    pub async fn shutdown(mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(sender) = self.proxy_shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.proxy_task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(sender) = self.proxy_shutdown.take() {
            let _ = sender.send(());
        }
    }
}

const MAX_PROXY_HEADER_BYTES: usize = 32 * 1024;
const MAX_PROXY_BODY_BYTES: usize = 1024 * 1024;
const MAX_PROXY_TUNNEL_BYTES: usize = 64 * 1024;

struct RawProxyRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn proxy_loop(listener: TcpListener, state: LabState, mut shutdown: oneshot::Receiver<()>) {
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, address)) if address.ip().is_loopback() => {
                    let state = state.clone();
                    tokio::spawn(async move { handle_proxy_connection(stream, state).await; });
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }
}

async fn handle_proxy_connection(mut client: TcpStream, state: LabState) {
    let request = match read_proxy_request(&mut client).await {
        Ok(request) => request,
        Err(reason) => {
            let _ = write_proxy_response(&mut client, 400, "Bad Request", None).await;
            state.record_unscoped_request("PROXY", "/", &reason);
            return;
        }
    };
    let headers = proxy_header_map(&request.headers);
    let Some(run_id) = headers.get("x-lab-run-id").cloned() else {
        state.record_unscoped_request(&request.method, &request.target, "missing x-lab-run-id");
        let _ = write_proxy_response(&mut client, 400, "Bad Request", None).await;
        return;
    };
    if state.plan_run(&run_id).is_ok() {
        handle_plan_proxy_connection(client, state, &run_id, request, headers).await;
        return;
    }
    let loaded = match state.loaded_for_run(&run_id) {
        Ok(loaded) => loaded,
        Err(_) => {
            state.record_unscoped_request(&request.method, &request.target, "unknown proxy run");
            let _ = write_proxy_response(&mut client, 404, "Not Found", None).await;
            return;
        }
    };
    let profile = loaded.scenario.network_profile.clone();
    let auth = match state.session(&run_id) {
        Ok(run) => proxy_authentication_state(&headers, &run),
        Err(_) => ProxyAuthenticationState::Invalid,
    };
    let is_connect = request.method.eq_ignore_ascii_case("CONNECT");
    let correlation_id = Uuid::new_v4().to_string();
    let mut audit = proxy_audit_record(ProxyAuditContext {
        run_id: &run_id,
        scenario: &loaded.scenario,
        method: &request.method,
        target: &request.target,
        profile: &profile,
        authentication: auth,
        response_status: 0,
        reason: None,
        blocked: false,
        correlation_id: correlation_id.clone(),
    });
    if let Some(reason) = proxy_request_shape_reason(&request) {
        audit.response_status = 400;
        audit.blocked = true;
        audit.external_target_rejected = true;
        audit.proxy_reason = Some(reason);
        let _ = state.record_request(&run_id, audit);
        let _ = write_proxy_response(&mut client, 400, "Bad Request", None).await;
        return;
    }
    if profile.mode == NetworkMode::Direct
        || (profile.mode == NetworkMode::HttpProxy && is_connect)
        || (profile.mode == NetworkMode::ConnectProxy && !is_connect)
    {
        audit.response_status = 403;
        audit.blocked = true;
        audit.proxy_reason = Some("profile_mismatch".to_owned());
        let _ = state.record_request(&run_id, audit);
        let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
        return;
    }
    if auth != ProxyAuthenticationState::Valid {
        audit.response_status = 407;
        audit.proxy_reason = Some("proxy_authentication_required".to_owned());
        let _ = state.record_request(&run_id, audit);
        let _ = write_proxy_response(
            &mut client,
            407,
            "Proxy Authentication Required",
            Some("Proxy-Authenticate: Lab\r\n"),
        )
        .await;
        return;
    }
    if matches!(profile.fault, ProxyFault::ConnectionRefused) {
        audit.response_status = 502;
        audit.proxy_reason = Some("connection_refused".to_owned());
        let _ = state.record_request(&run_id, audit);
        let _ = write_proxy_response(&mut client, 502, "Bad Gateway", None).await;
        return;
    }
    if matches!(profile.fault, ProxyFault::ConnectTimeout) {
        audit.response_status = 504;
        audit.proxy_reason = Some("connect_timeout".to_owned());
        let _ = state.record_request(&run_id, audit);
        tokio::time::sleep(Duration::from_millis(profile.virtual_timeout_ms.min(50))).await;
        let _ = write_proxy_response(&mut client, 504, "Gateway Timeout", None).await;
        return;
    }
    if matches!(profile.fault, ProxyFault::ResetBeforeResponse) {
        audit.proxy_reason = Some("reset_before_response".to_owned());
        let _ = state.record_request(&run_id, audit);
        return;
    }
    if matches!(profile.fault, ProxyFault::ResetAfterHeaders) {
        audit.response_status = 502;
        audit.proxy_reason = Some("reset_after_headers".to_owned());
        let _ = state.record_request(&run_id, audit);
        let _ = client
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n")
            .await;
        return;
    }
    if is_connect {
        proxy_connect(
            client,
            state,
            &run_id,
            &loaded.scenario,
            profile,
            request,
            audit,
        )
        .await;
    } else {
        proxy_forward(
            client,
            state,
            &run_id,
            &loaded.scenario,
            profile,
            request,
            audit,
        )
        .await;
    }
}

async fn handle_plan_proxy_connection(
    mut client: TcpStream,
    state: LabState,
    run_id: &str,
    request: RawProxyRequest,
    headers: BTreeMap<String, String>,
) {
    if let Some(reason) = proxy_request_shape_reason(&request) {
        let _ = write_proxy_response(&mut client, 400, "Bad Request", None).await;
        state.record_unscoped_request("PLAN_PROXY", &request.target, &reason);
        return;
    }
    let access = match state.plan_run_access(run_id) {
        Ok(access) => access,
        Err(_) => {
            let _ = write_proxy_response(&mut client, 410, "Gone", None).await;
            return;
        }
    };
    if headers.get("x-lab-source-capability") != Some(&access.source_capability) {
        let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
        return;
    }
    let plan = match state.plan_run(run_id) {
        Ok(run) => run.plan_snapshot,
        Err(_) => {
            let _ = write_proxy_response(&mut client, 404, "Not Found", None).await;
            return;
        }
    };
    let is_connect = request.method.eq_ignore_ascii_case("CONNECT");
    if plan.network_path.mode == PlanNetworkMode::Direct
        || (plan.network_path.mode == PlanNetworkMode::HttpProxy && is_connect)
        || (plan.network_path.mode == PlanNetworkMode::Connect && !is_connect)
    {
        let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
        return;
    }
    match plan.network_path.proxy_authentication {
        lab_core::ProxyAuthentication::Fails => {
            let _ = write_proxy_response(
                &mut client,
                407,
                "Proxy Authentication Required",
                Some("Proxy-Authenticate: Lab\r\n"),
            )
            .await;
            return;
        }
        lab_core::ProxyAuthentication::Succeeds => {
            let authorization = format!("Lab {}", access.source_capability);
            if headers.get("proxy-authorization") != Some(&authorization)
                || headers.get("x-lab-proxy-capability") != Some(&access.source_capability)
            {
                let _ = write_proxy_response(
                    &mut client,
                    407,
                    "Proxy Authentication Required",
                    Some("Proxy-Authenticate: Lab\r\n"),
                )
                .await;
                return;
            }
        }
        lab_core::ProxyAuthentication::NotRequired => {}
    }
    match plan.network_path.proxy_fault {
        lab_core::ProxySimulationFault::RejectRequest
        | lab_core::ProxySimulationFault::NotAllowlisted => {
            let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
            return;
        }
        lab_core::ProxySimulationFault::ConnectFailure => {
            let _ = write_proxy_response(&mut client, 502, "Bad Gateway", None).await;
            return;
        }
        lab_core::ProxySimulationFault::SlowResponse => {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        lab_core::ProxySimulationFault::Disconnect => return,
        lab_core::ProxySimulationFault::None => {}
    }
    let source_port = state
        .base_url()
        .and_then(|value| Url::parse(&value).ok())
        .and_then(|url| url.port_or_known_default())
        .unwrap_or_default();
    let (forward_request, path, source_id) = if is_connect {
        if request.target != format!("127.0.0.1:{source_port}") {
            let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
            return;
        }
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: keep-alive\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        // This is deliberately a controlled CONNECT simulation, not a real
        // TLS tunnel: the one request inside it stays plaintext so the server
        // can enforce that it targets only a local plan-source endpoint.
        let tunneled = match tokio::time::timeout(
            Duration::from_millis(1_000),
            read_proxy_request(&mut client),
        )
        .await
        {
            Ok(Ok(tunneled)) => tunneled,
            _ => {
                let _ = write_proxy_response(&mut client, 400, "Bad Request", None).await;
                return;
            }
        };
        if proxy_request_shape_reason(&tunneled).is_some()
            || tunneled.method.eq_ignore_ascii_case("CONNECT")
            || !tunneled.target.starts_with('/')
        {
            let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
            return;
        }
        let (path, source_id) = {
            let tunneled_path = tunneled
                .target
                .split_once('?')
                .map_or(tunneled.target.as_str(), |(path, _)| path);
            let Some((_, source_id)) = plan_source_route(tunneled_path) else {
                let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
                return;
            };
            (tunneled_path.to_owned(), source_id.to_owned())
        };
        (tunneled, path, source_id)
    } else {
        let target = match Url::parse(&request.target) {
            Ok(target)
                if target.host_str() == Some("127.0.0.1")
                    && target.port_or_known_default() == Some(source_port)
                    && plan_source_route(target.path()).is_some() =>
            {
                target
            }
            _ => {
                let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
                return;
            }
        };
        let (_, source_id) = plan_source_route(target.path()).expect("validated plan source route");
        let mut path = target.path().to_owned();
        if let Some(query) = target.query() {
            path.push('?');
            path.push_str(query);
        }
        (request, path, source_id.to_owned())
    };
    if !plan.network_path.allowlisted_sources.is_empty()
        && !plan
            .network_path
            .allowlisted_sources
            .iter()
            .any(|allowed| allowed == &source_id)
    {
        let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
        return;
    }
    let mut source = match TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)).await {
        Ok(stream) => stream,
        Err(_) => {
            let _ = write_proxy_response(&mut client, 502, "Bad Gateway", None).await;
            return;
        }
    };
    let mut forwarded = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{source_port}\r\n",
        forward_request.method, path
    );
    for (name, value) in &forward_request.headers {
        let normalized = name.to_ascii_lowercase();
        if matches!(
            normalized.as_str(),
            "host"
                | "connection"
                | "proxy-authorization"
                | "proxy-connection"
                | "x-lab-proxy-capability"
        ) {
            continue;
        }
        forwarded.push_str(&format!("{name}: {value}\r\n"));
    }
    forwarded.push_str("x-lab-proxy-correlation: plan-local\r\nConnection: close\r\n\r\n");
    if source.write_all(forwarded.as_bytes()).await.is_err()
        || source.write_all(&forward_request.body).await.is_err()
    {
        return;
    }
    let mut response = Vec::new();
    if !matches!(
        tokio::time::timeout(
            Duration::from_millis(1_000),
            source.read_to_end(&mut response)
        )
        .await,
        Ok(Ok(_))
    ) || response.len() > MAX_PROXY_TUNNEL_BYTES.saturating_mul(16)
    {
        let _ = write_proxy_response(&mut client, 502, "Bad Gateway", None).await;
        return;
    }
    let _ = client.write_all(&response).await;
}

async fn proxy_forward(
    mut client: TcpStream,
    state: LabState,
    run_id: &str,
    scenario: &Scenario,
    profile: NetworkProfile,
    request: RawProxyRequest,
    mut audit: AuditRecord,
) {
    let target = match allowed_forward_proxy_target(&state, run_id, scenario, &request) {
        Ok(target) => target,
        Err(reason) => {
            audit.response_status = 403;
            audit.blocked = true;
            audit.external_target_rejected = true;
            audit.proxy_reason = Some(reason);
            let _ = state.record_request(run_id, audit);
            let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
            return;
        }
    };
    audit.endpoint_id = scenario
        .endpoints
        .iter()
        .find(|endpoint| endpoint.request_match.path == target.path())
        .map(|endpoint| endpoint.id.clone());
    let endpoint_id = audit.endpoint_id.clone().unwrap_or_default();
    let script_claim = match state.claim_fault_script_step(
        run_id,
        &scenario.fault_script,
        FaultScriptStage::Proxy,
        &endpoint_id,
        &parse_query(target.query()),
        0,
    ) {
        Ok(claim) => claim,
        Err(_) => {
            let _ = write_proxy_response(&mut client, 409, "Conflict", None).await;
            return;
        }
    };
    match script_claim {
        FaultScriptClaim::Unscripted => {}
        FaultScriptClaim::Unexpected(reason) => {
            audit.response_status = 409;
            audit.blocked = true;
            audit.proxy_reason = Some("unexpected_script_step".to_owned());
            audit
                .mismatch_reasons
                .push(format!("unexpected_script_step: {reason}"));
            let _ = state.record_request(run_id, audit);
            let _ = write_proxy_response(&mut client, 409, "Conflict", None).await;
            return;
        }
        FaultScriptClaim::Matched(step) => {
            audit.script_step_id = Some(step.id);
            if step.proxy_fault != ProxyFault::None {
                audit.proxy_reason = Some(format!("fault_script_{:?}", step.proxy_fault));
                match step.proxy_fault {
                    ProxyFault::ResetBeforeResponse => {
                        let _ = state.record_request(run_id, audit);
                        return;
                    }
                    ProxyFault::ResetAfterHeaders => {
                        audit.response_status = 502;
                        let _ = state.record_request(run_id, audit);
                        let _ = client
                            .write_all(
                                b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n",
                            )
                            .await;
                        return;
                    }
                    ProxyFault::ConnectionRefused => {
                        audit.response_status = 502;
                        let _ = state.record_request(run_id, audit);
                        let _ = write_proxy_response(&mut client, 502, "Bad Gateway", None).await;
                        return;
                    }
                    ProxyFault::ConnectTimeout => {
                        audit.response_status = 504;
                        let _ = state.record_request(run_id, audit);
                        let _ =
                            write_proxy_response(&mut client, 504, "Gateway Timeout", None).await;
                        return;
                    }
                    ProxyFault::EgressDenied => {
                        audit.response_status = 403;
                        audit.blocked = true;
                        let _ = state.record_request(run_id, audit);
                        let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
                        return;
                    }
                    ProxyFault::TunnelCloseAfterBytes | ProxyFault::None => {}
                }
            }
        }
    }
    if matches!(profile.fault, ProxyFault::EgressDenied) {
        // The target has already passed the numeric-loopback allowlist, so
        // this is a scenario-selected local proxy fault rather than a client
        // egress attempt. It must not reach the source endpoint.
        audit.response_status = 403;
        audit.blocked = true;
        audit.proxy_reason = Some("egress_denied".to_owned());
        let _ = state.record_request(run_id, audit);
        let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
        return;
    }
    audit.response_status = 200;
    audit.proxy_reason = Some("forwarded".to_owned());
    let correlation = audit.correlation_id.clone().unwrap_or_default();
    let _ = state.record_request(run_id, audit);
    let source_port = target.port_or_known_default().unwrap_or_default();
    let mut source = match tokio::time::timeout(
        Duration::from_millis(profile.virtual_timeout_ms),
        TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => {
            let _ = write_proxy_response(&mut client, 502, "Bad Gateway", None).await;
            return;
        }
    };
    let mut path = target.path().to_owned();
    if let Some(query) = target.query() {
        path.push('?');
        path.push_str(query);
    }
    let mut forwarded = format!("{} {} HTTP/1.1\r\n", request.method, path);
    let mut wrote_host = false;
    for (name, value) in &request.headers {
        let normalized = name.to_ascii_lowercase();
        if matches!(
            normalized.as_str(),
            "proxy-authorization" | "x-lab-proxy-capability"
        ) {
            continue;
        }
        if normalized == "host" {
            wrote_host = true;
            forwarded.push_str(&format!("Host: 127.0.0.1:{source_port}\r\n"));
        } else {
            forwarded.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    if !wrote_host {
        forwarded.push_str(&format!("Host: 127.0.0.1:{source_port}\r\n"));
    }
    forwarded.push_str(&format!(
        "x-lab-proxy-correlation: {correlation}\r\nConnection: close\r\n\r\n"
    ));
    if source.write_all(forwarded.as_bytes()).await.is_err()
        || source.write_all(&request.body).await.is_err()
    {
        return;
    }
    let mut response = Vec::new();
    let result = tokio::time::timeout(
        Duration::from_millis(profile.virtual_timeout_ms.max(50)),
        source.read_to_end(&mut response),
    )
    .await;
    if !matches!(result, Ok(Ok(_))) || response.len() > MAX_PROXY_TUNNEL_BYTES.saturating_mul(16) {
        let _ = write_proxy_response(&mut client, 502, "Bad Gateway", None).await;
        return;
    }
    let _ = client.write_all(&response).await;
}

async fn proxy_connect(
    mut client: TcpStream,
    state: LabState,
    run_id: &str,
    scenario: &Scenario,
    profile: NetworkProfile,
    request: RawProxyRequest,
    mut audit: AuditRecord,
) {
    let port = match allowed_connect_proxy_target(&state, run_id, scenario, &request) {
        Ok(port) => port,
        Err(reason) => {
            audit.response_status = 403;
            audit.blocked = true;
            audit.external_target_rejected = true;
            audit.proxy_reason = Some(reason);
            let _ = state.record_request(run_id, audit);
            let _ = write_proxy_response(&mut client, 403, "Forbidden", None).await;
            return;
        }
    };
    let endpoint_id = scenario
        .endpoints
        .first()
        .map(|endpoint| endpoint.id.as_str())
        .unwrap_or_default();
    let mut scripted_fault = ProxyFault::None;
    match state.claim_fault_script_step(
        run_id,
        &scenario.fault_script,
        FaultScriptStage::Proxy,
        endpoint_id,
        &BTreeMap::new(),
        0,
    ) {
        Ok(FaultScriptClaim::Unscripted) => {}
        Ok(FaultScriptClaim::Matched(step)) => {
            audit.script_step_id = Some(step.id);
            scripted_fault = step.proxy_fault;
        }
        Ok(FaultScriptClaim::Unexpected(reason)) => {
            audit.response_status = 409;
            audit.blocked = true;
            audit.proxy_reason = Some("unexpected_script_step".to_owned());
            audit
                .mismatch_reasons
                .push(format!("unexpected_script_step: {reason}"));
            let _ = state.record_request(run_id, audit);
            let _ = write_proxy_response(&mut client, 409, "Conflict", None).await;
            return;
        }
        Err(_) => {
            let _ = write_proxy_response(&mut client, 409, "Conflict", None).await;
            return;
        }
    }
    audit.response_status = 200;
    if scripted_fault != ProxyFault::None || profile.fault != ProxyFault::None {
        audit.proxy_reason = Some("tunnel_truncated".to_owned());
        audit.transport_fault = Some("truncated".to_owned());
    } else {
        audit.proxy_reason = Some("connect_established".to_owned());
    }
    let correlation = audit.correlation_id.clone().unwrap_or_default();
    let _ = state.record_request(run_id, audit);
    let mut target = match TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
        Ok(target) => target,
        Err(_) => {
            let _ = write_proxy_response(&mut client, 502, "Bad Gateway", None).await;
            return;
        }
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    if matches!(profile.fault, ProxyFault::TunnelCloseAfterBytes) {
        return;
    }
    let limit = profile
        .tunnel_close_after_bytes
        .unwrap_or(MAX_PROXY_TUNNEL_BYTES)
        .min(MAX_PROXY_TUNNEL_BYTES);
    let mut inbound = vec![0_u8; limit.max(1)];
    let Ok(Ok(read)) = tokio::time::timeout(
        Duration::from_millis(profile.virtual_timeout_ms.max(50)),
        client.read(&mut inbound),
    )
    .await
    else {
        return;
    };
    if read == 0 {
        return;
    }
    let mut forwarded = inbound[..read].to_vec();
    if let Some(headers_end) = forwarded
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
    {
        let proxy_header = format!("\r\nx-lab-proxy-correlation: {correlation}").into_bytes();
        forwarded.splice(headers_end..headers_end, proxy_header);
    }
    if target.write_all(&forwarded).await.is_err() {
        return;
    }
    let mut outbound = vec![0_u8; limit.max(1)];
    if let Ok(Ok(written)) = tokio::time::timeout(
        Duration::from_millis(profile.virtual_timeout_ms.max(50)),
        target.read(&mut outbound),
    )
    .await
    {
        let _ = client.write_all(&outbound[..written]).await;
    }
}

fn allowed_forward_proxy_target(
    state: &LabState,
    run_id: &str,
    scenario: &Scenario,
    request: &RawProxyRequest,
) -> Result<Url, String> {
    if request.target.contains('%')
        || request.target.contains('@')
        || request.target.contains('#')
        || request.target.chars().any(char::is_control)
    {
        return Err("non_canonical_target".to_owned());
    }
    let source = state
        .base_url()
        .ok_or_else(|| "source_unavailable".to_owned())?;
    let source = Url::parse(&source).map_err(|_| "source_unavailable".to_owned())?;
    let expected_authority = format!(
        "127.0.0.1:{}",
        source.port_or_known_default().unwrap_or_default()
    );
    // `Url` deliberately accepts and canonicalizes several historical IPv4
    // spellings.  The local proxy's allowlist is intentionally textual as
    // well as semantic: only the exact numeric loopback authority advertised
    // by the manifest may reach the parser or the source socket.
    let expected_prefix = format!("http://{expected_authority}/");
    if !request.target.starts_with(&expected_prefix) {
        return Err("non_canonical_target".to_owned());
    }
    let target = Url::parse(&request.target).map_err(|_| "invalid_absolute_form".to_owned())?;
    if target.scheme() != "http"
        || target.host_str() != Some("127.0.0.1")
        || target.port_or_known_default() != source.port_or_known_default()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
    {
        return Err("egress_denied".to_owned());
    }
    if exact_proxy_host(request) != Some(expected_authority.as_str()) {
        return Err("host_authority_mismatch".to_owned());
    }
    if !scenario.endpoints.iter().any(|endpoint| {
        endpoint.request_match.path == target.path()
            && endpoint
                .request_match
                .method
                .as_str()
                .eq_ignore_ascii_case(&request.method)
    }) {
        return Err("unregistered_target".to_owned());
    }
    if request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-lab-run-id"))
        .is_none_or(|(_, value)| value != run_id)
    {
        return Err("cross_run_or_missing_run_id".to_owned());
    }
    Ok(target)
}

fn allowed_connect_proxy_target(
    state: &LabState,
    _run_id: &str,
    _scenario: &Scenario,
    request: &RawProxyRequest,
) -> Result<u16, String> {
    let authority = &request.target;
    if authority.contains('%')
        || authority.contains('@')
        || authority.contains('/')
        || authority.contains('#')
    {
        return Err("egress_denied".to_owned());
    }
    let (host, port) = authority
        .split_once(':')
        .ok_or_else(|| "invalid_connect_authority".to_owned())?;
    if host != "127.0.0.1"
        || port.is_empty()
        || port.contains(':')
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("egress_denied".to_owned());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "invalid_connect_authority".to_owned())?;
    let source = state
        .base_url()
        .ok_or_else(|| "source_unavailable".to_owned())?;
    let source = Url::parse(&source).map_err(|_| "source_unavailable".to_owned())?;
    if source.port_or_known_default() != Some(port) {
        return Err("unregistered_target".to_owned());
    }
    if exact_proxy_host(request) != Some(authority.as_str()) {
        return Err("host_authority_mismatch".to_owned());
    }
    Ok(port)
}

fn exact_proxy_host(request: &RawProxyRequest) -> Option<&str> {
    let mut hosts = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str());
    let host = hosts.next()?;
    hosts.next().is_none().then_some(host)
}

fn proxy_request_shape_reason(request: &RawProxyRequest) -> Option<String> {
    if request.method.is_empty()
        || !request
            .method
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic())
        || request.target.is_empty()
        || request.target.len() > 2_048
        || request.target.chars().any(char::is_control)
    {
        return Some("malformed_request_line".to_owned());
    }
    let mut names = BTreeMap::<String, usize>::new();
    let mut content_length = false;
    let mut transfer_encoding = false;
    for (name, value) in &request.headers {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.chars().any(char::is_control)
        {
            return Some("malformed_header".to_owned());
        }
        let normalized = name.to_ascii_lowercase();
        *names.entry(normalized.clone()).or_default() += 1;
        content_length |= normalized == "content-length";
        transfer_encoding |= normalized == "transfer-encoding";
    }
    if names.get("host").copied().unwrap_or_default() != 1 {
        return Some("host_header_ambiguity".to_owned());
    }
    if names.get("content-length").copied().unwrap_or_default() > 1 {
        return Some("content_length_ambiguity".to_owned());
    }
    if transfer_encoding && content_length {
        return Some("content_length_transfer_encoding_conflict".to_owned());
    }
    if transfer_encoding {
        return Some("transfer_encoding_not_supported".to_owned());
    }
    None
}

fn proxy_header_map(headers: &[(String, String)]) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect()
}

fn proxy_authentication_state(
    headers: &BTreeMap<String, String>,
    run: &RunSession,
) -> ProxyAuthenticationState {
    let Some(value) = headers.get("proxy-authorization") else {
        return ProxyAuthenticationState::Missing;
    };
    if !value.starts_with("Lab ") {
        return ProxyAuthenticationState::WrongScheme;
    }
    let expected = proxy_authorization_value(&run.run_id, &run.access_token);
    let capability = proxy_capability_value(&run.run_id, &run.access_token);
    let legacy_capability = legacy_proxy_capability_value(&run.run_id);
    let legacy_authorization = format!("Lab {legacy_capability}");
    if (value == &expected && headers.get("x-lab-proxy-capability") == Some(&capability))
        || (value == &legacy_authorization
            && headers.get("x-lab-proxy-capability") == Some(&legacy_capability))
    {
        ProxyAuthenticationState::Valid
    } else {
        ProxyAuthenticationState::Invalid
    }
}

fn proxy_capability_value(run_id: &str, access_token: &str) -> String {
    format!("cap-{run_id}-{access_token}")
}

fn proxy_authorization_value(run_id: &str, access_token: &str) -> String {
    format!("Lab {}", proxy_capability_value(run_id, access_token))
}

fn legacy_proxy_capability_value(run_id: &str) -> String {
    format!("cap-{run_id}")
}

fn source_capability_value(run_id: &str, access_token: &str) -> String {
    format!("src-{run_id}-{access_token}")
}

struct ProxyAuditContext<'a> {
    run_id: &'a str,
    scenario: &'a Scenario,
    method: &'a str,
    target: &'a str,
    profile: &'a NetworkProfile,
    authentication: ProxyAuthenticationState,
    response_status: u16,
    reason: Option<String>,
    blocked: bool,
    correlation_id: String,
}

fn proxy_audit_record(context: ProxyAuditContext<'_>) -> AuditRecord {
    let ProxyAuditContext {
        run_id,
        scenario,
        method,
        target,
        profile,
        authentication,
        response_status,
        reason,
        blocked,
        correlation_id,
    } = context;
    AuditRecord {
        sequence: 0,
        run_id: Some(run_id.to_owned()),
        scenario_id: scenario.id.clone(),
        timestamp: Utc::now(),
        method: method.to_owned(),
        path: "<proxy>".to_owned(),
        query: BTreeMap::new(),
        headers: BTreeMap::new(),
        redacted_headers: BTreeMap::new(),
        body: None,
        body_summary: None,
        endpoint_id: None,
        response_index: None,
        script_step_id: None,
        response_sequence: None,
        response_status,
        before_submission: false,
        virtual_wait_ms: 0,
        retry_after: None,
        consumed: false,
        blocked,
        external_target_rejected: blocked,
        matched: !blocked,
        extra: blocked,
        mismatch_reasons: reason.clone().into_iter().collect(),
        wire_bytes: 0,
        response_digest: None,
        decoded_bytes: 0,
        content_encoding: None,
        compression_limit_violation: None,
        event_type: AuditEventType::ProxyRequest,
        proxy_mode: Some(profile.mode),
        proxy_target: Some(target.to_owned()),
        proxy_authentication: authentication,
        proxy_reason: reason,
        correlation_id: Some(correlation_id),
        quota_scope: None,
        quota_remaining_before: None,
        quota_remaining_after: None,
        quota_consumed: false,
        quota_rate_limited: false,
        quota_recovery_virtual_wait_ms: None,
        transfer_mode: None,
        chunk_count: 0,
        transport_fault: None,
    }
}

fn quota_credential_identity(headers: &HeaderMap) -> String {
    let value = ["x-api-key", "authorization", "x-lab-credential"]
        .iter()
        .find_map(|name| headers.get(*name).and_then(|value| value.to_str().ok()))
        .unwrap_or("<none>");
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    format!("credential-{:016x}", hasher.finish())
}

fn quota_retry_after(profile: &QuotaProfile) -> String {
    match profile.retry_after_mode {
        RetryAfterMode::Seconds => profile.retry_after_ms.div_ceil(1_000).to_string(),
        RetryAfterMode::HttpDate => virtual_http_date_after(profile.retry_after_ms),
    }
}

fn quota_audit_record(
    run_id: &str,
    scenario: &Scenario,
    endpoint_id: &str,
    decision: &lab_core::QuotaDecision,
    _credential_identity: &str,
) -> AuditRecord {
    AuditRecord {
        sequence: 0,
        run_id: Some(run_id.to_owned()),
        scenario_id: scenario.id.clone(),
        timestamp: Utc::now(),
        method: "QUOTA".to_owned(),
        path: format!("<quota:{endpoint_id}>"),
        query: BTreeMap::new(),
        headers: BTreeMap::new(),
        redacted_headers: BTreeMap::new(),
        body: None,
        body_summary: None,
        endpoint_id: Some(endpoint_id.to_owned()),
        response_index: None,
        script_step_id: None,
        response_sequence: None,
        response_status: if decision.rate_limited {
            decision.profile.exhausted_status
        } else {
            200
        },
        before_submission: false,
        // This decision advertises a required delay; it is not proof that a
        // client actually waited.  Actual virtual elapsed time is recorded on
        // the following source request from its explicit loopback header.
        virtual_wait_ms: 0,
        retry_after: decision
            .rate_limited
            .then(|| quota_retry_after(&decision.profile)),
        consumed: decision.consumed,
        blocked: false,
        external_target_rejected: false,
        matched: true,
        extra: false,
        mismatch_reasons: Vec::new(),
        wire_bytes: 0,
        response_digest: None,
        decoded_bytes: 0,
        content_encoding: None,
        compression_limit_violation: None,
        event_type: AuditEventType::QuotaDecision,
        proxy_mode: None,
        proxy_target: None,
        proxy_authentication: ProxyAuthenticationState::NotApplicable,
        proxy_reason: None,
        correlation_id: None,
        quota_scope: Some(decision.profile.scope),
        quota_remaining_before: Some(decision.remaining_before),
        quota_remaining_after: Some(decision.remaining_after),
        quota_consumed: decision.consumed,
        quota_rate_limited: decision.rate_limited,
        quota_recovery_virtual_wait_ms: decision.profile.recover_after_virtual_ms,
        transfer_mode: None,
        chunk_count: 0,
        transport_fault: None,
    }
}

async fn read_proxy_request(stream: &mut TcpStream) -> Result<RawProxyRequest, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 2048];
    let header_end = loop {
        if bytes.len() > MAX_PROXY_HEADER_BYTES {
            return Err("proxy_header_too_large".to_owned());
        }
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|_| "proxy_read_failed".to_owned())?;
        if count == 0 {
            return Err("proxy_request_incomplete".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
    };
    let head = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "proxy_header_not_utf8".to_owned())?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "proxy_missing_request_line".to_owned())?;
    let mut request_line = request_line.split_whitespace();
    let method = request_line
        .next()
        .ok_or_else(|| "proxy_missing_method".to_owned())?
        .to_owned();
    let target = request_line
        .next()
        .ok_or_else(|| "proxy_missing_target".to_owned())?
        .to_owned();
    if request_line.next() != Some("HTTP/1.1") || request_line.next().is_some() {
        return Err("proxy_missing_version".to_owned());
    }
    let mut headers = Vec::new();
    let mut content_length = 0_usize;
    for line in lines.filter(|line| !line.is_empty()) {
        if headers.len() >= 64 || line.starts_with(' ') || line.starts_with('\t') {
            return Err("proxy_header_limit_or_obs_fold".to_owned());
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "proxy_malformed_header".to_owned())?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("proxy_malformed_header".to_owned());
        }
        let value = value.trim().to_owned();
        if value.chars().any(char::is_control) {
            return Err("proxy_malformed_header".to_owned());
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value
                .parse::<usize>()
                .map_err(|_| "proxy_invalid_content_length".to_owned())?;
        }
        headers.push((name.to_owned(), value));
    }
    if content_length > MAX_PROXY_BODY_BYTES {
        return Err("proxy_body_too_large".to_owned());
    }
    while bytes.len().saturating_sub(header_end) < content_length {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|_| "proxy_body_read_failed".to_owned())?;
        if count == 0 {
            return Err("proxy_body_incomplete".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len().saturating_sub(header_end) > MAX_PROXY_BODY_BYTES {
            return Err("proxy_body_too_large".to_owned());
        }
    }
    Ok(RawProxyRequest {
        method,
        target,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

async fn write_proxy_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    extra_headers: Option<&str>,
) -> Result<(), std::io::Error> {
    let extra_headers = extra_headers.unwrap_or_default();
    stream
        .write_all(format!("HTTP/1.1 {status} {reason}\r\n{extra_headers}Content-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())
        .await
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
    let (max_body_bytes, body_timeout) = request_body_limits(&state, &method, &path);
    let body = match tokio::time::timeout(body_timeout, to_bytes(body, max_body_bytes)).await {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error":"request body exceeds the local safety limit"}),
            );
        }
        Err(_) => {
            return json_response(
                StatusCode::REQUEST_TIMEOUT,
                json!({"error":"request body exceeded the local safety timeout"}),
            );
        }
    };
    if let Some(response) = console_asset_response(&method, &path) {
        return response;
    }
    if let Some(response) =
        control_response(&state, &method, &path, &query, &headers, &body, &base_url).await
    {
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

fn request_body_limits(state: &LabState, method: &Method, path: &str) -> (usize, Duration) {
    if path == "/api/plans"
        || path == "/api/plans/validate"
        || path == "/api/plans/import"
        || path.starts_with("/api/plans/")
    {
        return (1024 * 1024, Duration::from_millis(1_000));
    }
    if method == Method::POST
        && let Some((run_id, Some("submission"))) = run_route(path)
        && let Ok(loaded) = state.loaded_for_run(run_id)
    {
        let limits = loaded.scenario.submission;
        return (
            limits.max_bytes,
            Duration::from_millis(limits.max_submission_time_ms),
        );
    }
    let limits = SubmissionLimits::default();
    (
        16 * 1024 * 1024,
        Duration::from_millis(limits.max_submission_time_ms),
    )
}

async fn control_response(
    state: &LabState,
    method: &Method,
    path: &str,
    query: &BTreeMap<String, String>,
    headers: &HeaderMap,
    body: &[u8],
    base_url: &str,
) -> Option<Response> {
    if let Some(response) = plan_response(state, method, path, headers, body, base_url) {
        return Some(response);
    }
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
                        "target_domain": state.loaded_for_run(&run.run_id).ok().map(|loaded| loaded.scenario.root_domain),
                        "base_url": state.base_url().unwrap_or_else(|| base_url.to_owned()),
                        "manifest_url": format!("/api/runs/{}/manifest", run.run_id),
                        "submission_url": format!("/api/runs/{}/submission", run.run_id),
                        "report_url": format!("/api/runs/{}/report", run.run_id),
                        "required_source_header": "x-lab-run-id",
                        "status": run.status,
                        "required_request_header": {"x-lab-run-id": run.run_id},
                        "run_access_header": "x-lab-run-access-token",
                        "run_access_token": run.access_token,
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
    if let Some(response) = analysis_response(state, method, path, query.clone()) {
        return Some(response);
    }
    if let Some(response) = console_response(state, method, path, headers, body).await {
        return Some(response);
    }
    if let Some((run_id, action)) = run_route(path) {
        return Some(run_control_response(
            state, method, run_id, action, headers, body, base_url,
        ));
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

fn analysis_response(
    state: &LabState,
    method: &Method,
    path: &str,
    query: BTreeMap<String, String>,
) -> Option<Response> {
    let (view, detail_id) = if path == "/api/analysis/overview" {
        (AnalysisView::Overview, None)
    } else if path == "/api/analysis/coverage" {
        (AnalysisView::Coverage, None)
    } else if path == "/api/analysis/replays" {
        (AnalysisView::Replays, None)
    } else if path == "/api/analysis/campaigns" {
        (AnalysisView::Campaigns, None)
    } else if path == "/api/analysis/soak" {
        (AnalysisView::Soak, None)
    } else if path == "/api/analysis/evidence-graph" {
        (AnalysisView::EvidenceGraph, None)
    } else if path == "/api/analysis/timeline" {
        (AnalysisView::Timeline, None)
    } else if path == "/api/analysis/trends" {
        (AnalysisView::Trends, None)
    } else if let Some(id) = analysis_detail_id(path, "/api/analysis/replays/") {
        (AnalysisView::Replays, Some(id))
    } else if let Some(id) = analysis_detail_id(path, "/api/analysis/campaigns/") {
        (AnalysisView::Campaigns, Some(id))
    } else {
        let id = analysis_detail_id(path, "/api/analysis/soak/")?;
        (AnalysisView::Soak, Some(id))
    };
    if method != Method::GET {
        return Some(json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"schema_version": lab_core::ANALYSIS_SCHEMA_VERSION, "error": {"code":"ANALYSIS_READ_ONLY", "message":"analysis endpoints accept GET only"}}),
        ));
    }
    let mut parameters = query;
    let format = parameters
        .remove("format")
        .unwrap_or_else(|| "json".to_owned());
    if format != "json" && format != "markdown" && format != "md" {
        return Some(json_response(
            StatusCode::BAD_REQUEST,
            json!({"schema_version": lab_core::ANALYSIS_SCHEMA_VERSION, "error": {"code":"ANALYSIS_FORMAT_INVALID", "message":"format must be json or markdown"}}),
        ));
    }
    if let Some(id) = detail_id {
        parameters.insert("id".to_owned(), id.to_owned());
    }
    let request = match parse_analysis_request(view, &parameters) {
        Ok(request) => request,
        Err(error) => {
            return Some(json_response(
                StatusCode::BAD_REQUEST,
                json!({"schema_version": lab_core::ANALYSIS_SCHEMA_VERSION, "error": {"code":error.code(), "message":error.to_string()}}),
            ));
        }
    };
    let value = state.analysis_value(view, &request);
    if format == "markdown" || format == "md" {
        return Some(text_response(
            StatusCode::OK,
            "text/markdown; charset=utf-8",
            analysis_markdown(&value),
        ));
    }
    Some(json_response(StatusCode::OK, value))
}

fn analysis_detail_id<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let id = path.strip_prefix(prefix)?;
    (!id.is_empty() && !id.contains('/') && id.len() <= 256).then_some(id)
}

fn plan_response(
    state: &LabState,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    base_url: &str,
) -> Option<Response> {
    if method == Method::GET && path == "/api/plans" {
        let runs = state.list_plan_runs();
        let plans = state
            .plan_store()
            .list()
            .into_iter()
            .map(|plan| {
                let latest = runs
                    .iter()
                    .filter(|run| run.manifest.plan_id == plan.plan_id)
                    .max_by_key(|run| run.manifest.created_at);
                json!({
                    "schema_version": PLAN_SCHEMA_VERSION,
                    "plan_id": plan.plan_id,
                    "name": plan.name,
                    "description": plan.description,
                    "target_domain": plan.target_domain,
                    "seed": plan.seed,
                    "sources": plan.sources,
                    "status": plan.status,
                    "revision": plan.revision,
                    "created_at": plan.created_at,
                    "updated_at": plan.updated_at,
                    "plan_digest": plan.plan_digest,
                    "latest_run_status": latest.map(|run| run.report.status.clone()),
                    "latest_run_id": latest.map(|run| run.manifest.run_id.clone()),
                })
            })
            .collect::<Vec<_>>();
        return Some(json_response(
            StatusCode::OK,
            json!({"schema_version": PLAN_SCHEMA_VERSION, "plans": plans}),
        ));
    }
    if method == Method::GET && path == "/api/plans/storage" {
        return Some(match state.plan_store().storage_stats() {
            Ok(stats) => json_response(
                StatusCode::OK,
                serde_json::to_value(stats).expect("plan storage stats are serializable"),
            ),
            Err(error) => plan_error_from_anyhow(error),
        });
    }
    if method == Method::POST && path == "/api/plans/validate" {
        return Some(match serde_json::from_slice::<ExperimentPlan>(body) {
            Ok(plan) => json_response(
                StatusCode::OK,
                serde_json::to_value(validate_plan(plan, false))
                    .expect("plan validation is serializable"),
            ),
            Err(error) => plan_error(
                StatusCode::BAD_REQUEST,
                "PLAN_JSON_INVALID",
                format!("plan JSON is invalid: {error}"),
            ),
        });
    }
    if method == Method::POST && path == "/api/plans/import" {
        return Some(match serde_json::from_slice::<ExperimentPlan>(body) {
            Ok(plan) => match state.import_plan(plan) {
                Ok(plan) => json_response(
                    StatusCode::CREATED,
                    json!({"schema_version": PLAN_SCHEMA_VERSION, "plan": plan}),
                ),
                Err(error) => plan_error_from_anyhow(error),
            },
            Err(error) => plan_error(
                StatusCode::BAD_REQUEST,
                "PLAN_JSON_INVALID",
                format!("plan JSON is invalid: {error}"),
            ),
        });
    }
    if method == Method::POST && path == "/api/plans" {
        return Some(match serde_json::from_slice::<ExperimentPlan>(body) {
            Ok(plan) => match state.create_plan(plan) {
                Ok(plan) => json_response(
                    StatusCode::CREATED,
                    json!({"schema_version": PLAN_SCHEMA_VERSION, "plan": plan}),
                ),
                Err(error) => plan_error_from_anyhow(error),
            },
            Err(error) => plan_error(
                StatusCode::BAD_REQUEST,
                "PLAN_JSON_INVALID",
                format!("plan JSON is invalid: {error}"),
            ),
        });
    }
    if let Some(plan_id) = path.strip_prefix("/api/plans/") {
        let mut segments = plan_id.split('/');
        let plan_id = segments.next().unwrap_or_default();
        let action = segments.next();
        if segments.next().is_some() || plan_id.is_empty() {
            return None;
        }
        match (method, action) {
            (&Method::GET, None) => {
                return Some(match state.plan_store().get(plan_id) {
                    Some(plan) => json_response(
                        StatusCode::OK,
                        json!({"schema_version": PLAN_SCHEMA_VERSION, "plan": plan}),
                    ),
                    None => plan_error(
                        StatusCode::NOT_FOUND,
                        "PLAN_NOT_FOUND",
                        format!("plan {plan_id} does not exist"),
                    ),
                });
            }
            (&Method::PUT, None) => {
                return Some(match serde_json::from_slice::<ExperimentPlan>(body) {
                    Ok(plan) => match state.plan_store().update_if_revision(
                        plan_id,
                        plan,
                        expected_plan_revision(headers),
                    ) {
                        Ok(plan) => json_response(
                            StatusCode::OK,
                            json!({"schema_version": PLAN_SCHEMA_VERSION, "plan": plan}),
                        ),
                        Err(error) => plan_error_from_anyhow(error),
                    },
                    Err(error) => plan_error(
                        StatusCode::BAD_REQUEST,
                        "PLAN_JSON_INVALID",
                        format!("plan JSON is invalid: {error}"),
                    ),
                });
            }
            (&Method::DELETE, None) => {
                return Some(match state.delete_plan(plan_id) {
                    Ok(()) => json_response(
                        StatusCode::OK,
                        json!({"schema_version": PLAN_SCHEMA_VERSION, "deleted": true, "plan_id": plan_id}),
                    ),
                    Err(error) => plan_error_from_anyhow(error),
                });
            }
            (&Method::POST, Some("archive")) => {
                return Some(match state.archive_plan(plan_id) {
                    Ok(plan) => json_response(
                        StatusCode::OK,
                        json!({"schema_version": PLAN_SCHEMA_VERSION, "plan": plan}),
                    ),
                    Err(error) => plan_error_from_anyhow(error),
                });
            }
            (&Method::POST, Some("runs")) => {
                return Some(match state.run_plan(plan_id) {
                    Ok(run) => plan_run_response(
                        state,
                        StatusCode::CREATED,
                        &run,
                        base_url,
                        !is_console_request(headers),
                    ),
                    Err(error) => plan_error_from_anyhow(error),
                });
            }
            (&Method::POST, Some("simulate")) => {
                return Some(match state.simulate_plan(plan_id) {
                    Ok(run) => plan_run_response(
                        state,
                        StatusCode::CREATED,
                        &run,
                        base_url,
                        !is_console_request(headers),
                    ),
                    Err(error) => plan_error_from_anyhow(error),
                });
            }
            (&Method::POST, Some("export")) => {
                return Some(match state.plan_store().get(plan_id) {
                    Some(plan) => json_response(
                        StatusCode::OK,
                        json!({"schema_version": PLAN_SCHEMA_VERSION, "plan": plan}),
                    ),
                    None => plan_error(
                        StatusCode::NOT_FOUND,
                        "PLAN_NOT_FOUND",
                        format!("plan {plan_id} does not exist"),
                    ),
                });
            }
            _ => {}
        }
    }
    if let Some(run_path) = path.strip_prefix("/api/plan-runs/") {
        let mut segments = run_path.split('/');
        let run_id = segments.next().unwrap_or_default();
        let action = segments.next();
        if segments.next().is_some() || run_id.is_empty() {
            return None;
        }
        match (method, action) {
            (&Method::GET, None) => {
                return Some(plan_run_lookup(
                    state,
                    run_id,
                    |run| json!({"schema_version": PLAN_SCHEMA_VERSION, "manifest": run.manifest, "report": run.report}),
                ));
            }
            (&Method::GET, Some("audit")) => {
                return Some(plan_run_lookup(
                    state,
                    run_id,
                    |run| json!({"schema_version": PLAN_SCHEMA_VERSION, "run_id": run_id, "entries": run.audit}),
                ));
            }
            (&Method::GET, Some("report")) => {
                return Some(plan_run_lookup(
                    state,
                    run_id,
                    |run| json!({"schema_version": PLAN_SCHEMA_VERSION, "run_id": run_id, "report": run.report}),
                ));
            }
            (&Method::GET, Some("manifest")) => {
                return Some(plan_run_lookup(
                    state,
                    run_id,
                    |run| json!({"schema_version": PLAN_SCHEMA_VERSION, "run_id": run_id, "manifest": run.manifest}),
                ));
            }
            (&Method::POST, Some("replay")) => {
                return Some(match state.replay_plan_run(run_id) {
                    Ok(run) => plan_run_response(
                        state,
                        StatusCode::CREATED,
                        &run,
                        base_url,
                        !is_console_request(headers),
                    ),
                    Err(error) => plan_error_from_anyhow(error),
                });
            }
            (&Method::POST, Some("cancel")) => {
                return Some(match state.cancel_plan_run(run_id) {
                    Ok(run) => json_response(
                        StatusCode::OK,
                        json!({"schema_version": PLAN_SCHEMA_VERSION, "run_id": run_id, "cancelled": true, "report": run.report}),
                    ),
                    Err(error) => plan_error_from_anyhow(error),
                });
            }
            _ => {}
        }
    }
    None
}

fn plan_run_response(
    state: &LabState,
    status: StatusCode,
    run: &PlanRun,
    base_url: &str,
    include_source_credentials: bool,
) -> Response {
    let source_access = state.plan_run_access(&run.manifest.run_id).ok().map(|access| {
        let base = json!({
            "available": true,
            "expires_at": access.expires_at,
            "source_url_template": format!("{base_url}/api/plan-runs/{}/sources/{{source_id}}", access.run_id),
            "run_header_name": run.manifest.source_contract.run_header_name,
            "run_id": access.run_id,
            "source_capability_header": run.manifest.source_contract.source_capability_header,
            "fake_api_key_header": run.manifest.source_contract.fake_api_key_header,
            "network_mode": run.manifest.source_contract.network_mode,
            "proxy_url": (run.manifest.source_contract.network_mode != PlanNetworkMode::Direct).then(|| state.proxy_url()).flatten(),
        });
        if include_source_credentials {
            let mut access_with_credentials = base;
            let access_object = access_with_credentials
                .as_object_mut()
                .expect("plan source access must be an object");
            access_object.insert("source_capability".to_owned(), json!(access.source_capability));
            access_object.insert("fake_api_key".to_owned(), json!(access.fake_api_key));
            access_with_credentials
        } else {
            base
        }
    });
    let mut response = json_response(
        status,
        json!({
            "schema_version": PLAN_SCHEMA_VERSION,
            "run_id": run.manifest.run_id,
            "plan_id": run.manifest.plan_id,
            "manifest": run.manifest,
            "report": run.report,
            "audit_url": format!("/api/plan-runs/{}/audit", run.manifest.run_id),
            "report_url": format!("/api/plan-runs/{}/report", run.manifest.run_id),
            "manifest_url": format!("/api/plan-runs/{}/manifest", run.manifest.run_id),
            "source_access": source_access,
        }),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn is_console_request(headers: &HeaderMap) -> bool {
    headers
        .get("x-fqdn-console-request")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "1")
}

fn plan_run_lookup<F>(state: &LabState, run_id: &str, build: F) -> Response
where
    F: FnOnce(PlanRun) -> Value,
{
    match state.plan_run(run_id) {
        Ok(run) => json_response(StatusCode::OK, build(run)),
        Err(error) => plan_error_from_anyhow(error),
    }
}

fn plan_error_from_anyhow(error: anyhow::Error) -> Response {
    let message = error.to_string();
    let (code, human) = message.split_once(": ").map_or(
        ("PLAN_OPERATION_FAILED", message.as_str()),
        |(code, human)| (code, human),
    );
    let status = match code {
        "PLAN_NOT_FOUND" | "PLAN_RUN_NOT_FOUND" => StatusCode::NOT_FOUND,
        "PLAN_ALREADY_EXISTS" | "PLAN_REVISION_CONFLICT" => StatusCode::CONFLICT,
        "PLAN_ARCHIVED" | "PLAN_NOT_RUNNABLE" | "PLAN_DIGEST_MISMATCH" => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        _ => StatusCode::BAD_REQUEST,
    };
    plan_error(status, code, human)
}

fn expected_plan_revision(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::IF_MATCH)
        .or_else(|| headers.get("x-fqdn-plan-revision"))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .and_then(|value| value.trim_matches('"').parse::<u64>().ok())
}

fn plan_error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    json_response(
        status,
        json!({"schema_version": PLAN_SCHEMA_VERSION, "error": {"code": code, "message": message.into()}}),
    )
}

fn console_asset_response(method: &Method, path: &str) -> Option<Response> {
    if method != Method::GET {
        return None;
    }
    if path == "/console" {
        return Some(
            Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(header::LOCATION, "/console/")
                .body(Body::empty())
                .expect("static console redirect"),
        );
    }
    if path == "/favicon.ico" {
        return Some(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header(header::CACHE_CONTROL, "public, max-age=86400")
                .body(Body::empty())
                .expect("empty favicon response"),
        );
    }
    let asset = lab_console::asset(path)?;
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, asset.content_type)
            .header(
                "content-security-policy",
                "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; script-src 'self'; style-src 'self'",
            )
            .header("x-content-type-options", "nosniff")
            .body(Body::from(asset.body))
            .expect("static console response"),
    )
}

async fn console_response(
    state: &LabState,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Option<Response> {
    if method == Method::GET && path == "/api/console/preferences" {
        let preferences = lab_console::load_console_preferences();
        return Some(json_response(
            StatusCode::OK,
            json!({"auto_open": preferences.auto_open}),
        ));
    }
    if method == Method::PUT && path == "/api/console/preferences" {
        let preferences = match serde_json::from_slice::<lab_console::ConsolePreferences>(body) {
            Ok(preferences) => preferences,
            Err(_) => {
                return Some(json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"body must be {\"auto_open\": true|false}"}),
                ));
            }
        };
        return Some(match lab_console::save_console_preferences(preferences) {
            Ok(preferences) => {
                json_response(StatusCode::OK, json!({"auto_open": preferences.auto_open}))
            }
            Err(error) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("could not save local console preferences: {error}")}),
            ),
        });
    }
    if method == Method::GET && path == "/api/console/overview" {
        let catalog = lab_console::scenario_catalog(state.repository());
        let scenarios = catalog
            .get("scenarios")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut categories = BTreeMap::<String, usize>::new();
        for scenario in &scenarios {
            if let Some(category) = scenario.get("category").and_then(Value::as_str) {
                *categories.entry(category.to_owned()).or_default() += 1;
            }
        }
        let runs = state.list_runs();
        let latest = runs
            .iter()
            .max_by_key(|run| run.last_activity_at)
            .map(|run| {
                let report = state.latest_report(&run.run_id).ok().flatten();
                lab_console::run_value(
                    run,
                    state
                        .loaded_for_run(&run.run_id)
                        .ok()
                        .map(|loaded| loaded.scenario.root_domain),
                    report.as_ref(),
                )
            });
        return Some(json_response(
            StatusCode::OK,
            json!({
                "status": "ok", "base_url": state.base_url(), "loopback_only": true,
                "external_network_allowed": false, "real_dns": false,
                "scenario_count": scenarios.len(), "categories": categories,
                "active_run_count": runs.iter().filter(|run| matches!(run.status, lab_core::RunSessionStatus::Active | lab_core::RunSessionStatus::Reset | lab_core::RunSessionStatus::Submitted)).count(),
                "latest_run": latest,
                "verification": lab_console::latest_verification_summary(),
            }),
        ));
    }
    if method == Method::GET && path == "/api/console/scenarios" {
        return Some(json_response(
            StatusCode::OK,
            lab_console::scenario_catalog(state.repository()),
        ));
    }
    if method == Method::GET && path == "/api/console/runs" {
        let mut runs = state
            .list_runs()
            .iter()
            .map(|run| {
                let report = state.latest_report(&run.run_id).ok().flatten();
                lab_console::run_value(
                    run,
                    state
                        .loaded_for_run(&run.run_id)
                        .ok()
                        .map(|loaded| loaded.scenario.root_domain),
                    report.as_ref(),
                )
            })
            .collect::<Vec<_>>();
        runs.extend(
            state
                .deleted_run_history()
                .iter()
                .map(lab_console::deleted_run_value),
        );
        runs.sort_by_key(|run| {
            run.get("created_at")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        });
        runs.reverse();
        return Some(json_response(StatusCode::OK, json!({"runs": runs})));
    }
    if let Some(run_id) = console_run_route(path, "/audit")
        && method == Method::GET
    {
        return Some(match (state.audit(run_id), state.control_audit(run_id)) {
            (Ok(audit), Ok(control)) => {
                json_response(StatusCode::OK, lab_console::audit_value(&audit, &control))
            }
            (Err(error), _) | (_, Err(error)) => run_error_response(error),
        });
    }
    if let Some(run_id) = console_run_route(path, "/report")
        && method == Method::GET
    {
        return Some(match state.latest_report(run_id) {
            Ok(Some(report)) => json_response(
                StatusCode::OK,
                json!({"report": lab_console::report_value(&report)}),
            ),
            Ok(None) => json_response(StatusCode::OK, json!({"report": Value::Null})),
            Err(error) => run_error_response(error),
        });
    }
    if let Some(run_id) = console_run_route(path, "/reference")
        && method == Method::POST
    {
        let run = match state.session(run_id) {
            Ok(run) => run,
            Err(error) => return Some(run_error_response(error)),
        };
        if !has_run_access(&run, headers) {
            let _ = state.record_control_audit(
                run_id,
                method.as_str(),
                "stale_probe",
                path,
                "rejected",
            );
            return Some(json_response(
                StatusCode::FORBIDDEN,
                json!({"error":"run access capability is required"}),
            ));
        }
        let _ = state.record_control_audit(run_id, method.as_str(), "reference", path, "accepted");
        return Some(match run_console_reference(state, run_id).await {
            Ok(report) => json_response(
                StatusCode::OK,
                json!({"run_id": run_id, "status": report.status, "report": lab_console::report_value(&report)}),
            ),
            Err(error) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("reference client could not complete: {error}")}),
            ),
        });
    }
    None
}

fn console_run_route<'a>(path: &'a str, suffix: &str) -> Option<&'a str> {
    let run_id = path
        .strip_prefix("/api/console/runs/")?
        .strip_suffix(suffix)?;
    (!run_id.is_empty() && !run_id.contains('/')).then_some(run_id)
}

async fn run_console_reference(state: &LabState, run_id: &str) -> Result<RunReport, String> {
    let run = state
        .session(run_id)
        .map_err(|error| error.message().to_owned())?;
    let loaded = state
        .loaded_for_run(run_id)
        .map_err(|error| error.message().to_owned())?;
    let parsed_run_id = Uuid::parse_str(run_id).map_err(|error| error.to_string())?;
    let guard = EgressGuard::default();
    let runner = ReferenceRunner::new(guard.clone()).map_err(|error| error.to_string())?;
    let base_url = state
        .base_url()
        .ok_or_else(|| "local base URL is unavailable".to_owned())?;
    let proxy_url = state.proxy_url();
    let started = Utc::now();
    let collector = runner
        .run_with_proxy(
            &base_url,
            proxy_url.as_deref(),
            &loaded.scenario,
            parsed_run_id,
            "default",
        )
        .await
        .map_err(|error| error.to_string())?;
    let audit = state
        .audit(run_id)
        .map_err(|error| error.message().to_owned())?;
    let rejected_egress_urls = guard.rejected_urls();
    let mut report = judge_run(JudgeInput {
        run_id: parsed_run_id,
        scenario_id: &loaded.scenario.id,
        seed: run.seed,
        target_domain: &loaded.scenario.root_domain,
        started_at: started,
        finished_at: Utc::now(),
        collector_run: &collector,
        truth: &loaded.truth,
        assertions: &loaded.assertions,
        audit: &audit,
        rejected_egress_urls: &rejected_egress_urls,
    });
    enrich_report(&mut report, &loaded).map_err(|error| error.to_string())?;
    refresh_semantic_fingerprint(&mut report);
    state
        .set_report(run_id, report.clone())
        .map_err(|error| error.message().to_owned())?;
    Ok(report)
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
    headers: &HeaderMap,
    body: &[u8],
    base_url: &str,
) -> Response {
    let run = match state.session(run_id) {
        Ok(run) => run,
        Err(error) => return run_error_response(error),
    };
    if run_access_is_required(method, action) && !has_run_access(&run, headers) {
        let _ = state.record_control_audit(
            run_id,
            method.as_str(),
            "stale_probe",
            &format!("/api/runs/{run_id}/{}", action.unwrap_or_default()),
            "rejected",
        );
        return json_response(
            StatusCode::FORBIDDEN,
            json!({"error":"run access capability is required"}),
        );
    }
    let operation = action.unwrap_or("run");
    let _ = state.record_control_audit(
        run_id,
        method.as_str(),
        operation,
        &format!("/api/runs/{run_id}/{}", action.unwrap_or_default()),
        "accepted",
    );
    match (method, action) {
        (&Method::GET, None) => json_response(StatusCode::OK, run_summary(&run)),
        (&Method::GET, Some("requests")) => match state.audit(run_id) {
            Ok(requests) => {
                json_response(StatusCode::OK, json!({"run_id":run_id,"requests":requests}))
            }
            Err(error) => run_error_response(error),
        },
        (&Method::GET, Some("manifest")) => match manifest_for_run(state, run_id, base_url) {
            Ok(manifest) => json_response(
                StatusCode::OK,
                serde_json::to_value(manifest).expect("manifest is serializable"),
            ),
            Err(error) => run_error_response(error),
        },
        (&Method::GET, Some("truth")) => json_response(
            StatusCode::FORBIDDEN,
            json!({"error":"truth is not available through the external run API"}),
        ),
        (&Method::GET, Some("report")) => match state.latest_report(run_id) {
            Ok(report) => json_response(StatusCode::OK, json!({"run_id":run_id,"report":report})),
            Err(error) => run_error_response(error),
        },
        (&Method::POST, Some("reset")) => match state.reset_and_rotate(run_id) {
            Ok(updated) => json_response(
                StatusCode::OK,
                json!({"run_id":run_id,"reset":true,"run_access_token":updated.access_token}),
            ),
            Err(error) => run_error_response(error),
        },
        (&Method::POST, Some("cancel")) => {
            let virtual_wait_ms = headers
                .get("x-lab-client-virtual-wait-ms")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            match state.cancel(run_id, virtual_wait_ms) {
                Ok(()) => json_response(StatusCode::OK, json!({"run_id":run_id,"cancelled":true})),
                Err(error) => run_error_response(error),
            }
        }
        (&Method::POST, Some("submission")) => {
            submit_collector_result(state, run_id, &run, body, base_url)
        }
        (&Method::POST, Some("report")) => json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"error":"external clients cannot write RunReport; use submission"}),
        ),
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

fn run_access_is_required(method: &Method, action: Option<&str>) -> bool {
    matches!(
        (method, action),
        (
            &Method::GET,
            None | Some("requests") | Some("manifest") | Some("report")
        ) | (
            &Method::POST,
            Some("reset") | Some("cancel") | Some("submission")
        ) | (&Method::DELETE, None)
    )
}

fn has_run_access(run: &RunSession, headers: &HeaderMap) -> bool {
    headers
        .get("x-lab-run-access-token")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == run.access_token)
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

fn manifest_for_run(
    state: &LabState,
    run_id: &str,
    _request_base_url: &str,
) -> Result<RunManifest, RunStateError> {
    let run = state.session(run_id)?;
    let loaded = state.loaded_for_run(run_id)?;
    let base_url = state
        .base_url()
        .unwrap_or_else(|| "http://127.0.0.1".to_owned());
    let source_port = Url::parse(&base_url)
        .ok()
        .and_then(|url| url.port_or_known_default())
        .unwrap_or(0);
    let allowed_proxy_targets = if source_port == 0 {
        Vec::new()
    } else {
        vec![format!("127.0.0.1:{source_port}")]
    };
    let sources = loaded
        .scenario
        .endpoints
        .iter()
        .map(|endpoint| {
            let mut authentication = endpoint
                .request_match
                .headers
                .iter()
                .filter(|(name, _)| is_sensitive(name))
                .filter_map(|(name, rule)| {
                    rule.equals
                        .as_deref()
                        .map(|value| (name.clone(), manifest_value(value, &loaded.scenario)))
                })
                .collect::<BTreeMap<_, _>>();
            authentication.insert(
                "x-lab-source-capability".to_owned(),
                source_capability_value(&run.run_id, &run.access_token),
            );
            ManifestSource {
                source_id: endpoint.id.clone(),
                source_kind: endpoint.source_kind,
                source_label: endpoint
                    .source_label
                    .clone()
                    .unwrap_or_else(|| endpoint.id.clone()),
                base_url: base_url.clone(),
                method: endpoint.request_match.method,
                path_template: endpoint.request_match.path.clone(),
                required_query: endpoint
                    .request_match
                    .query
                    .iter()
                    .filter(|(_, rule)| rule.requires_value() && !rule.optional)
                    .map(|(name, rule)| {
                        (
                            name.clone(),
                            rule.equals
                                .as_deref()
                                .map(|value| manifest_value(value, &loaded.scenario))
                                .unwrap_or_default(),
                        )
                    })
                    .collect(),
                required_headers: endpoint
                    .request_match
                    .headers
                    .iter()
                    .filter(|(_, rule)| rule.requires_value() && !rule.optional)
                    .map(|(name, _)| name.clone())
                    .collect(),
                authentication_field_names: authentication.keys().cloned().collect(),
                authentication,
                pagination_mode: endpoint.pagination.mode,
                pagination_parameter: (endpoint.pagination.mode != PaginationMode::None)
                    .then(|| endpoint.pagination.parameter.clone()),
                next_page_field: (endpoint.pagination.mode != PaginationMode::None)
                    .then_some(endpoint.pagination.next_cursor_field.clone())
                    .flatten(),
                request_body_template: endpoint.request_body.clone(),
                request_body_content_type: endpoint
                    .request_body
                    .as_ref()
                    .map(|_| "application/json".to_owned()),
                run_header_name: "x-lab-run-id".to_owned(),
                allow_retry: endpoint.allow_retry,
                allow_redirect: false,
                local_test_only: true,
            }
        })
        .collect();
    let mut proxy_authentication = BTreeMap::new();
    let proxy_url = if loaded.scenario.network_profile.mode == NetworkMode::Direct {
        None
    } else {
        proxy_authentication.insert(
            "proxy_authorization".to_owned(),
            proxy_authorization_value(&run.run_id, &run.access_token),
        );
        proxy_authentication.insert(
            "proxy_capability".to_owned(),
            proxy_capability_value(&run.run_id, &run.access_token),
        );
        state.proxy_url()
    };
    let quota_profiles = loaded
        .scenario
        .endpoints
        .iter()
        .flat_map(|endpoint| {
            endpoint
                .quota
                .iter()
                .map(move |profile| ManifestQuotaProfile {
                    source_id: endpoint.id.clone(),
                    scope: profile.scope,
                    retry_after_mode: profile.retry_after_mode,
                    client_visible_limit: profile.success_limit,
                })
        })
        .collect();
    let first_reply = loaded
        .scenario
        .endpoints
        .iter()
        .flat_map(|endpoint| endpoint.replies.iter())
        .next();
    let transport_profile = ManifestTransportProfile {
        content_encoding: first_reply
            .and_then(|reply| {
                reply
                    .content_encoding_header
                    .as_deref()
                    .or(reply.encoding.as_deref())
            })
            .unwrap_or("identity")
            .to_owned(),
        transfer_mode: first_reply.map_or(TransferMode::ContentLength, |reply| reply.transfer_mode),
        client_visible_decoded_limit: loaded
            .scenario
            .runner
            .effective_max_decoded_response_bytes(),
    };
    Ok(RunManifest {
        schema_version: lab_core::V14_SCHEMA_VERSION.to_owned(),
        run_id: run.run_id,
        scenario_id: run.scenario_id,
        seed: run.seed,
        target_domain: loaded.scenario.root_domain,
        cancel_after_requests: loaded.scenario.runner.cancel_after_requests,
        network: ManifestNetwork {
            allowed_hosts: vec!["127.0.0.1".to_owned()],
            external_network_allowed: false,
            required_header: "x-lab-run-id".to_owned(),
        },
        network_profile: ManifestNetworkProfile {
            mode: loaded.scenario.network_profile.mode,
            proxy_url,
            proxy_authentication_field_names: if loaded.scenario.network_profile.mode
                == NetworkMode::Direct
            {
                Vec::new()
            } else {
                vec![
                    "proxy_authorization".to_owned(),
                    "proxy_capability".to_owned(),
                ]
            },
            proxy_authentication,
            proxy_must_be_used: loaded.scenario.network_profile.proxy_must_be_used,
            initial_proxy_auth_challenge: loaded
                .scenario
                .network_profile
                .initial_proxy_auth_challenge,
            allowed_proxy_targets: allowed_proxy_targets.clone(),
            connect_fixture_target: (loaded.scenario.network_profile.mode
                == NetworkMode::ConnectProxy)
                .then(|| allowed_proxy_targets.first().cloned())
                .flatten(),
            max_connections: loaded.scenario.network_profile.max_connections,
            virtual_timeout_ms: loaded.scenario.network_profile.virtual_timeout_ms,
            allow_retry: loaded.scenario.network_profile.allow_retry,
        },
        quota_profiles,
        transport_profile,
        sources,
        submission: ManifestSubmission {
            url: format!("/api/runs/{run_id}/submission"),
            max_bytes: loaded.scenario.submission.max_bytes,
            max_submission_time_ms: loaded.scenario.submission.max_submission_time_ms,
            finalizes_run: true,
        },
    })
}

fn manifest_value(value: &str, scenario: &Scenario) -> String {
    match value {
        "$ROOT_DOMAIN" | "$TARGET_DOMAIN" => scenario.root_domain.clone(),
        "$SEED" => scenario.seed.to_string(),
        "$OBSERVATION_TIME" => format!("2025-01-{:02}T00:00:00Z", scenario.seed % 28 + 1),
        _ => value.to_owned(),
    }
}

fn submit_collector_result(
    state: &LabState,
    run_id: &str,
    run: &RunSession,
    body: &[u8],
    _request_base_url: &str,
) -> Response {
    let loaded = match state.loaded_for_run(run_id) {
        Ok(loaded) => loaded,
        Err(error) => return run_error_response(error),
    };
    if body.len() > loaded.scenario.submission.max_bytes {
        return json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"error":"submission exceeds scenario max_bytes"}),
        );
    }
    let raw: Value = match serde_json::from_slice(body) {
        Ok(raw) => raw,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"submission must be valid JSON"}),
            );
        }
    };
    if let Some(field) = sensitive_field(&raw, "$") {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error":"submission contains a forbidden sensitive field","field":field}),
        );
    }
    if json_depth(&raw) > loaded.scenario.submission.max_depth {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error":"submission exceeds max nesting depth"}),
        );
    }
    let submission: CollectorSubmission = match serde_json::from_value(raw) {
        Ok(submission) => submission,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"submission schema is invalid or includes rejected fields"}),
            );
        }
    };
    let canonical_base_url = state
        .base_url()
        .unwrap_or_else(|| "http://127.0.0.1".to_owned());
    let mut collector = match validate_submission(&submission, &loaded, &canonical_base_url) {
        Ok(collector) => collector,
        Err(error) => return json_response(StatusCode::BAD_REQUEST, json!({"error":error})),
    };
    if let Err(error) = state.freeze_submission(run_id, submission.clone()) {
        return run_error_response(error);
    }
    let audit = match state.audit(run_id) {
        Ok(audit) => audit,
        Err(error) => return run_error_response(error),
    };
    // The client cannot declare a successful virtual wait. Derive it from the
    // immutable server audit before judging so quota assertions use the same
    // authoritative value that is exposed in the final report.
    let server_virtual_wait_ms = audit.iter().map(|record| record.virtual_wait_ms).sum();
    collector.virtual_waited_ms = server_virtual_wait_ms;
    collector.metrics.virtual_wait_ms = server_virtual_wait_ms;
    collector.filtered = filtered_from_audit(&collector, &loaded, &audit);
    let rejected_egress = audit
        .iter()
        .filter(|record| record.external_target_rejected)
        .map(|record| record.path.clone())
        .collect::<Vec<_>>();
    let mut report = judge_run(lab_core::JudgeInput {
        run_id: Uuid::parse_str(run_id).expect("run id has already been validated"),
        scenario_id: &loaded.scenario.id,
        seed: run.seed,
        target_domain: &loaded.scenario.root_domain,
        started_at: run.created_at,
        finished_at: Utc::now(),
        collector_run: &collector,
        truth: &loaded.truth,
        assertions: &loaded.assertions,
        audit: &audit,
        rejected_egress_urls: &rejected_egress,
    });
    // Client payloads never supply metrics, retry counts, virtual waits or
    // request totals.  These report values are derived exclusively from the
    // immutable server audit captured before the submission was frozen.
    report.metrics.request_count = audit.len();
    report.metrics.retry_count = audit
        .iter()
        .filter(|record| record.response_status == StatusCode::TOO_MANY_REQUESTS.as_u16())
        .count();
    report.virtual_waited_ms = server_virtual_wait_ms;
    report.metrics.virtual_wait_ms = report.virtual_waited_ms;
    let consistent = source_statuses_match_audit(&submission.source_statuses, &audit);
    report.assertions.submission_consistency = consistent;
    if !consistent {
        report
            .failures
            .push("submitted source_statuses do not match the immutable server audit".to_owned());
        report.status = lab_core::ReportStatus::Failed;
        report.result = lab_core::ReportStatus::Failed;
    }
    report.submission = SubmissionReport {
        received: true,
        collector_name: Some(submission.collector.name),
        collector_version: Some(submission.collector.version),
        finding_count: submission.findings.len(),
        accepted: true,
        rejected_fields: Vec::new(),
    };
    if let Err(error) = lab_core::enrich_report(&mut report, &loaded) {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":format!("cannot enrich public run report: {error}")}),
        );
    }
    refresh_semantic_fingerprint(&mut report);
    if let Err(error) = state.set_report(run_id, report.clone()) {
        return run_error_response(error);
    }
    json_response(
        StatusCode::CREATED,
        json!({
            "run_id":run_id,
            "accepted":true,
            "status":report.status,
            "report_url":format!("/api/runs/{run_id}/report"),
        }),
    )
}

fn validate_submission(
    submission: &CollectorSubmission,
    loaded: &LoadedScenario,
    base_url: &str,
) -> Result<CollectorRun, String> {
    let limits = &loaded.scenario.submission;
    if !matches!(
        submission.schema_version.as_str(),
        "1.2.1" | "1.3.0" | "1.4.0" | lab_core::V14_SCHEMA_VERSION
    ) {
        return Err("submission schema_version must be 1.2.1, 1.3.0, 1.4.0 or 1.4.1".to_owned());
    }
    if submission.collector.name.is_empty()
        || submission.collector.version.is_empty()
        || submission.collector.name.len() > limits.max_string_bytes
        || submission.collector.version.len() > limits.max_string_bytes
    {
        return Err("collector name and version must be bounded non-empty strings".to_owned());
    }
    if submission.target_domain != loaded.scenario.root_domain {
        return Err("submission target_domain does not match the run manifest".to_owned());
    }
    if submission.findings.len() > limits.max_findings {
        return Err("submission exceeds max_findings".to_owned());
    }
    if submission.source_statuses.keys().any(|source| {
        !loaded
            .scenario
            .endpoints
            .iter()
            .any(|endpoint| endpoint.id == *source)
    }) {
        return Err("source_statuses reference a source_id absent from the manifest".to_owned());
    }
    let mut collector = CollectorRun {
        source_statuses: submission.source_statuses.clone(),
        ..Default::default()
    };
    for finding in &submission.findings {
        if finding.fqdn.len() > limits.max_string_bytes {
            return Err("finding fqdn exceeds max string length".to_owned());
        }
        if finding.evidence.is_empty() && !limits.allow_evidence_free_findings {
            return Err("findings require at least one evidence entry".to_owned());
        }
        if finding.evidence.len() > limits.max_evidence_per_finding {
            return Err("finding exceeds max_evidence_per_finding".to_owned());
        }
        let fqdn = accept_candidate(
            &finding.fqdn,
            &loaded.scenario.root_domain,
            loaded.scenario.include_root,
        )
        .map_err(|_| "finding fqdn is invalid or outside target_domain".to_owned())?;
        for evidence in &finding.evidence {
            if evidence.source_id.len() > limits.max_string_bytes
                || evidence
                    .record_id
                    .as_ref()
                    .is_some_and(|value| value.len() > limits.max_string_bytes)
                || evidence
                    .url
                    .as_ref()
                    .is_some_and(|value| value.len() > limits.max_string_bytes)
                || evidence.tags.len() > limits.max_tags
                || evidence
                    .tags
                    .iter()
                    .any(|tag| tag.len() > limits.max_string_bytes)
            {
                return Err("evidence exceeds a configured size limit".to_owned());
            }
            let endpoint = loaded
                .scenario
                .endpoints
                .iter()
                .find(|endpoint| endpoint.id == evidence.source_id)
                .ok_or_else(|| "evidence source_id is absent from the manifest".to_owned())?;
            if endpoint.source_kind != evidence.source_kind {
                return Err("evidence source_kind does not match manifest source".to_owned());
            }
            if let Some(url) = &evidence.url
                && !is_local_source_url(url, base_url)
            {
                return Err("evidence url must point to a local FQDN Forge source".to_owned());
            }
            let mut observation_evidence = BTreeMap::new();
            if let Some(url) = &evidence.url {
                observation_evidence.insert("url".to_owned(), url.clone());
            }
            collector.observations.push(lab_core::Observation {
                fqdn: fqdn.clone(),
                source_kind: evidence.source_kind,
                source_name: endpoint
                    .source_label
                    .clone()
                    .unwrap_or_else(|| endpoint.id.clone()),
                record_id: evidence.record_id.clone(),
                observed_at: evidence.observed_at,
                tags: evidence.tags.clone(),
                confidence: evidence.confidence,
                evidence: observation_evidence,
            });
        }
    }
    collector.metrics.request_count = collector.source_statuses.len();
    Ok(collector)
}

fn is_local_source_url(value: &str, base_url: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let Ok(local) = Url::parse(base_url) else {
        return false;
    };
    url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port_or_known_default() == local.port_or_known_default()
        && url.username().is_empty()
        && url.password().is_none()
        && !url
            .query_pairs()
            .any(|(name, _)| is_sensitive(name.as_ref()))
}

fn source_statuses_match_audit(
    statuses: &BTreeMap<String, SourceStatus>,
    audit: &[AuditRecord],
) -> bool {
    statuses.iter().all(|(source, status)| {
        let records = audit
            .iter()
            .filter(|record| record.endpoint_id.as_deref() == Some(source.as_str()))
            .collect::<Vec<_>>();
        match status {
            SourceStatus::Success | SourceStatus::Succeeded | SourceStatus::Completed => {
                records.iter().any(|record| {
                    record.matched
                        && record.consumed
                        && (200..300).contains(&record.response_status)
                }) || audit.iter().any(|record| {
                    record.event_type == AuditEventType::ProxyRequest
                        && record.proxy_mode == Some(NetworkMode::ConnectProxy)
                        && record.matched
                        && record.response_status == 200
                })
            }
            SourceStatus::AuthFailed | SourceStatus::Unauthorized => records
                .iter()
                .any(|record| matches!(record.response_status, 401 | 403)),
            SourceStatus::RateLimited => records.iter().any(|record| record.response_status == 429),
            SourceStatus::Blocked => records.iter().any(|record| record.external_target_rejected),
            SourceStatus::Pending
            | SourceStatus::Running
            | SourceStatus::Partial
            | SourceStatus::Failed
            | SourceStatus::TimedOut
            | SourceStatus::Cancelled => true,
        }
    })
}

fn filtered_from_audit(
    collector: &CollectorRun,
    loaded: &LoadedScenario,
    audit: &[AuditRecord],
) -> Vec<FilteredCandidate> {
    audit
        .iter()
        .filter_map(|record| {
            let source_id = record.endpoint_id.as_ref()?;
            let reason = if record.transport_fault.as_deref() == Some("malformed_stream") {
                Some(FilterReason::Malformed)
            } else if record.compression_limit_violation.is_some()
                || (record.content_encoding.is_some()
                    && record.decoded_bytes
                        > loaded
                            .scenario
                            .runner
                            .effective_max_decoded_response_bytes()
                    && matches!(
                        collector.source_statuses.get(source_id),
                        Some(SourceStatus::Failed)
                    ))
            {
                Some(FilterReason::ResponseTooLarge)
            } else {
                None
            }?;
            Some(FilteredCandidate {
                value: source_id.clone(),
                reason,
                source_name: source_id.clone(),
            })
        })
        .collect()
}

fn sensitive_field(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::Object(values) => values.iter().find_map(|(name, value)| {
            let next = format!("{path}.{name}");
            if is_sensitive(name) {
                Some(next)
            } else {
                sensitive_field(value, &next)
            }
        }),
        Value::Array(values) => values
            .iter()
            .enumerate()
            .find_map(|(index, value)| sensitive_field(value, &format!("{path}[{index}]"))),
        _ => None,
    }
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
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
        RunStateError::AlreadySubmitted
        | RunStateError::CrossRunSubmission
        | RunStateError::RunNotAcceptingSubmission
        | RunStateError::RunNotAcceptingSourceRequests => StatusCode::CONFLICT,
    };
    json_response(status, json!({"error":error.message()}))
}

#[derive(Debug)]
struct PlanSourceReply {
    status: StatusCode,
    body: Vec<u8>,
    content_type: &'static str,
    content_encoding: Option<&'static str>,
    retry_after: Option<String>,
    link: Option<String>,
}

fn plan_source_route(path: &str) -> Option<(&str, &str)> {
    let path = path.strip_prefix("/api/plan-runs/")?;
    let mut segments = path.split('/');
    let run_id = segments.next()?;
    (segments.next()? == "sources").then_some(())?;
    let source_id = segments.next()?;
    segments.next().is_none().then_some((run_id, source_id))
}

async fn plan_source_response(
    state: &LabState,
    method: &Method,
    path: &str,
    query: &BTreeMap<String, String>,
    headers: &HeaderMap,
    body: &[u8],
    run_id: &str,
) -> Response {
    let Some((path_run_id, source_id)) = plan_source_route(path) else {
        return plan_source_error(
            StatusCode::NOT_FOUND,
            "PLAN_SOURCE_ROUTE_NOT_FOUND",
            "no local plan source matches this route",
        );
    };
    if path_run_id != run_id {
        return plan_source_error(
            StatusCode::CONFLICT,
            "PLAN_SOURCE_RUN_MISMATCH",
            "x-lab-run-id must match the plan source route",
        );
    }
    if !matches!(*method, Method::GET | Method::POST) {
        return plan_source_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "PLAN_SOURCE_METHOD_INVALID",
            "plan sources accept only GET or POST",
        );
    }
    let source_capability = headers
        .get("x-lab-source-capability")
        .and_then(|value| value.to_str().ok());
    let access = match state.authorize_plan_source(run_id, source_id, source_capability) {
        Ok(access) => access,
        Err(error) => return plan_source_error_from_anyhow(error),
    };
    let authentication = access
        .source
        .authentication
        .as_ref()
        .unwrap_or(&access.plan.authentication);
    let pagination = access
        .source
        .pagination
        .as_ref()
        .unwrap_or(&access.plan.pagination);
    let quota = access.source.quota.as_ref().unwrap_or(&access.plan.quota);
    let page = plan_source_page(pagination, query, body);
    let virtual_wait_ms = headers
        .get("x-lab-client-virtual-wait-ms")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let mut step = PlanRequestAuditStep {
        request_number: access.request_number,
        page: Some(page),
        pagination_token: Some(plan_pagination_token(pagination, page)),
        quota_consumed: quota.consume_per_page,
        virtual_wait_ms,
        authentication: authentication_outcome(authentication).to_owned(),
        network_mode: access.plan.network_path.mode,
        proxy_authentication: access.plan.network_path.proxy_authentication,
        proxy_fault: access.plan.network_path.proxy_fault,
        ..PlanRequestAuditStep::default()
    };
    if access.plan.network_path.mode != PlanNetworkMode::Direct
        && !headers.contains_key("x-lab-proxy-correlation")
    {
        step.response_status = StatusCode::FORBIDDEN.as_u16();
        step.rate_limit_reason = Some("proxy_required".to_owned());
        let _ = state.record_plan_source_request(run_id, source_id, step);
        return plan_source_error(
            StatusCode::FORBIDDEN,
            "PLAN_PROXY_REQUIRED",
            "this plan source must be reached through its local proxy",
        );
    }
    let supplied_key = match authentication.location {
        AuthenticationLocation::Header => headers
            .get("x-lab-plan-api-key")
            .and_then(|value| value.to_str().ok()),
        AuthenticationLocation::Query => query.get("api_key").map(String::as_str),
    };
    let authentication_rejected = match authentication.mode {
        AuthenticationMode::None => false,
        AuthenticationMode::FakeApiKey => supplied_key != access.fake_api_key.as_deref(),
        AuthenticationMode::MissingKey | AuthenticationMode::WrongKey => true,
    };
    if authentication_rejected {
        step.response_status = authentication.failure_status;
        step.authentication = match authentication.mode {
            AuthenticationMode::MissingKey => "missing_key_rejected".to_owned(),
            AuthenticationMode::WrongKey => "wrong_key_rejected".to_owned(),
            AuthenticationMode::FakeApiKey => "fake_key_rejected".to_owned(),
            AuthenticationMode::None => "not_required".to_owned(),
        };
        let _ = state.record_plan_source_request(run_id, source_id, step);
        return plan_source_error(
            StatusCode::from_u16(authentication.failure_status).unwrap_or(StatusCode::UNAUTHORIZED),
            "PLAN_AUTH_REJECTED",
            "the simulated authentication mode rejected this request",
        );
    }
    let quota_consumed = if quota.consume_per_page {
        access.request_number
    } else {
        0
    };
    let rate_limit_reason = if quota.rate_limit_on_request == Some(access.request_number) {
        Some("configured rate_limit_on_request".to_owned())
    } else if quota_consumed > quota.request_budget {
        Some("request_budget_exhausted".to_owned())
    } else {
        None
    };
    if let Some(reason) = rate_limit_reason {
        let status = if reason == "configured rate_limit_on_request" {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            match quota.exhausted_behaviour {
                QuotaExhaustedBehaviour::RateLimited => StatusCode::TOO_MANY_REQUESTS,
                QuotaExhaustedBehaviour::Forbidden => StatusCode::FORBIDDEN,
                QuotaExhaustedBehaviour::EmptyResult => StatusCode::OK,
            }
        };
        step.response_status = status.as_u16();
        step.rate_limit_reason = Some(reason.clone());
        step.retry_after =
            (status == StatusCode::TOO_MANY_REQUESTS).then(|| retry_after_value(quota));
        let retry_after = step.retry_after.clone();
        let _ = state.record_plan_source_request(run_id, source_id, step);
        if status == StatusCode::OK {
            return plan_source_reply(PlanSourceReply {
                status,
                body: serde_json::to_vec(
                    &json!({"schema_version": PLAN_SCHEMA_VERSION, "records": []}),
                )
                .expect("serializable local empty response"),
                content_type: "application/json",
                content_encoding: None,
                retry_after: None,
                link: None,
            });
        }
        return plan_source_reply(PlanSourceReply {
            status,
            body: serde_json::to_vec(
                &json!({"schema_version": PLAN_SCHEMA_VERSION, "error": reason}),
            )
            .expect("serializable local error"),
            content_type: "application/json",
            content_encoding: None,
            retry_after,
            link: None,
        });
    }
    let faults = access
        .source
        .faults
        .iter()
        .chain(access.plan.faults.iter())
        .collect::<Vec<_>>();
    if let Some(fault) = faults.iter().find(|fault| fault.trigger_page == page) {
        match state.consume_plan_fault(run_id, source_id, fault) {
            Ok(true) => {
                step.triggered_fault = Some(fault.kind);
                let reply = plan_fault_reply(
                    fault.kind,
                    quota,
                    &access.plan,
                    &access.source,
                    page,
                    pagination,
                );
                step.response_status = reply.status.as_u16();
                step.retry_after = reply.retry_after.clone();
                if reply.status == StatusCode::TOO_MANY_REQUESTS {
                    step.rate_limit_reason = Some("controlled status_429 fault".to_owned());
                }
                if fault.kind == PlanFaultKind::SlowResponse || fault.kind == PlanFaultKind::Timeout
                {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                let _ = state.record_plan_source_request(run_id, source_id, step);
                return plan_source_reply(reply);
            }
            Ok(false) => {}
            Err(error) => return plan_source_error_from_anyhow(error),
        }
    }
    if page == 0 || page > pagination.total_pages || pagination.invalid_page == Some(page) {
        step.response_status = StatusCode::BAD_REQUEST.as_u16();
        step.rate_limit_reason = Some("invalid_pagination_token".to_owned());
        let _ = state.record_plan_source_request(run_id, source_id, step);
        return plan_source_error(
            StatusCode::BAD_REQUEST,
            "PLAN_PAGINATION_INVALID",
            "the requested local page or cursor is invalid",
        );
    }
    let reply = plan_success_reply(&access.plan, &access.source, page, pagination);
    step.response_status = reply.status.as_u16();
    let _ = state.record_plan_source_request(run_id, source_id, step);
    plan_source_reply(reply)
}

fn plan_source_page(
    pagination: &PlanPagination,
    query: &BTreeMap<String, String>,
    body: &[u8],
) -> usize {
    let from_value = |value: Option<&str>| {
        value
            .and_then(|value| value.strip_prefix("cursor-").or(Some(value)))
            .and_then(|value| value.strip_prefix("page-").or(Some(value)))
            .and_then(|value| value.strip_prefix("body-").or(Some(value)))
            .and_then(|value| value.parse::<usize>().ok())
    };
    match pagination.mode {
        PlanPaginationMode::None => 1,
        PlanPaginationMode::Page | PlanPaginationMode::Link => {
            from_value(query.get("page").map(String::as_str)).unwrap_or(1)
        }
        PlanPaginationMode::Offset => query
            .get("offset")
            .and_then(|value| value.parse::<usize>().ok())
            .map(|offset| offset / pagination.page_size.max(1) + 1)
            .unwrap_or(1),
        PlanPaginationMode::Cursor => {
            from_value(query.get("cursor").map(String::as_str)).unwrap_or(1)
        }
        PlanPaginationMode::PostBody => serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| {
                value
                    .get("page")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .or_else(|| {
                        value
                            .get("cursor")
                            .and_then(Value::as_str)
                            .and_then(|value| from_value(Some(value)))
                    })
            })
            .unwrap_or(1),
    }
}

fn plan_pagination_token(pagination: &PlanPagination, page: usize) -> String {
    match pagination.mode {
        PlanPaginationMode::None => "single".to_owned(),
        PlanPaginationMode::Page => page.to_string(),
        PlanPaginationMode::Offset => page
            .saturating_sub(1)
            .saturating_mul(pagination.page_size)
            .to_string(),
        PlanPaginationMode::Cursor => format!("cursor-{page}"),
        PlanPaginationMode::Link => format!("page-{page}"),
        PlanPaginationMode::PostBody => format!("body-{page}"),
    }
}

fn plan_success_reply(
    plan: &ExperimentPlan,
    source: &lab_core::PlanSource,
    page: usize,
    pagination: &PlanPagination,
) -> PlanSourceReply {
    let records = plan_source_page_records(plan, source, page, pagination.page_size);
    let next_page =
        (page < pagination.total_pages && pagination.next_page_exists).then_some(page + 1);
    let mut link = next_page.map(|next| {
        format!(
            "</api/plan-runs/{{run_id}}/sources/{}?page={next}>; rel=\"next\"",
            source.id
        )
    });
    if pagination.empty_final_page_with_next && page == pagination.total_pages {
        link = Some(format!(
            "</api/plan-runs/{{run_id}}/sources/{}?page={}>; rel=\"next\"",
            source.id,
            page + 1
        ));
    }
    let (body, content_type) = match source.template {
        PlanSourceTemplate::GenericHtml => (
            format!("<ul>{}</ul>", records.iter().map(|record| format!("<li>{record}</li>")).collect::<String>()).into_bytes(),
            "text/html; charset=utf-8",
        ),
        PlanSourceTemplate::GenericCsv => (
            format!("host\n{}\n", records.join("\n")).into_bytes(),
            "text/csv; charset=utf-8",
        ),
        PlanSourceTemplate::GenericText => (records.join("\n").into_bytes(), "text/plain; charset=utf-8"),
        PlanSourceTemplate::Archive | PlanSourceTemplate::UrlSearch | PlanSourceTemplate::SearchEngine => (
            serde_json::to_vec(&json!({"schema_version": PLAN_SCHEMA_VERSION, "captures": records.iter().map(|record| json!({"url": format!("https://{record}/")})).collect::<Vec<_>>(), "next_page": next_page})).expect("serializable local response"),
            "application/json",
        ),
        PlanSourceTemplate::CodeSearch => (
            serde_json::to_vec(&json!({"schema_version": PLAN_SCHEMA_VERSION, "matches": records.iter().map(|record| json!({"snippet": format!("host = {record}")})).collect::<Vec<_>>(), "next_page": next_page})).expect("serializable local response"),
            "application/json",
        ),
        PlanSourceTemplate::Organization => (
            serde_json::to_vec(&json!({"schema_version": PLAN_SCHEMA_VERSION, "domains": records.iter().map(|record| json!({"domain": record})).collect::<Vec<_>>(), "next_page": next_page})).expect("serializable local response"),
            "application/json",
        ),
        PlanSourceTemplate::ThreatIntel => (
            serde_json::to_vec(&json!({"schema_version": PLAN_SCHEMA_VERSION, "indicators": records.iter().map(|record| json!({"hostname": record})).collect::<Vec<_>>(), "next_page": next_page})).expect("serializable local response"),
            "application/json",
        ),
        PlanSourceTemplate::GenericJson | PlanSourceTemplate::CustomRest | PlanSourceTemplate::UserImport => (
            serde_json::to_vec(&json!({"schema_version": PLAN_SCHEMA_VERSION, "items": records.iter().map(|record| json!({"host": record})).collect::<Vec<_>>(), "next_page": next_page})).expect("serializable local response"),
            "application/json",
        ),
        PlanSourceTemplate::Certificate | PlanSourceTemplate::PassiveDns => (
            serde_json::to_vec(&json!({"schema_version": PLAN_SCHEMA_VERSION, "records": records.iter().map(|record| json!({"name": record})).collect::<Vec<_>>(), "next_page": next_page})).expect("serializable local response"),
            "application/json",
        ),
    };
    PlanSourceReply {
        status: StatusCode::OK,
        body,
        content_type,
        content_encoding: None,
        retry_after: None,
        link,
    }
}

fn plan_fault_reply(
    kind: PlanFaultKind,
    quota: &PlanQuota,
    plan: &ExperimentPlan,
    source: &lab_core::PlanSource,
    page: usize,
    pagination: &PlanPagination,
) -> PlanSourceReply {
    let success = || plan_success_reply(plan, source, page, pagination);
    match kind {
        PlanFaultKind::Status401 => plan_error_reply(StatusCode::UNAUTHORIZED, "controlled_401"),
        PlanFaultKind::Status403 => plan_error_reply(StatusCode::FORBIDDEN, "controlled_403"),
        PlanFaultKind::Status404 => plan_error_reply(StatusCode::NOT_FOUND, "controlled_404"),
        PlanFaultKind::Status429 => PlanSourceReply {
            retry_after: Some(retry_after_value(quota)),
            ..plan_error_reply(StatusCode::TOO_MANY_REQUESTS, "controlled_429")
        },
        PlanFaultKind::Status500 => {
            plan_error_reply(StatusCode::INTERNAL_SERVER_ERROR, "controlled_500")
        }
        PlanFaultKind::Status502 => plan_error_reply(StatusCode::BAD_GATEWAY, "controlled_502"),
        PlanFaultKind::Status503 | PlanFaultKind::Timeout | PlanFaultKind::Disconnect => {
            plan_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                "controlled_transport_failure",
            )
        }
        PlanFaultKind::EmptyResponse => PlanSourceReply {
            status: StatusCode::OK,
            body: Vec::new(),
            content_type: "application/json",
            content_encoding: None,
            retry_after: None,
            link: None,
        },
        PlanFaultKind::NoContent => PlanSourceReply {
            status: StatusCode::NO_CONTENT,
            body: Vec::new(),
            content_type: "application/json",
            content_encoding: None,
            retry_after: None,
            link: None,
        },
        PlanFaultKind::InvalidJson => PlanSourceReply {
            status: StatusCode::OK,
            body: b"{not-json".to_vec(),
            content_type: "application/json",
            content_encoding: None,
            retry_after: None,
            link: None,
        },
        PlanFaultKind::TruncatedJson => PlanSourceReply {
            status: StatusCode::OK,
            body: b"{\"items\":[".to_vec(),
            content_type: "application/json",
            content_encoding: None,
            retry_after: None,
            link: None,
        },
        PlanFaultKind::HtmlInsteadOfJson => PlanSourceReply {
            status: StatusCode::OK,
            body: b"<html><body>local controlled error</body></html>".to_vec(),
            content_type: "text/html; charset=utf-8",
            content_encoding: None,
            retry_after: None,
            link: None,
        },
        PlanFaultKind::WrongContentType => {
            let mut reply = success();
            reply.content_type = "text/plain; charset=utf-8";
            reply
        }
        PlanFaultKind::WrongContentLength | PlanFaultKind::MalformedChunked => {
            plan_error_reply(StatusCode::BAD_GATEWAY, "controlled_framing_failure")
        }
        PlanFaultKind::Gzip | PlanFaultKind::Deflate | PlanFaultKind::Brotli => {
            plan_compressed_reply(kind, success())
        }
        PlanFaultKind::CorruptCompression => PlanSourceReply {
            status: StatusCode::OK,
            body: vec![0, 159, 255, 17],
            content_type: "application/json",
            content_encoding: Some("gzip"),
            retry_after: None,
            link: None,
        },
        PlanFaultKind::ResponseTooLarge => PlanSourceReply {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            body: vec![b'x'; 1024 * 1024],
            content_type: "application/octet-stream",
            content_encoding: None,
            retry_after: None,
            link: None,
        },
        PlanFaultKind::SlowResponse => success(),
    }
}

fn plan_error_reply(status: StatusCode, error: &str) -> PlanSourceReply {
    PlanSourceReply {
        status,
        body: serde_json::to_vec(&json!({"schema_version": PLAN_SCHEMA_VERSION, "error": error}))
            .expect("serializable local error"),
        content_type: "application/json",
        content_encoding: None,
        retry_after: None,
        link: None,
    }
}

fn plan_compressed_reply(kind: PlanFaultKind, mut reply: PlanSourceReply) -> PlanSourceReply {
    let (encoding, body) = match kind {
        PlanFaultKind::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(&reply.body)
                .expect("local gzip fixture encodes");
            (
                "gzip",
                encoder.finish().expect("local gzip fixture finishes"),
            )
        }
        PlanFaultKind::Deflate => {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(&reply.body)
                .expect("local deflate fixture encodes");
            (
                "deflate",
                encoder.finish().expect("local deflate fixture finishes"),
            )
        }
        PlanFaultKind::Brotli => {
            let mut encoder = CompressorWriter::new(Vec::new(), 4 * 1024, 5, 22);
            encoder
                .write_all(&reply.body)
                .expect("local brotli fixture encodes");
            ("br", encoder.into_inner())
        }
        _ => return reply,
    };
    reply.body = body;
    reply.content_encoding = Some(encoding);
    reply
}

fn plan_source_reply(reply: PlanSourceReply) -> Response {
    let mut builder = Response::builder()
        .status(reply.status)
        .header(header::CONTENT_TYPE, reply.content_type)
        .header("cache-control", "no-store");
    if let Some(content_encoding) = reply.content_encoding {
        builder = builder.header(header::CONTENT_ENCODING, content_encoding);
    }
    if let Some(retry_after) = reply.retry_after {
        builder = builder.header(header::RETRY_AFTER, retry_after);
    }
    if let Some(link) = reply.link {
        builder = builder.header(header::LINK, link);
    }
    builder
        .body(Body::from(reply.body))
        .expect("static plan source response")
}

fn plan_source_error(status: StatusCode, code: &str, message: &str) -> Response {
    let mut response = json_response(
        status,
        json!({"schema_version": PLAN_SCHEMA_VERSION, "error": {"code": code, "message": message}}),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn plan_source_error_from_anyhow(error: anyhow::Error) -> Response {
    let message = error.to_string();
    let (code, human) = message.split_once(": ").map_or(
        ("PLAN_SOURCE_OPERATION_FAILED", message.as_str()),
        |(code, human)| (code, human),
    );
    let status = match code {
        "PLAN_RUN_NOT_FOUND" | "PLAN_SOURCE_NOT_FOUND" => StatusCode::NOT_FOUND,
        "PLAN_SOURCE_CAPABILITY_INVALID" => StatusCode::FORBIDDEN,
        "PLAN_SOURCE_CAPABILITY_UNAVAILABLE" => StatusCode::GONE,
        _ => StatusCode::BAD_REQUEST,
    };
    plan_source_error(status, code, human)
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
    if plan_source_route(&path).is_some() {
        return plan_source_response(&state, &method, &path, &query, &headers, &body, run_id).await;
    }
    let run = match state.session(run_id) {
        Ok(run) => run,
        Err(error) => {
            state.record_unscoped_request(method.as_ref(), &path, error.message());
            return run_error_response(error);
        }
    };
    if !matches!(
        run.status,
        lab_core::RunSessionStatus::Active | lab_core::RunSessionStatus::Reset
    ) {
        return run_error_response(RunStateError::RunNotAcceptingSourceRequests);
    }
    if let Some(capability) = headers
        .get("x-lab-source-capability")
        .and_then(|value| value.to_str().ok())
        && capability != source_capability_value(&run.run_id, &run.access_token)
    {
        let loaded = match state.loaded_for_run(run_id) {
            Ok(loaded) => loaded,
            Err(error) => return run_error_response(error),
        };
        let mut record = audit_record(AuditInput {
            run_id,
            scenario: &loaded.scenario,
            endpoint: None,
            method: &method,
            path: &path,
            query,
            headers: &headers,
            body: &body,
            response_index: None,
            response_status: 403,
            matched: false,
            extra: true,
            mismatch_reasons: vec!["stale_source_capability".to_owned()],
        });
        record.blocked = true;
        record.proxy_reason = Some("stale_source_capability".to_owned());
        let _ = state.record_request(run_id, record);
        return json_response(
            StatusCode::FORBIDDEN,
            json!({"error":"source capability is stale or invalid"}),
        );
    }
    let loaded = match state.loaded_for_run(run_id) {
        Ok(loaded) => loaded,
        Err(error) => {
            state.record_unscoped_request(method.as_ref(), &path, error.message());
            let status = match error {
                RunStateError::InvalidRunId => StatusCode::BAD_REQUEST,
                RunStateError::UnknownRun => StatusCode::CONFLICT,
                RunStateError::AlreadySubmitted
                | RunStateError::CrossRunSubmission
                | RunStateError::RunNotAcceptingSubmission
                | RunStateError::RunNotAcceptingSourceRequests => StatusCode::CONFLICT,
            };
            return json_response(status, json!({"error":error.message()}));
        }
    };
    if loaded.scenario.network_profile.proxy_must_be_used
        && !headers.contains_key("x-lab-proxy-correlation")
    {
        let mut record = audit_record(AuditInput {
            run_id,
            scenario: &loaded.scenario,
            endpoint: None,
            method: &method,
            path: &path,
            query: query.clone(),
            headers: &headers,
            body: &body,
            response_index: None,
            response_status: 403,
            matched: false,
            extra: true,
            mismatch_reasons: vec!["proxy_required".to_owned()],
        });
        record.blocked = true;
        record.proxy_reason = Some("proxy_required".to_owned());
        let _ = state.record_request(run_id, record);
        return json_response(
            StatusCode::FORBIDDEN,
            json!({"error":"this source requires its local proxy"}),
        );
    }
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
    let client_virtual_wait_ms = headers
        .get("x-lab-client-virtual-wait-ms")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let script_claim = match state.claim_fault_script_step(
        run_id,
        &loaded.scenario.fault_script,
        FaultScriptStage::Source,
        &endpoint.id,
        &query,
        client_virtual_wait_ms,
    ) {
        Ok(claim) => claim,
        Err(error) => return run_error_response(error),
    };
    let (script_step_id, scripted_response_index, script_expects_rate_limit) = match script_claim {
        FaultScriptClaim::Unscripted => (None, None, false),
        FaultScriptClaim::Matched(step) => (
            Some(step.id),
            step.response_index,
            step.expect_quota_rate_limited,
        ),
        FaultScriptClaim::Unexpected(reason) => {
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
                response_status: StatusCode::CONFLICT.as_u16(),
                matched: false,
                extra: true,
                mismatch_reasons: vec![format!("unexpected_script_step: {reason}")],
            });
            let _ = state.record_request(run_id, record);
            return json_response(
                StatusCode::CONFLICT,
                json!({"error":"request did not match the current fault-script step"}),
            );
        }
    };
    if !endpoint.quota.is_empty() {
        let credential_identity = quota_credential_identity(&headers);
        let decisions = match state.evaluate_quota(
            run_id,
            &endpoint.id,
            &endpoint.quota,
            &credential_identity,
            client_virtual_wait_ms,
        ) {
            Ok(decisions) => decisions,
            Err(error) => return run_error_response(error),
        };
        let rate_limited = decisions.iter().any(|decision| decision.rate_limited);
        for decision in &decisions {
            let _ = state.record_request(
                run_id,
                quota_audit_record(
                    run_id,
                    &loaded.scenario,
                    &endpoint.id,
                    decision,
                    &credential_identity,
                ),
            );
        }
        if rate_limited {
            let decision = decisions
                .iter()
                .find(|decision| decision.rate_limited)
                .expect("rate-limited decision exists");
            let status = StatusCode::from_u16(decision.profile.exhausted_status)
                .unwrap_or(StatusCode::TOO_MANY_REQUESTS);
            let mut record = audit_record(AuditInput {
                run_id,
                scenario: &loaded.scenario,
                endpoint: Some(endpoint),
                method: &method,
                path: &path,
                query: query.clone(),
                headers: &headers,
                body: &body,
                response_index: None,
                response_status: status.as_u16(),
                matched: true,
                extra: false,
                mismatch_reasons: Vec::new(),
            });
            record.retry_after = Some(quota_retry_after(&decision.profile));
            record.virtual_wait_ms = client_virtual_wait_ms;
            record.script_step_id = script_step_id;
            if !script_expects_rate_limit && !loaded.scenario.fault_script.is_empty() {
                record.matched = false;
                record.extra = true;
                record
                    .mismatch_reasons
                    .push("fault script did not expect a quota rejection".to_owned());
            }
            let _ = state.record_request(run_id, record);
            return Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .header("retry-after", quota_retry_after(&decision.profile))
                .header(
                    "x-lab-virtual-wait-ms",
                    decision.profile.retry_after_ms.to_string(),
                )
                .header(header::CONNECTION, "close")
                .body(Body::from("{\"error\":\"synthetic quota exhausted\"}"))
                .expect("static quota response");
        }
    }
    if script_expects_rate_limit {
        let mut record = audit_record(AuditInput {
            run_id,
            scenario: &loaded.scenario,
            endpoint: Some(endpoint),
            method: &method,
            path: &path,
            query,
            headers: &headers,
            body: &body,
            response_index: None,
            response_status: StatusCode::CONFLICT.as_u16(),
            matched: false,
            extra: true,
            mismatch_reasons: vec![
                "fault script expected a quota rejection but the quota permitted the request"
                    .to_owned(),
            ],
        });
        record.script_step_id = script_step_id;
        let _ = state.record_request(run_id, record);
        return json_response(
            StatusCode::CONFLICT,
            json!({"error":"fault-script quota expectation was not met"}),
        );
    }
    let index = if let Some(index) = scripted_response_index {
        if index >= endpoint.replies.len() {
            let mut record = audit_record(AuditInput {
                run_id,
                scenario: &loaded.scenario,
                endpoint: Some(endpoint),
                method: &method,
                path: &path,
                query,
                headers: &headers,
                body: &body,
                response_index: None,
                response_status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                matched: false,
                extra: true,
                mismatch_reasons: vec!["fault script references an invalid reply index".to_owned()],
            });
            record.script_step_id = script_step_id;
            let _ = state.record_request(run_id, record);
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"fault-script reply index is invalid"}),
            );
        }
        index
    } else {
        match state.claim_response_index(run_id, &endpoint.id, endpoint.replies.len()) {
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
        }
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
    record.script_step_id = script_step_id;
    record.retry_after = reply.retry_after.clone().or_else(|| {
        reply
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
            .map(|(_, value)| value.clone())
    });
    record.virtual_wait_ms = client_virtual_wait_ms;
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
        return reply_response(
            &state,
            run_id,
            ReplyResponseInput {
                endpoint_id: &endpoint.id,
                response_index: index,
                status,
                reply,
                runner: &loaded.scenario.runner,
                bytes: Vec::new(),
            },
        )
        .await;
    }
    match response_body(reply, endpoint, &loaded, profile, run_id, &template_context) {
        Ok(bytes) => {
            reply_response(
                &state,
                run_id,
                ReplyResponseInput {
                    endpoint_id: &endpoint.id,
                    response_index: index,
                    status,
                    reply,
                    runner: &loaded.scenario.runner,
                    bytes,
                },
            )
            .await
        }
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

struct ReplyResponseInput<'a> {
    endpoint_id: &'a str,
    response_index: usize,
    status: StatusCode,
    reply: &'a Reply,
    runner: &'a lab_core::RunnerConfig,
    bytes: Vec<u8>,
}

async fn reply_response(state: &LabState, run_id: &str, input: ReplyResponseInput<'_>) -> Response {
    let ReplyResponseInput {
        endpoint_id,
        response_index,
        status,
        reply,
        runner,
        bytes,
    } = input;
    let decoded = if reply.malformed_body {
        b"{malformed-response".to_vec()
    } else {
        bytes
    };
    let decoded_bytes = decoded.len();
    let mut encoded = match encode_response_body(reply, &decoded) {
        Ok(encoded) => encoded,
        Err(error) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":format!("could not encode local fixture: {error}")}),
            );
        }
    };
    if (reply.gzip_corrupt || reply.encoding_corrupt) && !encoded.is_empty() {
        let index = encoded.len() - 1;
        encoded[index] ^= 0xff;
    }
    if (reply.gzip_truncated || reply.encoding_truncated) && !encoded.is_empty() {
        encoded.truncate(encoded.len().saturating_sub(8));
    }
    let sent = if reply.disconnect
        || reply.connection_reset
        || reply.close_before_body
        || reply.truncated_body
    {
        encoded[..encoded.len() / 2].to_vec()
    } else {
        encoded
    };
    let content_encoding = reply
        .content_encoding_header
        .clone()
        .or_else(|| reply.encoding.clone())
        .filter(|encoding| !encoding.eq_ignore_ascii_case("identity"));
    let compression_limit_violation = compression_limit_violation(
        runner,
        content_encoding.as_deref(),
        sent.len(),
        decoded_bytes,
    );
    let _ = state.set_response_metrics(
        run_id,
        ResponseMetrics {
            endpoint_id: endpoint_id.to_owned(),
            response_index,
            wire_bytes: sent.len(),
            decoded_bytes,
            response_digest: Some(stable_digest(&json!({"bytes": sent}))),
            content_encoding: content_encoding.clone(),
            compression_limit_violation,
            transfer_mode: Some(reply.transfer_mode),
            chunk_count: if reply.transfer_mode == TransferMode::Chunked {
                reply.chunk_count
            } else {
                0
            },
            transport_fault: (reply.malformed_content_length.is_some()
                || reply.malformed_chunk
                || reply.truncated_body
                || reply.encoding_corrupt
                || reply.encoding_truncated)
                .then(|| {
                    if reply.malformed_content_length.is_some() {
                        "framing_conflict".to_owned()
                    } else if reply.malformed_chunk {
                        "malformed_chunk".to_owned()
                    } else if reply.truncated_body {
                        "truncated".to_owned()
                    } else {
                        "malformed_stream".to_owned()
                    }
                }),
        },
    );
    if reply.first_byte_delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(reply.first_byte_delay_ms)).await;
    }
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, reply.content_type())
        .header(header::CONNECTION, "close");
    let transport_fault = reply.disconnect
        || reply.connection_reset
        || reply.close_before_body
        || reply.truncated_body
        || reply.malformed_chunk;
    if let Some(location) = &reply.redirect {
        builder = builder.header(header::LOCATION, location);
    }
    if reply.virtual_wait_ms > 0 {
        builder = builder.header("x-lab-virtual-wait-ms", reply.virtual_wait_ms.to_string());
    }
    if let Some(retry_after) = &reply.retry_after {
        builder = builder.header("retry-after", retry_after);
    }
    if let Some(encoding) = content_encoding {
        builder = builder.header(header::CONTENT_ENCODING, encoding);
    }
    for (name, value) in &reply.headers {
        builder = builder.header(name, value);
    }
    if !transport_fault
        && (reply.transfer_mode == TransferMode::ContentLength
            || reply.malformed_content_length.is_some())
    {
        builder = builder.header(
            header::CONTENT_LENGTH,
            reply
                .malformed_content_length
                .unwrap_or(sent.len())
                .to_string(),
        );
    }
    let body = if reply.transfer_mode == TransferMode::Chunked {
        let chunks = response_chunks(&sent, reply.chunk_count.max(1));
        let mut events = chunks
            .into_iter()
            .map(|chunk| Ok::<Bytes, io::Error>(Bytes::from(chunk)))
            .collect::<Vec<_>>();
        if transport_fault {
            events.push(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "synthetic chunked transport fault",
            )));
        }
        Body::from_stream(stream::iter(events))
    } else if transport_fault || reply.malformed_content_length.is_some() {
        let error = io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "synthetic transport fault",
        );
        if transport_fault {
            Body::from_stream(stream::iter(vec![
                Ok::<Bytes, io::Error>(Bytes::from(sent)),
                Err(error),
            ]))
        } else {
            Body::from_stream(stream::iter(vec![Ok::<Bytes, io::Error>(Bytes::from(
                sent,
            ))]))
        }
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

fn encode_response_body(reply: &Reply, decoded: &[u8]) -> Result<Vec<u8>, String> {
    let encoding = reply.encoding.as_deref().unwrap_or("identity");
    if encoding.eq_ignore_ascii_case("identity")
        || encoding.eq_ignore_ascii_case("utf-8")
        || encoding.eq_ignore_ascii_case("utf8")
    {
        return Ok(decoded.to_vec());
    }
    if encoding.eq_ignore_ascii_case("gzip") {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(decoded)
            .map_err(|error| error.to_string())?;
        return encoder.finish().map_err(|error| error.to_string());
    }
    if encoding.eq_ignore_ascii_case("deflate") {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(decoded)
            .map_err(|error| error.to_string())?;
        return encoder.finish().map_err(|error| error.to_string());
    }
    if encoding.eq_ignore_ascii_case("br") {
        let mut encoder = CompressorWriter::new(Vec::new(), 4 * 1024, 5, 22);
        encoder
            .write_all(decoded)
            .map_err(|error| error.to_string())?;
        return Ok(encoder.into_inner());
    }
    Err("unsupported local content encoding".to_owned())
}

fn response_chunks(bytes: &[u8], requested: usize) -> Vec<Vec<u8>> {
    if bytes.is_empty() {
        return vec![Vec::new()];
    }
    let count = requested.min(bytes.len()).max(1);
    let chunk_size = bytes.len().div_ceil(count);
    bytes.chunks(chunk_size).map(ToOwned::to_owned).collect()
}

fn compression_limit_violation(
    runner: &lab_core::RunnerConfig,
    encoding: Option<&str>,
    wire_bytes: usize,
    decoded_bytes: usize,
) -> Option<String> {
    if !encoding.is_some_and(|value| !value.eq_ignore_ascii_case("identity")) {
        return None;
    }
    if wire_bytes > runner.effective_max_wire_response_bytes() {
        return Some("max_wire_response_bytes exceeded".to_owned());
    }
    if decoded_bytes > runner.effective_max_decoded_response_bytes() {
        return Some("max_decoded_response_bytes exceeded".to_owned());
    }
    if wire_bytes == 0 || decoded_bytes > wire_bytes.saturating_mul(runner.max_expansion_ratio) {
        return Some("max_expansion_ratio exceeded".to_owned());
    }
    None
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
        script_step_id: None,
        response_sequence: response_index,
        response_status,
        before_submission: false,
        redacted_headers,
        virtual_wait_ms: 0,
        retry_after: None,
        consumed: matched,
        blocked: false,
        external_target_rejected: false,
        matched,
        extra,
        mismatch_reasons,
        wire_bytes: 0,
        response_digest: None,
        decoded_bytes: 0,
        content_encoding: None,
        compression_limit_violation: None,
        event_type: AuditEventType::SourceRequest,
        proxy_mode: None,
        proxy_target: None,
        proxy_authentication: ProxyAuthenticationState::NotApplicable,
        proxy_reason: None,
        correlation_id: headers
            .get("x-lab-proxy-correlation")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        quota_scope: None,
        quota_remaining_before: None,
        quota_remaining_after: None,
        quota_consumed: false,
        quota_rate_limited: false,
        quota_recovery_virtual_wait_ms: None,
        transfer_mode: None,
        chunk_count: 0,
        transport_fault: None,
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
        "api_key",
        "apikey",
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

fn text_response(status: StatusCode, content_type: &'static str, value: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, value.len())
        .body(Body::from(value))
        .expect("static text response builder")
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use lab_core::{
        AuditRecord, EgressGuard, ExperimentPlan, JudgeInput, LoadedScenario, PlanFault,
        PlanFaultKind, PlanNetworkMode, ReferenceRunner, ReportStatus, RunReport,
        ScenarioRepository, SourceStatus, judge_run,
    };
    use reqwest::{Client, StatusCode};
    use serde_json::json;
    use std::{collections::BTreeMap, fs, net::Ipv4Addr, path::PathBuf};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    use url::Url;
    use uuid::Uuid;

    use super::{LocalServer, TemplateContext, materialize_text};

    fn repository() -> ScenarioRepository {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios");
        ScenarioRepository::load(root).expect("load scenarios")
    }

    fn plan_test_root(label: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-artifacts")
            .join(format!("lab-server-{label}-{}", Uuid::new_v4().simple()))
            .join("plans")
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

    fn run_access_token(server: &LocalServer, run_id: Uuid) -> String {
        server
            .state
            .session(&run_id.to_string())
            .expect("test run")
            .access_token
    }

    async fn requests(
        server: &LocalServer,
        client: &Client,
        base_url: &str,
        run_id: Uuid,
    ) -> Vec<AuditRecord> {
        let value: serde_json::Value = client
            .get(format!("{base_url}/api/runs/{run_id}/requests"))
            .header("x-lab-run-access-token", run_access_token(server, run_id))
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
        server: &LocalServer,
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
        let audit = requests(server, client, base_url, run_id).await;
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
        server.set_report(report.clone());
        report
    }

    #[tokio::test]
    async fn analysis_routes_use_an_isolated_redacted_artifact_root() {
        let temporary =
            std::env::temp_dir().join(format!("fqdn-forge-analysis-api-{}", Uuid::new_v4()));
        let plan_root = temporary.join("plans");
        let analysis_root = temporary.join("analysis-artifacts");
        fs::create_dir_all(analysis_root.join("reports")).expect("analysis reports directory");
        let repository = repository();
        let server = LocalServer::spawn_on_with_roots(
            repository.clone(),
            None,
            None,
            plan_root,
            analysis_root.clone(),
        )
        .await
        .expect("analysis server");
        let client = Client::new();
        let base_url = server.base_url();
        let loaded = repository.get("001-basic-certificate").expect("scenario");
        let run_id = create_run(&client, &base_url, &loaded.scenario.id).await;
        let mut report = run_report(&server, &client, &base_url, loaded, run_id).await;
        report
            .failures
            .push("Authorization: synthetic-not-exported".to_owned());
        fs::write(
            analysis_root.join("reports").join("valid.json"),
            serde_json::to_vec(&report).expect("serialize report"),
        )
        .expect("write report");
        fs::write(analysis_root.join("reports").join("broken.json"), b"{")
            .expect("write broken artifact");

        let overview: serde_json::Value = client
            .get(format!("{base_url}/api/analysis/overview"))
            .send()
            .await
            .expect("analysis overview")
            .error_for_status()
            .expect("overview status")
            .json()
            .await
            .expect("overview JSON");
        assert_eq!(overview["schema_version"], "1.0");
        assert_eq!(overview["data"]["reports"]["count"], 1);
        assert_eq!(overview["diagnostics"][0]["code"], "ARTIFACT_UNREADABLE");
        assert!(
            !overview
                .to_string()
                .to_ascii_lowercase()
                .contains("authorization")
        );

        let timeline: serde_json::Value = client
            .get(format!(
                "{base_url}/api/analysis/timeline?run={run_id}&limit=2"
            ))
            .send()
            .await
            .expect("analysis timeline")
            .error_for_status()
            .expect("timeline status")
            .json()
            .await
            .expect("timeline JSON");
        assert!(timeline["data"]["events"].as_array().is_some());

        let invalid = client
            .get(format!(
                "{base_url}/api/analysis/coverage?path=../../artifacts"
            ))
            .send()
            .await
            .expect("invalid filter response");
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        let invalid: serde_json::Value = invalid.json().await.expect("invalid JSON");
        assert_eq!(invalid["error"]["code"], "ANALYSIS_FILTER_INVALID");

        server.shutdown().await;
        fs::remove_dir_all(&temporary).expect("remove isolated analysis artifacts");
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
    async fn public_manifest_advertises_post_body_contract() {
        let server = LocalServer::spawn(repository(), Some("036-custom-rest-post"))
            .await
            .expect("start server");
        let client = Client::new();
        let base_url = server.base_url();
        let created: serde_json::Value = client
            .post(format!("{base_url}/api/runs"))
            .json(&serde_json::json!({"scenario_id":"036-custom-rest-post"}))
            .send()
            .await
            .expect("create run")
            .error_for_status()
            .expect("create run status")
            .json()
            .await
            .expect("create run JSON");
        let run_id = created["run_id"].as_str().expect("run ID");
        let access_token = created["run_access_token"].as_str().expect("access token");
        let manifest: serde_json::Value = client
            .get(format!("{base_url}/api/runs/{run_id}/manifest"))
            .header("x-lab-run-access-token", access_token)
            .send()
            .await
            .expect("manifest")
            .error_for_status()
            .expect("manifest status")
            .json()
            .await
            .expect("manifest JSON");
        let source = &manifest["sources"][0];
        assert_eq!(
            source["request_body_template"],
            json!({"query":"subdomains","mode":"strict"})
        );
        assert_eq!(source["request_body_content_type"], "application/json");
        assert!(
            source["authentication"]["x-lab-source-capability"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn public_manifest_advertises_cancellation_contract() {
        let server = LocalServer::spawn(repository(), Some("020-cancellation-and-egress-guard"))
            .await
            .expect("start server");
        let client = Client::new();
        let base_url = server.base_url();
        let run_id = create_run(&client, &base_url, "020-cancellation-and-egress-guard").await;
        let manifest: serde_json::Value = client
            .get(format!("{base_url}/api/runs/{run_id}/manifest"))
            .header("x-lab-run-access-token", run_access_token(&server, run_id))
            .send()
            .await
            .expect("manifest")
            .error_for_status()
            .expect("manifest status")
            .json()
            .await
            .expect("manifest JSON");
        assert_eq!(manifest["cancel_after_requests"], 1);
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
            .header("x-lab-run-access-token", run_access_token(&server, run_id))
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
                .header("x-lab-run-access-token", run_access_token(&server, run_id))
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
            run_report(&server, &client, &base_url, &loaded, first),
            run_report(&server, &client, &base_url, &loaded, second)
        );
        assert_eq!(first_report.status, ReportStatus::Passed);
        assert_eq!(second_report.status, ReportStatus::Passed);
        let first_audit = requests(&server, &client, &base_url, first).await;
        let second_audit = requests(&server, &client, &base_url, second).await;
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
            .header("x-lab-run-access-token", run_access_token(&server, first))
            .send()
            .await
            .expect("reset");
        assert_eq!(reset.status(), StatusCode::OK);
        let second_report = run_report(&server, &client, &base_url, &loaded, second).await;
        assert_eq!(second_report.status, ReportStatus::Passed);
        assert!(
            requests(&server, &client, &base_url, first)
                .await
                .is_empty()
        );
        assert_eq!(
            response_indices(&requests(&server, &client, &base_url, second).await),
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
            run_report(&server, &client, &base_url, &pages, pages_id),
            run_report(&server, &client, &base_url, &rate_limit, rate_id)
        );
        assert_eq!(pages_report.status, ReportStatus::Passed);
        assert_eq!(rate_report.status, ReportStatus::Passed);
        assert_eq!(pages_report.virtual_waited_ms, 0);
        assert_eq!(rate_report.virtual_waited_ms, 1_000);
        assert_eq!(
            response_indices(&requests(&server, &client, &base_url, pages_id).await),
            vec![0, 1]
        );
        assert_eq!(
            response_indices(&requests(&server, &client, &base_url, rate_id).await),
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
        assert!(
            requests(&server, &client, &base_url, run_id)
                .await
                .is_empty()
        );
        let diagnostics = client
            .get(format!("{base_url}/api/diagnostics/unscoped-requests"))
            .send()
            .await
            .expect("diagnostics")
            .text()
            .await
            .expect("diagnostics body");
        assert!(diagnostics.contains("missing x-lab-run-id"));
        let report = run_report(&server, &client, &base_url, &loaded, run_id).await;
        assert_eq!(report.status, ReportStatus::Passed);
        assert_eq!(
            response_indices(&requests(&server, &client, &base_url, run_id).await),
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
        let audit = requests(&server, &client, &base_url, page_id).await;
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
            !serde_json::to_string(&requests(&server, &client, &base_url, rate_id).await)
                .expect("audit JSON")
                .contains("wrong-key")
        );
        let good_rate_id = create_run(&client, &base_url, &rate_limit.scenario.id).await;
        let rate_report = run_report(&server, &client, &base_url, &rate_limit, good_rate_id).await;
        assert_eq!(rate_report.status, ReportStatus::Passed);
        assert!(
            !serde_json::to_string(&requests(&server, &client, &base_url, good_rate_id).await)
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
            response_indices(&requests(&server, &client, &base_url, correct_run).await),
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
        assert!(
            response_indices(&requests(&server, &client, &base_url, wrong_run).await).is_empty()
        );

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
        let redirect_audit = requests(&server, &client, &base_url, redirect_run).await;
        assert_eq!(redirect_audit.len(), 1);
        assert_eq!(redirect_audit[0].response_status, 302);
        assert!(redirect_audit[0].blocked);
        assert!(redirect_audit[0].external_target_rejected);
        server.shutdown().await;
        fs::remove_dir_all(temporary_root).expect("remove temporary scenarios");
    }

    #[tokio::test]
    async fn plan_api_has_a_complete_local_lifecycle_and_replays_its_snapshot() {
        let server =
            LocalServer::spawn_with_plan_root(repository(), None, plan_test_root("plan-lifecycle"))
                .await
                .expect("server");
        let client = Client::new();
        let base_url = server.base_url();
        let mut plan = ExperimentPlan::example();
        plan.plan_id = format!("plan-api-{}", Uuid::new_v4().simple());
        plan.authentication.mode = lab_core::AuthenticationMode::FakeApiKey;

        let created: serde_json::Value = client
            .post(format!("{base_url}/api/plans"))
            .json(&plan)
            .send()
            .await
            .expect("create plan")
            .error_for_status()
            .expect("created plan status")
            .json()
            .await
            .expect("created plan JSON");
        assert_eq!(created["schema_version"], "0.2");
        let digest = created["plan"]["plan_digest"]
            .as_str()
            .expect("plan digest")
            .to_owned();

        let mut updated_plan = created["plan"].clone();
        updated_plan["description"] = "Updated through the API lifecycle test".into();
        let updated: serde_json::Value = client
            .put(format!("{base_url}/api/plans/{}", plan.plan_id))
            .json(&updated_plan)
            .send()
            .await
            .expect("update plan")
            .error_for_status()
            .expect("update status")
            .json()
            .await
            .expect("update JSON");
        assert_eq!(updated["plan"]["revision"], 1);
        assert_eq!(updated["plan"]["plan_digest"], digest);

        let mut stale_plan = created["plan"].clone();
        stale_plan["description"] = "Stale browser draft".into();
        let stale = client
            .put(format!("{base_url}/api/plans/{}", plan.plan_id))
            .header("if-match", "\"0\"")
            .json(&stale_plan)
            .send()
            .await
            .expect("stale conditional update response");
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let stale: serde_json::Value = stale.json().await.expect("stale update JSON");
        assert_eq!(stale["error"]["code"], "PLAN_REVISION_CONFLICT");

        let exported: serde_json::Value = client
            .post(format!("{base_url}/api/plans/{}/export", plan.plan_id))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("export plan")
            .error_for_status()
            .expect("export status")
            .json()
            .await
            .expect("export JSON");
        assert_eq!(exported["plan"]["plan_digest"], digest);
        let imported_id = format!("{}-import", plan.plan_id);
        let mut imported_plan = exported["plan"].clone();
        imported_plan["plan_id"] = imported_id.clone().into();
        let imported: serde_json::Value = client
            .post(format!("{base_url}/api/plans/import"))
            .json(&imported_plan)
            .send()
            .await
            .expect("import plan")
            .error_for_status()
            .expect("import status")
            .json()
            .await
            .expect("import JSON");
        assert_eq!(imported["plan"]["plan_digest"], digest);

        let run: serde_json::Value = client
            .post(format!("{base_url}/api/plans/{}/runs", plan.plan_id))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("run plan")
            .error_for_status()
            .expect("run status")
            .json()
            .await
            .expect("run JSON");
        assert_eq!(run["report"]["status"], "passed");
        assert_eq!(run["report"]["egress_attempted"], false);
        assert_eq!(run["manifest"]["execution_mode"], "external_integration");
        let run_id = run["run_id"].as_str().expect("run ID").to_owned();

        let console_run: serde_json::Value = client
            .post(format!("{base_url}/api/plans/{}/runs", plan.plan_id))
            .header("x-fqdn-console-request", "1")
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("console run plan")
            .error_for_status()
            .expect("console run status")
            .json()
            .await
            .expect("console run JSON");
        assert_eq!(console_run["source_access"]["available"], true);
        assert!(
            console_run["source_access"]
                .get("source_capability")
                .is_none()
        );
        assert!(console_run["source_access"].get("fake_api_key").is_none());

        let simulation: serde_json::Value = client
            .post(format!("{base_url}/api/plans/{}/simulate", plan.plan_id))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("simulate plan")
            .error_for_status()
            .expect("simulation status")
            .json()
            .await
            .expect("simulation JSON");
        assert_eq!(simulation["manifest"]["execution_mode"], "local_simulation");
        let audit: serde_json::Value = client
            .get(format!("{base_url}/api/plan-runs/{run_id}/audit"))
            .send()
            .await
            .expect("audit")
            .error_for_status()
            .expect("audit status")
            .json()
            .await
            .expect("audit JSON");
        assert_eq!(audit["entries"].as_array().map(Vec::len), Some(1));
        assert!(audit["entries"][0]["expected_requests"].is_array());
        assert!(audit["entries"][0]["actual_requests"].is_array());

        let source_access = &run["source_access"];
        let source_url = source_access["source_url_template"]
            .as_str()
            .expect("source URL template")
            .replace("{source_id}", "certificate");
        let capability = source_access["source_capability"]
            .as_str()
            .expect("ephemeral source capability");
        let fake_key = source_access["fake_api_key"]
            .as_str()
            .expect("ephemeral fake API key");
        let rejected = client
            .get(&source_url)
            .header("x-lab-run-id", &run_id)
            .header("x-lab-source-capability", capability)
            .send()
            .await
            .expect("missing fake key request");
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        let source_response = client
            .get(source_url)
            .header("x-lab-run-id", &run_id)
            .header("x-lab-source-capability", capability)
            .header("x-lab-plan-api-key", fake_key)
            .send()
            .await
            .expect("local plan source")
            .error_for_status()
            .expect("source status");
        assert_eq!(
            source_response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let source: serde_json::Value = source_response.json().await.expect("source JSON");
        assert_eq!(source["schema_version"], "0.2");
        assert!(source["records"].is_array());
        let source_audit: serde_json::Value = client
            .get(format!("{base_url}/api/plan-runs/{run_id}/audit"))
            .send()
            .await
            .expect("updated audit")
            .error_for_status()
            .expect("updated audit status")
            .json()
            .await
            .expect("updated audit JSON");
        assert_eq!(
            source_audit["entries"][0]["actual_requests"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        let manifest: serde_json::Value = client
            .get(format!("{base_url}/api/plan-runs/{run_id}/manifest"))
            .send()
            .await
            .expect("plan manifest")
            .error_for_status()
            .expect("plan manifest status")
            .json()
            .await
            .expect("plan manifest JSON");
        assert!(manifest["manifest"].get("source_capability").is_none());
        assert!(!manifest.to_string().contains(capability));

        let cancelled = client
            .post(format!("{base_url}/api/plan-runs/{run_id}/cancel"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("cancel plan source");
        assert_eq!(cancelled.status(), StatusCode::OK);
        let stale = client
            .get(
                source_access["source_url_template"]
                    .as_str()
                    .expect("source URL")
                    .replace("{source_id}", "certificate"),
            )
            .header("x-lab-run-id", &run_id)
            .header("x-lab-source-capability", capability)
            .send()
            .await
            .expect("stale plan source");
        assert_eq!(stale.status(), StatusCode::GONE);

        let replay: serde_json::Value = client
            .post(format!("{base_url}/api/plan-runs/{run_id}/replay"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("replay")
            .error_for_status()
            .expect("replay status")
            .json()
            .await
            .expect("replay JSON");
        assert_eq!(
            replay["report"]["fixture_digest"],
            run["report"]["fixture_digest"]
        );
        assert_eq!(
            replay["report"]["truth_digest"],
            run["report"]["truth_digest"]
        );
        assert_eq!(replay["manifest"]["replayed_from"], run_id);
        assert_eq!(replay["manifest"]["execution_mode"], "external_integration");

        let storage: serde_json::Value = client
            .get(format!("{base_url}/api/plans/storage"))
            .send()
            .await
            .expect("storage diagnostics")
            .error_for_status()
            .expect("storage status")
            .json()
            .await
            .expect("storage JSON");
        assert_eq!(storage["plan_count"], 2);
        assert!(storage["run_count"].as_u64().unwrap_or_default() >= 3);

        let archived: serde_json::Value = client
            .post(format!("{base_url}/api/plans/{}/archive", plan.plan_id))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("archive plan")
            .error_for_status()
            .expect("archive status")
            .json()
            .await
            .expect("archive JSON");
        assert_eq!(archived["plan"]["status"], "archived");
        assert_eq!(archived["plan"]["revision"], 2);
        let archived_run = client
            .post(format!("{base_url}/api/plans/{}/runs", plan.plan_id))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("archived plan run rejection");
        assert_eq!(archived_run.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            archived_run
                .text()
                .await
                .expect("archived run error body")
                .contains("PLAN_ARCHIVED")
        );

        client
            .delete(format!("{base_url}/api/plans/{}", plan.plan_id))
            .send()
            .await
            .expect("delete plan")
            .error_for_status()
            .expect("delete status");
        client
            .delete(format!("{base_url}/api/plans/{imported_id}"))
            .send()
            .await
            .expect("delete imported plan")
            .error_for_status()
            .expect("delete imported status");
        let retained_manifest = client
            .get(format!("{base_url}/api/plan-runs/{run_id}"))
            .send()
            .await
            .expect("retained run manifest");
        assert_eq!(retained_manifest.status(), StatusCode::OK);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn plan_source_fault_occurrences_and_compression_are_runtime_bounded() {
        let server =
            LocalServer::spawn_with_plan_root(repository(), None, plan_test_root("plan-faults"))
                .await
                .expect("server");
        let client = Client::new();
        let base_url = server.base_url();
        let mut plan = ExperimentPlan::example();
        plan.plan_id = format!("plan-faults-{}", Uuid::new_v4().simple());
        plan.sources[0].faults.push(PlanFault {
            kind: PlanFaultKind::Status503,
            trigger_page: 1,
            occurrences: 1,
        });
        let mut gzip_source = plan.sources[0].clone();
        gzip_source.id = "gzip".to_owned();
        gzip_source.faults = vec![PlanFault {
            kind: PlanFaultKind::Gzip,
            trigger_page: 1,
            occurrences: 1,
        }];
        plan.sources.push(gzip_source);
        client
            .post(format!("{base_url}/api/plans"))
            .json(&plan)
            .send()
            .await
            .expect("create fault plan")
            .error_for_status()
            .expect("fault plan status");
        let run: serde_json::Value = client
            .post(format!("{base_url}/api/plans/{}/runs", plan.plan_id))
            .json(&json!({}))
            .send()
            .await
            .expect("run fault plan")
            .error_for_status()
            .expect("fault run status")
            .json()
            .await
            .expect("fault run JSON");
        let run_id = run["run_id"].as_str().expect("fault run ID");
        let capability = run["source_access"]["source_capability"]
            .as_str()
            .expect("fault capability");
        let source_url = run["source_access"]["source_url_template"]
            .as_str()
            .expect("fault source URL")
            .replace("{source_id}", "certificate");
        let first = client
            .get(&source_url)
            .header("x-lab-run-id", run_id)
            .header("x-lab-source-capability", capability)
            .send()
            .await
            .expect("first controlled fault request");
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
        let recovered: serde_json::Value = client
            .get(&source_url)
            .header("x-lab-run-id", run_id)
            .header("x-lab-source-capability", capability)
            .send()
            .await
            .expect("retry after one-shot fault")
            .error_for_status()
            .expect("recovered source status")
            .json()
            .await
            .expect("recovered source JSON");
        assert_eq!(recovered["schema_version"], "0.2");

        let gzip_url = run["source_access"]["source_url_template"]
            .as_str()
            .expect("gzip source URL")
            .replace("{source_id}", "gzip");
        let gzip_target = Url::parse(&gzip_url).expect("gzip URL");
        let gzip_port = gzip_target
            .port_or_known_default()
            .expect("gzip source port");
        let mut gzip_stream = TcpStream::connect((Ipv4Addr::LOCALHOST, gzip_port))
            .await
            .expect("connect gzip plan source");
        let gzip_request = format!(
            "GET {} HTTP/1.1\r\nHost: 127.0.0.1:{gzip_port}\r\nx-lab-run-id: {run_id}\r\nx-lab-source-capability: {capability}\r\nConnection: close\r\n\r\n",
            gzip_target.path()
        );
        gzip_stream
            .write_all(gzip_request.as_bytes())
            .await
            .expect("request compressed source");
        let mut gzip_response = Vec::new();
        gzip_stream
            .read_to_end(&mut gzip_response)
            .await
            .expect("read compressed source");
        let header_end = gzip_response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("compressed response headers")
            + 4;
        let gzip_headers =
            String::from_utf8_lossy(&gzip_response[..header_end]).to_ascii_lowercase();
        assert!(gzip_headers.starts_with("http/1.1 200"));
        assert!(gzip_headers.contains("content-encoding: gzip"));
        assert!(gzip_headers.contains("cache-control: no-store"));
        assert!(gzip_response[header_end..].starts_with(&[0x1f, 0x8b]));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn plan_sources_use_the_loopback_http_proxy_and_connect_contracts() {
        let server =
            LocalServer::spawn_with_plan_root(repository(), None, plan_test_root("plan-proxy"))
                .await
                .expect("server");
        let client = Client::new();
        let base_url = server.base_url();
        let proxy_port = Url::parse(&server.proxy_url())
            .expect("proxy URL")
            .port_or_known_default()
            .expect("proxy port");

        let mut http_plan = ExperimentPlan::example();
        http_plan.plan_id = format!("plan-http-proxy-{}", Uuid::new_v4().simple());
        http_plan.network_path.mode = PlanNetworkMode::HttpProxy;
        http_plan.network_path.proxy_authentication = lab_core::ProxyAuthentication::Succeeds;
        client
            .post(format!("{base_url}/api/plans"))
            .json(&http_plan)
            .send()
            .await
            .expect("create HTTP proxy plan")
            .error_for_status()
            .expect("HTTP proxy plan status");
        let run: serde_json::Value = client
            .post(format!("{base_url}/api/plans/{}/runs", http_plan.plan_id))
            .json(&json!({}))
            .send()
            .await
            .expect("run HTTP proxy plan")
            .error_for_status()
            .expect("HTTP proxy run status")
            .json()
            .await
            .expect("HTTP proxy run JSON");
        let run_id = run["run_id"].as_str().expect("run ID");
        let access = &run["source_access"];
        let source_url = access["source_url_template"]
            .as_str()
            .expect("source URL")
            .replace("{source_id}", "certificate");
        let capability = access["source_capability"]
            .as_str()
            .expect("source capability");
        let direct = client
            .get(&source_url)
            .header("x-lab-run-id", run_id)
            .header("x-lab-source-capability", capability)
            .send()
            .await
            .expect("direct source request");
        assert_eq!(direct.status(), StatusCode::FORBIDDEN);

        let mut proxy = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .expect("connect local proxy");
        let request = format!(
            "GET {source_url} HTTP/1.1\r\nHost: 127.0.0.1\r\nx-lab-run-id: {run_id}\r\nx-lab-source-capability: {capability}\r\nProxy-Authorization: Lab {capability}\r\nx-lab-proxy-capability: {capability}\r\nConnection: close\r\n\r\n"
        );
        proxy
            .write_all(request.as_bytes())
            .await
            .expect("write proxied source request");
        let mut forwarded = Vec::new();
        proxy
            .read_to_end(&mut forwarded)
            .await
            .expect("read proxied source response");
        assert!(String::from_utf8_lossy(&forwarded).starts_with("HTTP/1.1 200"));

        let mut connect_plan = ExperimentPlan::example();
        connect_plan.plan_id = format!("plan-connect-{}", Uuid::new_v4().simple());
        connect_plan.network_path.mode = PlanNetworkMode::Connect;
        client
            .post(format!("{base_url}/api/plans"))
            .json(&connect_plan)
            .send()
            .await
            .expect("create CONNECT plan")
            .error_for_status()
            .expect("CONNECT plan status");
        let connect_run: serde_json::Value = client
            .post(format!(
                "{base_url}/api/plans/{}/runs",
                connect_plan.plan_id
            ))
            .json(&json!({}))
            .send()
            .await
            .expect("run CONNECT plan")
            .error_for_status()
            .expect("CONNECT run status")
            .json()
            .await
            .expect("CONNECT run JSON");
        let connect_id = connect_run["run_id"].as_str().expect("CONNECT run ID");
        let connect_capability = connect_run["source_access"]["source_capability"]
            .as_str()
            .expect("CONNECT capability");
        let source_port = Url::parse(&base_url)
            .expect("source URL")
            .port_or_known_default()
            .expect("source port");
        let mut tunnel = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .expect("connect local proxy for CONNECT");
        let connect_request = format!(
            "CONNECT 127.0.0.1:{source_port} HTTP/1.1\r\nHost: 127.0.0.1:{source_port}\r\nx-lab-run-id: {connect_id}\r\nx-lab-source-capability: {connect_capability}\r\nConnection: close\r\n\r\n"
        );
        tunnel
            .write_all(connect_request.as_bytes())
            .await
            .expect("write CONNECT request");
        let mut established = [0_u8; 256];
        let established_count = tunnel
            .read(&mut established)
            .await
            .expect("read CONNECT establishment");
        let connected = String::from_utf8_lossy(&established[..established_count]);
        assert!(connected.starts_with("HTTP/1.1 200"));
        let tunneled_source_request = format!(
            "GET /api/plan-runs/{connect_id}/sources/certificate HTTP/1.1\r\nHost: 127.0.0.1:{source_port}\r\nx-lab-run-id: {connect_id}\r\nx-lab-source-capability: {connect_capability}\r\nConnection: close\r\n\r\n"
        );
        tunnel
            .write_all(tunneled_source_request.as_bytes())
            .await
            .expect("write controlled request through CONNECT");
        tunnel.shutdown().await.expect("finish CONNECT request");
        let mut connected_source = Vec::new();
        tunnel
            .read_to_end(&mut connected_source)
            .await
            .expect("read CONNECT source response");
        let connected_source = String::from_utf8_lossy(&connected_source);
        assert!(connected_source.starts_with("HTTP/1.1 200"));
        assert!(connected_source.contains("\"schema_version\":\"0.2\""));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn console_workflow_is_loopback_only_bilingual_and_redacted() {
        let repository = repository();
        assert!(
            repository
                .all()
                .iter()
                .all(|loaded| lab_console::has_zh_translation(&loaded.scenario.id))
        );
        let server = LocalServer::spawn(repository, None).await.expect("server");
        let client = Client::new();
        let base_url = server.base_url();

        let console = client
            .get(format!("{base_url}/console/"))
            .send()
            .await
            .expect("console page");
        assert_eq!(console.status(), StatusCode::OK);
        assert!(
            console
                .headers()
                .get("content-security-policy")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("connect-src 'self'"))
        );
        assert!(
            console
                .text()
                .await
                .expect("console HTML")
                .contains("/console/app.js")
        );
        let console_html = client
            .get(format!("{base_url}/console/"))
            .send()
            .await
            .expect("console page second read")
            .text()
            .await
            .expect("console HTML second read");
        assert!(console_html.contains("/console/plans.js"));
        let favicon = client
            .get(format!("{base_url}/favicon.ico"))
            .send()
            .await
            .expect("favicon response");
        assert_eq!(favicon.status(), StatusCode::NO_CONTENT);
        let script = client
            .get(format!("{base_url}/console/app.js"))
            .send()
            .await
            .expect("console script")
            .text()
            .await
            .expect("script text");
        assert!(!script.contains("https://"));
        assert!(!script.contains("fetch(\"http"));
        let plans_script = client
            .get(format!("{base_url}/console/plans.js"))
            .send()
            .await
            .expect("plan console script")
            .text()
            .await
            .expect("plan console script text");
        assert!(!plans_script.contains("https://"));
        assert!(!plans_script.contains("http://"));

        let overview: serde_json::Value = client
            .get(format!("{base_url}/api/console/overview"))
            .send()
            .await
            .expect("overview")
            .json()
            .await
            .expect("overview JSON");
        assert_eq!(overview["scenario_count"], 114);
        assert_eq!(overview["loopback_only"], true);
        assert_eq!(overview["external_network_allowed"], false);
        let scenarios: serde_json::Value = client
            .get(format!("{base_url}/api/console/scenarios"))
            .send()
            .await
            .expect("scenario catalog")
            .json()
            .await
            .expect("catalog JSON");
        assert_eq!(scenarios["scenarios"].as_array().map(Vec::len), Some(114));
        assert!(scenarios["scenarios"].as_array().is_some_and(|items| {
            items.iter().all(|item| {
                item["display"]["en"]["name"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
                    && item["display"]["en"]["description"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty())
                    && item["display"]["zh"]["name"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty())
                    && item["display"]["zh"]["description"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty())
            })
        }));

        let created: serde_json::Value = client
            .post(format!("{base_url}/api/runs"))
            .json(&serde_json::json!({"scenario_id":"001-basic-certificate","seed":17}))
            .send()
            .await
            .expect("create run")
            .json()
            .await
            .expect("created run JSON");
        let run_id = created["run_id"].as_str().expect("run ID").to_owned();
        let token = created["run_access_token"]
            .as_str()
            .expect("capability")
            .to_owned();
        let manifest: serde_json::Value = client
            .get(format!("{base_url}/api/runs/{run_id}/manifest"))
            .header("x-lab-run-access-token", &token)
            .send()
            .await
            .expect("manifest")
            .json()
            .await
            .expect("manifest JSON");
        assert!(manifest.get("truth").is_none());

        let reference = client
            .post(format!("{base_url}/api/console/runs/{run_id}/reference"))
            .header("x-lab-run-access-token", &token)
            .send()
            .await
            .expect("reference run");
        assert_eq!(reference.status(), StatusCode::OK);
        let report: serde_json::Value = client
            .get(format!("{base_url}/api/console/runs/{run_id}/report"))
            .send()
            .await
            .expect("console report")
            .json()
            .await
            .expect("console report JSON");
        let report_text = serde_json::to_string(&report).expect("report text");
        assert!(!report_text.contains(&token));
        assert!(!report_text.contains("\"truth\""));

        let reset: serde_json::Value = client
            .post(format!("{base_url}/api/runs/{run_id}/reset"))
            .header("x-lab-run-access-token", &token)
            .send()
            .await
            .expect("reset")
            .json()
            .await
            .expect("reset JSON");
        let stale = client
            .get(format!("{base_url}/api/runs/{run_id}/manifest"))
            .header("x-lab-run-access-token", &token)
            .send()
            .await
            .expect("stale capability probe");
        assert_eq!(stale.status(), StatusCode::FORBIDDEN);
        let audit: serde_json::Value = client
            .get(format!("{base_url}/api/console/runs/{run_id}/audit"))
            .send()
            .await
            .expect("console audit")
            .json()
            .await
            .expect("audit JSON");
        assert!(audit["entries"].as_array().is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry["operation"] == "stale_probe")
        }));

        client
            .delete(format!("{base_url}/api/runs/{run_id}"))
            .header(
                "x-lab-run-access-token",
                reset["run_access_token"].as_str().expect("rotated token"),
            )
            .send()
            .await
            .expect("delete run")
            .error_for_status()
            .expect("delete status");
        let runs: serde_json::Value = client
            .get(format!("{base_url}/api/console/runs"))
            .send()
            .await
            .expect("console runs")
            .json()
            .await
            .expect("runs JSON");
        assert!(runs["runs"].as_array().is_some_and(|runs| {
            runs.iter()
                .any(|run| run["run_id"] == run_id && run["status"] == "deleted")
        }));
        server.shutdown().await;
    }
}
