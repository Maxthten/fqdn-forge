use std::{env, fs, io::Read, path::PathBuf, process::ExitCode};

use anyhow::Context;
use brotli::Decompressor;
use chrono::Utc;
use flate2::read::{GzDecoder, ZlibDecoder};
use lab_core::{
    AuditEventType, Baseline, CollectorRun, EgressGuard, JudgeInput, Observation, ReferenceRunner,
    ReportStatus, ScenarioRepository, SoakPreset, SourceKind, SourceStatus, V14_SCHEMA_VERSION,
    baseline_from_reports, campaign_definitions, campaign_manifest, compare_baseline,
    coverage_check, coverage_markdown, coverage_report, enrich_report, judge_run,
    refresh_semantic_fingerprint, report_differences, report_json, run_soak, semantic_difference,
    semantic_fingerprint,
};
use lab_server::LocalServer;
use reqwest::{
    Client, Proxy,
    header::{HeaderMap, HeaderValue},
    redirect::Policy,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use url::Url;
use uuid::Uuid;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

async fn run() -> anyhow::Result<bool> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().map(String::as_str).unwrap_or("help");
    let repository = ScenarioRepository::load(scenarios_dir())?;
    match command {
        "validate" => {
            let issues = repository.validate();
            if issues.is_empty() {
                println!(
                    "validated {} scenarios; no network was started",
                    repository.all().len()
                );
                Ok(true)
            } else {
                for issue in issues {
                    eprintln!("{}: {}", issue.scenario_id, issue.message);
                }
                Ok(false)
            }
        }
        "list" => {
            for loaded in repository.all() {
                println!(
                    "{}\t{}\t{}",
                    loaded.scenario.id, loaded.scenario.name, loaded.scenario.description
                );
            }
            Ok(true)
        }
        "run" => run_command(&repository, &args).await,
        "repeat" => repeat_command(&repository, &args).await,
        "replay" => replay_command(&repository, &args).await,
        "conformance" => conformance_command(&repository, &args).await,
        "self-test" => self_test(&repository).await,
        "campaign" => campaign_command(&repository, &args).await,
        "coverage" => coverage_command(&repository, &args).await,
        "baseline" => baseline_command(&repository, &args).await,
        "soak" => soak_command(&repository, &args),
        "proxy-regression" => proxy_regression_command(&repository).await,
        "serve" => serve_command(repository, &args).await,
        _ => {
            print_help();
            Ok(true)
        }
    }
}

fn scenarios_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios")
}

async fn run_command(repository: &ScenarioRepository, args: &[String]) -> anyhow::Result<bool> {
    let all = args.iter().any(|arg| arg == "--all");
    let requested = flag_value(args, "--scenario");
    let group = flag_value(args, "--group");
    if !all && requested.is_none() && group.is_none() {
        anyhow::bail!(
            "use: lab-cli run --all | --scenario <id> | --group network|proxy|quota|transport|combination|lifecycle"
        );
    }
    let profile = flag_value(args, "--profile").unwrap_or_else(|| "default".to_owned());
    if profile != "default" && profile != "stress" {
        anyhow::bail!("--profile must be default or stress");
    }
    let report_dir = flag_value(args, "--report-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("artifacts/reports"));
    let seed = flag_value(args, "--seed")
        .map(|value| value.parse::<u64>())
        .transpose()?;
    fs::create_dir_all(&report_dir)?;
    let ids = if all {
        repository
            .all()
            .iter()
            .map(|loaded| loaded.scenario.id.clone())
            .collect()
    } else if let Some(group) = group {
        let ids = repository
            .all()
            .iter()
            .filter(|loaded| scenario_in_group(&loaded.scenario.id, &group))
            .map(|loaded| loaded.scenario.id.clone())
            .collect::<Vec<_>>();
        if ids.is_empty() {
            anyhow::bail!(
                "--group must be network, proxy, quota, transport, combination or lifecycle"
            );
        }
        ids
    } else {
        vec![requested.expect("checked above")]
    };
    let mut passed = true;
    for id in ids {
        let mut report = run_one(repository, &id, &profile, seed).await?;
        let report_path = report_dir.join(format!(
            "{}-{}-seed-{}.json",
            report.scenario_id, profile, report.seed
        ));
        report.replay_command = format!(
            "cargo run -p lab-cli -- replay --report {}",
            report_path.display()
        );
        fs::write(&report_path, report_json(&report)?)?;
        print_report(&report, &report_path);
        passed &= report.status == ReportStatus::Passed;
    }
    Ok(passed)
}

fn scenario_in_group(id: &str, group: &str) -> bool {
    let number = id
        .split('-')
        .next()
        .and_then(|value| value.parse::<u16>().ok());
    matches!(
        (group, number),
        ("network", Some(61..=66))
            | ("network", Some(91..=100))
            | ("proxy", Some(62..=66))
            | ("proxy", Some(94..=106))
            | ("transport", Some(79..=84))
            | ("transport", Some(92..=98))
            | ("quota", Some(85..=90))
            | ("quota", Some(91..=100))
            | ("combination", Some(91..=100))
            | ("lifecycle", Some(105..=106))
            | ("lifecycle", Some(111..=112))
    )
}

async fn run_one(
    repository: &ScenarioRepository,
    id: &str,
    profile: &str,
    seed_override: Option<u64>,
) -> anyhow::Result<lab_core::RunReport> {
    let mut loaded = repository
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("unknown scenario {id}"))?
        .clone();
    if let Some(seed) = seed_override {
        loaded.scenario.seed = seed;
    }
    let server = LocalServer::spawn(repository.clone(), None)
        .await
        .map_err(anyhow::Error::msg)?;
    let started = Utc::now();
    let guard = EgressGuard::default();
    let runner = ReferenceRunner::new(guard.clone())?;
    let control_client = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .build()?;
    let created_run = create_run(
        &control_client,
        &server.base_url(),
        id,
        Some(loaded.scenario.seed),
    )
    .await?;
    let proxy_url = server.proxy_url();
    let collector = runner
        .run_with_proxy(
            &server.base_url(),
            Some(&proxy_url),
            &loaded.scenario,
            created_run.run_id,
            profile,
        )
        .await?;
    let finished = Utc::now();
    let audit = fetch_audit(&control_client, &server.base_url(), &created_run).await?;
    let rejected = guard.rejected_urls();
    let target = target_domain(&loaded.scenario);
    let mut report = judge_run(JudgeInput {
        run_id: created_run.run_id,
        scenario_id: &loaded.scenario.id,
        seed: loaded.scenario.seed,
        target_domain: &target,
        started_at: started,
        finished_at: finished,
        collector_run: &collector,
        truth: &loaded.truth,
        assertions: &loaded.assertions,
        audit: &audit,
        rejected_egress_urls: &rejected,
    });
    enrich_report(&mut report, &loaded)?;
    // This is the built-in reference path, not an external HTTP client.  The
    // public HTTP API deliberately rejects report writes; external tools can
    // only submit findings to the server-side judge.
    server.set_report(report.clone());
    server.shutdown().await;
    Ok(report)
}

async fn repeat_command(repository: &ScenarioRepository, args: &[String]) -> anyhow::Result<bool> {
    let count = flag_value(args, "--count")
        .ok_or_else(|| anyhow::anyhow!("use: lab-cli repeat --count <positive number>"))?
        .parse::<usize>()?;
    if count == 0 {
        anyhow::bail!("--count must be greater than zero");
    }
    let profile = flag_value(args, "--profile").unwrap_or_else(|| "default".to_owned());
    let requested = flag_value(args, "--scenario");
    let ids = requested.map_or_else(
        || {
            repository
                .all()
                .iter()
                .map(|loaded| loaded.scenario.id.clone())
                .collect::<Vec<_>>()
        },
        |id| vec![id],
    );
    let mut total = 0_usize;
    let mut first_failure = None;
    for round in 1..=count {
        for id in &ids {
            total += 1;
            let report = run_one(repository, id, &profile, None).await?;
            if report.status != ReportStatus::Passed {
                first_failure = Some((round, report));
                break;
            }
        }
        if first_failure.is_some() {
            break;
        }
    }
    println!(
        "repeat rounds: {count}; runs: {total}; failures: {}",
        usize::from(first_failure.is_some())
    );
    if let Some((round, report)) = &first_failure {
        println!("first failure round: {round}");
        println!("first failure scenario: {}", report.scenario_id);
        println!("seed: {}; run_id: {}", report.seed, report.run_id);
        if let Some(request) = report.requests.first() {
            println!("first failure request: {} {}", request.method, request.path);
        }
        println!("replay: {}", report.replay_command);
    }
    Ok(first_failure.is_none())
}

async fn replay_command(repository: &ScenarioRepository, args: &[String]) -> anyhow::Result<bool> {
    let path = flag_value(args, "--report")
        .ok_or_else(|| anyhow::anyhow!("use: lab-cli replay --report <report-path>"))?;
    let prior: lab_core::RunReport = serde_json::from_slice(&fs::read(&path)?)?;
    let strict = args.iter().any(|arg| arg == "--strict");
    if strict
        && !matches!(
            prior.schema_version.as_str(),
            "1.2.1" | "1.3.0" | V14_SCHEMA_VERSION
        )
    {
        eprintln!("strict replay requires a compatible 1.2.1, 1.3.0 or 1.4.0 report schema");
        return Ok(false);
    }
    if repository.get(&prior.scenario_id).is_none() {
        eprintln!(
            "strict replay scenario is no longer available: {}",
            prior.scenario_id
        );
        return Ok(false);
    }
    let mut replay = run_one(repository, &prior.scenario_id, "default", Some(prior.seed)).await?;
    let legacy_provenance = prior.provenance.scenario_revision_digest.is_empty()
        || prior.provenance.fixture_digest.is_empty();
    let provenance_status = if !strict {
        "not_checked".to_owned()
    } else if legacy_provenance {
        "legacy_provenance_unavailable".to_owned()
    } else if prior.provenance.scenario_revision_digest
        != replay.provenance.scenario_revision_digest
    {
        "scenario_revision_changed".to_owned()
    } else if prior.provenance.fixture_digest != replay.provenance.fixture_digest
        || prior.provenance.campaign_id != replay.provenance.campaign_id
        || prior.provenance.campaign_seed != replay.provenance.campaign_seed
    {
        "fixture_or_campaign_changed".to_owned()
    } else {
        "matched".to_owned()
    };
    let diff_summary = if strict {
        report_differences(&prior, &replay, 50)
    } else {
        Default::default()
    };
    let difference = diff_summary
        .differences
        .first()
        .map(|difference| difference.path.clone())
        .or_else(|| {
            strict
                .then(|| semantic_difference(&prior, &replay))
                .flatten()
        });
    let matched = if strict {
        provenance_status == "matched"
            && prior.semantic_fingerprint == semantic_fingerprint(&prior)
            && prior.semantic_fingerprint == replay.semantic_fingerprint
            && diff_summary.differences.is_empty()
            && diff_summary.truncated == 0
    } else {
        replay.status == prior.status
            && replay.scenario_id == prior.scenario_id
            && replay.seed == prior.seed
            && replay.target_domain == prior.target_domain
    };
    let report_path = PathBuf::from(&path);
    let parent = report_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = report_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("report");
    let comparison_path = parent.join(format!(
        "{stem}-{}-replay-{}.json",
        if strict { "strict" } else { "standard" },
        Uuid::new_v4()
    ));
    replay.replay.strict = strict;
    replay.replay.matched = Some(matched);
    replay.replay.first_difference = difference.clone();
    replay.replay.provenance_status = Some(provenance_status.clone());
    replay.replay.differences = diff_summary.differences;
    replay.replay.difference_counts = diff_summary.counts;
    replay.replay.truncated_difference_count = diff_summary.truncated;
    replay.replay.comparison_report = Some(comparison_path.display().to_string());
    refresh_semantic_fingerprint(&mut replay);
    fs::write(&comparison_path, report_json(&replay)?)?;
    println!("replay scenario: {}", replay.scenario_id);
    println!(
        "replay result: {}",
        if matched { "matched" } else { "mismatch" }
    );
    println!("seed: {}; new run_id: {}", replay.seed, replay.run_id);
    if let Some(difference) = difference {
        println!("first semantic difference: {difference}");
    }
    if strict {
        println!("provenance: {provenance_status}");
        println!(
            "differences: {} (truncated {})",
            replay.replay.differences.len(),
            replay.replay.truncated_difference_count
        );
    }
    println!("comparison report: {}", comparison_path.display());
    Ok(matched && replay.status == ReportStatus::Passed)
}

async fn conformance_command(
    repository: &ScenarioRepository,
    args: &[String],
) -> anyhow::Result<bool> {
    let scenario =
        flag_value(args, "--scenario").unwrap_or_else(|| "067-external-submission-pass".to_owned());
    let server = LocalServer::spawn(repository.clone(), None)
        .await
        .map_err(anyhow::Error::msg)?;
    let result = external_http_conformance(&server.base_url(), &scenario).await;
    server.shutdown().await;
    let report = result?;
    let passed = report.get("status").and_then(serde_json::Value::as_str) == Some("passed");
    println!(
        "external HTTP conformance {scenario}: {}",
        if passed { "passed" } else { "failed" }
    );
    if !passed {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(passed)
}

/// An intentionally black-box client: after receiving a base URL it uses only
/// public HTTP responses. It does not receive LabState, scenario files, truth
/// or assertions.
async fn external_http_conformance(
    base_url: &str,
    scenario_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let client = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .build()?;
    let create: serde_json::Value = client
        .post(format!("{base_url}/api/runs"))
        .json(&serde_json::json!({"scenario_id":scenario_id}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let run_id = create
        .get("run_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("public create-run response is missing run_id"))?;
    let run_access_header = create
        .get("run_access_header")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!("public create-run response is missing run_access_header")
        })?;
    let run_access_token = create
        .get("run_access_token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("public create-run response is missing run_access_token"))?;
    let manifest: serde_json::Value = client
        .get(format!("{base_url}/api/runs/{run_id}/manifest"))
        .header(run_access_header, run_access_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if manifest.get("truth").is_some() {
        anyhow::bail!("manifest leaked truth");
    }
    let target_domain = manifest
        .get("target_domain")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("manifest is missing target_domain"))?;
    let sources = manifest
        .get("sources")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("manifest is missing sources"))?;
    let network = manifest
        .get("network_profile")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("manifest is missing network_profile"))?;
    let max_decoded_bytes = manifest
        .get("transport_profile")
        .and_then(|profile| profile.get("client_visible_decoded_limit"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|limit| usize::try_from(limit).ok())
        .ok_or_else(|| anyhow::anyhow!("manifest transport_profile is missing decoded limit"))?;
    let network_mode = network
        .get("mode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("direct");
    let proxy_values = network
        .get("proxy_authentication")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let source_client = if network_mode == "http_proxy" {
        let proxy_url = network
            .get("proxy_url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("http_proxy manifest is missing proxy_url"))?;
        let parsed = Url::parse(proxy_url)?;
        if parsed.scheme() != "http" || parsed.host_str() != Some("127.0.0.1") {
            anyhow::bail!("manifest proxy_url is not numeric IPv4 loopback");
        }
        Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .proxy(Proxy::http(proxy_url)?)
            .build()?
    } else {
        Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .build()?
    };
    let mut findings = Vec::new();
    let mut source_statuses = serde_json::Map::new();
    if network_mode == "connect_proxy" {
        let status = connect_conformance_probe(network, run_id).await?;
        for source in sources {
            let source_id = source
                .get("source_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("manifest source is missing source_id"))?;
            source_statuses.insert(
                source_id.to_owned(),
                serde_json::Value::String(status.to_owned()),
            );
        }
    } else {
        for source in sources {
            let source_id = source
                .get("source_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("manifest source is missing source_id"))?;
            let source_kind = source
                .get("source_kind")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("manifest source is missing source_kind"))?;
            let source_base = source
                .get("base_url")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("manifest source is missing base_url"))?;
            let path = source
                .get("path_template")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("manifest source is missing path_template"))?;
            let query = source
                .get("required_query")
                .and_then(serde_json::Value::as_object)
                .cloned()
                .unwrap_or_default();
            let authentication = source
                .get("authentication")
                .and_then(serde_json::Value::as_object)
                .cloned()
                .unwrap_or_default();
            let url = format!("{source_base}{path}");
            let allow_retry = source
                .get("allow_retry")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let mut virtual_wait_ms = 0_u64;
            let mut attempts = 0_usize;
            let response = loop {
                attempts = attempts.saturating_add(1);
                let mut request = match source.get("method").and_then(serde_json::Value::as_str) {
                    Some("POST") => source_client.post(&url),
                    Some("PUT") => source_client.put(&url),
                    Some("DELETE") => source_client.delete(&url),
                    _ => source_client.get(&url),
                }
                .header("x-lab-run-id", run_id)
                .header("x-lab-data-profile", "default")
                .header("x-lab-client-virtual-wait-ms", virtual_wait_ms.to_string())
                .query(&query);
                for (name, value) in &authentication {
                    let value = value.as_str().ok_or_else(|| {
                        anyhow::anyhow!("manifest source authentication value is not a string")
                    })?;
                    request = request.header(name, value);
                }
                if network_mode == "http_proxy" {
                    if let Some(value) = proxy_values
                        .get("proxy_authorization")
                        .and_then(serde_json::Value::as_str)
                    {
                        request = request.header("proxy-authorization", value);
                    }
                    if let Some(value) = proxy_values
                        .get("proxy_capability")
                        .and_then(serde_json::Value::as_str)
                    {
                        request = request.header("x-lab-proxy-capability", value);
                    }
                }
                let response = match request.send().await {
                    Ok(response) => response,
                    Err(_) => {
                        source_statuses.insert(source_id.to_owned(), serde_json::json!("failed"));
                        break None;
                    }
                };
                if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                    && allow_retry
                    && attempts < 4
                {
                    let waited = response
                        .headers()
                        .get("x-lab-virtual-wait-ms")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(0);
                    virtual_wait_ms = virtual_wait_ms.saturating_add(waited.max(1));
                    continue;
                }
                break Some(response);
            };
            let Some(response) = response else {
                continue;
            };
            let evidence_url = response.url().to_string();
            if !response.status().is_success() {
                let status = match response.status() {
                    reqwest::StatusCode::TOO_MANY_REQUESTS => "rate_limited",
                    reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                        "auth_failed"
                    }
                    reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::GATEWAY_TIMEOUT => {
                        "timed_out"
                    }
                    _ => "failed",
                };
                source_statuses.insert(source_id.to_owned(), serde_json::json!(status));
                continue;
            }
            source_statuses.insert(source_id.to_owned(), serde_json::json!("succeeded"));
            let response_headers = response.headers().clone();
            let wire = match response.bytes().await {
                Ok(wire) => wire,
                Err(_) => {
                    source_statuses.insert(source_id.to_owned(), serde_json::json!("failed"));
                    continue;
                }
            };
            let decoded = match decode_conformance_body(&response_headers, &wire, max_decoded_bytes)
            {
                Ok(decoded) => decoded,
                Err(_) => {
                    source_statuses.insert(source_id.to_owned(), serde_json::json!("failed"));
                    continue;
                }
            };
            let payload: serde_json::Value = match serde_json::from_slice(&decoded) {
                Ok(payload) => payload,
                Err(_) => {
                    source_statuses.insert(source_id.to_owned(), serde_json::json!("failed"));
                    continue;
                }
            };
            for item in payload
                .get("items")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(fqdn) = item.get("host").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                findings.push(serde_json::json!({
                    "fqdn":fqdn,
                    "evidence":[{
                        "source_id":source_id,
                        "source_kind":source_kind.clone(),
                        "record_id":item.get("id").and_then(serde_json::Value::as_str),
                        "url":evidence_url.clone(),
                        "observed_at":item.get("observed_at").and_then(serde_json::Value::as_str),
                        "tags":item.get("tags").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "confidence":item.get("confidence").and_then(serde_json::Value::as_f64),
                    }]
                }));
            }
        }
    }
    let submission = serde_json::json!({
        "schema_version":"1.4.0",
        "collector":{"name":"fqdn-forge-http-conformance","version":"1.4.0"},
        "target_domain":target_domain,
        "source_statuses":source_statuses,
        "findings":findings,
    });
    client
        .post(format!("{base_url}/api/runs/{run_id}/submission"))
        .header(run_access_header, run_access_token)
        .json(&submission)
        .send()
        .await?
        .error_for_status()?;
    let report: serde_json::Value = client
        .get(format!("{base_url}/api/runs/{run_id}/report"))
        .header(run_access_header, run_access_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let report = report
        .get("report")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("public report response is missing report"))?;
    if report.get("truth").is_some() {
        anyhow::bail!("public report leaked truth");
    }
    Ok(report)
}

fn decode_conformance_body(
    headers: &HeaderMap,
    wire: &[u8],
    max_decoded_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    let encoding = headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("identity");
    if encoding.eq_ignore_ascii_case("identity") || encoding.eq_ignore_ascii_case("utf-8") {
        return Ok(wire.to_vec());
    }
    if encoding.contains(',') {
        anyhow::bail!("conformance rejects conflicting Content-Encoding headers");
    }
    let mut decoded = Vec::new();
    if encoding.eq_ignore_ascii_case("gzip") {
        GzDecoder::new(wire).read_to_end(&mut decoded)?;
    } else if encoding.eq_ignore_ascii_case("deflate") {
        ZlibDecoder::new(wire).read_to_end(&mut decoded)?;
    } else if encoding.eq_ignore_ascii_case("br") {
        Decompressor::new(wire, 8 * 1024).read_to_end(&mut decoded)?;
    } else {
        anyhow::bail!("conformance rejects unsupported Content-Encoding");
    }
    if decoded.len() > max_decoded_bytes {
        anyhow::bail!("conformance decoded body exceeds local safety limit");
    }
    Ok(decoded)
}

async fn connect_conformance_probe(
    network: &serde_json::Map<String, serde_json::Value>,
    run_id: &str,
) -> anyhow::Result<&'static str> {
    let proxy_url = network
        .get("proxy_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("connect_proxy manifest is missing proxy_url"))?;
    let proxy = Url::parse(proxy_url)?;
    if proxy.scheme() != "http" || proxy.host_str() != Some("127.0.0.1") {
        anyhow::bail!("connect proxy is not numeric IPv4 loopback");
    }
    let target = network
        .get("connect_fixture_target")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("connect_proxy manifest is missing fixture target"))?;
    let port = proxy
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("connect proxy is missing a port"))?;
    let values = network
        .get("proxy_authentication")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("connect_proxy manifest is missing authentication"))?;
    let authorization = values
        .get("proxy_authorization")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("connect_proxy authentication is missing authorization"))?;
    let capability = values
        .get("proxy_capability")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("connect_proxy authentication is missing capability"))?;
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nx-lab-run-id: {run_id}\r\nProxy-Authorization: {authorization}\r\nx-lab-proxy-capability: {capability}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = [0_u8; 512];
    let count = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        stream.read(&mut response),
    )
    .await
    .map_err(|_| anyhow::anyhow!("local CONNECT probe timed out"))??;
    let response = String::from_utf8_lossy(&response[..count]);
    Ok(if response.starts_with("HTTP/1.1 200") {
        "succeeded"
    } else if response.starts_with("HTTP/1.1 407") || response.starts_with("HTTP/1.1 403") {
        "auth_failed"
    } else if response.starts_with("HTTP/1.1 504") {
        "timed_out"
    } else {
        "failed"
    })
}

async fn campaign_command(
    repository: &ScenarioRepository,
    args: &[String],
) -> anyhow::Result<bool> {
    match args.get(1).map(String::as_str) {
        Some("list") => {
            println!("{}", serde_json::to_string_pretty(&campaign_definitions())?);
            Ok(true)
        }
        Some("run") => {
            let campaign = flag_value(args, "--campaign").ok_or_else(|| {
                anyhow::anyhow!("use: lab-cli campaign run --campaign <id> --seed <number>")
            })?;
            let seed = flag_value(args, "--seed")
                .ok_or_else(|| anyhow::anyhow!("campaign run requires --seed"))?
                .parse::<u64>()?;
            let output = flag_value(args, "--output")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(format!("artifacts/campaigns/{campaign}-seed-{seed}.json"))
                });
            let report = execute_campaign(repository, &campaign, seed).await?;
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, serde_json::to_string_pretty(&report)?)?;
            println!(
                "campaign: {}; seed: {}; result: {:?}",
                campaign, seed, report.report.status
            );
            println!("campaign report: {}", output.display());
            Ok(report.report.status == ReportStatus::Passed)
        }
        Some("replay") => {
            let path = flag_value(args, "--report").ok_or_else(|| {
                anyhow::anyhow!("use: lab-cli campaign replay --report <campaign-report>")
            })?;
            let prior: lab_core::CampaignReport = serde_json::from_slice(&fs::read(path)?)?;
            let current =
                execute_campaign(repository, &prior.manifest.campaign_id, prior.manifest.seed)
                    .await?;
            let matched = prior.manifest.fixture_digest == current.manifest.fixture_digest
                && prior.manifest.truth_digest == current.manifest.truth_digest
                && prior.report.semantic_fingerprint == current.report.semantic_fingerprint;
            println!(
                "campaign replay: {}",
                if matched { "matched" } else { "mismatch" }
            );
            Ok(matched)
        }
        _ => {
            println!(
                "use: lab-cli campaign list | run --campaign <id> --seed <number> | replay --report <campaign-report>"
            );
            Ok(false)
        }
    }
}

async fn execute_campaign(
    repository: &ScenarioRepository,
    campaign: &str,
    seed: u64,
) -> anyhow::Result<lab_core::CampaignReport> {
    let manifest = campaign_manifest(repository, campaign, seed)?;
    let mut report = run_one(repository, &manifest.scenario_id, "default", Some(seed)).await?;
    report.provenance.campaign_id = Some(manifest.campaign_id.clone());
    report.provenance.campaign_seed = Some(seed);
    report.provenance.fixture_digest = manifest.fixture_digest.clone();
    report.replay_command = manifest.reproduction_command.clone();
    report.diagnostics.recommended_replay_command = manifest.reproduction_command.clone();
    refresh_semantic_fingerprint(&mut report);
    Ok(lab_core::CampaignReport {
        schema_version: V14_SCHEMA_VERSION.to_owned(),
        manifest,
        report,
    })
}

async fn coverage_command(
    repository: &ScenarioRepository,
    args: &[String],
) -> anyhow::Result<bool> {
    if args.iter().any(|arg| arg == "--check") {
        let issues = coverage_check(repository);
        if issues.is_empty() {
            println!(
                "coverage check passed for {} scenarios",
                repository.all().len()
            );
            return Ok(true);
        }
        for issue in issues {
            eprintln!("coverage: {issue}");
        }
        return Ok(false);
    }
    let format = flag_value(args, "--format").unwrap_or_else(|| "json".to_owned());
    let output = flag_value(args, "--output")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(if format == "markdown" {
                "artifacts/coverage.md"
            } else {
                "artifacts/coverage.json"
            })
        });
    let report = coverage_report(repository);
    let payload = match format.as_str() {
        "json" => serde_json::to_string_pretty(&report)?,
        "markdown" | "md" => coverage_markdown(&report),
        _ => anyhow::bail!("--format must be json or markdown"),
    };
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, payload)?;
    println!("coverage report: {}", output.display());
    Ok(true)
}

async fn baseline_command(
    repository: &ScenarioRepository,
    args: &[String],
) -> anyhow::Result<bool> {
    match args.get(1).map(String::as_str) {
        Some("generate") => {
            let profile = flag_value(args, "--profile").unwrap_or_else(|| "v1.4-core".to_owned());
            let output = flag_value(args, "--output")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(format!("artifacts/baselines/{profile}.json")));
            let reports = run_baseline_suite(repository).await?;
            let baseline = baseline_from_reports(&profile, &reports);
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, serde_json::to_string_pretty(&baseline)?)?;
            println!(
                "baseline: {} entries written to {}",
                baseline.entries.len(),
                output.display()
            );
            Ok(true)
        }
        Some("compare") => {
            let baseline_path = flag_value(args, "--baseline")
                .ok_or_else(|| anyhow::anyhow!("baseline compare requires --baseline <path>"))?;
            let report_path = flag_value(args, "--report").ok_or_else(|| {
                anyhow::anyhow!("baseline compare requires --report <report-path>")
            })?;
            let baseline: Baseline = serde_json::from_slice(&fs::read(baseline_path)?)?;
            let report: lab_core::RunReport = serde_json::from_slice(&fs::read(report_path)?)?;
            let comparison = compare_baseline(&baseline, &report);
            println!("{}", serde_json::to_string_pretty(&comparison)?);
            Ok(comparison.matched)
        }
        Some("check") => {
            let baseline_path = flag_value(args, "--baseline")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("artifacts/baselines/v1.4-core.json"));
            let baseline: Baseline =
                serde_json::from_slice(&fs::read(&baseline_path).with_context(|| {
                    format!("baseline check cannot read {}", baseline_path.display())
                })?)?;
            let mut passed = true;
            for report in run_baseline_suite(repository).await? {
                let comparison = compare_baseline(&baseline, &report);
                if !comparison.matched {
                    eprintln!(
                        "baseline mismatch for {}: {} differences",
                        report.scenario_id,
                        comparison.differences.len()
                    );
                    passed = false;
                }
            }
            Ok(passed)
        }
        _ => {
            println!(
                "use: lab-cli baseline generate --profile v1.4-core | compare --baseline <path> --report <path> | check [--baseline <path>]"
            );
            Ok(false)
        }
    }
}

async fn run_baseline_suite(
    repository: &ScenarioRepository,
) -> anyhow::Result<Vec<lab_core::RunReport>> {
    let ids = [
        "091-pagination-second-page-rate-limit",
        "094-proxy-auth-then-source-rate-limit",
        "097-source-503-then-chunked-success",
        "099-multi-source-global-quota-isolation",
        "101-proxy-target-canonicalization",
        "107-json-structural-mutation-campaign",
        "110-transport-framing-mutation-campaign",
        "111-mixed-lifecycle-soak",
        "114-coverage-and-baseline-integrity",
    ];
    let mut reports = Vec::with_capacity(ids.len());
    for id in ids {
        reports.push(run_one(repository, id, "default", None).await?);
    }
    Ok(reports)
}

fn soak_command(repository: &ScenarioRepository, args: &[String]) -> anyhow::Result<bool> {
    if args.get(1).map(String::as_str) != Some("run") {
        println!(
            "use: lab-cli soak run --preset smoke|standard|release [--seed <number>] [--output <path>]"
        );
        return Ok(false);
    }
    let preset = match flag_value(args, "--preset").as_deref().unwrap_or("smoke") {
        "smoke" => SoakPreset::Smoke,
        "standard" => SoakPreset::Standard,
        "release" => SoakPreset::Release,
        _ => anyhow::bail!("--preset must be smoke, standard or release"),
    };
    let seed = flag_value(args, "--seed")
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(11_100);
    let output = flag_value(args, "--output")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(
                format!("artifacts/soak/{:?}-seed-{seed}.json", preset).to_ascii_lowercase(),
            )
        });
    let report = run_soak(repository.clone(), preset, seed)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_string_pretty(&report)?)?;
    let passed = report.invariants.values().all(|value| *value) && report.last_failure.is_none();
    println!(
        "soak: {} operations, {} concurrency, {}",
        report.operations,
        report.concurrency,
        if passed { "passed" } else { "failed" }
    );
    println!("soak report: {}", output.display());
    Ok(passed)
}

async fn proxy_regression_command(repository: &ScenarioRepository) -> anyhow::Result<bool> {
    let mut passed = true;
    for id in [
        "101-proxy-target-canonicalization",
        "102-proxy-authority-header-ambiguity",
        "103-proxy-encoded-and-userinfo-targets",
        "104-proxy-framing-and-header-limits",
    ] {
        let report = run_one(repository, id, "default", None).await?;
        println!("proxy regression {id}: {:?}", report.status);
        passed &= report.status == ReportStatus::Passed;
    }
    let raw_passed = raw_proxy_adversarial_regression(repository).await?;
    println!(
        "proxy regression raw target/authority/header matrix: {}",
        if raw_passed { "passed" } else { "failed" }
    );
    Ok(passed && raw_passed)
}

async fn raw_proxy_adversarial_regression(repository: &ScenarioRepository) -> anyhow::Result<bool> {
    let server = LocalServer::spawn(repository.clone(), None)
        .await
        .map_err(anyhow::Error::msg)?;
    let result = async {
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .build()?;
        let run = create_run(
            &client,
            &server.base_url(),
            "062-proxy-http-forward-success",
            Some(62),
        )
        .await?;
        let manifest: serde_json::Value = client
            .get(format!("{}/api/runs/{}/manifest", server.base_url(), run.run_id))
            .header("x-lab-run-access-token", &run.access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let source = manifest
            .get("sources")
            .and_then(serde_json::Value::as_array)
            .and_then(|sources| sources.first())
            .ok_or_else(|| anyhow::anyhow!("proxy regression manifest has no source"))?;
        let source_base = source
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("proxy regression source has no base_url"))?;
        let source_path = source
            .get("path_template")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("proxy regression source has no path_template"))?;
        let mut target = Url::parse(&format!("{source_base}{source_path}"))?;
        if let Some(query) = source
            .get("required_query")
            .and_then(serde_json::Value::as_object)
        {
            target
                .query_pairs_mut()
                .extend_pairs(query.iter().filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.as_str(), value))
                }));
        }
        let target: String = target.into();
        let source = Url::parse(source_base)?;
        let source_port = source
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("proxy regression source has no port"))?;
        let authority = format!("127.0.0.1:{source_port}");
        let authentication = manifest
            .get("network_profile")
            .and_then(|profile| profile.get("proxy_authentication"))
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| anyhow::anyhow!("proxy regression manifest has no proxy authentication"))?;
        let authorization = authentication
            .get("proxy_authorization")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("proxy regression authorization is missing"))?;
        let capability = authentication
            .get("proxy_capability")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("proxy regression capability is missing"))?;
        let proxy_port = Url::parse(&server.proxy_url())?
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("local proxy has no port"))?;
        let base_headers = format!(
            "x-lab-run-id: {}\r\nProxy-Authorization: {authorization}\r\nx-lab-proxy-capability: {capability}\r\nConnection: close\r\n",
            run.run_id
        );
        let request = |candidate: String, host: String, extra: &str| {
            format!(
                "GET {candidate} HTTP/1.1\r\nHost: {host}\r\n{base_headers}{extra}\r\n"
            )
        };
        let cases = vec![
            (
                "hostname",
                request(
                    target.replacen("127.0.0.1", "localhost", 1),
                    format!("localhost:{source_port}"),
                    "",
                ),
            ),
            (
                "short-ipv4",
                request(
                    target.replacen("127.0.0.1", "127.1", 1),
                    format!("127.1:{source_port}"),
                    "",
                ),
            ),
            (
                "zero-ipv4",
                request(
                    target.replacen("127.0.0.1", "0.0.0.0", 1),
                    format!("0.0.0.0:{source_port}"),
                    "",
                ),
            ),
            (
                "ipv6",
                request(
                    target.replacen("127.0.0.1", "[::1]", 1),
                    format!("[::1]:{source_port}"),
                    "",
                ),
            ),
            (
                "non-http-scheme",
                request(target.replacen("http:", "https:", 1), authority.clone(), ""),
            ),
            (
                "userinfo",
                request(
                    target.replacen("http://", "http://user@", 1),
                    authority.clone(),
                    "",
                ),
            ),
            (
                "encoded-host",
                request(
                    target.replacen("127.0.0.1", "127%2e0%2e0%2e1", 1),
                    authority.clone(),
                    "",
                ),
            ),
            (
                "fragment",
                request(format!("{target}#forbidden"), authority.clone(), ""),
            ),
            (
                "host-mismatch",
                request(target.clone(), "127.0.0.1:1".to_owned(), ""),
            ),
            (
                "duplicate-host",
                request(
                    target.clone(),
                    authority.clone(),
                    "Host: 127.0.0.1:1\r\n",
                ),
            ),
            (
                "content-length-transfer-encoding-conflict",
                request(
                    target.clone(),
                    authority.clone(),
                    "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
                ),
            ),
        ];
        for (name, raw) in &cases {
            let status = raw_proxy_status(proxy_port, raw).await?;
            if status != 400 && status != 403 {
                anyhow::bail!("proxy regression case {name} returned unexpected HTTP status {status}");
            }
        }
        let audit = fetch_audit(&client, &server.base_url(), &run).await?;
        let rejected = audit
            .iter()
            .filter(|record| record.event_type == AuditEventType::ProxyRequest)
            .collect::<Vec<_>>();
        if rejected.len() != cases.len()
            || rejected.iter().any(|record| {
                !record.blocked || !record.external_target_rejected || record.response_status == 200
            })
            || audit
                .iter()
                .any(|record| record.event_type == AuditEventType::SourceRequest)
            || audit
                .iter()
                .any(|record| record.event_type == AuditEventType::QuotaDecision)
        {
            anyhow::bail!(
                "rejected proxy targets must be blocked before source forwarding or quota consumption"
            );
        }
        let status = raw_proxy_status(proxy_port, &request(target, authority, "")).await?;
        if status != 200 {
            anyhow::bail!("a correct proxy request must remain usable after rejected inputs");
        }
        let audit = fetch_audit(&client, &server.base_url(), &run).await?;
        let source_requests = audit
            .iter()
            .filter(|record| record.event_type == AuditEventType::SourceRequest)
            .count();
        if source_requests != 1 {
            anyhow::bail!("the correct proxy request did not produce exactly one source request");
        }
        Ok(true)
    }
    .await;
    server.shutdown().await;
    result
}

async fn raw_proxy_status(proxy_port: u16, request: &str) -> anyhow::Result<u16> {
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, proxy_port)).await?;
    stream.write_all(request.as_bytes()).await?;
    let mut response = [0_u8; 512];
    let count = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        stream.read(&mut response),
    )
    .await
    .map_err(|_| anyhow::anyhow!("local proxy regression probe timed out"))??;
    let response = std::str::from_utf8(&response[..count])?;
    response
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("local proxy regression response has no status"))?
        .parse()
        .map_err(Into::into)
}

async fn serve_command(repository: ScenarioRepository, args: &[String]) -> anyhow::Result<bool> {
    let scenario = flag_value(args, "--scenario");
    let port = flag_value(args, "--port")
        .map(|value| value.parse::<u16>())
        .transpose()?;
    let server = LocalServer::spawn_on(
        repository,
        scenario.as_deref(),
        Some(port.unwrap_or(18_080)),
    )
    .await
    .map_err(anyhow::Error::msg)?;
    println!("localhost test service: {}", server.base_url());
    if let Some(run_id) = server.developer_run_id() {
        println!("deprecated single-session convenience run: {run_id}");
        println!("manual source requests still need x-lab-run-id: {run_id}");
    }
    println!("automation must create sessions with POST /api/runs.");
    println!("only 127.0.0.1 is bound; press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    server.shutdown().await;
    Ok(true)
}

async fn self_test(repository: &ScenarioRepository) -> anyhow::Result<bool> {
    let report_dir = PathBuf::from("artifacts/reports/self-test");
    fs::create_dir_all(&report_dir)?;
    let checks = [
        ("scope", "007-scope-boundaries"),
        ("pagination", "012-pagination-success"),
        ("authentication", "015-rate-limit-retry"),
        ("rate-limit", "015-rate-limit-retry"),
        ("evidence", "003-basic-passive-dns"),
        ("retry", "015-rate-limit-retry"),
        ("url-extraction", "050-url-boundaries"),
        ("egress", "007-scope-boundaries"),
    ];
    let mut all_rejected = true;
    for (kind, scenario_id) in checks {
        let report = run_negative_client(repository, kind, scenario_id).await?;
        let rejected = report.status == ReportStatus::Failed && !report.failures.is_empty();
        let path = report_dir.join(format!("self-test-{kind}.json"));
        fs::write(&path, report_json(&report)?)
            .with_context(|| format!("cannot write self-test report {}", path.display()))?;
        println!(
            "negative client {kind}: {} ({})",
            if rejected {
                "correctly rejected"
            } else {
                "NOT rejected"
            },
            path.display()
        );
        all_rejected &= rejected;
    }
    Ok(all_rejected)
}

async fn run_negative_client(
    repository: &ScenarioRepository,
    kind: &str,
    scenario_id: &str,
) -> anyhow::Result<lab_core::RunReport> {
    let loaded = repository
        .get(scenario_id)
        .ok_or_else(|| anyhow::anyhow!("unknown scenario {scenario_id}"))?
        .clone();
    let server = LocalServer::spawn(repository.clone(), None)
        .await
        .map_err(anyhow::Error::msg)?;
    let client = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .build()?;
    let created_run = create_run(
        &client,
        &server.base_url(),
        scenario_id,
        Some(loaded.scenario.seed),
    )
    .await?;
    let run_id = created_run.run_id;
    let started = Utc::now();
    let mut collector = CollectorRun::default();
    let mut rejected = Vec::new();
    match kind {
        "scope" => {
            let _ = client
                .get(format!(
                    "{}/generic/v1/search?domain=acme.test",
                    server.base_url()
                ))
                .header("x-lab-run-id", run_id.to_string())
                .send()
                .await?;
            collector.observations.push(Observation {
                fqdn: "evil-acme.test".to_owned(),
                source_kind: SourceKind::GenericJson,
                source_name: "generic-search".to_owned(),
                record_id: Some("bad-scope".to_owned()),
                observed_at: None,
                tags: Vec::new(),
                confidence: None,
                evidence: std::collections::BTreeMap::new(),
            });
            collector
                .source_statuses
                .insert("generic-search".to_owned(), SourceStatus::Success);
        }
        "pagination" => {
            for _ in 0..3 {
                let _ = client
                    .get(format!(
                        "{}/pages/v1/search?domain=acme.test",
                        server.base_url()
                    ))
                    .header("x-lab-run-id", run_id.to_string())
                    .send()
                    .await?;
            }
            collector
                .source_statuses
                .insert("pages".to_owned(), SourceStatus::Failed);
        }
        "authentication" => {
            let _ = client
                .get(format!(
                    "{}/key/v1/search?domain=acme.test",
                    server.base_url()
                ))
                .header("x-lab-run-id", run_id.to_string())
                .send()
                .await?;
            collector
                .source_statuses
                .insert("key-search".to_owned(), SourceStatus::AuthFailed);
        }
        "rate-limit" => {
            let mut headers = HeaderMap::new();
            headers.insert("x-api-key", HeaderValue::from_static("lab-demo-key"));
            headers.insert(
                "x-lab-run-id",
                HeaderValue::from_str(&run_id.to_string()).expect("UUID header value"),
            );
            for _ in 0..2 {
                let _ = client
                    .get(format!(
                        "{}/key/v1/search?domain=acme.test",
                        server.base_url()
                    ))
                    .headers(headers.clone())
                    .send()
                    .await?;
            }
            collector
                .source_statuses
                .insert("key-search".to_owned(), SourceStatus::Success);
        }
        "evidence" => {
            let _ = client
                .get(format!(
                    "{}/dns/v1/history?domain=acme.test",
                    server.base_url()
                ))
                .header("x-lab-run-id", run_id.to_string())
                .send()
                .await?;
            collector.observations.push(Observation {
                fqdn: "old.acme.test".to_owned(),
                source_kind: SourceKind::PassiveDns,
                source_name: "passive-dns".to_owned(),
                record_id: Some("d1".to_owned()),
                observed_at: None,
                tags: Vec::new(),
                confidence: None,
                evidence: std::collections::BTreeMap::new(),
            });
            collector.observations.push(Observation {
                fqdn: "mail.acme.test".to_owned(),
                source_kind: SourceKind::PassiveDns,
                source_name: "passive-dns".to_owned(),
                record_id: Some("d2".to_owned()),
                observed_at: None,
                tags: Vec::new(),
                confidence: None,
                evidence: std::collections::BTreeMap::new(),
            });
            collector
                .source_statuses
                .insert("passive-dns".to_owned(), SourceStatus::Success);
        }
        "retry" => {
            let _ = client
                .get(format!(
                    "{}/key/v1/search?domain=acme.test",
                    server.base_url()
                ))
                .header("x-api-key", "lab-demo-key")
                .header("x-lab-run-id", run_id.to_string())
                .send()
                .await?;
            collector
                .source_statuses
                .insert("key-search".to_owned(), SourceStatus::Success);
        }
        "url-extraction" => {
            let _ = client
                .get(format!("{}/v12/url?domain=acme.test", server.base_url()))
                .header("x-lab-run-id", run_id.to_string())
                .send()
                .await?;
            collector.observations.push(Observation {
                fqdn: "https://api.acme.test:8443/path?source=negative#fragment".to_owned(),
                source_kind: SourceKind::GenericJson,
                source_name: "url-source".to_owned(),
                record_id: Some("url-not-host".to_owned()),
                observed_at: None,
                tags: Vec::new(),
                confidence: None,
                evidence: std::collections::BTreeMap::new(),
            });
            collector
                .source_statuses
                .insert("url-source".to_owned(), SourceStatus::Success);
        }
        "egress" => {
            let guard = EgressGuard::default();
            collector = ReferenceRunner::new(guard.clone())?
                .run(&server.base_url(), &loaded.scenario, run_id, "default")
                .await?;
            assert!(
                guard
                    .validate("https://outside.invalid/should-never-be-requested")
                    .is_err(),
                "the negative client must be blocked before any external network request"
            );
            rejected = guard.rejected_urls();
        }
        _ => unreachable!("fixed self-test set"),
    }
    let audit = fetch_audit(&client, &server.base_url(), &created_run).await?;
    let report = judge_run(JudgeInput {
        run_id,
        scenario_id,
        seed: loaded.scenario.seed,
        target_domain: &target_domain(&loaded.scenario),
        started_at: started,
        finished_at: Utc::now(),
        collector_run: &collector,
        truth: &loaded.truth,
        assertions: &loaded.assertions,
        audit: &audit,
        rejected_egress_urls: &rejected,
    });
    server.shutdown().await;
    Ok(report)
}

#[derive(Clone)]
struct CreatedRun {
    run_id: Uuid,
    access_token: String,
}

async fn create_run(
    client: &Client,
    base_url: &str,
    scenario_id: &str,
    seed: Option<u64>,
) -> anyhow::Result<CreatedRun> {
    let response = client
        .post(format!("{base_url}/api/runs"))
        .json(&serde_json::json!({"scenario_id":scenario_id,"seed":seed}))
        .send()
        .await?
        .error_for_status()?;
    let value: serde_json::Value = response.json().await?;
    let run_id = value
        .get("run_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("run creation response is missing run_id"))?;
    let access_token = value
        .get("run_access_token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("run creation response is missing run_access_token"))?;
    Ok(CreatedRun {
        run_id: Uuid::parse_str(run_id)?,
        access_token: access_token.to_owned(),
    })
}

async fn fetch_audit(
    client: &Client,
    base_url: &str,
    run: &CreatedRun,
) -> anyhow::Result<Vec<lab_core::AuditRecord>> {
    let response = client
        .get(format!("{base_url}/api/runs/{}/requests", run.run_id))
        .header("x-lab-run-access-token", &run.access_token)
        .send()
        .await?
        .error_for_status()?;
    let value: serde_json::Value = response.json().await?;
    serde_json::from_value(
        value
            .get("requests")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("run request response is missing requests"))?,
    )
    .map_err(Into::into)
}

fn print_report(report: &lab_core::RunReport, path: &std::path::Path) {
    println!("scenario: {}", report.scenario_id);
    println!(
        "result: {}",
        if report.status == ReportStatus::Passed {
            "passed"
        } else {
            "failed"
        }
    );
    println!("assertions: {}/8", report.assertions.passed_count());
    println!(
        "requests: total {}, unmatched {}, extra {}, blocked egress {}",
        report.request_summary.total,
        report.request_summary.unmatched,
        report.request_summary.extra,
        report.request_summary.rejected_egress_attempts
    );
    println!("virtual wait: {} ms", report.virtual_waited_ms);
    if let Some(failure) = report.failures.first() {
        println!("failure: {failure}");
    }
    println!("report: {}", path.display());
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|argument| argument == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn print_help() {
    println!(
        "lab-cli commands:\n  validate\n  list\n  run --all | --scenario <id> | --group network|proxy|quota|transport|combination|lifecycle [--seed <number>] [--profile default|stress] [--report-dir artifacts/reports]\n  repeat --count <number> [--scenario <id>] [--profile default|stress]\n  replay [--strict] --report <report-path>\n  campaign list | run --campaign <id> --seed <number> | replay --report <campaign-report>\n  coverage --format json|markdown --output <path> | --check\n  baseline generate --profile v1.4-core | compare --baseline <path> --report <path> | check\n  soak run --preset smoke|standard|release\n  proxy-regression\n  conformance [--scenario 067-external-submission-pass]\n  self-test\n  serve [--scenario <id>] [--port 18080]"
    );
}

fn target_domain(scenario: &lab_core::Scenario) -> String {
    scenario
        .root_domain
        .replace("$SEED", &scenario.seed.to_string())
}

#[cfg(test)]
mod tests {
    use super::{external_http_conformance, run_negative_client, run_one, scenarios_dir};
    use lab_core::{ReportStatus, ScenarioRepository};
    use lab_server::LocalServer;
    use uuid::Uuid;

    #[tokio::test]
    async fn every_scenario_is_a_rust_regression_test() {
        let repository = ScenarioRepository::load(scenarios_dir()).expect("load scenarios");
        assert_eq!(repository.all().len(), 114);
        for loaded in repository.all() {
            let report = run_one(&repository, &loaded.scenario.id, "default", None)
                .await
                .expect("scenario run");
            assert_eq!(
                report.status,
                ReportStatus::Passed,
                "scenario {} should pass",
                loaded.scenario.id
            );
            if loaded.scenario.id == "019-large-dataset" {
                assert_eq!(report.metrics.raw_records, 10_000);
                assert!(report.metrics.response_bytes > 0);
                assert!(report.metrics.elapsed_ms < 10_000);
            }
            if matches!(
                loaded.scenario.id.as_str(),
                "020-cancellation-and-egress-guard" | "058-cancel-pagination"
            ) {
                assert!(report.metrics.cancelled);
                assert_eq!(
                    report.metrics.cancellation_reason.as_deref(),
                    Some("cancel_after_requests")
                );
            }
        }
    }

    #[tokio::test]
    async fn negative_clients_reuse_test_callable_logic() {
        let repository = ScenarioRepository::load(scenarios_dir()).expect("load scenarios");
        for (kind, scenario_id) in [
            ("scope", "007-scope-boundaries"),
            ("pagination", "012-pagination-success"),
            ("authentication", "015-rate-limit-retry"),
            ("rate-limit", "015-rate-limit-retry"),
            ("evidence", "003-basic-passive-dns"),
            ("retry", "015-rate-limit-retry"),
            ("url-extraction", "050-url-boundaries"),
            ("egress", "007-scope-boundaries"),
        ] {
            let report = run_negative_client(&repository, kind, scenario_id)
                .await
                .expect("negative client run");
            assert_eq!(
                report.status,
                ReportStatus::Failed,
                "{kind} must be rejected"
            );
            assert!(!report.failures.is_empty(), "{kind} needs failure evidence");
            let expected_reason = match kind {
                "egress" => "rejected egress count mismatch",
                "retry" => "request contract did not match assertions.yaml",
                "url-extraction" => "FQDN mismatch",
                _ => continue,
            };
            assert!(
                report
                    .failures
                    .iter()
                    .any(|failure| failure.contains(expected_reason)),
                "{kind} needs a readable failure reason"
            );
        }
    }

    #[tokio::test]
    async fn independent_http_client_completes_the_public_contract_without_truth() {
        let repository = ScenarioRepository::load(scenarios_dir()).expect("load scenarios");
        let server = LocalServer::spawn(repository, None)
            .await
            .expect("start local test service");
        let report = external_http_conformance(&server.base_url(), "067-external-submission-pass")
            .await
            .expect("public HTTP contract");
        assert_eq!(
            report.get("status").and_then(serde_json::Value::as_str),
            Some("passed")
        );
        assert!(report.get("truth").is_none());
        assert_eq!(
            report
                .get("submission")
                .and_then(|value| value.get("received"))
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn public_submission_contract_rejects_security_and_lifecycle_abuse() {
        let repository = ScenarioRepository::load(scenarios_dir()).expect("load scenarios");
        let server = LocalServer::spawn(repository, None)
            .await
            .expect("start local test service");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("HTTP client");
        let base_url = server.base_url();
        assert_eq!(
            client
                .get(format!("{base_url}/v121/search"))
                .send()
                .await
                .expect("unscoped source request")
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs"))
                .json(&serde_json::json!({"scenario_id":"not-a-scenario"}))
                .send()
                .await
                .expect("unknown scenario request")
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        let created: serde_json::Value = client
            .post(format!("{base_url}/api/runs"))
            .json(&serde_json::json!({"scenario_id":"067-external-submission-pass","seed":67}))
            .send()
            .await
            .expect("create run")
            .error_for_status()
            .expect("create run status")
            .json()
            .await
            .expect("create run JSON");
        let run_id = created["run_id"].as_str().expect("run id").to_owned();
        let run_access_token = created["run_access_token"]
            .as_str()
            .expect("run access token")
            .to_owned();
        assert_eq!(
            client
                .get(format!("{base_url}/api/runs/{run_id}/truth"))
                .send()
                .await
                .expect("truth request")
                .status(),
            reqwest::StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .get(format!("{base_url}/api/runs/{}/manifest", Uuid::new_v4()))
                .send()
                .await
                .expect("unknown manifest request")
                .status(),
            reqwest::StatusCode::NOT_FOUND
        );
        let manifest: serde_json::Value = client
            .get(format!("{base_url}/api/runs/{run_id}/manifest"))
            .header("x-lab-run-access-token", &run_access_token)
            .send()
            .await
            .expect("manifest request")
            .error_for_status()
            .expect("manifest status")
            .json()
            .await
            .expect("manifest JSON");
        let source = &manifest["sources"][0];
        let source_url = format!(
            "{}{}",
            source["base_url"].as_str().expect("source base URL"),
            source["path_template"].as_str().expect("source path")
        );
        let source_response = client
            .get(&source_url)
            .header("x-lab-run-id", &run_id)
            .query(&source["required_query"])
            .send()
            .await
            .expect("source request")
            .error_for_status()
            .expect("source status");
        let evidence_url = source_response.url().to_string();
        let source_kind = source["source_kind"].clone();
        let target = manifest["target_domain"].as_str().expect("target domain");
        let correct_submission = serde_json::json!({
            "schema_version":"1.2.1",
            "collector":{"name":"negative-contract-test","version":"1.2.1"},
            "target_domain":target,
            "source_statuses":{"search-source":"succeeded"},
            "findings":[{"fqdn":format!("api.{target}"),"evidence":[{"source_id":"search-source","source_kind":source_kind,"record_id":"synthetic-67-1","url":evidence_url,"observed_at":"2025-01-12T00:00:00Z","tags":["synthetic"],"confidence":80}]}]
        });
        let mut invalid_target = correct_submission.clone();
        invalid_target["target_domain"] = serde_json::json!("other.acme.test");
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", &run_access_token)
                .json(&invalid_target)
                .send()
                .await
                .expect("invalid target submission")
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        let mut unknown_source = correct_submission.clone();
        unknown_source["source_statuses"] = serde_json::json!({"unknown-source":"succeeded"});
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", &run_access_token)
                .json(&unknown_source)
                .send()
                .await
                .expect("unknown source submission")
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        let mut out_of_scope = correct_submission.clone();
        out_of_scope["findings"][0]["fqdn"] = serde_json::json!("outside.evil.test");
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", &run_access_token)
                .json(&out_of_scope)
                .send()
                .await
                .expect("out of scope submission")
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        let mut no_evidence = correct_submission.clone();
        no_evidence["findings"][0]["evidence"] = serde_json::json!([]);
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", &run_access_token)
                .json(&no_evidence)
                .send()
                .await
                .expect("missing evidence submission")
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        let mut forged = correct_submission.clone();
        forged["passed"] = serde_json::json!(true);
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", &run_access_token)
                .json(&forged)
                .send()
                .await
                .expect("forged result submission")
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        let mut sensitive = correct_submission.clone();
        sensitive["authorization"] = serde_json::json!("Bearer real-looking-secret");
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", &run_access_token)
                .json(&sensitive)
                .send()
                .await
                .expect("sensitive submission")
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        let mut sensitive_evidence_url = correct_submission.clone();
        sensitive_evidence_url["findings"][0]["evidence"][0]["url"] =
            serde_json::json!(format!("{evidence_url}&api_key=synthetic-secret"));
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", &run_access_token)
                .json(&sensitive_evidence_url)
                .send()
                .await
                .expect("sensitive evidence URL submission")
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        let oversized = format!(
            "{{\"schema_version\":\"1.2.1\",\"padding\":\"{}\"}}",
            "x".repeat(8 * 1024 * 1024)
        );
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", &run_access_token)
                .header("content-type", "application/json")
                .body(oversized)
                .send()
                .await
                .expect("oversized submission")
                .status(),
            reqwest::StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", &run_access_token)
                .json(&correct_submission)
                .send()
                .await
                .expect("valid submission")
                .status(),
            reqwest::StatusCode::CREATED
        );
        let audit: serde_json::Value = client
            .get(format!("{base_url}/api/runs/{run_id}/requests"))
            .header("x-lab-run-access-token", &run_access_token)
            .send()
            .await
            .expect("submission audit request")
            .error_for_status()
            .expect("submission audit status")
            .json()
            .await
            .expect("submission audit JSON");
        assert_eq!(audit["requests"][0]["before_submission"], true);
        assert_eq!(
            client
                .get(&source_url)
                .header("x-lab-run-id", &run_id)
                .query(&source["required_query"])
                .send()
                .await
                .expect("post-submission source request")
                .status(),
            reqwest::StatusCode::CONFLICT
        );
        let reset: serde_json::Value = client
            .post(format!("{base_url}/api/runs/{run_id}/reset"))
            .header("x-lab-run-access-token", &run_access_token)
            .send()
            .await
            .expect("reset submitted run")
            .error_for_status()
            .expect("reset submitted run status")
            .json()
            .await
            .expect("reset submitted run JSON");
        let reset_access_token = reset["run_access_token"]
            .as_str()
            .expect("reset must rotate the run access token");
        assert_eq!(
            client
                .get(&source_url)
                .header("x-lab-run-id", &run_id)
                .query(&source["required_query"])
                .send()
                .await
                .expect("source request after reset")
                .status(),
            reqwest::StatusCode::OK
        );
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", reset_access_token)
                .json(&correct_submission)
                .send()
                .await
                .expect("submission after reset")
                .status(),
            reqwest::StatusCode::CREATED
        );
        let second_run: serde_json::Value = client
            .post(format!("{base_url}/api/runs"))
            .json(&serde_json::json!({"scenario_id":"067-external-submission-pass","seed":67}))
            .send()
            .await
            .expect("second run")
            .error_for_status()
            .expect("second run status")
            .json()
            .await
            .expect("second run JSON");
        let second_run_id = second_run["run_id"].as_str().expect("second run id");
        let second_run_access_token = second_run["run_access_token"]
            .as_str()
            .expect("second run access token");
        assert_eq!(
            client
                .get(format!("{base_url}/api/runs/{run_id}/report"))
                .header("x-lab-run-access-token", second_run_access_token)
                .send()
                .await
                .expect("cross-run report request")
                .status(),
            reqwest::StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/reset"))
                .header("x-lab-run-access-token", second_run_access_token)
                .send()
                .await
                .expect("cross-run reset request")
                .status(),
            reqwest::StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .delete(format!("{base_url}/api/runs/{run_id}"))
                .header("x-lab-run-access-token", second_run_access_token)
                .send()
                .await
                .expect("cross-run delete request")
                .status(),
            reqwest::StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{second_run_id}/submission"))
                .header("x-lab-run-access-token", second_run_access_token)
                .json(&correct_submission)
                .send()
                .await
                .expect("cross-run submission")
                .status(),
            reqwest::StatusCode::CONFLICT
        );
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", &run_access_token)
                .json(&correct_submission)
                .send()
                .await
                .expect("stale token submission")
                .status(),
            reqwest::StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/submission"))
                .header("x-lab-run-access-token", reset_access_token)
                .json(&correct_submission)
                .send()
                .await
                .expect("duplicate submission with refreshed token")
                .status(),
            reqwest::StatusCode::CONFLICT
        );
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/report"))
                .json(&serde_json::json!({"status":"passed"}))
                .send()
                .await
                .expect("forged report route")
                .status(),
            reqwest::StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            client
                .delete(format!("{base_url}/api/runs/{second_run_id}"))
                .header("x-lab-run-access-token", second_run_access_token)
                .send()
                .await
                .expect("delete secondary run")
                .status(),
            reqwest::StatusCode::NO_CONTENT
        );
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{second_run_id}/submission"))
                .header("x-lab-run-access-token", second_run_access_token)
                .json(&correct_submission)
                .send()
                .await
                .expect("submission to deleted run")
                .status(),
            reqwest::StatusCode::NOT_FOUND
        );
        server.shutdown().await;
    }

    #[tokio::test]
    #[ignore = "explicit stress verification only"]
    async fn large_dataset_stress_reports_all_raw_records() {
        let repository = ScenarioRepository::load(scenarios_dir()).expect("load scenarios");
        let report = run_one(&repository, "019-large-dataset", "stress", None)
            .await
            .expect("stress run");
        assert_eq!(report.status, ReportStatus::Passed);
        assert_eq!(report.metrics.raw_records, 100_000);
        assert!(report.metrics.elapsed_ms < 60_000);
    }
}
