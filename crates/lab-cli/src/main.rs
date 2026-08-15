use std::{env, fs, path::PathBuf, process::ExitCode};

use anyhow::Context;
use chrono::Utc;
use lab_core::{
    CollectorRun, EgressGuard, JudgeInput, Observation, ReferenceRunner, ReportStatus,
    ScenarioRepository, SourceKind, SourceStatus, judge_run, refresh_semantic_fingerprint,
    report_json, semantic_difference, semantic_fingerprint,
};
use lab_server::LocalServer;
use reqwest::{
    Client,
    header::{HeaderMap, HeaderValue},
    redirect::Policy,
};
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
    if !all && requested.is_none() {
        anyhow::bail!("use: lab-cli run --all | --scenario <id>");
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
    let control_client = Client::builder().redirect(Policy::none()).build()?;
    let run_id = create_run(
        &control_client,
        &server.base_url(),
        id,
        Some(loaded.scenario.seed),
    )
    .await?;
    let collector = runner
        .run(&server.base_url(), &loaded.scenario, run_id, profile)
        .await?;
    let finished = Utc::now();
    let audit = fetch_audit(&control_client, &server.base_url(), run_id).await?;
    let rejected = guard.rejected_urls();
    let target = target_domain(&loaded.scenario);
    let report = judge_run(JudgeInput {
        run_id,
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
    if strict && prior.schema_version != "1.2.1" {
        eprintln!("strict replay requires a compatible 1.2.1 report schema");
        return Ok(false);
    }
    let mut replay = run_one(repository, &prior.scenario_id, "default", Some(prior.seed)).await?;
    let matched = if strict {
        prior.semantic_fingerprint == semantic_fingerprint(&prior)
            && prior.semantic_fingerprint == replay.semantic_fingerprint
            && semantic_difference(&prior, &replay).is_none()
    } else {
        replay.status == prior.status
            && replay.scenario_id == prior.scenario_id
            && replay.seed == prior.seed
            && replay.target_domain == prior.target_domain
    };
    let difference = strict
        .then(|| semantic_difference(&prior, &replay))
        .flatten();
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
    Ok(passed)
}

/// An intentionally black-box client: after receiving a base URL it uses only
/// public HTTP responses. It does not receive LabState, scenario files, truth
/// or assertions.
async fn external_http_conformance(
    base_url: &str,
    scenario_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let client = Client::builder().redirect(Policy::none()).build()?;
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
    let manifest: serde_json::Value = client
        .get(format!("{base_url}/api/runs/{run_id}/manifest"))
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
    let mut findings = Vec::new();
    let mut source_statuses = serde_json::Map::new();
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
        let url = format!("{source_base}{path}");
        let mut request = match source.get("method").and_then(serde_json::Value::as_str) {
            Some("POST") => client.post(&url),
            Some("PUT") => client.put(&url),
            Some("DELETE") => client.delete(&url),
            _ => client.get(&url),
        }
        .header("x-lab-run-id", run_id)
        .query(&query);
        // The run header is mandatory. A source-specific fake credential is
        // intentionally not inferred or copied from private scenario state.
        request = request.header("x-lab-data-profile", "default");
        let response = request.send().await?;
        let evidence_url = response.url().to_string();
        if !response.status().is_success() {
            source_statuses.insert(source_id.to_owned(), serde_json::json!("failed"));
            continue;
        }
        source_statuses.insert(source_id.to_owned(), serde_json::json!("succeeded"));
        let payload: serde_json::Value = response.json().await?;
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
    let submission = serde_json::json!({
        "schema_version":"1.2.1",
        "collector":{"name":"fqdn-forge-http-conformance","version":"1.2.1"},
        "target_domain":target_domain,
        "source_statuses":source_statuses,
        "findings":findings,
    });
    client
        .post(format!("{base_url}/api/runs/{run_id}/submission"))
        .json(&submission)
        .send()
        .await?
        .error_for_status()?;
    let report: serde_json::Value = client
        .get(format!("{base_url}/api/runs/{run_id}/report"))
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
    let client = Client::builder().redirect(Policy::none()).build()?;
    let run_id = create_run(
        &client,
        &server.base_url(),
        scenario_id,
        Some(loaded.scenario.seed),
    )
    .await?;
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
    let audit = fetch_audit(&client, &server.base_url(), run_id).await?;
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

async fn create_run(
    client: &Client,
    base_url: &str,
    scenario_id: &str,
    seed: Option<u64>,
) -> anyhow::Result<Uuid> {
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
    Ok(Uuid::parse_str(run_id)?)
}

async fn fetch_audit(
    client: &Client,
    base_url: &str,
    run_id: Uuid,
) -> anyhow::Result<Vec<lab_core::AuditRecord>> {
    let response = client
        .get(format!("{base_url}/api/runs/{run_id}/requests"))
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
        "lab-cli commands:\n  validate\n  list\n  run --all | --scenario <id> [--seed <number>] [--profile default|stress] [--report-dir artifacts/reports]\n  repeat --count <number> [--scenario <id>] [--profile default|stress]\n  replay [--strict] --report <report-path>\n  conformance [--scenario 067-external-submission-pass]\n  self-test\n  serve [--scenario <id>] [--port 18080]"
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
        assert_eq!(repository.all().len(), 72);
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
                .json(&correct_submission)
                .send()
                .await
                .expect("valid submission")
                .status(),
            reqwest::StatusCode::CREATED
        );
        let audit: serde_json::Value = client
            .get(format!("{base_url}/api/runs/{run_id}/requests"))
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
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{run_id}/reset"))
                .send()
                .await
                .expect("reset submitted run")
                .status(),
            reqwest::StatusCode::OK
        );
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
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{second_run_id}/submission"))
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
                .json(&correct_submission)
                .send()
                .await
                .expect("duplicate submission")
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
                .send()
                .await
                .expect("delete secondary run")
                .status(),
            reqwest::StatusCode::NO_CONTENT
        );
        assert_eq!(
            client
                .post(format!("{base_url}/api/runs/{second_run_id}/submission"))
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
