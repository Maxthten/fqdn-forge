use std::{env, fs, path::PathBuf, process::ExitCode};

use chrono::Utc;
use lab_core::{
    CollectorRun, EgressGuard, JudgeInput, Observation, ReferenceRunner, ReportStatus,
    ScenarioRepository, SourceKind, SourceStatus, judge_run, report_json,
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
        let report = run_one(repository, &id, &profile).await?;
        let report_path = report_dir.join(format!("{}-{}.json", report.scenario_id, profile));
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
) -> anyhow::Result<lab_core::RunReport> {
    let loaded = repository
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("unknown scenario {id}"))?
        .clone();
    let server = LocalServer::spawn(repository.clone(), None)
        .await
        .map_err(anyhow::Error::msg)?;
    let started = Utc::now();
    let guard = EgressGuard::default();
    let runner = ReferenceRunner::new(guard.clone())?;
    let control_client = Client::builder().redirect(Policy::none()).build()?;
    let run_id = create_run(&control_client, &server.base_url(), id).await?;
    let collector = runner
        .run(&server.base_url(), &loaded.scenario, run_id, profile)
        .await?;
    let finished = Utc::now();
    let audit = fetch_audit(&control_client, &server.base_url(), run_id).await?;
    let rejected = guard.rejected_urls();
    let report = judge_run(JudgeInput {
        run_id,
        scenario_id: &loaded.scenario.id,
        seed: loaded.scenario.seed,
        started_at: started,
        finished_at: finished,
        collector_run: &collector,
        truth: &loaded.truth,
        assertions: &loaded.assertions,
        audit: &audit,
        rejected_egress_urls: &rejected,
    });
    store_report(&control_client, &server.base_url(), run_id, &report).await?;
    server.shutdown().await;
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
    let report_dir = PathBuf::from("artifacts/reports");
    fs::create_dir_all(&report_dir)?;
    let checks = [
        ("scope", "007-scope-boundaries"),
        ("pagination", "012-pagination-success"),
        ("authentication", "015-rate-limit-retry"),
        ("rate-limit", "015-rate-limit-retry"),
        ("evidence", "003-basic-passive-dns"),
    ];
    let mut all_rejected = true;
    for (kind, scenario_id) in checks {
        let report = run_negative_client(repository, kind, scenario_id).await?;
        let rejected = report.status == ReportStatus::Failed && !report.failures.is_empty();
        let path = report_dir.join(format!("self-test-{kind}.json"));
        fs::write(&path, report_json(&report)?)?;
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
    let run_id = create_run(&client, &server.base_url(), scenario_id).await?;
    let started = Utc::now();
    let mut collector = CollectorRun::default();
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
            });
            collector.observations.push(Observation {
                fqdn: "mail.acme.test".to_owned(),
                source_kind: SourceKind::PassiveDns,
                source_name: "passive-dns".to_owned(),
                record_id: Some("d2".to_owned()),
                observed_at: None,
            });
            collector
                .source_statuses
                .insert("passive-dns".to_owned(), SourceStatus::Success);
        }
        _ => unreachable!("fixed self-test set"),
    }
    let audit = fetch_audit(&client, &server.base_url(), run_id).await?;
    let rejected = Vec::new();
    let report = judge_run(JudgeInput {
        run_id,
        scenario_id,
        seed: loaded.scenario.seed,
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

async fn create_run(client: &Client, base_url: &str, scenario_id: &str) -> anyhow::Result<Uuid> {
    let response = client
        .post(format!("{base_url}/api/runs"))
        .json(&serde_json::json!({"scenario_id":scenario_id}))
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

async fn store_report(
    client: &Client,
    base_url: &str,
    run_id: Uuid,
    report: &lab_core::RunReport,
) -> anyhow::Result<()> {
    client
        .post(format!("{base_url}/api/runs/{run_id}/report"))
        .json(report)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
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
    println!("assertions: {}/7", report.assertions.passed_count());
    println!(
        "requests: total {}, unmatched {}, extra {}, blocked egress {}",
        report.requests.total,
        report.requests.unmatched,
        report.requests.extra,
        report.requests.rejected_egress_attempts
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
        "lab-cli commands:\n  validate\n  list\n  run --all | --scenario <id> [--profile default|stress] [--report-dir artifacts/reports]\n  self-test\n  serve [--scenario <id>] [--port 18080]"
    );
}

#[cfg(test)]
mod tests {
    use super::{run_negative_client, run_one, scenarios_dir};
    use lab_core::{ReportStatus, ScenarioRepository};

    #[tokio::test]
    async fn every_scenario_is_a_rust_regression_test() {
        let repository = ScenarioRepository::load(scenarios_dir()).expect("load scenarios");
        assert_eq!(repository.all().len(), 20);
        for loaded in repository.all() {
            let report = run_one(&repository, &loaded.scenario.id, "default")
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
        }
    }

    #[tokio::test]
    #[ignore = "explicit stress verification only"]
    async fn large_dataset_stress_reports_all_raw_records() {
        let repository = ScenarioRepository::load(scenarios_dir()).expect("load scenarios");
        let report = run_one(&repository, "019-large-dataset", "stress")
            .await
            .expect("stress run");
        assert_eq!(report.status, ReportStatus::Passed);
        assert_eq!(report.metrics.raw_records, 100_000);
        assert!(report.metrics.elapsed_ms < 60_000);
    }
}
