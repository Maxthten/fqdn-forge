use std::{
    collections::BTreeMap,
    env, fs,
    io::Read,
    path::PathBuf,
    process::{Command, ExitCode},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::Context;
use brotli::Decompressor;
use chrono::Utc;
use csv::ReaderBuilder;
use flate2::read::{GzDecoder, ZlibDecoder};
use lab_console::load_console_preferences;
use lab_core::{
    AuditEventType, Baseline, CollectorRun, EgressGuard, ExperimentPlan, JudgeInput, NetworkMode,
    Observation, PlanExecutionMode, PlanStore, ReferenceRunner, ReportStatus, ScenarioRepository,
    SoakAction, SoakPreset, SoakReport, SourceKind, SourceStatus, V14_SCHEMA_VERSION,
    baseline_from_reports, campaign_definitions, campaign_loaded_scenario, campaign_manifest,
    compare_baseline, coverage_check, coverage_markdown, coverage_report, enrich_report,
    execute_plan_with_mode, judge_run, refresh_semantic_fingerprint, report_differences,
    report_json, semantic_difference, semantic_fingerprint, soak_baseline_from_report,
    validate_plan,
};
use lab_server::LocalServer;
use reqwest::{
    Client, Proxy,
    header::{HeaderMap, HeaderValue},
    redirect::Policy,
};
use scraper::{Html, Selector};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Barrier,
    task::JoinSet,
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
        "soak" => soak_command(&repository, &args).await,
        "proxy-regression" => proxy_regression_command(&repository).await,
        "plan" => plan_command(&args).await,
        "serve" => serve_command(repository, &args).await,
        "console" => console_command(repository, &args).await,
        _ => {
            print_help();
            Ok(true)
        }
    }
}

fn scenarios_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios")
}

fn plans_dir() -> PathBuf {
    scenarios_dir()
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("artifacts")
        .join("plans")
}

fn plan_store_dir(args: &[String]) -> PathBuf {
    flag_value(args, "--test-plan-root")
        .map(PathBuf::from)
        .unwrap_or_else(plans_dir)
}

async fn plan_command(args: &[String]) -> anyhow::Result<bool> {
    let operation = args.get(1).map(String::as_str).unwrap_or("help");
    let json_output = args.iter().any(|value| value == "--format=json")
        || flag_value(args, "--format").as_deref() == Some("json");
    if let Some(format) = flag_value(args, "--format")
        && format != "json"
    {
        anyhow::bail!("--format must be json when supplied");
    }
    let store = PlanStore::open(plan_store_dir(args))?;
    match operation {
        "list" => {
            let plans = store.list();
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"schema_version":"0.2", "plans":plans})
                    )?
                );
            } else {
                for plan in plans {
                    println!(
                        "{}\t{}\t{}\t{} source(s)\t{:?}",
                        plan.plan_id,
                        plan.name,
                        plan.updated_at.to_rfc3339(),
                        plan.sources.len(),
                        plan.status
                    );
                }
            }
            Ok(true)
        }
        "validate" => {
            let result = validate_plan(plan_from_file(args)?, true);
            if json_output {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if result.valid {
                println!(
                    "valid plan; digest {}",
                    result.plan_digest.as_deref().unwrap_or("<not calculated>")
                );
            } else {
                for issue in &result.issues {
                    eprintln!("{} {}: {}", issue.code, issue.field, issue.message);
                }
            }
            Ok(result.valid)
        }
        "create" => {
            let plan = store.create(plan_from_file(args)?)?;
            print_plan(&plan, json_output)?;
            Ok(true)
        }
        "show" => {
            let id = required_flag(args, "--id")?;
            let plan = store
                .get(&id)
                .ok_or_else(|| anyhow::anyhow!("PLAN_NOT_FOUND: plan {id} does not exist"))?;
            print_plan(&plan, json_output)?;
            Ok(true)
        }
        "run" | "simulate" => {
            let id = required_flag(args, "--id")?;
            let plan = store
                .get(&id)
                .ok_or_else(|| anyhow::anyhow!("PLAN_NOT_FOUND: plan {id} does not exist"))?;
            if plan.status == lab_core::PlanStatus::Archived {
                anyhow::bail!("PLAN_ARCHIVED: archived plans cannot be run");
            }
            if plan.status != lab_core::PlanStatus::Runnable {
                anyhow::bail!("PLAN_NOT_RUNNABLE: only plans marked runnable can be run");
            }
            let run = execute_plan_with_mode(plan, None, PlanExecutionMode::LocalSimulation);
            store.save_run(&run)?;
            print_plan_run(&run, json_output)?;
            Ok(run.report.status == "passed")
        }
        "update" => {
            let id = required_flag(args, "--id")?;
            let plan = store.update(&id, plan_from_file(args)?)?;
            print_plan(&plan, json_output)?;
            Ok(true)
        }
        "replay" => {
            let run_id = required_flag(args, "--run")?;
            let prior = store.load_run(&run_id)?;
            let run = execute_plan_with_mode(
                prior.plan_snapshot,
                Some(run_id),
                prior.manifest.execution_mode,
            );
            store.save_run(&run)?;
            print_plan_run(&run, json_output)?;
            Ok(run.report.status == "passed")
        }
        "export" => {
            let id = required_flag(args, "--id")?;
            let output = PathBuf::from(required_flag(args, "--output")?);
            let plan = store
                .get(&id)
                .ok_or_else(|| anyhow::anyhow!("PLAN_NOT_FOUND: plan {id} does not exist"))?;
            fs::write(&output, serde_json::to_vec_pretty(&plan)?)
                .with_context(|| format!("cannot write plan export {}", output.display()))?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"schema_version":"0.2", "plan_id":id, "output":output})
                    )?
                );
            } else {
                println!("exported plan {id} to {}", output.display());
            }
            Ok(true)
        }
        "import" => {
            let plan = store.import(plan_from_file(args)?)?;
            print_plan(&plan, json_output)?;
            Ok(true)
        }
        "archive" => {
            let id = required_flag(args, "--id")?;
            let plan = store.archive(&id)?;
            print_plan(&plan, json_output)?;
            Ok(true)
        }
        "delete" => {
            let id = required_flag(args, "--id")?;
            store.delete(&id)?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"schema_version":"0.2", "deleted":true, "plan_id":id})
                    )?
                );
            } else {
                println!("deleted plan {id}");
            }
            Ok(true)
        }
        "storage" => {
            let stats = store.storage_stats()?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&stats)?);
            } else {
                println!(
                    "plans: {}; runs: {}; bytes: {}; plans: {}; runs: {}",
                    stats.plan_count,
                    stats.run_count,
                    stats.total_bytes,
                    stats.plans_directory,
                    stats.runs_directory
                );
            }
            Ok(true)
        }
        "result" => {
            let run_id = required_flag(args, "--run")?;
            let run = store.load_run(&run_id)?;
            print_plan_run(&run, json_output)?;
            Ok(run.report.status == "passed")
        }
        "manifest" | "export-manifest" => {
            let run_id = required_flag(args, "--run")?;
            let output = PathBuf::from(required_flag(args, "--output")?);
            let run = store.load_run(&run_id)?;
            // The immutable manifest intentionally contains only the source
            // contract and expiry policy, never a live capability or fake key.
            fs::write(&output, serde_json::to_vec_pretty(&run.manifest)?)
                .with_context(|| format!("cannot write plan manifest {}", output.display()))?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"schema_version":"0.2", "run_id":run_id, "output":output})
                    )?
                );
            } else {
                println!(
                    "exported immutable manifest {run_id} to {}",
                    output.display()
                );
            }
            Ok(true)
        }
        _ => {
            println!(
                "lab-cli plan list | validate --file <plan.json> | create --file <plan.json> | show --id <plan-id> | update --id <plan-id> --file <plan.json> | run|simulate --id <plan-id> | replay --run <run-id> | export --id <plan-id> --output <plan.json> | import --file <plan.json> | archive --id <plan-id> | delete --id <plan-id> | storage | result --run <run-id> | manifest --run <run-id> --output <manifest.json> [--format json]"
            );
            Ok(operation == "help")
        }
    }
}

fn plan_from_file(args: &[String]) -> anyhow::Result<ExperimentPlan> {
    let path = PathBuf::from(required_flag(args, "--file")?);
    let metadata = fs::metadata(&path)
        .with_context(|| format!("cannot inspect plan file {}", path.display()))?;
    if metadata.len() > 1024 * 1024 {
        anyhow::bail!("PLAN_TOO_LARGE: plan file exceeds the 1 MiB safety limit");
    }
    serde_json::from_slice(&fs::read(&path)?)
        .with_context(|| format!("cannot parse plan file {}", path.display()))
}

fn required_flag(args: &[String], flag: &str) -> anyhow::Result<String> {
    flag_value(args, flag).ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

fn print_plan(plan: &ExperimentPlan, json_output: bool) -> anyhow::Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"schema_version":"0.2", "plan":plan})
            )?
        );
    } else {
        println!("plan: {} ({})", plan.name, plan.plan_id);
        println!("status: {:?}; revision: {}", plan.status, plan.revision);
        println!(
            "sources: {}; digest: {}",
            plan.sources.len(),
            plan.plan_digest
        );
    }
    Ok(())
}

fn print_plan_run(run: &lab_core::PlanRun, json_output: bool) -> anyhow::Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"schema_version":"0.2", "manifest":run.manifest, "report":run.report, "audit":run.audit})
            )?
        );
    } else {
        println!("plan: {}", run.report.plan_id);
        println!("run: {}", run.manifest.run_id);
        println!("result: {}", run.report.status);
        println!(
            "requests: {}; retries: {}; rate limited: {}; virtual wait: {} ms",
            run.report.requests,
            run.report.retries,
            run.report.rate_limited_sources,
            run.report.virtual_wait_ms
        );
        println!(
            "digests: fixture {}; truth {}; plan {}; manifest {}",
            run.report.fixture_digest,
            run.report.truth_digest,
            run.report.plan_digest,
            run.report.manifest_digest
        );
        if let Some(failure) = run.report.failures.first() {
            println!("failure: {failure}");
        }
    }
    Ok(())
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
    loaded = campaign_loaded_scenario(&loaded, loaded.scenario.seed);
    let server = LocalServer::spawn(repository.clone(), None)
        .await
        .map_err(anyhow::Error::msg)?;
    if matches!(
        id,
        "102-proxy-authority-header-ambiguity"
            | "105-stale-capability-after-reset-delete"
            | "106-concurrent-cross-run-lifecycle"
    ) {
        let result =
            external_http_conformance_with_seed(&server.base_url(), id, Some(loaded.scenario.seed))
                .await
                .and_then(|report| serde_json::from_value(report).map_err(Into::into));
        server.shutdown().await;
        return result;
    }
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
    if loaded.scenario.network_profile.initial_proxy_auth_challenge
        && loaded.scenario.network_profile.mode == NetworkMode::HttpProxy
    {
        proxy_auth_challenge_probe(&server.proxy_url(), &server.base_url(), created_run.run_id)
            .await?;
    }
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
        eprintln!("strict replay requires a compatible 1.2.1, 1.3.0, 1.4.0 or 1.4.1 report schema");
        return Ok(false);
    }
    if repository.get(&prior.scenario_id).is_none() {
        eprintln!(
            "strict replay scenario is no longer available: {}",
            prior.scenario_id
        );
        return Ok(false);
    }
    let mut replay = replay_report_for_prior(repository, &prior).await?;
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
        "fixture_or_mutation_changed".to_owned()
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

async fn replay_report_for_prior(
    repository: &ScenarioRepository,
    prior: &lab_core::RunReport,
) -> anyhow::Result<lab_core::RunReport> {
    let uses_public_submission = prior.submission.received
        && prior
            .submission
            .collector_name
            .as_deref()
            .is_some_and(|name| {
                name.starts_with("fqdn-forge-public-")
                    || name.starts_with("fqdn-forge-http-conformance")
            });
    if !uses_public_submission {
        return run_one(repository, &prior.scenario_id, "default", Some(prior.seed)).await;
    }
    let server = LocalServer::spawn(repository.clone(), None)
        .await
        .map_err(anyhow::Error::msg)?;
    let result = external_http_conformance_with_seed(
        &server.base_url(),
        &prior.scenario_id,
        Some(prior.seed),
    )
    .await
    .and_then(|report| serde_json::from_value(report).map_err(Into::into));
    server.shutdown().await;
    result
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
    external_http_conformance_with_seed(base_url, scenario_id, None).await
}

async fn external_http_conformance_with_seed(
    base_url: &str,
    scenario_id: &str,
    seed: Option<u64>,
) -> anyhow::Result<serde_json::Value> {
    let client = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .build()?;
    match scenario_id {
        "105-stale-capability-after-reset-delete" => {
            return public_lifecycle_105_conformance(&client, base_url, seed).await;
        }
        "106-concurrent-cross-run-lifecycle" => {
            return public_lifecycle_106_conformance(&client, base_url, seed).await;
        }
        _ => {}
    }
    let create: serde_json::Value = client
        .post(format!("{base_url}/api/runs"))
        .json(&serde_json::json!({"scenario_id":scenario_id,"seed":seed}))
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
    let network_allows_retry = network
        .get("allow_retry")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
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
    if network_mode == "http_proxy"
        && network
            .get("initial_proxy_auth_challenge")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    {
        let source = sources
            .first()
            .ok_or_else(|| anyhow::anyhow!("proxy-auth conformance needs one manifest source"))?;
        proxy_auth_challenge_from_manifest(network, source, run_id).await?;
    }
    let mut findings = Vec::new();
    let mut source_statuses = serde_json::Map::new();
    if network_mode == "connect_proxy" {
        for source in sources {
            let source_id = source
                .get("source_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("manifest source is missing source_id"))?;
            let (status, mut source_findings) =
                connect_conformance_probe(network, source, run_id, max_decoded_bytes).await?;
            source_statuses.insert(source_id.to_owned(), serde_json::Value::String(status));
            findings.append(&mut source_findings);
        }
    } else {
        for source in sources {
            let source_id = source
                .get("source_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("manifest source is missing source_id"))?;
            let (mut status, mut source_findings) = collect_manifest_source(
                &source_client,
                source,
                network_mode,
                network_allows_retry,
                scenario_id == "100-cancel-during-quota-recovery",
                &proxy_values,
                run_id,
                max_decoded_bytes,
            )
            .await?;
            if scenario_id == "100-cancel-during-quota-recovery" && status == "rate_limited" {
                client
                    .post(format!("{base_url}/api/runs/{run_id}/cancel"))
                    .header(run_access_header, run_access_token)
                    .header("x-lab-client-virtual-wait-ms", "2000")
                    .send()
                    .await?
                    .error_for_status()?;
                status = "cancelled".to_owned();
            }
            source_statuses.insert(source_id.to_owned(), serde_json::Value::String(status));
            findings.append(&mut source_findings);
        }
    }
    let collector_name = seed.map_or_else(
        || "fqdn-forge-http-conformance".to_owned(),
        |seed| format!("fqdn-forge-http-conformance-seed-{seed}"),
    );
    let submission = serde_json::json!({
        "schema_version":V14_SCHEMA_VERSION,
        "collector":{"name":collector_name,"version":V14_SCHEMA_VERSION},
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
    let cleanup = client
        .delete(format!("{base_url}/api/runs/{run_id}"))
        .header(run_access_header, run_access_token)
        .send()
        .await?;
    if cleanup.status() != reqwest::StatusCode::NO_CONTENT {
        anyhow::bail!("public conformance could not clean up its completed run");
    }
    Ok(report)
}

/// Drives an advertised source exclusively through fields returned by the
/// public manifest.  Pagination and virtual retry time are state local to one
/// source, so a rejected request cannot accidentally advance another source.
#[allow(clippy::too_many_arguments)]
async fn collect_manifest_source(
    client: &Client,
    source: &serde_json::Value,
    network_mode: &str,
    network_allows_retry: bool,
    stop_on_rate_limit: bool,
    proxy_values: &serde_json::Map<String, serde_json::Value>,
    run_id: &str,
    max_decoded_bytes: usize,
) -> anyhow::Result<(String, Vec<serde_json::Value>)> {
    let source_id = source
        .get("source_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("manifest source is missing source_id"))?;
    let source_kind = source
        .get("source_kind")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("manifest source is missing source_kind"))?;
    let base_url = source
        .get("base_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("manifest source is missing base_url"))?;
    let path = source
        .get("path_template")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("manifest source is missing path_template"))?;
    let authentication = source
        .get("authentication")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut query = source
        .get("required_query")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, value)| value.as_str().map(|value| (name.clone(), value.to_owned())))
        .collect::<BTreeMap<_, _>>();
    let pagination_mode = source
        .get("pagination_mode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("none");
    let pagination_parameter = source
        .get("pagination_parameter")
        .and_then(serde_json::Value::as_str);
    let next_page_field = source
        .get("next_page_field")
        .and_then(serde_json::Value::as_str);
    if pagination_mode == "page"
        && let Some(parameter) = pagination_parameter
    {
        query
            .entry(parameter.to_owned())
            .or_insert_with(|| "1".to_owned());
    }
    let allow_retry = network_allows_retry
        || source
            .get("allow_retry")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    let url = format!("{base_url}{path}");
    let mut findings = Vec::new();
    let mut virtual_wait_ms = 0_u64;
    let mut attempts = 0_usize;
    let mut seen_tokens = Vec::new();
    loop {
        attempts = attempts.saturating_add(1);
        if attempts > 8 {
            return Ok(("failed".to_owned(), findings));
        }
        let mut request = match source.get("method").and_then(serde_json::Value::as_str) {
            Some("POST") => client.post(&url),
            Some("PUT") => client.put(&url),
            Some("DELETE") => client.delete(&url),
            _ => client.get(&url),
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
            for (manifest_name, header_name) in [
                ("proxy_authorization", "proxy-authorization"),
                ("proxy_capability", "x-lab-proxy-capability"),
            ] {
                if let Some(value) = proxy_values
                    .get(manifest_name)
                    .and_then(serde_json::Value::as_str)
                {
                    request = request.header(header_name, value);
                }
            }
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) if allow_retry && attempts < 4 => continue,
            Err(_) => return Ok(("failed".to_owned(), findings)),
        };
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS && stop_on_rate_limit {
            return Ok(("rate_limited".to_owned(), findings));
        }
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
            && allow_retry
            && attempts < 4
        {
            virtual_wait_ms =
                virtual_wait_ms.saturating_add(retry_after_virtual_ms(response.headers()));
            continue;
        }
        if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
            && allow_retry
            && attempts < 4
        {
            continue;
        }
        if !response.status().is_success() {
            let status = match response.status() {
                reqwest::StatusCode::TOO_MANY_REQUESTS => "rate_limited",
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => "auth_failed",
                reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::GATEWAY_TIMEOUT => {
                    "timed_out"
                }
                _ => "failed",
            };
            return Ok((status.to_owned(), findings));
        }
        let evidence_url = response.url().to_string();
        let response_headers = response.headers().clone();
        let wire = match response.bytes().await {
            Ok(wire) => wire,
            Err(_) => return Ok(("failed".to_owned(), findings)),
        };
        let decoded = match decode_conformance_body(&response_headers, &wire, max_decoded_bytes) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(("failed".to_owned(), findings)),
        };
        let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
            for (fqdn, record_id) in public_text_response_records(&response_headers, &decoded) {
                findings.push(serde_json::json!({
                    "fqdn":fqdn,
                    "evidence":[{
                        "source_id":source_id,
                        "source_kind":source_kind.clone(),
                        "record_id":record_id,
                        "url":evidence_url,
                        "observed_at":serde_json::Value::Null,
                        "tags":[],
                        "confidence":serde_json::Value::Null,
                    }]
                }));
            }
            return Ok(("succeeded".to_owned(), findings));
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
                    "url":evidence_url,
                    "observed_at":item.get("observed_at").and_then(serde_json::Value::as_str),
                    "tags":item.get("tags").cloned().unwrap_or_else(|| serde_json::json!([])),
                    "confidence":item.get("confidence").and_then(serde_json::Value::as_f64),
                }]
            }));
        }
        let next_token = next_page_field
            .and_then(|field| payload.get(field))
            .and_then(|value| match value {
                serde_json::Value::String(value) if !value.is_empty() => Some(value.clone()),
                serde_json::Value::Number(value) => Some(value.to_string()),
                _ => None,
            });
        let Some(token) = next_token else {
            return Ok(("succeeded".to_owned(), findings));
        };
        let Some(parameter) = pagination_parameter else {
            return Ok(("failed".to_owned(), findings));
        };
        if seen_tokens.iter().any(|seen| seen == &token) {
            return Ok(("failed".to_owned(), findings));
        }
        seen_tokens.push(token.clone());
        query.insert(parameter.to_owned(), token);
    }
}

/// Parses bounded text, HTML, and CSV replies that a source advertised over
/// the public manifest. This remains entirely response-driven: it neither
/// loads campaign fixtures nor consults scenario truth.
fn public_text_response_records(
    headers: &HeaderMap,
    decoded: &[u8],
) -> Vec<(String, Option<String>)> {
    let Ok(body) = std::str::from_utf8(decoded) else {
        return Vec::new();
    };
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if content_type.starts_with("text/csv") {
        return public_csv_response_records(body);
    }
    if content_type.starts_with("text/html") {
        return public_html_response_records(body);
    }
    body.split_whitespace()
        .take(256)
        .filter_map(public_response_candidate)
        .map(|fqdn| (fqdn, None))
        .collect()
}

fn public_csv_response_records(body: &str) -> Vec<(String, Option<String>)> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(body.as_bytes());
    let Ok(headers) = reader.headers().cloned() else {
        return Vec::new();
    };
    let host_index = headers.iter().position(|header| header == "host");
    let record_id_index = headers.iter().position(|header| header == "id");
    let Some(host_index) = host_index else {
        return Vec::new();
    };
    reader
        .records()
        .take(64)
        .filter_map(Result::ok)
        .filter_map(|record| {
            let fqdn = record.get(host_index).and_then(public_response_candidate)?;
            let record_id = record_id_index
                .and_then(|index| record.get(index))
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            Some((fqdn, record_id))
        })
        .collect()
}

fn public_html_response_records(body: &str) -> Vec<(String, Option<String>)> {
    let document = Html::parse_fragment(body);
    let Ok(selector) = Selector::parse("a[href]") else {
        return Vec::new();
    };
    document
        .select(&selector)
        .take(64)
        .filter_map(|anchor| anchor.value().attr("href"))
        .filter_map(public_response_candidate)
        .map(|fqdn| (fqdn, None))
        .collect()
}

fn public_response_candidate(value: &str) -> Option<String> {
    let value = value.trim_matches(|character: char| "\"'<>),;".contains(character));
    let candidate = Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| value.to_owned());
    lab_core::normalize_domain(&candidate).ok()
}

fn retry_after_virtual_ms(headers: &HeaderMap) -> u64 {
    let Some(value) = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
    else {
        return 1;
    };
    if let Ok(seconds) = value.parse::<u64>() {
        return seconds.saturating_mul(1_000).max(1);
    }
    // HTTP-date is intentionally parsed, but the loopback virtual clock uses
    // the bounded V1.4 retry quantum rather than wall-clock time.
    chrono::DateTime::parse_from_rfc2822(value)
        .map(|_| 2_000)
        .unwrap_or(1)
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
    source: &serde_json::Value,
    run_id: &str,
    max_decoded_bytes: usize,
) -> anyhow::Result<(String, Vec<serde_json::Value>)> {
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
    if !response.starts_with("HTTP/1.1 200") {
        let status = if response.starts_with("HTTP/1.1 407") || response.starts_with("HTTP/1.1 403")
        {
            "auth_failed"
        } else if response.starts_with("HTTP/1.1 504") {
            "timed_out"
        } else {
            "failed"
        };
        return Ok((status.to_owned(), Vec::new()));
    }
    let source_id = source
        .get("source_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("CONNECT source is missing source_id"))?;
    let source_kind = source
        .get("source_kind")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("CONNECT source is missing source_kind"))?;
    let base_url = source
        .get("base_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("CONNECT source is missing base_url"))?;
    let path = source
        .get("path_template")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("CONNECT source is missing path_template"))?;
    let mut url = Url::parse(&format!("{base_url}{path}"))?;
    if let Some(query) = source
        .get("required_query")
        .and_then(serde_json::Value::as_object)
    {
        url.query_pairs_mut().extend_pairs(
            query
                .iter()
                .filter_map(|(name, value)| value.as_str().map(|value| (name.as_str(), value))),
        );
    }
    let host = format!(
        "127.0.0.1:{}",
        url.port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("CONNECT source URL is missing a port"))?
    );
    let request_path = if let Some(query) = url.query() {
        format!("{}?{query}", url.path())
    } else {
        url.path().to_owned()
    };
    let mut request = format!(
        "GET {request_path} HTTP/1.1\r\nHost: {host}\r\nx-lab-run-id: {run_id}\r\nx-lab-data-profile: default\r\nx-lab-client-virtual-wait-ms: 0\r\nConnection: close\r\n"
    );
    if let Some(authentication) = source
        .get("authentication")
        .and_then(serde_json::Value::as_object)
    {
        for (name, value) in authentication {
            let value = value.as_str().ok_or_else(|| {
                anyhow::anyhow!("CONNECT source authentication value is not a string")
            })?;
            request.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    request.push_str("\r\n");
    if stream.write_all(request.as_bytes()).await.is_err() {
        return Ok(("failed".to_owned(), Vec::new()));
    }
    let mut wire = Vec::new();
    if !matches!(
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.read_to_end(&mut wire),
        )
        .await,
        Ok(Ok(_))
    ) {
        return Ok(("failed".to_owned(), Vec::new()));
    }
    let Some(headers_end) = wire.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(("failed".to_owned(), Vec::new()));
    };
    let response_head = std::str::from_utf8(&wire[..headers_end])?;
    let mut lines = response_head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Ok(("failed".to_owned(), Vec::new()));
    }
    let mut headers = HeaderMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (Ok(name), Ok(value)) = (
            name.parse::<reqwest::header::HeaderName>(),
            value.trim().parse::<HeaderValue>(),
        ) else {
            continue;
        };
        headers.insert(name, value);
    }
    let decoded =
        match decode_conformance_body(&headers, &wire[headers_end + 4..], max_decoded_bytes) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(("failed".to_owned(), Vec::new())),
        };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
        return Ok(("succeeded".to_owned(), Vec::new()));
    };
    let evidence_url: String = url.into();
    let findings = payload
        .get("items")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let fqdn = item.get("host").and_then(serde_json::Value::as_str)?;
            Some(serde_json::json!({
                "fqdn":fqdn,
                "evidence":[{
                    "source_id":source_id,
                    "source_kind":source_kind.clone(),
                    "record_id":item.get("id").and_then(serde_json::Value::as_str),
                    "url":evidence_url,
                    "observed_at":item.get("observed_at").and_then(serde_json::Value::as_str),
                    "tags":item.get("tags").cloned().unwrap_or_else(|| serde_json::json!([])),
                    "confidence":item.get("confidence").and_then(serde_json::Value::as_f64),
                }]
            }))
        })
        .collect();
    Ok(("succeeded".to_owned(), findings))
}

async fn proxy_auth_challenge_probe(
    proxy_url: &str,
    source_url: &str,
    run_id: Uuid,
) -> anyhow::Result<()> {
    let proxy = Url::parse(proxy_url)?;
    let source = Url::parse(source_url)?;
    let port = proxy
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("proxy URL has no port"))?;
    let target = format!(
        "http://127.0.0.1:{}{}",
        source.port_or_known_default().unwrap_or_default(),
        "/v14/094?domain=s094.v14.test"
    );
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nx-lab-run-id: {run_id}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = [0_u8; 256];
    let count = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        stream.read(&mut response),
    )
    .await??;
    let response = String::from_utf8_lossy(&response[..count]);
    if !response.starts_with("HTTP/1.1 407") {
        anyhow::bail!("proxy auth challenge did not return 407");
    }
    Ok(())
}

async fn proxy_auth_challenge_from_manifest(
    network: &serde_json::Map<String, serde_json::Value>,
    source: &serde_json::Value,
    run_id: &str,
) -> anyhow::Result<()> {
    let proxy_url = network
        .get("proxy_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("proxy-auth manifest is missing proxy_url"))?;
    let proxy = Url::parse(proxy_url)?;
    if proxy.scheme() != "http" || proxy.host_str() != Some("127.0.0.1") {
        anyhow::bail!("proxy-auth manifest proxy is not numeric IPv4 loopback");
    }
    let base_url = source
        .get("base_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("proxy-auth manifest source is missing base_url"))?;
    let path = source
        .get("path_template")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("proxy-auth manifest source is missing path_template"))?;
    let mut target = Url::parse(&format!("{base_url}{path}"))?;
    if let Some(query) = source
        .get("required_query")
        .and_then(serde_json::Value::as_object)
    {
        target.query_pairs_mut().extend_pairs(
            query
                .iter()
                .filter_map(|(name, value)| value.as_str().map(|value| (name.as_str(), value))),
        );
    }
    let target: String = target.into();
    let source = Url::parse(base_url)?;
    let host = format!(
        "127.0.0.1:{}",
        source
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("proxy-auth source has no port"))?
    );
    let port = proxy
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("proxy-auth proxy has no port"))?;
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nx-lab-run-id: {run_id}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = [0_u8; 256];
    let count = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        stream.read(&mut response),
    )
    .await
    .map_err(|_| anyhow::anyhow!("proxy-auth loopback challenge timed out"))??;
    if !std::str::from_utf8(&response[..count])?.starts_with("HTTP/1.1 407") {
        anyhow::bail!("proxy-auth loopback challenge did not return 407");
    }
    Ok(())
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
            let prior_integrity = prior.report.semantic_fingerprint
                == semantic_fingerprint(&prior.report)
                && prior.manifest.scenario_id == prior.report.scenario_id
                && prior.report.provenance.campaign_id.as_deref()
                    == Some(prior.manifest.campaign_id.as_str())
                && prior.report.provenance.campaign_seed == Some(prior.manifest.seed)
                && prior.report.provenance.campaign_operators == prior.manifest.operators
                && prior.report.provenance.fixture_digest == prior.manifest.fixture_digest
                && prior.report.provenance.actual_truth_digest == prior.manifest.truth_digest;
            let matched = prior_integrity
                && prior.manifest.fixture_digest == current.manifest.fixture_digest
                && prior.manifest.truth_digest == current.manifest.truth_digest
                && prior.report.semantic_fingerprint == current.report.semantic_fingerprint
                && prior.report.provenance.actual_response_digest
                    == current.report.provenance.actual_response_digest
                && prior.report.provenance.actual_truth_digest
                    == current.report.provenance.actual_truth_digest;
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
    report.provenance.campaign_operators = manifest.operators.clone();
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
            let mut baseline = baseline_from_reports(&profile, &reports);
            let soak =
                run_public_soak_for_repository(repository, SoakPreset::Smoke, 11_100).await?;
            baseline.public_soak = Some(soak_baseline_from_report(&soak));
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
            match &baseline.public_soak {
                Some(expected) => {
                    let actual =
                        run_public_soak_for_repository(repository, expected.preset, expected.seed)
                            .await?;
                    if !soak_baseline_matches(expected, &actual) {
                        eprintln!("baseline mismatch for public soak summary");
                        passed = false;
                    }
                }
                None => {
                    eprintln!("baseline is missing its required public soak summary");
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
        "111-mixed-lifecycle-soak",
        "112-concurrent-mixed-fault-soak",
        "114-coverage-and-baseline-integrity",
    ];
    let mut reports = Vec::with_capacity(ids.len());
    for id in ids {
        reports.push(run_one(repository, id, "default", None).await?);
    }
    for (campaign, seed) in [
        ("107-json-structural-mutation-campaign", 10_701),
        ("108-text-html-csv-mutation-campaign", 10_801),
        ("109-pagination-token-mutation-campaign", 10_901),
        ("110-transport-framing-mutation-campaign", 11_001),
    ] {
        reports.push(execute_campaign(repository, campaign, seed).await?.report);
    }
    Ok(reports)
}

const PUBLIC_SOAK_ACTIONS_PER_LIFECYCLE: usize = 13;
const PUBLIC_SOAK_SCENARIO_POOL: &[&str] = &[
    "091-pagination-second-page-rate-limit",
    "094-proxy-auth-then-source-rate-limit",
    "096-connect-tunnel-truncated-payload",
    "099-multi-source-global-quota-isolation",
    "101-proxy-target-canonicalization",
    "105-stale-capability-after-reset-delete",
    "106-concurrent-cross-run-lifecycle",
    "107-json-structural-mutation-campaign",
    "111-mixed-lifecycle-soak",
    "112-concurrent-mixed-fault-soak",
];
const PUBLIC_SOAK_LIFECYCLE_SCENARIOS: &[&str] = &[
    "111-mixed-lifecycle-soak",
    "112-concurrent-mixed-fault-soak",
    "107-json-structural-mutation-campaign",
];

async fn soak_command(repository: &ScenarioRepository, args: &[String]) -> anyhow::Result<bool> {
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
    let report = run_public_soak_for_repository(repository, preset, seed).await?;
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

async fn run_public_soak_for_repository(
    repository: &ScenarioRepository,
    preset: SoakPreset,
    seed: u64,
) -> anyhow::Result<SoakReport> {
    cleanup_public_soak_replay_artifacts()?;
    let server = LocalServer::spawn(repository.clone(), None)
        .await
        .map_err(anyhow::Error::msg)?;
    let result = run_public_http_soak(&server, preset, seed).await;
    server.shutdown().await;
    let mut report = result?;
    report
        .invariants
        .insert("server_shutdown_completed".to_owned(), true);
    Ok(report)
}

fn soak_baseline_matches(expected: &lab_core::SoakBaseline, actual: &SoakReport) -> bool {
    actual.operations >= expected.minimum_operations
        && actual.concurrency == expected.concurrency
        && actual.action_counts == expected.action_counts
        && actual.outcome_counts == expected.outcome_counts
        && expected
            .invariants
            .keys()
            .all(|name| actual.invariants.get(name) == Some(&true))
        && actual.last_failure.is_none()
}

/// Release soak uses the same loopback control, source, proxy, submission and
/// report interfaces exposed to a collector.  The only state read is the final
/// resource summary after every public lifecycle task has finished.
async fn run_public_http_soak(
    server: &LocalServer,
    preset: SoakPreset,
    seed: u64,
) -> anyhow::Result<SoakReport> {
    let base_url = server.base_url();
    let concurrency = preset.concurrency().min(preset.operations());
    let cycles_per_lane = preset
        .operations()
        .div_ceil(concurrency * PUBLIC_SOAK_ACTIONS_PER_LIFECYCLE);
    let start = Arc::new(Barrier::new(concurrency));
    let next_index = Arc::new(AtomicUsize::new(0));
    let mut workers = JoinSet::new();
    for lane in 0..concurrency {
        let start = Arc::clone(&start);
        let next_index = Arc::clone(&next_index);
        let base_url = base_url.clone();
        workers.spawn(async move {
            let client = Client::builder()
                .redirect(Policy::none())
                .no_proxy()
                .build()?;
            start.wait().await;
            let mut actions =
                Vec::with_capacity(cycles_per_lane * PUBLIC_SOAK_ACTIONS_PER_LIFECYCLE);
            let mut lane_failure = None;
            for cycle in 0..cycles_per_lane {
                let cycle_result = async {
                    if lane == 0 && cycle == 0 {
                        run_public_soak_connect_probe(
                            &client,
                            &base_url,
                            &next_index,
                            &mut actions,
                            lane,
                            seed,
                        )
                        .await?;
                        run_public_soak_script_fault_probe(
                            &client,
                            &base_url,
                            &next_index,
                            &mut actions,
                            lane,
                            seed,
                        )
                        .await?;
                    }
                    let scenario_id = PUBLIC_SOAK_LIFECYCLE_SCENARIOS
                        [(lane + cycle) % PUBLIC_SOAK_LIFECYCLE_SCENARIOS.len()];
                    let lifecycle_seed = seed
                        .wrapping_add((lane as u64).wrapping_mul(10_000))
                        .wrapping_add(cycle as u64);
                    run_public_soak_lifecycle(
                        &client,
                        &base_url,
                        scenario_id,
                        lifecycle_seed,
                        &next_index,
                        &mut actions,
                        lane,
                        cycle == 0,
                        lane == 0 && cycle == 0,
                    )
                    .await
                }
                .await;
                if let Err(error) = cycle_result {
                    lane_failure = Some(error.to_string());
                    break;
                }
            }
            Ok::<(Vec<SoakAction>, Option<String>), anyhow::Error>((actions, lane_failure))
        });
    }

    let mut actions = Vec::new();
    let mut last_failure = None;
    while let Some(result) = workers.join_next().await {
        match result {
            Ok(Ok((mut lane_actions, lane_failure))) => {
                actions.append(&mut lane_actions);
                if last_failure.is_none() {
                    last_failure = lane_failure;
                }
            }
            Ok(Err(error)) if last_failure.is_none() => last_failure = Some(error.to_string()),
            Err(error) if last_failure.is_none() => {
                last_failure = Some(format!("public soak worker failed: {error}"));
            }
            _ => {}
        }
    }
    actions.sort_by_key(|action| action.index);
    let action_counts = soak_counts(&actions, |action| &action.endpoint);
    let outcome_counts = soak_counts(&actions, |action| &action.outcome);
    let resources = server.resource_summary();
    let expected_minimum = preset.operations();
    let trace_coverage = public_soak_trace_coverage(&actions);
    let evidence_endpoints = ["source", "proxy", "connect", "submission", "report"];
    let all_actions_have_evidence = actions.iter().all(|action| {
        !evidence_endpoints.contains(&action.endpoint.as_str()) || action.audit_count > 0
    });
    let invariants = BTreeMap::from([
        (
            "public_actions_at_least_preset".to_owned(),
            actions.len() >= expected_minimum,
        ),
        ("has_source_actions".to_owned(), trace_coverage["source"]),
        ("has_proxy_actions".to_owned(), trace_coverage["proxy"]),
        ("has_connect_actions".to_owned(), trace_coverage["connect"]),
        (
            "has_submission_actions".to_owned(),
            trace_coverage["submission"],
        ),
        ("has_replay_actions".to_owned(), trace_coverage["replay"]),
        (
            "release_trace_coverage_complete".to_owned(),
            trace_coverage.values().all(|covered| *covered),
        ),
        (
            "trace_has_public_endpoint_evidence".to_owned(),
            all_actions_have_evidence,
        ),
        (
            "trace_uses_no_internal_helpers".to_owned(),
            actions
                .iter()
                .all(|action| action.endpoint != "internal-test-helper"),
        ),
        (
            "trace_run_identifiers_are_redacted_and_present".to_owned(),
            actions.iter().all(|action| {
                action
                    .run_id
                    .as_deref()
                    .is_some_and(|run_id| run_id.len() == 8)
            }),
        ),
        (
            "no_live_runs".to_owned(),
            resources.active_runs == 0 && resources.reset_runs == 0,
        ),
        (
            "no_active_proxy_connections".to_owned(),
            resources.active_proxy_connections == 0,
        ),
        (
            "no_quota_state_entries".to_owned(),
            resources.quota_state_entries == 0,
        ),
        (
            "trace_is_ordered_and_complete".to_owned(),
            actions.windows(2).all(|pair| pair[0].index < pair[1].index)
                && actions.iter().all(|action| action.run_id.is_some()),
        ),
        (
            "temporary_replay_artifacts_cleaned".to_owned(),
            public_soak_replay_artifacts_clean(),
        ),
    ]);
    Ok(SoakReport {
        schema_version: V14_SCHEMA_VERSION.to_owned(),
        preset,
        seed,
        operations: actions.len(),
        concurrency,
        action_trace: actions,
        scenario_pool: PUBLIC_SOAK_SCENARIO_POOL
            .iter()
            .map(|scenario| (*scenario).to_owned())
            .collect(),
        trace_coverage,
        action_counts,
        outcome_counts,
        resources,
        invariants,
        last_failure,
        reproduction_command: format!(
            "cargo run -p lab-cli -- soak run --preset {} --seed {seed}",
            match preset {
                SoakPreset::Smoke => "smoke",
                SoakPreset::Standard => "standard",
                SoakPreset::Release => "release",
            }
        ),
    })
}

fn soak_counts<F>(actions: &[SoakAction], key: F) -> BTreeMap<String, usize>
where
    F: Fn(&SoakAction) -> &String,
{
    actions.iter().fold(BTreeMap::new(), |mut counts, action| {
        *counts.entry(key(action).clone()).or_default() += 1;
        counts
    })
}

#[allow(clippy::too_many_arguments)]
fn record_public_soak_action(
    actions: &mut Vec<SoakAction>,
    next_index: &AtomicUsize,
    lane: usize,
    operation: &str,
    endpoint: &str,
    scenario_id: &str,
    run: &CreatedRun,
    seed: u64,
    outcome: &str,
    audit_count: usize,
) {
    actions.push(SoakAction {
        index: next_index.fetch_add(1, Ordering::Relaxed) + 1,
        lane,
        operation: operation.to_owned(),
        scenario_id: scenario_id.to_owned(),
        outcome: outcome.to_owned(),
        run_id: Some(run.run_id.to_string()[..8].to_owned()),
        endpoint: endpoint.to_owned(),
        seed,
        audit_count,
    });
}

#[allow(clippy::too_many_arguments)]
async fn run_public_soak_lifecycle(
    client: &Client,
    base_url: &str,
    scenario_id: &str,
    seed: u64,
    next_index: &AtomicUsize,
    actions: &mut Vec<SoakAction>,
    lane: usize,
    strict_replay: bool,
    strict_replay_mismatch: bool,
) -> anyhow::Result<()> {
    let mut run = create_run(client, base_url, scenario_id, Some(seed)).await?;
    let result = async {
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "create",
            "control",
            scenario_id,
            &run,
            seed,
            "success",
            0,
        );
        let old_manifest = public_manifest(client, base_url, &run).await?;
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "manifest",
            "manifest",
            scenario_id,
            &run,
            seed,
            "success",
            0,
        );
        let (source_statuses, findings, source_endpoint) =
            collect_public_manifest(client, &old_manifest, &run.run_id.to_string()).await?;
        if !public_source_succeeded(&source_statuses) {
            anyhow::bail!("public soak source did not reach a successful terminal status");
        }
        let source_audit_count = fetch_audit(client, base_url, &run).await?.len();
        record_public_soak_action(
            actions,
            next_index,
            lane,
            if source_endpoint == "proxy" {
                "source_proxy"
            } else {
                "source_direct"
            },
            &source_endpoint,
            scenario_id,
            &run,
            seed,
            "success",
            source_audit_count,
        );
        let mut submission = public_submission_payload(&old_manifest, source_statuses, findings)?;
        submission["collector"]["name"] =
            serde_json::Value::String(format!("fqdn-forge-public-soak-seed-{seed}"));
        let mut invalid_submission = submission.clone();
        invalid_submission["fake_token"] = serde_json::Value::String("redacted".to_owned());
        submit_public_rejected(client, base_url, &run, &invalid_submission).await?;
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "submission_invalid",
            "submission",
            scenario_id,
            &run,
            seed,
            "expected_rejected",
            fetch_audit(client, base_url, &run).await?.len(),
        );
        submit_public(client, base_url, &run, &submission).await?;
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "submission_valid",
            "submission",
            scenario_id,
            &run,
            seed,
            "success",
            fetch_audit(client, base_url, &run).await?.len(),
        );
        let report = public_report(client, base_url, &run).await?;
        if report.status != ReportStatus::Passed || report.requests.is_empty() {
            anyhow::bail!("public soak submission did not produce a complete passed report");
        }
        if report
            .requests
            .iter()
            .any(|audit| audit.run_id != Some(run.run_id.to_string()))
        {
            anyhow::bail!("public soak report contains cross-run audit evidence");
        }
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "report",
            "report",
            scenario_id,
            &run,
            seed,
            "success",
            report.requests.len(),
        );
        if strict_replay {
            run_strict_public_soak_replay(&report, true).await?;
            record_public_soak_action(
                actions,
                next_index,
                lane,
                "replay_strict",
                "replay",
                scenario_id,
                &run,
                seed,
                "matched",
                report.requests.len(),
            );
        }
        if strict_replay_mismatch {
            run_strict_public_soak_replay(&report, false).await?;
            record_public_soak_action(
                actions,
                next_index,
                lane,
                "replay_intentional_mismatch",
                "replay",
                scenario_id,
                &run,
                seed,
                "expected_mismatch",
                report.requests.len(),
            );
        }

        let stale_access_token = run.access_token.clone();
        let reset: serde_json::Value = client
            .post(format!("{base_url}/api/runs/{}/reset", run.run_id))
            .header("x-lab-run-access-token", &run.access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        run.access_token = reset
            .get("run_access_token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("reset response is missing replacement capability"))?
            .to_owned();
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "reset",
            "control",
            scenario_id,
            &run,
            seed,
            "success",
            0,
        );
        let stale_manifest_response = client
            .get(format!("{base_url}/api/runs/{}/manifest", run.run_id))
            .header("x-lab-run-access-token", stale_access_token)
            .send()
            .await?;
        if stale_manifest_response.status().is_success() {
            anyhow::bail!("reset left the old run-control capability usable");
        }
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "stale_after_reset_control",
            "stale_probe",
            scenario_id,
            &run,
            seed,
            "expected_rejected",
            0,
        );
        let (stale_statuses, _, _) =
            collect_public_manifest(client, &old_manifest, &run.run_id.to_string()).await?;
        if public_source_succeeded(&stale_statuses) {
            anyhow::bail!("reset left the old source or proxy capability usable");
        }
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "stale_after_reset_source",
            "stale_probe",
            scenario_id,
            &run,
            seed,
            "expected_rejected",
            fetch_audit(client, base_url, &run).await?.len(),
        );
        let new_manifest = public_manifest(client, base_url, &run).await?;
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "manifest_after_reset",
            "manifest",
            scenario_id,
            &run,
            seed,
            "success",
            0,
        );
        let (new_statuses, _, new_source_endpoint) =
            collect_public_manifest(client, &new_manifest, &run.run_id.to_string()).await?;
        if !public_source_succeeded(&new_statuses) {
            anyhow::bail!("new source/proxy capability did not work after reset");
        }
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "source_after_reset",
            &new_source_endpoint,
            scenario_id,
            &run,
            seed,
            "success",
            fetch_audit(client, base_url, &run).await?.len(),
        );
        delete_public_run(client, base_url, &run).await?;
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "delete",
            "control",
            scenario_id,
            &run,
            seed,
            "success",
            0,
        );
        ensure_post_delete_rejections(
            client,
            base_url,
            &run,
            &old_manifest,
            &new_manifest,
            &submission,
        )
        .await?;
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "stale_after_delete",
            "stale_probe",
            scenario_id,
            &run,
            seed,
            "expected_rejected",
            0,
        );
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = delete_public_run(client, base_url, &run).await;
    }
    result
}

async fn run_public_soak_script_fault_probe(
    client: &Client,
    base_url: &str,
    next_index: &AtomicUsize,
    actions: &mut Vec<SoakAction>,
    lane: usize,
    seed: u64,
) -> anyhow::Result<()> {
    let scenario_id = "111-mixed-lifecycle-soak";
    let run = create_run(client, base_url, scenario_id, Some(seed)).await?;
    let result = async {
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "create",
            "control",
            scenario_id,
            &run,
            seed,
            "success",
            0,
        );
        let manifest = public_manifest(client, base_url, &run).await?;
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "manifest",
            "manifest",
            scenario_id,
            &run,
            seed,
            "success",
            0,
        );
        let (statuses, _, endpoint) =
            collect_public_manifest(client, &manifest, &run.run_id.to_string()).await?;
        if !public_source_succeeded(&statuses) {
            anyhow::bail!("script-fault soak probe did not complete its initial source request");
        }
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "source_direct",
            &endpoint,
            scenario_id,
            &run,
            seed,
            "success",
            fetch_audit(client, base_url, &run).await?.len(),
        );
        let (fault_statuses, _, _) =
            collect_public_manifest(client, &manifest, &run.run_id.to_string()).await?;
        if public_source_succeeded(&fault_statuses) {
            anyhow::bail!("script-fault soak probe accepted an out-of-order source request");
        }
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "source_script_fault",
            &endpoint,
            scenario_id,
            &run,
            seed,
            "expected_rejected",
            fetch_audit(client, base_url, &run).await?.len(),
        );
        delete_public_run(client, base_url, &run).await?;
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "delete",
            "control",
            scenario_id,
            &run,
            seed,
            "success",
            0,
        );
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = delete_public_run(client, base_url, &run).await;
    }
    result
}

async fn run_public_soak_connect_probe(
    client: &Client,
    base_url: &str,
    next_index: &AtomicUsize,
    actions: &mut Vec<SoakAction>,
    lane: usize,
    seed: u64,
) -> anyhow::Result<()> {
    let scenario_id = "096-connect-tunnel-truncated-payload";
    let run = create_run(client, base_url, scenario_id, Some(seed)).await?;
    let result = async {
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "create",
            "control",
            scenario_id,
            &run,
            seed,
            "success",
            0,
        );
        let manifest = public_manifest(client, base_url, &run).await?;
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "manifest",
            "manifest",
            scenario_id,
            &run,
            seed,
            "success",
            0,
        );
        let (statuses, _, endpoint) =
            collect_public_manifest(client, &manifest, &run.run_id.to_string()).await?;
        if endpoint != "connect" || public_source_succeeded(&statuses) {
            anyhow::bail!("CONNECT soak probe did not expose the expected truncated tunnel result");
        }
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "connect_truncated",
            "connect",
            scenario_id,
            &run,
            seed,
            "expected_rejected",
            fetch_audit(client, base_url, &run).await?.len(),
        );
        delete_public_run(client, base_url, &run).await?;
        record_public_soak_action(
            actions,
            next_index,
            lane,
            "delete",
            "control",
            scenario_id,
            &run,
            seed,
            "success",
            0,
        );
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = delete_public_run(client, base_url, &run).await;
    }
    result
}

fn public_soak_trace_coverage(actions: &[SoakAction]) -> BTreeMap<String, bool> {
    let has_endpoint = |endpoint: &str| actions.iter().any(|action| action.endpoint == endpoint);
    BTreeMap::from([
        ("control".to_owned(), has_endpoint("control")),
        ("manifest".to_owned(), has_endpoint("manifest")),
        ("source".to_owned(), has_endpoint("source")),
        ("proxy".to_owned(), has_endpoint("proxy")),
        ("connect".to_owned(), has_endpoint("connect")),
        ("submission".to_owned(), has_endpoint("submission")),
        ("report".to_owned(), has_endpoint("report")),
        ("replay".to_owned(), has_endpoint("replay")),
        ("stale_probe".to_owned(), has_endpoint("stale_probe")),
        (
            "valid_submission".to_owned(),
            actions
                .iter()
                .any(|action| action.operation == "submission_valid"),
        ),
        (
            "invalid_submission".to_owned(),
            actions
                .iter()
                .any(|action| action.operation == "submission_invalid"),
        ),
        (
            "expected_rejection".to_owned(),
            actions
                .iter()
                .any(|action| action.outcome == "expected_rejected"),
        ),
        (
            "strict_replay_matched".to_owned(),
            actions.iter().any(|action| action.outcome == "matched"),
        ),
        (
            "strict_replay_mismatch".to_owned(),
            actions
                .iter()
                .any(|action| action.outcome == "expected_mismatch"),
        ),
        (
            "script_fault".to_owned(),
            actions
                .iter()
                .any(|action| action.operation == "source_script_fault"),
        ),
        (
            "campaign_or_dynamic_fixture".to_owned(),
            actions.iter().any(|action| {
                action.scenario_id == "107-json-structural-mutation-campaign"
                    && action.endpoint == "source"
            }),
        ),
        (
            "reset_stale_rejection".to_owned(),
            actions
                .iter()
                .any(|action| action.operation == "stale_after_reset_source"),
        ),
        (
            "delete_stale_rejection".to_owned(),
            actions
                .iter()
                .any(|action| action.operation == "stale_after_delete"),
        ),
        (
            "multiple_lanes".to_owned(),
            actions
                .iter()
                .map(|action| action.lane)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                >= 2,
        ),
    ])
}

async fn run_strict_public_soak_replay(
    report: &lab_core::RunReport,
    expected_match: bool,
) -> anyhow::Result<()> {
    let directory = PathBuf::from("artifacts/soak/replay");
    fs::create_dir_all(&directory)?;
    let stem = format!("public-soak-replay-{}-{}", report.seed, Uuid::new_v4());
    let input_path = directory.join(format!("{stem}.json"));
    let mut replay_input = report.clone();
    if !expected_match {
        replay_input.virtual_waited_ms = replay_input.virtual_waited_ms.saturating_add(1);
    }
    let result = async {
        fs::write(&input_path, report_json(&replay_input)?)?;
        let executable = env::current_exe()?;
        let replay_path = input_path.clone();
        let output = tokio::task::spawn_blocking(move || {
            Command::new(executable)
                .args(["replay", "--strict", "--report"])
                .arg(replay_path)
                .output()
        })
        .await
        .context("strict replay process did not complete")??;
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let matched = output.status.success() && transcript.contains("replay result: matched");
        let explained_mismatch = !output.status.success()
            && transcript.contains("replay result: mismatch")
            && (transcript.contains("first semantic difference:")
                || transcript.contains("provenance:"));
        if expected_match && !matched {
            anyhow::bail!("strict replay did not match the public report: {transcript}");
        }
        if !expected_match && !explained_mismatch {
            anyhow::bail!("strict replay did not reject the controlled public-report mismatch");
        }
        Ok(())
    }
    .await;
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(&stem) {
            fs::remove_file(entry.path())?;
        }
    }
    result
}

fn public_soak_replay_artifacts_clean() -> bool {
    fs::read_dir("artifacts/soak/replay").map_or(true, |entries| {
        entries.flatten().all(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with("public-soak-replay-")
        })
    })
}

fn cleanup_public_soak_replay_artifacts() -> anyhow::Result<()> {
    let directory = PathBuf::from("artifacts/soak/replay");
    if !directory.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("public-soak-replay-")
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

async fn public_manifest(
    client: &Client,
    base_url: &str,
    run: &CreatedRun,
) -> anyhow::Result<serde_json::Value> {
    client
        .get(format!("{base_url}/api/runs/{}/manifest", run.run_id))
        .header("x-lab-run-access-token", &run.access_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .map_err(Into::into)
}

async fn submit_public(
    client: &Client,
    base_url: &str,
    run: &CreatedRun,
    submission: &serde_json::Value,
) -> anyhow::Result<()> {
    let response = client
        .post(format!("{base_url}/api/runs/{}/submission", run.run_id))
        .header("x-lab-run-access-token", &run.access_token)
        .json(submission)
        .send()
        .await?;
    if response.status() != reqwest::StatusCode::CREATED {
        anyhow::bail!(
            "public submission did not receive HTTP 201 (received {})",
            response.status()
        );
    }
    Ok(())
}

async fn submit_public_rejected(
    client: &Client,
    base_url: &str,
    run: &CreatedRun,
    submission: &serde_json::Value,
) -> anyhow::Result<()> {
    let response = client
        .post(format!("{base_url}/api/runs/{}/submission", run.run_id))
        .header("x-lab-run-access-token", &run.access_token)
        .json(submission)
        .send()
        .await?;
    if response.status().is_success() {
        anyhow::bail!("intentionally invalid public submission was accepted");
    }
    Ok(())
}

async fn delete_public_run(
    client: &Client,
    base_url: &str,
    run: &CreatedRun,
) -> anyhow::Result<()> {
    let response = client
        .delete(format!("{base_url}/api/runs/{}", run.run_id))
        .header("x-lab-run-access-token", &run.access_token)
        .send()
        .await?;
    if response.status() != reqwest::StatusCode::NO_CONTENT {
        anyhow::bail!("public soak could not delete a lifecycle run");
    }
    Ok(())
}

async fn public_report(
    client: &Client,
    base_url: &str,
    run: &CreatedRun,
) -> anyhow::Result<lab_core::RunReport> {
    let response: serde_json::Value = client
        .get(format!("{base_url}/api/runs/{}/report", run.run_id))
        .header("x-lab-run-access-token", &run.access_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    serde_json::from_value(
        response
            .get("report")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("public report response is missing report"))?,
    )
    .map_err(Into::into)
}

fn public_submission_payload(
    manifest: &serde_json::Value,
    source_statuses: serde_json::Map<String, serde_json::Value>,
    findings: Vec<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let target_domain = manifest
        .get("target_domain")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("manifest is missing target_domain"))?;
    Ok(serde_json::json!({
        "schema_version": V14_SCHEMA_VERSION,
        "collector":{"name":"fqdn-forge-public-soak","version":V14_SCHEMA_VERSION},
        "target_domain":target_domain,
        "source_statuses":source_statuses,
        "findings":findings,
    }))
}

fn public_source_succeeded(source_statuses: &serde_json::Map<String, serde_json::Value>) -> bool {
    !source_statuses.is_empty()
        && source_statuses
            .values()
            .all(|status| status.as_str() == Some("succeeded"))
}

async fn collect_public_manifest(
    client: &Client,
    manifest: &serde_json::Value,
    run_id: &str,
) -> anyhow::Result<(
    serde_json::Map<String, serde_json::Value>,
    Vec<serde_json::Value>,
    String,
)> {
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
    let network_allows_retry = network
        .get("allow_retry")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let proxy_values = network
        .get("proxy_authentication")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut source_statuses = serde_json::Map::new();
    let mut findings = Vec::new();
    if network_mode == "connect_proxy" {
        for source in sources {
            let source_id = source
                .get("source_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("manifest source is missing source_id"))?;
            let (status, mut source_findings) =
                connect_conformance_probe(network, source, run_id, max_decoded_bytes).await?;
            source_statuses.insert(source_id.to_owned(), serde_json::Value::String(status));
            findings.append(&mut source_findings);
        }
        return Ok((source_statuses, findings, "connect".to_owned()));
    }
    let source_client = source_client_for_manifest(network)?;
    for source in sources {
        let source_id = source
            .get("source_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("manifest source is missing source_id"))?;
        let (status, mut source_findings) = collect_manifest_source(
            &source_client,
            source,
            network_mode,
            network_allows_retry,
            false,
            &proxy_values,
            run_id,
            max_decoded_bytes,
        )
        .await?;
        source_statuses.insert(source_id.to_owned(), serde_json::Value::String(status));
        findings.append(&mut source_findings);
    }
    let endpoint = if network_mode == "http_proxy" {
        "proxy"
    } else {
        "source"
    };
    let _ = client;
    Ok((source_statuses, findings, endpoint.to_owned()))
}

fn source_client_for_manifest(
    network: &serde_json::Map<String, serde_json::Value>,
) -> anyhow::Result<Client> {
    let network_mode = network
        .get("mode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("direct");
    if network_mode != "http_proxy" {
        return Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .map_err(Into::into);
    }
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
        .build()
        .map_err(Into::into)
}

async fn ensure_post_delete_rejections(
    client: &Client,
    base_url: &str,
    run: &CreatedRun,
    old_manifest: &serde_json::Value,
    new_manifest: &serde_json::Value,
    submission: &serde_json::Value,
) -> anyhow::Result<()> {
    for path in ["manifest", "report"] {
        let response = client
            .get(format!("{base_url}/api/runs/{}/{path}", run.run_id))
            .header("x-lab-run-access-token", &run.access_token)
            .send()
            .await?;
        if response.status().is_success() {
            anyhow::bail!("delete left the {path} endpoint accessible");
        }
    }
    let submission_response = client
        .post(format!("{base_url}/api/runs/{}/submission", run.run_id))
        .header("x-lab-run-access-token", &run.access_token)
        .json(submission)
        .send()
        .await?;
    if submission_response.status().is_success() {
        anyhow::bail!("delete left the submission endpoint accessible");
    }
    for manifest in [old_manifest, new_manifest] {
        let (statuses, _, _) =
            collect_public_manifest(client, manifest, &run.run_id.to_string()).await?;
        if public_source_succeeded(&statuses) {
            anyhow::bail!("delete left a source or proxy capability usable");
        }
    }
    Ok(())
}

async fn public_lifecycle_105_conformance(
    client: &Client,
    base_url: &str,
    seed: Option<u64>,
) -> anyhow::Result<serde_json::Value> {
    let mut run = create_run(
        client,
        base_url,
        "105-stale-capability-after-reset-delete",
        seed,
    )
    .await?;
    let result = async {
        let old_manifest = public_manifest(client, base_url, &run).await?;
        let (old_statuses, _, _) =
            collect_public_manifest(client, &old_manifest, &run.run_id.to_string()).await?;
        if !public_source_succeeded(&old_statuses) {
            anyhow::bail!("105 old source/proxy capability was not initially usable");
        }
        let stale_access_token = run.access_token.clone();
        let reset: serde_json::Value = client
            .post(format!("{base_url}/api/runs/{}/reset", run.run_id))
            .header("x-lab-run-access-token", &run.access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        run.access_token = reset
            .get("run_access_token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("105 reset did not return a new capability"))?
            .to_owned();
        let stale_control = client
            .get(format!("{base_url}/api/runs/{}/manifest", run.run_id))
            .header("x-lab-run-access-token", stale_access_token)
            .send()
            .await?;
        if stale_control.status().is_success() {
            anyhow::bail!("105 stale control capability remained valid after reset");
        }
        let (stale_statuses, _, _) =
            collect_public_manifest(client, &old_manifest, &run.run_id.to_string()).await?;
        if public_source_succeeded(&stale_statuses) {
            anyhow::bail!("105 stale source/proxy capability remained valid after reset");
        }
        let new_manifest = public_manifest(client, base_url, &run).await?;
        let (source_statuses, findings, _) =
            collect_public_manifest(client, &new_manifest, &run.run_id.to_string()).await?;
        if !public_source_succeeded(&source_statuses) {
            anyhow::bail!("105 replacement source/proxy capability was not usable");
        }
        let submission = public_submission_payload(&new_manifest, source_statuses, findings)?;
        let deleted = client
            .delete(format!("{base_url}/api/runs/{}", run.run_id))
            .header("x-lab-run-access-token", &run.access_token)
            .send()
            .await?;
        if deleted.status() != reqwest::StatusCode::NO_CONTENT {
            anyhow::bail!("105 delete did not return HTTP 204");
        }
        ensure_post_delete_rejections(
            client,
            base_url,
            &run,
            &old_manifest,
            &new_manifest,
            &submission,
        )
        .await?;
        let probe = create_run(
            client,
            base_url,
            "105-stale-capability-after-reset-delete",
            seed,
        )
        .await?;
        let probe_result = async {
            let manifest = public_manifest(client, base_url, &probe).await?;
            let (statuses, findings, _) =
                collect_public_manifest(client, &manifest, &probe.run_id.to_string()).await?;
            if !public_source_succeeded(&statuses) {
                anyhow::bail!("105 replacement run observed lifecycle contamination");
            }
            let probe_submission = public_submission_payload(&manifest, statuses, findings)?;
            submit_public(client, base_url, &probe, &probe_submission).await?;
            let report = public_report(client, base_url, &probe).await?;
            if report.status != ReportStatus::Passed {
                anyhow::bail!("105 fresh run did not produce a passed report");
            }
            serde_json::to_value(report).map_err(Into::into)
        }
        .await;
        let deleted_probe = client
            .delete(format!("{base_url}/api/runs/{}", probe.run_id))
            .header("x-lab-run-access-token", &probe.access_token)
            .send()
            .await?;
        if deleted_probe.status() != reqwest::StatusCode::NO_CONTENT {
            anyhow::bail!("105 replacement run could not be deleted");
        }
        probe_result
    }
    .await;
    if result.is_err() {
        let _ = client
            .delete(format!("{base_url}/api/runs/{}", run.run_id))
            .header("x-lab-run-access-token", &run.access_token)
            .send()
            .await;
    }
    result
}

async fn public_lifecycle_106_conformance(
    client: &Client,
    base_url: &str,
    seed: Option<u64>,
) -> anyhow::Result<serde_json::Value> {
    let a = create_run(client, base_url, "106-concurrent-cross-run-lifecycle", seed).await?;
    let mut b = create_run(
        client,
        base_url,
        "106-concurrent-cross-run-lifecycle",
        seed.map(|value| value.wrapping_add(1)),
    )
    .await?;
    let result = async {
        let (a_manifest, _) = tokio::try_join!(
            public_manifest(client, base_url, &a),
            public_manifest(client, base_url, &b)
        )?;
        let a_run_id = a.run_id.to_string();
        let b_run_id = b.run_id.to_string();
        let (cross_statuses, _, _) =
            collect_public_manifest(client, &a_manifest, &b_run_id).await?;
        if public_source_succeeded(&cross_statuses) {
            anyhow::bail!("106 accepted a cross-run source capability");
        }
        let reset: serde_json::Value = client
            .post(format!("{base_url}/api/runs/{}/reset", b.run_id))
            .header("x-lab-run-access-token", &b.access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        b.access_token = reset
            .get("run_access_token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("106 reset did not return a new capability"))?
            .to_owned();
        let b_manifest = public_manifest(client, base_url, &b).await?;
        let ((a_statuses, a_findings, _), (b_statuses, b_findings, _)) = tokio::try_join!(
            collect_public_manifest(client, &a_manifest, &a_run_id),
            collect_public_manifest(client, &b_manifest, &b_run_id)
        )?;
        if !public_source_succeeded(&a_statuses) || !public_source_succeeded(&b_statuses) {
            anyhow::bail!("106 concurrent runs did not each complete their own source request");
        }
        let a_submission = public_submission_payload(&a_manifest, a_statuses, a_findings)?;
        let b_submission = public_submission_payload(&b_manifest, b_statuses, b_findings)?;
        submit_public(client, base_url, &a, &a_submission).await?;
        let a_report = public_report(client, base_url, &a).await?;
        if a_report.status != ReportStatus::Passed {
            anyhow::bail!("106 first run did not produce a passed report");
        }
        let cross_submission = client
            .post(format!("{base_url}/api/runs/{}/submission", b.run_id))
            .header("x-lab-run-access-token", &b.access_token)
            .json(&a_submission)
            .send()
            .await?;
        if cross_submission.status().is_success() {
            anyhow::bail!("106 accepted a cross-run submission payload");
        }
        let cross_report = client
            .get(format!("{base_url}/api/runs/{}/report", a.run_id))
            .header("x-lab-run-access-token", &b.access_token)
            .send()
            .await?;
        if cross_report.status().is_success() {
            anyhow::bail!("106 accepted a cross-run report capability");
        }
        let a_audit = fetch_audit(client, base_url, &a).await?;
        if a_audit
            .iter()
            .any(|record| record.run_id.as_deref() != Some(&a_run_id))
        {
            anyhow::bail!("106 first run audit contains cross-run ownership");
        }
        let a_deleted = client
            .delete(format!("{base_url}/api/runs/{}", a.run_id))
            .header("x-lab-run-access-token", &a.access_token)
            .send()
            .await?;
        if a_deleted.status() != reqwest::StatusCode::NO_CONTENT {
            anyhow::bail!("106 first run could not be deleted");
        }
        let b_manifest_after_a_delete = public_manifest(client, base_url, &b).await?;
        if b_manifest_after_a_delete
            .get("run_id")
            .and_then(serde_json::Value::as_str)
            != Some(&b_run_id)
        {
            anyhow::bail!("106 second run manifest was contaminated by first-run deletion");
        }
        submit_public(client, base_url, &b, &b_submission).await?;
        let b_report = public_report(client, base_url, &b).await?;
        if b_report.status != ReportStatus::Passed {
            anyhow::bail!("106 second run could not complete while the first run reset/delete");
        }
        let b_audit = fetch_audit(client, base_url, &b).await?;
        if b_audit
            .iter()
            .any(|record| record.run_id.as_deref() != Some(&b_run_id))
        {
            anyhow::bail!("106 second run audit contains cross-run ownership");
        }
        serde_json::to_value(b_report).map_err(Into::into)
    }
    .await;
    for run in [&a, &b] {
        let _ = client
            .delete(format!("{base_url}/api/runs/{}", run.run_id))
            .header("x-lab-run-access-token", &run.access_token)
            .send()
            .await;
    }
    result
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
        for scenario_id in [
            "101-proxy-target-canonicalization",
            "102-proxy-authority-header-ambiguity",
            "103-proxy-encoded-and-userinfo-targets",
            "104-proxy-framing-and-header-limits",
        ] {
            raw_proxy_scenario_regression(
                &client,
                &server.base_url(),
                &server.proxy_url(),
                scenario_id,
            )
            .await?;
        }
        Ok(true)
    }
    .await;
    server.shutdown().await;
    result
}

async fn raw_proxy_scenario_regression(
    client: &Client,
    base_url: &str,
    proxy_url: &str,
    scenario_id: &str,
) -> anyhow::Result<()> {
    let seed = scenario_id
        .split('-')
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    let run = create_run(client, base_url, scenario_id, seed).await?;
    let result = async {
        let manifest = public_manifest(client, base_url, &run).await?;
        let source = manifest
            .get("sources")
            .and_then(serde_json::Value::as_array)
            .and_then(|sources| sources.first())
            .ok_or_else(|| anyhow::anyhow!("proxy regression manifest has no source"))?;
        let target = public_source_target(source)?;
        let source_url = Url::parse(
            source
                .get("base_url")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("proxy regression source has no base_url"))?,
        )?;
        let source_port = source_url
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
        let proxy_port = Url::parse(proxy_url)?
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("local proxy has no port"))?;
        let headers = format!(
            "x-lab-run-id: {}\r\nProxy-Authorization: {authorization}\r\nx-lab-proxy-capability: {capability}\r\nConnection: close\r\n",
            run.run_id
        );
        let http_request = |candidate: String, host: String, extra: &str| {
            format!("GET {candidate} HTTP/1.1\r\nHost: {host}\r\n{headers}{extra}\r\n")
        };
        let connect_request = |candidate: String, host: String, extra: &str| {
            format!("CONNECT {candidate} HTTP/1.1\r\nHost: {host}\r\n{headers}{extra}\r\n")
        };
        let cases = match scenario_id {
            "101-proxy-target-canonicalization" => vec![
                http_request(
                    target.replacen("127.0.0.1", "localhost", 1),
                    format!("localhost:{source_port}"),
                    "",
                ),
                http_request(
                    target.replacen("127.0.0.1", "127.1", 1),
                    format!("127.1:{source_port}"),
                    "",
                ),
            ],
            "102-proxy-authority-header-ambiguity" => {
                let connect_target = manifest
                    .get("network_profile")
                    .and_then(|profile| profile.get("connect_fixture_target"))
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("CONNECT manifest is missing fixture target"))?;
                vec![connect_request(
                    connect_target.to_owned(),
                    "127.0.0.1:1".to_owned(),
                    "",
                )]
            }
            "103-proxy-encoded-and-userinfo-targets" => vec![
                http_request(
                    target.replacen("http://", "http://user@", 1),
                    authority.clone(),
                    "",
                ),
                http_request(
                    target.replacen("127.0.0.1", "127%2e0%2e0%2e1", 1),
                    authority.clone(),
                    "",
                ),
            ],
            "104-proxy-framing-and-header-limits" => vec![
                http_request(
                    target.clone(),
                    authority.clone(),
                    "Host: 127.0.0.1:1\r\n",
                ),
                http_request(
                    target.clone(),
                    authority.clone(),
                    "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
                ),
            ],
            _ => anyhow::bail!("unsupported proxy regression scenario {scenario_id}"),
        };
        for raw in &cases {
            let status = raw_proxy_status(proxy_port, raw).await?;
            if status != 400 && status != 403 {
                anyhow::bail!("{scenario_id} raw proxy rejection returned HTTP {status}");
            }
        }
        let audit = fetch_audit(client, base_url, &run).await?;
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
                "{scenario_id} malformed proxy traffic reached source or consumed quota"
            );
        }
        if scenario_id == "102-proxy-authority-header-ambiguity" {
            let network = manifest
                .get("network_profile")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| anyhow::anyhow!("CONNECT manifest is missing network profile"))?;
            let (status, _) = connect_conformance_probe(
                network,
                source,
                &run.run_id.to_string(),
                manifest
                    .get("transport_profile")
                    .and_then(|profile| profile.get("client_visible_decoded_limit"))
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|limit| usize::try_from(limit).ok())
                    .ok_or_else(|| anyhow::anyhow!("CONNECT manifest is missing decoded limit"))?,
            )
            .await?;
            if status != "succeeded" {
                anyhow::bail!("{scenario_id} valid CONNECT probe was not healthy");
            }
        } else {
            let status = raw_proxy_status(proxy_port, &http_request(target, authority, "")).await?;
            if status != 200 {
                anyhow::bail!("{scenario_id} valid proxy request returned HTTP {status}");
            }
        }
        let audit = fetch_audit(client, base_url, &run).await?;
        if audit
            .iter()
            .filter(|record| record.event_type == AuditEventType::SourceRequest)
            .count()
            != 1
        {
            anyhow::bail!("{scenario_id} valid proxy request did not produce exactly one source request");
        }
        Ok(())
    }
    .await;
    let cleanup = client
        .delete(format!("{base_url}/api/runs/{}", run.run_id))
        .header("x-lab-run-access-token", &run.access_token)
        .send()
        .await?;
    if cleanup.status() != reqwest::StatusCode::NO_CONTENT {
        anyhow::bail!("{scenario_id} raw proxy regression could not delete its run");
    }
    result
}

fn public_source_target(source: &serde_json::Value) -> anyhow::Result<String> {
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
        target.query_pairs_mut().extend_pairs(
            query
                .iter()
                .filter_map(|(key, value)| value.as_str().map(|value| (key.as_str(), value))),
        );
    }
    Ok(target.into())
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

async fn console_command(repository: ScenarioRepository, args: &[String]) -> anyhow::Result<bool> {
    let mut port = 18_080_u16;
    let mut no_open = false;
    let mut plan_root = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--no-open" => {
                no_open = true;
                index += 1;
            }
            "--port" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    anyhow::anyhow!("console --port requires a value from 1 to 65535")
                })?;
                port = value.parse::<u16>()?;
                if port == 0 {
                    anyhow::bail!("console --port must be in the range 1 to 65535");
                }
                index += 2;
            }
            "--test-plan-root" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    anyhow::anyhow!("console --test-plan-root requires a directory")
                })?;
                plan_root = Some(PathBuf::from(value));
                index += 2;
            }
            value => {
                anyhow::bail!(
                    "unknown console option: {value}; use --port <1-65535>, --no-open, or --test-plan-root <directory>"
                )
            }
        }
    }
    let server = match plan_root {
        Some(plan_root) => {
            LocalServer::spawn_on_with_plan_root(repository, None, Some(port), plan_root).await
        }
        None => LocalServer::spawn_on(repository, None, Some(port)).await,
    }
    .map_err(|error| {
        anyhow::anyhow!(
            "could not start the loopback console at 127.0.0.1:{port}: {error}. Choose a free local port with console --port <1-65535>."
        )
    })?;
    let url = format!("{}/console/", server.base_url());
    println!("FQDN Forge Console: {url}");
    println!("only 127.0.0.1 is bound; no public network, real DNS, or real credentials are used.");
    if !no_open && load_console_preferences().auto_open {
        if let Err(error) = open_browser(&url) {
            eprintln!(
                "could not open the default browser ({error}); the console is still running at {url}"
            );
        }
    } else if !no_open {
        println!(
            "automatic browser opening is disabled in local console preferences; copy the URL above to open it manually."
        );
    }
    tokio::signal::ctrl_c().await?;
    server.shutdown().await;
    Ok(true)
}

fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
            .map(|_| ())
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(url).spawn().map(|_| ())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open").arg(url).spawn().map(|_| ())
    }
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
        "lab-cli commands:\n  validate\n  list\n  run --all | --scenario <id> | --group network|proxy|quota|transport|combination|lifecycle [--seed <number>] [--profile default|stress] [--report-dir artifacts/reports]\n  repeat --count <number> [--scenario <id>] [--profile default|stress]\n  replay [--strict] --report <report-path>\n  campaign list | run --campaign <id> --seed <number> | replay --report <campaign-report>\n  coverage --format json|markdown --output <path> | --check\n  baseline generate --profile v1.4-core | compare --baseline <path> --report <path> | check\n  soak run --preset smoke|standard|release\n  proxy-regression\n  conformance [--scenario 067-external-submission-pass]\n  self-test\n  plan list|validate|create|show|update|run|simulate|replay|export|import|archive|delete|storage|result|manifest [--format json]\n  serve [--scenario <id>] [--port <1-65535>]\n  console [--port <1-65535>] [--no-open]"
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
