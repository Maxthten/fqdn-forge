use std::{fs, path::PathBuf, process::Command};

use serde_json::Value;
use uuid::Uuid;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lab-cli"))
}

fn test_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-artifacts")
        .join(format!("lab-cli-plan-{}", Uuid::new_v4().simple()))
        .join("plans")
}

fn run_plan(root: &PathBuf, arguments: &[&str]) -> std::process::Output {
    binary()
        .args(arguments)
        .arg("--test-plan-root")
        .arg(root)
        .output()
        .expect("run lab-cli plan command")
}

fn json_output(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON command output")
}

#[test]
fn cli_plan_lifecycle_is_isolated_and_records_local_simulation() {
    let root = test_root();
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plans/basic.json");
    let update_file = root
        .parent()
        .expect("test root parent")
        .join("updated.json");
    fs::create_dir_all(update_file.parent().expect("test artifact directory"))
        .expect("create test artifact directory");

    let mut updated: Value =
        serde_json::from_slice(&fs::read(&fixture).expect("read plan fixture"))
            .expect("fixture JSON");
    updated["description"] = "CLI lifecycle update".into();
    fs::write(
        &update_file,
        serde_json::to_vec_pretty(&updated).expect("serialize updated plan"),
    )
    .expect("write updated plan");

    let plan_id = updated["plan_id"].as_str().expect("fixture plan ID");
    let fixture_arg = fixture.to_string_lossy().into_owned();
    let update_arg = update_file.to_string_lossy().into_owned();
    let root_arg = root.to_string_lossy().into_owned();

    let created = json_output(run_plan(
        &root,
        &["plan", "create", "--file", &fixture_arg, "--format", "json"],
    ));
    assert_eq!(created["plan"]["plan_id"], plan_id);

    let updated = json_output(run_plan(
        &root,
        &[
            "plan",
            "update",
            "--id",
            plan_id,
            "--file",
            &update_arg,
            "--format",
            "json",
        ],
    ));
    assert_eq!(updated["plan"]["revision"], 1);

    let local_run = json_output(run_plan(
        &root,
        &["plan", "simulate", "--id", plan_id, "--format", "json"],
    ));
    assert_eq!(local_run["manifest"]["execution_mode"], "local_simulation");

    let replay_run = json_output(run_plan(
        &root,
        &[
            "plan",
            "replay",
            "--run",
            local_run["manifest"]["run_id"].as_str().expect("run ID"),
            "--format",
            "json",
        ],
    ));
    assert_eq!(replay_run["manifest"]["execution_mode"], "local_simulation");

    let archived = json_output(run_plan(
        &root,
        &["plan", "archive", "--id", plan_id, "--format", "json"],
    ));
    assert_eq!(archived["plan"]["status"], "archived");
    let archived_run = run_plan(&root, &["plan", "run", "--id", plan_id, "--format", "json"]);
    assert!(!archived_run.status.success());
    assert!(String::from_utf8_lossy(&archived_run.stderr).contains("PLAN_ARCHIVED"));

    let deleted = json_output(run_plan(
        &root,
        &["plan", "delete", "--id", plan_id, "--format", "json"],
    ));
    assert_eq!(deleted["deleted"], true);

    let storage = json_output(run_plan(&root, &["plan", "storage", "--format", "json"]));
    assert_eq!(storage["plan_count"], 0);
    assert_eq!(storage["run_count"], 2);
    assert_eq!(storage["plans_directory"], root_arg);
}
