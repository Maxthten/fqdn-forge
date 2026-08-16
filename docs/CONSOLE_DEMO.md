# FQDN Forge Console GUI 0.1 demonstration record

This record describes the repeatable local demonstration used for GUI 0.1 acceptance. It intentionally contains no real host, credential, capability, fixture, or truth data.

## Start and inspect

```powershell
cargo run -p lab-cli -- console --port 18081 --no-open
```

Expected result:

- Prints `http://127.0.0.1:18081/console/`.
- Binds only `127.0.0.1` and continues to run when the browser is not opened automatically.
- Serves the bundled `/console/`, `/console/app.js`, and `/console/style.css` resources without CDN or other external requests.

## Browser workflow

1. Open the printed URL and verify the fixed six-page navigation: Dashboard, Scenarios, Runs, Audit, Reports, and Settings.
2. Switch Chinese/English; the current page and in-memory run state remain unchanged.
3. In **Scenarios**, search or filter the 114 standard scenarios, select one, and confirm its detail opens above the list with local simulation metadata and a seed field.
4. Create an external-integration run, inspect its redacted manifest, and acknowledge the fake-credential warning before copying its full local test configuration.
5. Run the explicitly labelled platform reference client. Confirm that the generated audit and report appear through the normal loopback HTTP/proxy path.
6. In **Audit**, switch timeline/table and use operation, source, and failure filters. Copying an entry only copies its redacted model.
7. In **Reports**, confirm the passed/failed summary, metrics, findings, filtered candidates, source status, evidence, assertions, diagnostics, reproduction command, and redacted JSON copy.
8. In **Settings**, verify that only permitted preferences can change. Toggle `Open browser at next startup`, restart `lab-cli console` without `--no-open`, and confirm the CLI honors the persisted local boolean.

## Automated evidence

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p lab-cli -- validate
cargo run -p lab-cli -- run --all
.\scripts\verify.ps1 -Repeat 20
```

The final command writes the Dashboard's Git-ignored verification summary only after all its checks succeed.
