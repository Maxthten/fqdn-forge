# FQDN Forge Console (GUI 0.1.1)

## Start

```powershell
cargo run -p lab-cli -- console
cargo run -p lab-cli -- console --no-open
cargo run -p lab-cli -- console --port 18081 --no-open
```

The console always binds the local station to numeric IPv4 loopback only. The command prints the full URL, normally `http://127.0.0.1:18080/console/`. If the browser cannot be opened automatically, the service remains available at that URL. `Ctrl+C` uses the existing graceful server and proxy shutdown path.

## Scope and safety

- The bundled HTML, CSS, and JavaScript are served from the local binary. There are no CDN assets, remote fonts, telemetry, service workers, DNS lookups, public APIs, or network fallback paths.
- The console only calls same-origin loopback endpoints and its HTTP response supplies a self-only Content Security Policy.
- It is a test-station UI, not a domain input form or a scanner. The target domain always comes from a fixed standard scenario and its seed.
- The browser never receives scenario truth or fixture data. The console read models also redact capability, fake authorization, proxy authorization, request bodies, and sensitive header values.
- The console always uses a light theme. Language, page, and history-limit preferences are saved only in browser local storage. The separate `Open browser at next startup` preference is a single non-sensitive boolean at Git-ignored `artifacts/console/preferences.json` so `lab-cli console` can honor it before a browser exists. Capabilities, fake credentials, manifests, and reports are retained only in the current page memory.

## Pages

The fixed navigation contains six pages:

1. **Dashboard** shows local health, base URL, the 114-scenario count, categories, active runs, recent run/report status, and the latest persisted full-verification summary. A summary appears only after a successful full verification; otherwise the dashboard clearly reports that no complete record is available.
2. **Scenarios** searches and filters all standard scenarios, provides Chinese and English names/descriptions, exposes safe local-simulation metadata, and creates a run with an explicit seed.
3. **Runs** lists active/completed/reset/deleted runs, presents a redacted manifest, permits an explicitly confirmed full-manifest copy, runs the platform reference client, and offers confirmed reset/delete.
4. **Audit** shows a shared redacted read model as a timeline or table. It includes source, proxy, CONNECT, quota, lifecycle, manifest/report/control, and stale-capability events when present.
5. **Reports** converts the server report into metrics, findings, filtered candidates, source status, assertions, diagnostics, reproduction command, and a redacted JSON copy.
6. **Settings** changes only language and non-sensitive display preferences, and documents the immutable safety settings.

## Reference run and external integration

An external-integration run only creates a scoped run and gives the user the local manifest needed by an external collector. The console does not make source requests or submit a result on that collector's behalf.

The **platform reference client** is a separate action. It uses the existing `ReferenceRunner` against the running server's ordinary loopback HTTP/proxy routes, then writes the normal server report. Its button is deliberately labelled as a platform self-check/demo; it is not evidence that an external collector passed.

## Verification

`lab-server` includes a console workflow test that verifies: self-only browser resources/CSP, no external script URL, all 114 Chinese mappings, overview safety flags, run creation, manifest truth protection, reference run, redacted report, stale capability rejection after reset, and deleted-run history.

After `scripts/verify.ps1` succeeds, it writes a non-sensitive, Git-ignored record at `artifacts/console/verification-summary.json`. The dashboard reads only its passed timestamp, command, repeat count, 114-scenario count, and release-soak operation count; it never reads reports, truth, run IDs, or credentials from that record.

Run the full project gates before release:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
.\scripts\verify.ps1 -Repeat 20
```
