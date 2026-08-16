# FQDN Forge

> A deterministic, loopback-only test platform for passive subdomain and FQDN collectors.

**FQDN Forge is not a subdomain collector.** It is an offline test station for building and validating one. It imitates the *shape* and failure modes of public passive-data services without contacting them: certificate transparency, passive DNS, web archives, code search, threat intelligence, search indexes, custom REST endpoints, proxies, quotas, and transport faults.

The project is designed for legal local development. It binds only to `127.0.0.1` and uses synthetic fixtures. It never performs public-network requests, DNS resolution, active scanning, real API calls, or real credential handling.

Current release: **v1.4.1**.

## What it tests

FQDN Forge currently provides **114 deterministic scenarios**. They let a future collector prove that it can correctly request passive sources, normalize names, preserve evidence, obey API limits, and recover safely from realistic failures.

| Area | Examples covered |
|---|---|
| Passive source formats | Certificate records, passive DNS, archive URLs, search results, threat-intel records, code-search text, CSV, HTML, nested JSON, and generic REST payloads |
| Domain correctness | Wildcards, root names, duplicates, case, trailing dots, URL host extraction, Unicode/Punycode, nested names, and out-of-scope lookalikes |
| Request contracts | Query parameters, POST bodies, headers, fake keys, page/offset/cursor/Link pagination, authentication, and source-specific schemas |
| Service behaviour | Empty results, 401/403, 429 with `Retry-After`, 5xx errors, timeouts, disconnects, malformed payloads, large responses, and cancellation |
| Network paths | Loopback HTTP proxying, proxy authentication, CONNECT lifecycle, target canonicalization, header ambiguity, chunked framing, gzip/deflate/brotli, and corrupt streams |
| Lifecycle and evidence | Isolated runs, submit/report APIs, reset/delete, stale capabilities, audit trails, quotas, evidence merging, strict replay, baselines, and coverage policy checks |
| Resilience | Seeded mutation campaigns, combined faults, concurrency, 100,000-record stress inputs, release soak, and resource-leak checks |

All scenario data is synthetic and deterministic. A seed reproduces the same data, request sequence, and expected result.

## Safety model

The following boundaries are deliberate and are part of the test contract:

- The server listens only on `127.0.0.1`.
- The built-in reference client rejects non-loopback destinations before making a request.
- Automatic redirects and system/environment proxies are disabled for verification clients.
- The local proxy allowlists only FQDN Forge run-scoped loopback endpoints.
- Scenario fixtures contain fake keys only; sensitive-looking headers, URL credentials, and request fields are redacted in reports.
- Runs are isolated: source responses, quotas, audits, submissions, reports, reset/delete state, and capabilities cannot cross from one run into another.

This project is for testing software you own or are authorized to test. It is not designed to enumerate real internet assets.

## Quick start

### Prerequisites

- A stable Rust toolchain with Cargo.
- Windows PowerShell is used by the full verification script; the Rust CLI itself is cross-platform.

From the repository root:

```powershell
# Validate the 114 scenario definitions without starting a server.
cargo run -p lab-cli -- validate

# See available scenarios and groups.
cargo run -p lab-cli -- list

# Run every built-in regression scenario through the local service.
cargo run -p lab-cli -- run --all

# Start the local browser console (opens the system browser by default).
cargo run -p lab-cli -- console

# Run the complete release verification suite.
.\scripts\verify.ps1 -Repeat 20
```

The complete verification is intentionally substantial. It includes formatting, Clippy, unit/integration tests, all scenarios, protocol conformance, mutation campaigns, coverage policy gates, baselines, strict replay, a 100,000-record stress test, a release HTTP soak, and 20 repeated regression rounds.

## Local browser console

FQDN Forge Console is a bundled, offline browser control surface for the test station. It is not an internet site and does not add collection, DNS, scanning, proxy, or credential features.

```powershell
# Listen only on 127.0.0.1:18080 and open the browser.
cargo run -p lab-cli -- console

# Keep the service running but do not launch the browser.
cargo run -p lab-cli -- console --no-open

# Use another explicit loopback port.
cargo run -p lab-cli -- console --port 18081 --no-open
```

The console URL is printed as `http://127.0.0.1:<port>/console/`. It has Chinese and English views for six pages: Dashboard, Scenarios, Runs, Audit, Reports, and Settings. It can create an isolated external-integration run, show a redacted manifest, invoke the platform reference client through the existing local HTTP/proxy path, and present redacted audit/report read models.

Capabilities and fake credentials remain in browser memory only. They are never written to local storage, URLs, browser-visible audit data, or the report read model. The complete usage and security contract is in [docs/CONSOLE.md](docs/CONSOLE.md).

## Common commands

```powershell
# Run focused scenario groups.
cargo run -p lab-cli -- run --group network
cargo run -p lab-cli -- run --group proxy
cargo run -p lab-cli -- run --group quota
cargo run -p lab-cli -- run --group transport
cargo run -p lab-cli -- run --group combination
cargo run -p lab-cli -- run --group lifecycle

# Run one scenario with an explicit reproducible seed.
cargo run -p lab-cli -- run --scenario 059-seed-reproducible --seed 59

# Inspect source compatibility and network/proxy contracts from outside the core.
cargo run -p lab-cli -- conformance --scenario 062-proxy-http-forward-success
cargo run -p lab-cli -- proxy-regression

# Generate and validate the scenario coverage matrix.
cargo run -p lab-cli -- coverage --format markdown --output artifacts/coverage.md
cargo run -p lab-cli -- coverage --check

# Run and replay bounded mutation campaigns.
cargo run -p lab-cli -- campaign list
cargo run -p lab-cli -- campaign run --campaign 107-json-structural-mutation-campaign --seed 10701
cargo run -p lab-cli -- campaign replay --report artifacts/campaigns/107-json-structural-mutation-campaign-seed-10701.json

# Compare deterministic logical baselines and reports.
cargo run -p lab-cli -- baseline generate --profile v1.4-core
cargo run -p lab-cli -- baseline check
cargo run -p lab-cli -- replay --strict --report artifacts/reports/091-pagination-second-page-rate-limit-default-seed-91.json

# Exercise the real public loopback lifecycle under load.
cargo run -p lab-cli -- soak run --preset smoke --seed 11100
cargo run -p lab-cli -- soak run --preset release --seed 11100
```

`release` soak uses one real loopback service and eight concurrent lanes. It exercises control, manifest, source, proxy, CONNECT, submission, report, strict replay, reset/delete, stale-capability rejection, and resource cleanup through public interfaces. It does not substitute internal state calls for these operations.

## Testing an external collector

Start the local service:

```powershell
cargo run -p lab-cli -- serve --port 18080
```

Your collector should create its own scoped run first:

```text
POST /api/runs
Content-Type: application/json

{"scenario_id":"021-internet-search-nested-json","seed":21}
```

The create response gives the run ID and its run-scoped control capability. Fetch that run's manifest through the public manifest endpoint to obtain its target domain, local source endpoints, fake credentials, and (when relevant) a local proxy endpoint. Use only the values returned by that manifest. Then:

1. Fetch the local passive source data using the required request contract.
2. Extract and normalize eligible FQDNs only within the target domain.
3. Submit findings and source status through the run's public submission endpoint.
4. Retrieve the server-generated report and audit trail.
5. Use reset/delete and stale-capability cases to confirm lifecycle isolation.

The test station judges the submission independently against its expected truth and recorded request audits. A collector should never depend on scenario YAML, fixture files, or truth files.

## Scenario layout

Each scenario directory under `scenarios/` contains deterministic inputs and expectations:

```text
scenarios/<id>-<name>/
  scenario.yaml     # source definitions, request contracts, and behaviour
  truth.yaml        # hidden expected discoveries and evidence requirements
  assertions.yaml   # audit, timing, network, quota, and transport expectations
  fixtures/         # synthetic payloads when needed
```

The major scenario ranges are:

- `001`–`060`: baseline passive-source data, parsing, normalization, pagination, errors, and performance.
- `061`–`090`: local network, proxy, compression, quotas, caching, and concurrency.
- `091`–`100`: combined pagination, quota, proxy, and transport faults.
- `101`–`106`: proxy security boundaries and scoped run lifecycle.
- `107`–`110`: deterministic, seed-driven mutation campaigns.
- `111`–`114`: lifecycle soak, replay provenance, coverage policy, and baseline integrity.

## Reports and reproducibility

Run reports are written below `artifacts/` (which is intentionally ignored by Git). They record the scenario, seed, target domain, findings, evidence, source status, assertions, request/proxy/quota/transport audits, redacted diagnostics, and provenance needed for strict replay.

Useful outputs include:

```text
artifacts/reports/     # scenario and replay reports
artifacts/campaigns/   # mutation campaign reports
artifacts/coverage.*   # JSON/Markdown coverage matrices
artifacts/baselines/   # deterministic logical baseline data
artifacts/soak/        # release soak action traces and resource invariants
```

`target/`, `artifacts/`, and `reports/` are generated local files. They are not part of source control and must not be committed.

## Repository structure

```text
crates/
  lab-core/       scenario models, fixtures, judging, state, replay, coverage, campaigns
  lab-server/     loopback HTTP control/source/proxy service
  lab-console/    safe console DTOs, bilingual mappings, and bundled local web assets
  lab-cli/        command-line runner, conformance client, verification utilities
scenarios/        synthetic test definitions and fixtures
scripts/          release verification script
coverage-policy.yaml
```

## Release verification

Before treating a change as release-ready, run:

```powershell
.\scripts\verify.ps1 -Repeat 20
```

For v1.4.1, success means all 114 scenarios pass, 20 repeated rounds finish with zero failures, and the release soak completes at least 1,000 real loopback actions with at least eight concurrent lanes. The script also verifies network isolation and ensures generated output is outside Git scope.

## Status

This is an evolving local development and test platform. The GUI 0.1 console is intentionally limited to local run/audit/report workflows; it does not turn FQDN Forge into a production collection tool.
