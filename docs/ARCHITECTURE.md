# Architecture

`lab-core` owns the YAML schemas, controlled `SourceKind` registry, scenario loading and static validation, domain normalization, egress guard, deterministic reference runner, metrics and truth judge. `lab-server` binds only `127.0.0.1`, hosts synthetic fixtures and implements the JSON Run Session API. `lab-cli` exposes `validate`, `list`, `run`, `self-test` and `serve`. `lab-console` remains a DTO shell; it does not introduce an HTML UI.

## Session isolation

`LabState` stores `runs: Map<run_id, RunSession>` plus a separate unscoped diagnostic audit. A `RunSession` owns its scenario ID, timestamps, lifecycle state, per-endpoint response counters, redacted audit and optional report. Source endpoints resolve their rules only from the `x-lab-run-id` session; there is no global active scenario for automated execution. State locks are held only for the short in-memory read/write operation and are released before body generation, response delay or any network wait.

The normal path is `POST /api/runs` → source requests with `x-lab-run-id` → `POST /api/runs/{id}/report`. `reset` and `delete` affect only that run. Deprecated global routes exist solely for an explicit `serve --scenario` developer convenience session and are marked `deprecated: true`.

## Validation and verification

`validate` loads all 20 scenarios without starting HTTP or using a network. It checks fixture containment, request/response sequences, pagination and retry consistency, generator limits, assertion bounds and controlled source kinds. `cargo test` runs the same 20-scenario runner logic used by `lab-cli run`, the same five negative-client routines used by `lab-cli self-test`, and concurrent session integration tests. Scenario 019 reports structured metrics for response bytes, raw records, candidates, unique FQDNs, duplicates, filters, elapsed time and a conservative buffer estimate.

The reference runner sends all traffic through `EgressGuard` before request construction. It accepts only credential-free `http://127.0.0.1:<port>` URLs and disables redirects. Root domains occur only in request data, never as connection hosts. No public network, real API key, DNS query, database, cloud service, GUI or graph visualization is part of this architecture.
