#!/usr/bin/env node
// GUI 1.0 browser regression. It uses only Node built-ins and a local
// Chromium-family browser. Every generated report, profile, plan and download
// lives below one temporary directory passed to the loopback console.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sleep = milliseconds => new Promise(resolveSleep => setTimeout(resolveSleep, milliseconds));
const quote = value => JSON.stringify(value);
const waitForExit = (child, timeout = 5_000) => new Promise(resolveExit => {
  if (child.exitCode !== null) return resolveExit();
  const timer = setTimeout(resolveExit, timeout);
  child.once("exit", () => { clearTimeout(timer); resolveExit(); });
});
const freePort = () => new Promise((resolvePort, reject) => {
  const server = createServer();
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => {
    const { port } = server.address();
    server.close(error => error ? reject(error) : resolvePort(port));
  });
});
function browserPath() {
  const candidates = [process.env.CHROME_PATH, process.env.CHROMIUM_PATH, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "/usr/bin/google-chrome", "/usr/bin/chromium"].filter(Boolean);
  const browser = candidates.find(candidate => existsSync(candidate));
  if (!browser) throw new Error("No local Chrome, Chromium, or Edge executable was found; set CHROME_PATH to run browser regressions.");
  return browser;
}
async function waitForHttp(url, timeout = 45_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try { if ((await fetch(url)).ok) return; } catch { /* service is still starting */ }
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${url}`);
}
async function waitForDebugger(port) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = pages.find(candidate => candidate.type === "page");
      if (page?.webSocketDebuggerUrl) return page.webSocketDebuggerUrl;
    } catch { /* Chromium is still starting. */ }
    await sleep(100);
  }
  throw new Error("Timed out waiting for the Chromium debugger");
}
class Cdp {
  #next = 1;
  #pending = new Map();
  constructor(socket) {
    this.socket = socket;
    this.network = [];
    this.console = [];
    socket.addEventListener("message", event => {
      const message = JSON.parse(event.data);
      if (message.id) {
        const pending = this.#pending.get(message.id);
        if (!pending) return;
        this.#pending.delete(message.id);
        message.error ? pending.reject(new Error(message.error.message)) : pending.resolve(message.result || {});
        return;
      }
      if (message.method === "Network.requestWillBeSent") this.network.push(message.params.request.url);
      if (message.method === "Runtime.exceptionThrown") this.console.push(message.params.exceptionDetails.text);
      if (message.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(message.params.type)) this.console.push(message.params.args.map(item => item.value || item.description || "").join(" "));
    });
  }
  static async connect(endpoint) {
    const socket = new WebSocket(endpoint);
    await new Promise((resolveOpen, rejectOpen) => { socket.addEventListener("open", resolveOpen, { once: true }); socket.addEventListener("error", rejectOpen, { once: true }); });
    return new Cdp(socket);
  }
  command(method, params = {}) {
    const id = this.#next++;
    const result = new Promise((resolvePending, rejectPending) => this.#pending.set(id, { resolve: resolvePending, reject: rejectPending }));
    this.socket.send(JSON.stringify({ id, method, params }));
    return result;
  }
  async evaluate(expression) {
    const result = await this.command("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true, userGesture: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result?.value;
  }
  async close() { try { await this.command("Browser.close"); } catch { /* browser is already closed */ } this.socket.close(); }
}
async function hashTree(directory) {
  const digest = createHash("sha256");
  const visit = async current => {
    const entries = await readdir(current, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = join(current, entry.name);
      digest.update(entry.name);
      if (entry.isDirectory()) await visit(path);
      else digest.update(await readFile(path));
    }
  };
  await visit(directory);
  return digest.digest("hex");
}

async function main() {
  const temporary = await mkdtemp(join(tmpdir(), "fqdn-forge-gui-100-"));
  const analysisRoot = join(temporary, "analysis-artifacts");
  const planRoot = join(temporary, "plans");
  const scenarioRoot = join(temporary, "scenarios");
  const profileRoot = join(temporary, "browser-profile");
  const targetDirectory = join(root, "target-gui100-browser");
  const fixtureTargetDirectory = join(root, "target-gui100-fixtures");
  const port = await freePort();
  const debugPort = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const environment = { ...process.env, CARGO_TARGET_DIR: targetDirectory };
  const fixtureEnvironment = { ...process.env, CARGO_TARGET_DIR: fixtureTargetDirectory };
  await mkdir(scenarioRoot, { recursive: true });
  await Promise.all(["001-basic-certificate", "015-rate-limit-retry", "023-threat-intel-evidence", "107-json-structural-mutation-campaign"].map(id => cp(join(root, "scenarios", id), join(scenarioRoot, id), { recursive: true })));
  await writeFile(join(temporary, "coverage-policy.yaml"), `required_combinations:
  - http_proxy+proxy_auth+rate_limit
  - http_proxy+per_source+retry_recovery
  - connect_proxy+truncated+resource
  - direct+per_key+deflate
  - direct+global_run+multi_source
  - brotli+rate_limit/recovery
  - chunked+malformed/content-length-conflict
  - pagination+rate_limit+retry_recovery
  - campaign+json/html/csv/text
  - campaign+pagination
  - campaign+transport
  - lifecycle+concurrent+reset/delete
  - proxy_rejection+source_requests=0+quota_decisions=0
  - strict_replay+provenance_difference
  - baseline+scenario_fixture_digest
exceptions:
  - id: gui100-approved-combination-exception
    rule: campaign+pagination
    dimension: high_risk_combination
    value: campaign+pagination
    reason: Synthetic GUI fixture exception.
    created_on: "2026-08-17"
    expires_on: "2026-12-31"
    reference: fixture-only
    replacement: 109-pagination-token-mutation-campaign
    security_relevant: false
  - id: gui100-expired-combination-exception
    rule: strict_replay+provenance_difference
    dimension: high_risk_combination
    value: strict_replay+provenance_difference
    reason: Synthetic expired GUI fixture exception.
    created_on: "2025-01-01"
    expires_on: "2026-08-16"
    reference: fixture-only
    replacement: 113-replay-provenance-and-multi-diff
    security_relevant: false
`);
  const runCli = argumentsList => new Promise((resolveRun, rejectRun) => {
    const child = spawn("cargo", ["run", "-q", "-p", "lab-cli", "--", ...argumentsList], { cwd: root, env: fixtureEnvironment, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", chunk => { output += chunk; });
    child.stderr.on("data", chunk => { output += chunk; });
    child.once("exit", code => code === 0 ? resolveRun(output) : rejectRun(new Error(`lab-cli ${argumentsList.join(" ")} failed (${code}): ${output}`)));
  });
  const consoleServer = spawn("cargo", ["run", "-q", "-p", "lab-cli", "--", "console", "--no-open", "--port", String(port), "--test-plan-root", planRoot, "--test-analysis-root", analysisRoot, "--test-scenario-root", scenarioRoot], { cwd: root, env: environment, stdio: ["ignore", "pipe", "pipe"] });
  const browser = spawn(browserPath(), ["--headless=new", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run", "--no-default-browser-check", "--remote-debugging-address=127.0.0.1", `--remote-debugging-port=${debugPort}`, `--user-data-dir=${profileRoot}`, "about:blank"], { stdio: "ignore" });
  let cdp;
  const failures = [];
  const wait = async (expression, description, timeout = 12_000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) { if (await cdp.evaluate(expression)) return; await sleep(50); }
    throw new Error(`Timed out waiting for ${description}; page text: ${await cdp.evaluate("document.body.innerText.slice(0, 1200)")}`);
  };
  const click = async selector => {
    assert.equal(await cdp.evaluate(`(() => { const item = document.querySelector(${quote(selector)}); if (!item) return false; item.click(); return true; })()`), true, `missing ${selector}`);
  };
  const input = async (selector, text) => cdp.evaluate(`(() => { const item = document.querySelector(${quote(selector)}); if (!item) throw new Error(${quote(`missing ${selector}`)}); item.value = ${quote(text)}; item.dispatchEvent(new Event("input", {bubbles:true})); return item.value; })()`);
  const json = path => cdp.evaluate(`fetch(${quote(path)}, { headers: { "x-fqdn-console-request": "1" } }).then(response => response.json())`);
  const open = async page => {
    if (await cdp.evaluate("location.protocol === 'about:'")) {
      await cdp.command("Page.navigate", { url: `${baseUrl}/console/` });
      await wait("document.readyState === 'complete'", "initial console page");
    }
    const selector = `[data-page="${page}"]`;
    assert.equal(await cdp.evaluate(`(() => { const item = document.querySelector(${quote(selector)}); if (!item) return false; item.click(); return true; })()`), true, `missing navigation ${page}`);
    await wait(`document.querySelector(${quote(selector)})?.classList.contains("active")`, `${page} navigation`);
  };
  const run = async (id, test) => {
    try { await test(); console.log(`${id} PASS`); }
    catch (error) { failures.push(error); console.error(`${id} FAIL: ${error.message}${cdp?.console?.length ? `\nconsole: ${cdp.console.join(" | ")}` : ""}`); }
  };

  try {
    await waitForHttp(`${baseUrl}/health`);
    cdp = await Cdp.connect(await waitForDebugger(debugPort));
    await cdp.command("Page.enable"); await cdp.command("Runtime.enable"); await cdp.command("Network.enable");

    await run("GUI-100-001", async () => {
      await open("analysis");
      await wait("document.body.innerText.includes('Reports') || document.body.innerText.includes('报告')", "empty analysis overview");
      assert.ok(await cdp.evaluate("document.body.innerText.includes('0')"));
    });

    await runCli(["run", "--scenario", "001-basic-certificate", "--seed", "1", "--report-dir", join(analysisRoot, "reports")]);
    await runCli(["run", "--scenario", "015-rate-limit-retry", "--seed", "15", "--report-dir", join(analysisRoot, "reports")]);
    await runCli(["run", "--scenario", "023-threat-intel-evidence", "--seed", "23", "--report-dir", join(analysisRoot, "reports")]);
    const reportDirectory = join(analysisRoot, "reports");
    const reportFiles = await readdir(reportDirectory);
    const replayInput = join(reportDirectory, reportFiles.find(name => name.startsWith("015-")));
    const baseReport = JSON.parse(await readFile(replayInput, "utf8"));
    const runId = index => `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
    const matchedReplay = JSON.parse(JSON.stringify(baseReport));
    matchedReplay.run_id = runId(10);
    matchedReplay.replay = { strict: true, matched: true, comparison_report: "fixture:matched", first_difference: null, provenance_status: "matched", differences: [], difference_counts: {}, truncated_difference_count: 0 };
    await writeFile(join(reportDirectory, "fixture-replay-matched.json"), JSON.stringify(matchedReplay));
    const mismatchedReplay = JSON.parse(JSON.stringify(baseReport));
    mismatchedReplay.run_id = runId(11);
    mismatchedReplay.status = "failed";
    mismatchedReplay.result = "failed";
    mismatchedReplay.failures = ["Authorization: synthetic-not-exported"];
    mismatchedReplay.replay = {
      strict: true,
      matched: false,
      comparison_report: "fixture:mismatch",
      first_difference: "$.provenance.fixture_digest",
      provenance_status: "fixture_or_mutation_changed",
      differences: [
        { category: "provenance", path: "$.provenance.fixture_digest", previous: "[redacted]", current: "[redacted]" },
        { category: "audit", path: "$.virtual_wait_ms", previous: "1000", current: "0" }
      ],
      difference_counts: { provenance: 1, audit: 1 },
      truncated_difference_count: 0
    };
    await writeFile(join(reportDirectory, "fixture-replay-mismatch.json"), JSON.stringify(mismatchedReplay));
    await runCli(["campaign", "run", "--campaign", "107-json-structural-mutation-campaign", "--seed", "10701", "--output", join(analysisRoot, "campaigns", "campaign.json")]);
    const trendSource = join(reportDirectory, reportFiles.find(name => name.startsWith("001-")));
    const trendTemplate = JSON.parse(await readFile(trendSource, "utf8"));
    for (let index = 0; index < 305; index += 1) {
      const trendReport = JSON.parse(JSON.stringify(trendTemplate));
      const timestamp = new Date(Date.UTC(2026, 0, 1, 0, index, 0)).toISOString();
      trendReport.run_id = runId(100 + index);
      trendReport.started_at = timestamp;
      trendReport.finished_at = timestamp;
      await writeFile(join(reportDirectory, `trend-${index}.json`), JSON.stringify(trendReport));
    }
    const campaign = JSON.parse(await readFile(join(analysisRoot, "campaigns", "campaign.json"), "utf8"));
    const failedCampaign = JSON.parse(JSON.stringify(campaign));
    failedCampaign.manifest.campaign_id = "fixture-failed-campaign";
    failedCampaign.report.status = "failed";
    failedCampaign.report.result = "failed";
    failedCampaign.report.failures = ["synthetic fixture mutation mismatch"];
    failedCampaign.report.diagnostics.failure_categories = { fixture: 1 };
    await writeFile(join(analysisRoot, "campaigns", "campaign-failed.json"), JSON.stringify(failedCampaign));
    await mkdir(join(analysisRoot, "soak"), { recursive: true });
    const soak = (seed, failed) => ({
      schema_version: "1.4.1", preset: "standard", seed, operations: 250, concurrency: 4,
      action_trace: [], scenario_pool: ["001-basic-certificate"], trace_coverage: { source: true },
      action_counts: { retry: 2, source: 250 }, outcome_counts: { rate_limited: 1, blocked_egress: 0, cancelled: 0 },
      resources: { active_runs: failed ? 1 : 0, reset_runs: 0, deleted_runs: 2, active_proxy_connections: 0, audit_records: 0, quota_state_entries: 0, report_count: 0, fixture_bytes: 128, rejection_count: 0 },
      invariants: { no_live_runs: !failed, no_active_proxy_connections: true },
      last_failure: failed ? "synthetic resource leak" : null,
      reproduction_command: `lab-cli soak run --preset standard --seed ${seed}`
    });
    await writeFile(join(analysisRoot, "soak", "fixture-passed.json"), JSON.stringify(soak(1001, false)));
    await writeFile(join(analysisRoot, "soak", "fixture-failed.json"), JSON.stringify(soak(1002, true)));
    await writeFile(join(reportDirectory, "deliberately-broken.json"), "{");

    await run("GUI-100-002", async () => { await open("coverage"); await wait("document.querySelectorAll('tbody tr').length > 0", "coverage matrix"); const coverage = await json("/api/analysis/coverage"); const statuses = new Set(coverage.data.cells.map(cell => cell.status)); for (const expected of ["covered", "partial", "missing", "excepted", "expired_exception"]) assert.ok(statuses.has(expected), `coverage status ${expected}`); });
    await run("GUI-100-003", async () => { await input('[data-analysis-filter="coverage"][data-analysis-key="status"]', "partial"); await click('[data-analysis-action="load"][data-analysis-page="coverage"]'); await wait("document.body.innerText.includes('partial')", "partial coverage filter"); assert.ok((await json("/api/analysis/coverage?status=partial")).data.cells.every(cell => cell.status === "partial")); });
    await run("GUI-100-004", async () => { await open("replays"); await wait("document.body.innerText.includes('matched')", "matched replay"); assert.ok((await json("/api/analysis/replays?status=matched")).data.comparisons.some(item => item.difference_count === 0)); });
    await run("GUI-100-005", async () => { await open("replays"); await input('[data-analysis-filter="replays"][data-analysis-key="status"]', "mismatch"); await click('[data-analysis-action="load"][data-analysis-page="replays"]'); await wait("document.body.innerText.includes('fixture_or_mutation_changed')", "replay mismatch explanation"); const mismatches = (await json("/api/analysis/replays?status=mismatch")).data.comparisons; assert.ok(mismatches.some(item => item.first_difference_path === "$.provenance.fixture_digest" && item.difference_count === 2)); assert.ok(!JSON.stringify(mismatches).includes("synthetic-not-exported")); });
    await run("GUI-100-006", async () => { await open("campaigns"); await wait("document.body.innerText.includes('107-json-structural-mutation-campaign')", "campaign summary"); const campaigns = (await json("/api/analysis/campaigns")).data.campaigns; assert.ok(campaigns.some(item => item.status === "passed")); assert.ok(campaigns.some(item => item.status === "failed" && item.failure_categories.fixture === 1)); });
    await run("GUI-100-007", async () => { await open("soak"); await wait("document.querySelectorAll('tbody tr').length >= 2", "soak summaries"); const soaks = (await json("/api/analysis/soak")).data.soaks; assert.ok(soaks.some(item => item.seed === 1001 && item.concurrency === 4 && item.operations === 250 && item.status === "passed")); assert.ok(soaks.some(item => item.seed === 1002 && item.status === "failed" && item.resources.active_runs === 1)); });
    await run("GUI-100-008", async () => { await open("evidence"); await wait("Boolean(document.querySelector('[data-analysis-filter=evidence][data-analysis-key=scenario]'))", "evidence filters"); await input('[data-analysis-filter="evidence"][data-analysis-key="scenario"]', "023-threat-intel-evidence"); await click('[data-analysis-action="load"][data-analysis-page="evidence"]'); await wait("Boolean(document.querySelector('.evidence-svg'))", "evidence graph"); await click('[data-analysis-action="graph-view"]'); await wait("Boolean(document.querySelector('.table-wrap'))", "evidence table alternative"); assert.ok((await json("/api/analysis/evidence-graph?scenario=023-threat-intel-evidence")).data.nodes.length > 0); });
    await run("GUI-100-009", async () => { await input('[data-analysis-filter="evidence"][data-analysis-key="scenario"]', "001-basic-certificate"); await click('[data-analysis-action="load"][data-analysis-page="evidence"]'); await wait("document.body.innerText.includes('Result truncated') || document.body.innerText.includes('结果已截断')", "evidence truncation"); const graph = await json("/api/analysis/evidence-graph?scenario=001-basic-certificate"); assert.equal(graph.truncated, true); assert.ok(graph.data.total_nodes > graph.data.nodes.length); });
    await run("GUI-100-010", async () => { await open("timelineTrend"); await wait("Boolean(document.querySelector('[data-analysis-filter=timelineTrend][data-analysis-key=run]'))", "timeline controls"); await input('[data-analysis-filter="timelineTrend"][data-analysis-key="run"]', baseReport.run_id); await click('[data-analysis-action="load"][data-analysis-page="timelineTrend"]'); await wait("document.body.innerText.includes('Retry-After')", "rate-limit timeline"); const events = (await json(`/api/analysis/timeline?run=${baseReport.run_id}`)).data.events; assert.deepEqual(events.map(event => event.status), [429, 200]); assert.deepEqual(events.map(event => event.virtual_time_ms), [0, 1000]); });
    await run("GUI-100-011", async () => { await input('[data-analysis-filter="timelineTrend"][data-analysis-key="source"]', "key-search"); await input('[data-analysis-filter="timelineTrend"][data-analysis-key="status"]', "429"); await click('[data-analysis-action="load"][data-analysis-page="timelineTrend"]'); await wait("document.body.innerText.includes('429')", "timeline filters"); const filtered = (await json(`/api/analysis/timeline?run=${baseReport.run_id}&source=key-search&status=429`)).data.events; assert.equal(filtered.length, 1); });
    await run("GUI-100-012", async () => { const trends = await json("/api/analysis/trends"); assert.ok(trends.data.source_point_count > 300); assert.equal(trends.data.points.length, 300); assert.deepEqual([...trends.data.points].map(point => point.timestamp), trends.data.points.map(point => point.timestamp).sort()); const empty = await json("/api/analysis/trends?scenario=not-present"); assert.deepEqual(empty.data.points, []); });
    await run("GUI-100-013", async () => { await open("coverage"); await wait("Boolean(document.querySelector('[data-analysis-export=json]'))", "analysis export controls"); await click('[data-analysis-export="json"]'); await click('[data-analysis-export="markdown"]'); await sleep(200); const exported = await json("/api/analysis/coverage"); assert.equal(exported.schema_version, "1.0"); assert.ok(Object.hasOwn(exported, "filters") && Object.hasOwn(exported, "truncated")); assert.ok(cdp.network.some(url => url.includes("/api/analysis/") && url.includes("format=markdown"))); assert.ok(!JSON.stringify(exported).includes("synthetic-not-exported")); });
    await run("GUI-100-014", async () => { await open("timelineTrend"); const before = await cdp.evaluate("document.querySelector('[data-analysis-filter=timelineTrend][data-analysis-key=scenario]')?.value"); await click('[data-action="lang"]'); await wait("document.documentElement.lang === 'zh' || document.documentElement.lang === 'en'", "language toggle"); assert.equal(await cdp.evaluate("document.querySelector('[data-analysis-filter=timelineTrend][data-analysis-key=scenario]')?.value"), before); assert.ok(await cdp.evaluate("document.querySelector('h1')?.textContent.length > 0")); });
    await run("GUI-100-015", async () => { await cdp.command("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true }); await sleep(100); assert.deepEqual(await cdp.evaluate("[document.documentElement.scrollWidth, document.documentElement.clientWidth]"), [390, 390]); assert.ok(await cdp.evaluate("Boolean(document.querySelector('.trend-svg, .table-wrap, .empty'))")); await cdp.command("Emulation.clearDeviceMetricsOverride"); });
    await run("GUI-100-016", async () => { const external = cdp.network.filter(url => /^https?:/i.test(url)).filter(url => !["127.0.0.1", "localhost"].includes(new URL(url).hostname)); assert.deepEqual(external, []); assert.deepEqual(cdp.console, []); });
    await run("GUI-100-017", async () => { const first = await hashTree(analysisRoot); for (const page of ["analysis", "coverage", "replays", "campaigns", "soak", "evidence", "timelineTrend"]) await open(page); assert.equal(await hashTree(analysisRoot), first); });

    if (failures.length) throw new AggregateError(failures, `${failures.length} GUI 1.0 browser regression case(s) failed`);
    console.log("GUI 1.0 browser regression: 17 passed, 0 failed");
  } finally {
    await cdp?.close();
    if (browser.exitCode === null) browser.kill();
    if (consoleServer.exitCode === null) consoleServer.kill();
    await waitForExit(browser); await waitForExit(consoleServer);
    await rm(temporary, { recursive: true, force: true });
  }
}

await main();
