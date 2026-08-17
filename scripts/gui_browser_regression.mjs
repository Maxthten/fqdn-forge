#!/usr/bin/env node
// Browser regression suite for GUI 0.2.2. It intentionally uses only Node's
// built-ins plus a locally installed Chromium-family browser, so it adds no
// runtime or package-manager dependency to FQDN Forge.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = JSON.parse(await readFile(join(root, "fixtures/plans/gui_022_advanced.json"), "utf8"));
const sleep = milliseconds => new Promise(resolveSleep => setTimeout(resolveSleep, milliseconds));
const waitForExit = (child, timeout = 5_000) => new Promise(resolveExit => {
  if (child.exitCode !== null) return resolveExit();
  const timer = setTimeout(resolveExit, timeout);
  child.once("exit", () => { clearTimeout(timer); resolveExit(); });
});

async function removeTemporaryDirectory(directory) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      await rm(directory, { recursive: true, force: true });
      return;
    } catch (error) {
      if (attempt === 9) {
        console.warn(`Could not remove temporary browser artifacts at ${directory}: ${error.message}`);
        return;
      }
      await sleep(200);
    }
  }
}

async function freePort() {
  return await new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(error => error ? reject(error) : resolvePort(address.port));
    });
  });
}

async function waitForHttp(url, timeout = 30_000) {
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
      lastError = new Error(`${url} returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${url}: ${lastError?.message || "unknown error"}`);
}

function browserPath() {
  const candidates = [
    process.env.CHROME_PATH,
    process.env.CHROMIUM_PATH,
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].filter(Boolean);
  const browser = candidates.find(candidate => existsSync(candidate));
  if (!browser) throw new Error("No local Chrome, Chromium, or Edge executable was found; set CHROME_PATH to run browser regressions.");
  return browser;
}

class Cdp {
  #nextId = 1;
  #pending = new Map();
  constructor(socket) {
    this.socket = socket;
    this.network = [];
    this.console = [];
    socket.addEventListener("message", event => this.#receive(JSON.parse(event.data)));
  }
  static async connect(endpoint) {
    const socket = new WebSocket(endpoint);
    await new Promise((resolveOpen, reject) => {
      socket.addEventListener("open", resolveOpen, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    return new Cdp(socket);
  }
  #receive(message) {
    if (message.id) {
      const pending = this.#pending.get(message.id);
      if (!pending) return;
      this.#pending.delete(message.id);
      if (message.error) pending.reject(new Error(`${message.error.message} (${message.error.code})`));
      else pending.resolve(message.result || {});
      return;
    }
    if (message.method === "Network.requestWillBeSent") {
      this.network.push({
        url: message.params.request.url,
        method: message.params.request.method,
        postData: message.params.request.postData || null,
      });
    }
    if (message.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(message.params.type)) {
      this.console.push({ type: message.params.type, args: message.params.args.map(argument => argument.value ?? argument.description ?? "") });
    }
    if (message.method === "Runtime.exceptionThrown") this.console.push({ type: "exception", text: message.params.exceptionDetails.text });
    if (message.method === "Page.javascriptDialogOpening") {
      void this.command("Page.handleJavaScriptDialog", { accept: true }).catch(() => {});
    }
  }
  command(method, params = {}) {
    const id = this.#nextId++;
    const result = new Promise((resolvePending, rejectPending) => this.#pending.set(id, { resolve: resolvePending, reject: rejectPending }));
    this.socket.send(JSON.stringify({ id, method, params }));
    return result;
  }
  async evaluate(expression) {
    const response = await this.command("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true, userGesture: true });
    if (response.exceptionDetails) throw new Error(response.exceptionDetails.exception?.description || response.exceptionDetails.text);
    return response.result?.value;
  }
  async close() {
    try { await this.command("Browser.close"); } catch { /* the browser may already be closing */ }
    this.socket.close();
  }
}

async function waitForDebugger(port) {
  const endpoint = `http://127.0.0.1:${port}/json/list`;
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      const pages = await (await fetch(endpoint)).json();
      const page = pages.find(candidate => candidate.type === "page");
      if (page?.webSocketDebuggerUrl) return page.webSocketDebuggerUrl;
    } catch { /* Chromium has not opened its DevTools port yet. */ }
    await sleep(100);
  }
  throw new Error("Timed out waiting for the Chromium DevTools endpoint");
}

const quote = value => JSON.stringify(value);

async function main() {
  const artifactRoot = await mkdtemp(join(tmpdir(), "fqdn-forge-gui-022-"));
  const planRoot = join(artifactRoot, "plans");
  const profileRoot = join(artifactRoot, "browser-profile");
  const port = await freePort();
  const debugPort = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const consoleServer = spawn("cargo", ["run", "-q", "-p", "lab-cli", "--", "console", "--no-open", "--port", String(port), "--test-plan-root", planRoot], { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
  let serverOutput = "";
  consoleServer.stdout.on("data", chunk => { serverOutput += chunk; });
  consoleServer.stderr.on("data", chunk => { serverOutput += chunk; });
  const browser = spawn(browserPath(), ["--headless=new", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run", "--no-default-browser-check", "--remote-debugging-address=127.0.0.1", `--remote-debugging-port=${debugPort}`, `--user-data-dir=${profileRoot}`, "about:blank"], { stdio: "ignore" });
  let cdp;
  let counter = 0;
  let navigation = 0;
  let retainArtifacts = false;
  const nextId = label => `plan_gui_022_${label}_${Date.now().toString(36)}_${(++counter).toString(36)}`;
  const api = async (path, options = {}) => {
    const response = await fetch(`${baseUrl}${path}`, { headers: { "content-type": "application/json", ...(options.headers || {}) }, ...options });
    const body = await response.json();
    if (!response.ok) throw new Error(`${path}: ${body?.error?.code || body?.error?.message || response.status}`);
    return body;
  };
  const wait = async (expression, description, timeout = 10_000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      if (await cdp.evaluate(expression)) return;
      await sleep(50);
    }
    throw new Error(`Timed out waiting for ${description}`);
  };
  const dom = async (selector, property = "value") => cdp.evaluate(`(() => { const element = document.querySelector(${quote(selector)}); return element ? element[${quote(property)}] : null; })()`);
  const click = async selector => {
    const clicked = await cdp.evaluate(`(() => { const element = document.querySelector(${quote(selector)}); if (!element) return false; element.click(); return true; })()`);
    assert.equal(clicked, true, `missing clickable element ${selector}`);
  };
  const input = async (selector, value, event = "input") => {
    const actual = await cdp.evaluate(`(() => { const element = document.querySelector(${quote(selector)}); if (!element) throw new Error("missing input ${selector}"); element.value = ${quote(value)}; element.dispatchEvent(new Event(${quote(event)}, { bubbles: true })); return element.value; })()`);
    assert.equal(actual, value, `input ${selector} accepted its value`);
  };
  const check = async (selector, checked) => {
    const actual = await cdp.evaluate(`(() => { const element = document.querySelector(${quote(selector)}); if (!element) throw new Error(${quote(`missing checkbox ${selector}`)}); element.checked = ${checked}; element.dispatchEvent(new Event("change", { bubbles: true })); return element.checked; })()`);
    assert.equal(actual, checked, `checkbox ${selector} changed`);
  };
  const clearFetches = () => cdp.evaluate("window.__guiTestFetches = []; true");
  const fetched = () => cdp.evaluate("window.__guiTestFetches || []");
  const waitForIdle = () => wait("!document.querySelector('[aria-busy=\"true\"]')", "the current UI operation to complete");
  const newDraft = async () => { await click('[data-plan-action="new"]'); await wait("Boolean(document.querySelector('#plan-editor'))", "the plan editor"); };
  const save = async () => { await click('[data-plan-action="save"]'); await waitForIdle(); await wait("Boolean(document.querySelector('#plan-editor')) && document.querySelector('#plan-editor').innerText.length > 0", "saved editor render"); };
  const closeEditor = async () => {
    if (!await dom("#plan-editor", "id")) return;
    await cdp.evaluate("window.confirm = () => true; true");
    await click('[data-plan-action="close"]');
    await wait("!document.querySelector('#plan-editor')", "editor close");
  };
  const createSaved = async (name, id = nextId("saved")) => {
    await newDraft();
    await input("#plan-name", name);
    await input("#plan-id", id);
    await input("#plan-domain", `${id.replace(/[^a-z0-9-]/gi, "-")}.test`);
    await input("#plan-seed", "20260817");
    await save();
    return id;
  };
  const openPlans = async () => {
    await cdp.command("Page.navigate", { url: `${baseUrl}/console/` });
    await wait("document.readyState === 'complete'", "console page load", 15_000);
    await cdp.evaluate("localStorage.setItem('fqdn-forge.page', 'plans'); true");
    await cdp.command("Page.navigate", { url: `${baseUrl}/console/?gui-browser-test=${++navigation}` });
    await wait("Boolean(document.querySelector('#plan-search'))", "experiment plans page", 15_000);
    await cdp.evaluate(`(() => { if (window.__guiTestFetchInstalled) return true; window.__guiTestFetchInstalled = true; window.__guiTestFetches = []; const originalFetch = window.fetch.bind(window); window.fetch = async (...argumentsList) => { const record = { url: String(argumentsList[0]), requestBody: argumentsList[1]?.body || null, status: null, body: null }; window.__guiTestFetches.push(record); const response = await originalFetch(...argumentsList); record.status = response.status; response.clone().text().then(body => { record.body = body; }).catch(() => {}); return response; }; return true; })()`);
  };
  const importDraft = async plan => {
    await newDraft();
    await input("#plan-import", JSON.stringify(plan, null, 2));
    await click('[data-plan-action="import"]');
    await waitForIdle();
    await wait(`document.querySelector('#plan-name')?.value === ${quote(plan.name)}`, "imported plan draft");
  };
  const exportedPlan = async id => (await api(`/api/plans/${encodeURIComponent(id)}/export`, { method: "POST", body: "{}" })).plan;
  const advancedPlan = (label, name = `Advanced ${label}`) => ({ ...structuredClone(fixture), plan_id: nextId(label), name, plan_digest: "", revision: 0 });
  const failures = [];
  const captureFailure = async (id, error) => {
    retainArtifacts = true;
    const failureRoot = join(artifactRoot, `failure-${id}`);
    await rm(failureRoot, { recursive: true, force: true });
    await writeFile(join(artifactRoot, `failure-${id}.json`), JSON.stringify({ id, error: error.stack || String(error), network: cdp?.network || [], console: cdp?.console || [] }, null, 2));
    if (cdp) {
      try {
        const image = await cdp.command("Page.captureScreenshot", { format: "png" });
        await writeFile(join(artifactRoot, `failure-${id}.png`), Buffer.from(image.data, "base64"));
      } catch { /* retain the structured record even when the tab is unavailable */ }
    }
  };
  const run = async (id, test) => {
    try {
      await openPlans();
      await test();
      console.log(`${id} PASS`);
    } catch (error) {
      failures.push({ id, error });
      await captureFailure(id, error);
      console.error(`${id} FAIL: ${error.message}`);
    }
  };

  try {
    await waitForHttp(`${baseUrl}/api/plans`);
    cdp = await Cdp.connect(await waitForDebugger(debugPort));
    await cdp.command("Page.enable");
    await cdp.command("Runtime.enable");
    await cdp.command("Network.enable");
    await cdp.command("Log.enable");

    await run("GUI-222-001", async () => {
      await newDraft();
      const id = await dom("#plan-id");
      await click('[data-action="lang"]');
      await wait(`document.querySelector('#plan-id')?.value === ${quote(id)}`, "stable ID after language change");
      await click('[data-plan-action="add-fault"]');
      await wait(`document.querySelector('#plan-id')?.value === ${quote(id)}`, "stable ID after editor render");
      await input("#plan-domain", "not-a-test-domain.invalid");
      await click('[data-plan-action="validate"]');
      await waitForIdle();
      assert.equal(await dom("#plan-id"), id);
      await click('[data-action="lang"]');
    });

    await run("GUI-222-002", async () => {
      await newDraft();
      const name = "Latest validation name";
      await input("#plan-name", name);
      await clearFetches();
      await click('[data-plan-action="validate"]');
      await wait("window.__guiTestFetches.some(request => request.url.includes('/api/plans/validate'))", "validate request");
      const requests = await fetched();
      const request = requests.find(item => item.url.includes("/api/plans/validate"));
      assert.equal(JSON.parse(request.requestBody).name, name);
    });

    await run("GUI-222-003", async () => {
      await newDraft();
      const id = nextId("save");
      await input("#plan-name", "Saved latest fields");
      await input("#plan-id", id);
      await input("#plan-domain", "latest-fields.test");
      await input("#plan-seed", "20260818");
      await save();
      const plan = (await api(`/api/plans/${id}`)).plan;
      assert.deepEqual([plan.name, plan.target_domain, plan.seed], ["Saved latest fields", "latest-fields.test", 20260818]);
    });

    await run("GUI-222-004", async () => {
      const id = await createSaved("Validate is not save");
      const before = await api("/api/plans/storage");
      const original = (await api(`/api/plans/${id}`)).plan;
      await input("#plan-name", "Draft validation only");
      await click('[data-plan-action="validate"]');
      await waitForIdle();
      const after = await api("/api/plans/storage");
      const persisted = (await api(`/api/plans/${id}`)).plan;
      assert.equal(after.plan_count, before.plan_count);
      assert.equal(persisted.revision, original.revision);
      assert.equal(persisted.name, original.name);
    });

    await run("GUI-222-005", async () => {
      const plan = advancedPlan("import", "Import without save");
      const before = await api("/api/plans/storage");
      await importDraft(plan);
      assert.equal((await api("/api/plans/storage")).plan_count, before.plan_count);
      await save();
      assert.equal((await api("/api/plans/storage")).plan_count, before.plan_count + 1);
    });

    await run("GUI-222-006", async () => {
      await newDraft();
      await input("#plan-name", "Draft remains on failed import");
      const invalid = "{not valid JSON";
      await input("#plan-import", invalid);
      await click('[data-plan-action="import"]');
      await waitForIdle();
      assert.equal(await dom("#plan-name"), "Draft remains on failed import");
      assert.equal(await dom("#plan-import"), invalid);
      assert.ok(await cdp.evaluate("Boolean(document.querySelector('[data-plan-import-feedback] .error'))"));
    });

    await run("GUI-222-007", async () => {
      await newDraft();
      await input("#plan-name", "Failed save keeps draft");
      await input("#plan-domain", "outside-the-lab.example");
      await click('[data-plan-action="save"]');
      await waitForIdle();
      assert.equal(await dom("#plan-name"), "Failed save keeps draft");
      assert.ok(await cdp.evaluate("Boolean(document.querySelector('[data-plan-editor-feedback] .error'))"));
    });

    await run("GUI-222-008", async () => {
      const plan = advancedPlan("faults", "Fault round trip");
      await importDraft(plan);
      await input("#plan-name", "Fault round trip renamed");
      await save();
      const exported = await exportedPlan(plan.plan_id);
      assert.deepEqual(exported.faults, plan.faults);
    });

    await run("GUI-222-009", async () => {
      const plan = advancedPlan("overrides", "403 and source overrides");
      await importDraft(plan);
      await input("#plan-description", "ordinary field only");
      await save();
      const exported = await exportedPlan(plan.plan_id);
      assert.equal(exported.authentication.failure_status, 403);
      assert.deepEqual(exported.sources[0].authentication, plan.sources[0].authentication);
      assert.deepEqual(exported.sources[0].quota, plan.sources[0].quota);
      assert.deepEqual(exported.sources[0].pagination, plan.sources[0].pagination);
      assert.deepEqual(exported.sources[0].faults, plan.sources[0].faults);
    });

    await run("GUI-222-010", async () => {
      const plan = advancedPlan("restore-source", "Restore source advanced configuration");
      await importDraft(plan);
      const source = '[name="plan-template"][value="certificate"]';
      await check(source, false);
      await check(source, true);
      await save();
      const exported = await exportedPlan(plan.plan_id);
      assert.deepEqual(exported.sources[0].authentication, plan.sources[0].authentication);
      assert.deepEqual(exported.sources[0].quota, plan.sources[0].quota);
      assert.deepEqual(exported.sources[0].pagination, plan.sources[0].pagination);
      assert.deepEqual(exported.sources[0].faults, plan.sources[0].faults);
    });

    await run("GUI-222-011", async () => {
      const first = await createSaved("Unsaved protection first");
      await closeEditor();
      const second = await createSaved("Unsaved protection second");
      await closeEditor();
      await click(`[data-plan-action="edit"][data-id="${first}"]`);
      await wait(`document.querySelector('#plan-id')?.value === ${quote(first)}`, "first plan editor");
      await input("#plan-name", "Unsaved first draft");
      await cdp.evaluate("window.confirm = () => false; true");
      await click(`[data-plan-action="edit"][data-id="${second}"]`);
      assert.equal(await dom("#plan-name"), "Unsaved first draft");
      await cdp.evaluate("window.confirm = () => true; true");
      await click(`[data-plan-action="edit"][data-id="${second}"]`);
      await wait(`document.querySelector('#plan-id')?.value === ${quote(second)}`, "second plan after discard confirmation");
    });

    await run("GUI-222-012", async () => {
      const id = await createSaved("Run button idempotence");
      await closeEditor();
      await clearFetches();
      const selector = `[data-plan-action="simulate"][data-id="${id}"]`;
      await click(selector);
      await click(selector);
      await wait("Boolean(document.querySelector('.plan-result'))", "local run result", 20_000);
      await sleep(100);
      const starts = (await fetched()).filter(request => request.url.includes(`/api/plans/${id}/simulate`));
      assert.equal(starts.length, 1);
    });

    await run("GUI-222-013", async () => {
      const alpha = await createSaved("Filter state alpha");
      await closeEditor();
      await createSaved("Filter state beta");
      await closeEditor();
      await input("#plan-search", "Filter state alpha");
      await input("#plan-status-filter", "runnable", "change");
      await input("#plan-sort", "oldest", "change");
      await click('[data-plan-action="refresh"]');
      await waitForIdle();
      await click('[data-action="lang"]');
      assert.equal(await dom("#plan-search"), "Filter state alpha");
      assert.equal(await dom("#plan-status-filter"), "runnable");
      assert.equal(await dom("#plan-sort"), "oldest");
      assert.ok(await cdp.evaluate(`document.body.innerText.includes(${quote(alpha)})`));
      await click('[data-action="lang"]');
    });

    await run("GUI-222-014", async () => {
      await cdp.command("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
      await sleep(100);
      const dimensions = await cdp.evaluate("[document.documentElement.scrollWidth, document.documentElement.clientWidth]");
      assert.deepEqual(dimensions, [390, 390]);
      await cdp.command("Emulation.clearDeviceMetricsOverride");
    });

    await run("GUI-222-015", async () => {
      await newDraft();
      await input("#plan-name", "Language keeps this draft");
      if (await cdp.evaluate("document.documentElement.lang !== 'zh'")) await click('[data-action="lang"]');
      await wait("document.documentElement.lang === 'zh'", "Chinese console");
      assert.equal(await dom("#plan-name"), "Language keeps this draft");
      assert.ok(await cdp.evaluate("document.body.innerText.includes('导入 JSON') && document.body.innerText.includes('高级 JSON')"));
      await click('[data-action="lang"]');
    });

    await run("GUI-222-016", async () => {
      cdp.network = [];
      cdp.console = [];
      const faviconStatus = await cdp.evaluate("fetch('/favicon.ico').then(response => response.status)");
      assert.equal(faviconStatus, 204);
      await sleep(100);
      const externalRequests = cdp.network.filter(request => /^https?:/i.test(request.url)).filter(request => !["127.0.0.1", "localhost"].includes(new URL(request.url).hostname));
      assert.deepEqual(externalRequests, []);
      assert.deepEqual(cdp.console, []);
    });

    await run("GUI-222-017", async () => {
      const id = await createSaved("Console temporary data redaction");
      await closeEditor();
      await clearFetches();
      await click(`[data-plan-action="external"][data-id="${id}"]`);
      await wait("Boolean(document.querySelector('.plan-result'))", "external integration run", 20_000);
      await sleep(100);
      const response = (await fetched()).find(request => request.url.includes(`/api/plans/${id}/runs`));
      assert.ok(response, "the external-run response was captured");
      const sourceAccess = JSON.parse(response.body).source_access;
      assert.equal(Object.hasOwn(sourceAccess, "source_capability"), false);
      assert.equal(Object.hasOwn(sourceAccess, "fake_api_key"), false);
      const browserStorage = await cdp.evaluate("JSON.stringify({ localStorage: Object.fromEntries(Object.entries(localStorage)), sessionStorage: Object.fromEntries(Object.entries(sessionStorage)) })");
      assert.equal(/source_capability|fake_api_key/i.test(browserStorage), false);
    });

    if (failures.length) throw new AggregateError(failures.map(item => item.error), `${failures.length} browser regression case(s) failed`);
    console.log("GUI 0.2.2 browser regression: 17 passed, 0 failed");
  } catch (error) {
    if (!failures.length) await captureFailure("bootstrap", error);
    console.error(`Browser artifacts retained at ${artifactRoot}`);
    throw error;
  } finally {
    await cdp?.close();
    if (browser.exitCode === null) browser.kill();
    if (consoleServer.exitCode === null) consoleServer.kill();
    await waitForExit(browser);
    await waitForExit(consoleServer);
    if (!retainArtifacts) await removeTemporaryDirectory(artifactRoot);
    if (consoleServer.exitCode && serverOutput) console.error(serverOutput);
  }
}

await main();
