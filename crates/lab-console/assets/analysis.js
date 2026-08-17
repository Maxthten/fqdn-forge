(() => {
  "use strict";

  const pages = new Set(["analysis", "coverage", "replays", "campaigns", "soak", "evidence", "timelineTrend"]);
  const cache = new Map();
  const ui = { coverageDetail: null, graphNodeId: null, graphView: "graph", graphZoom: 1, timelineView: "timeline", trendView: "chart" };
  const labels = {
    en: {
      analysis: "Analysis overview", coverage: "Coverage matrix", replays: "Replay differences", campaigns: "Campaign", soak: "Soak", evidence: "Evidence graph", timelineTrend: "Timeline & trends",
      loading: "Loading server-generated analysis…", apply: "Apply filters", clear: "Clear", exportJson: "Export JSON", exportMarkdown: "Export Markdown", truncated: "Result truncated. Narrow filters or continue with the cursor.",
      empty: "No saved analysis data matches the current filters.", local: "Simulated offline test data · local read-only analysis", status: "Status", dimension: "Dimension", search: "Search", scenario: "Scenario", run: "Run ID", source: "Source", fqdn: "FQDN", verdict: "Verdict", evidenceType: "Evidence type", preset: "Preset", category: "Difference category", time: "Time", events: "Events", trends: "Trends", graph: "Graph", table: "Table", zoomIn: "Zoom in", zoomOut: "Zoom out", reset: "Reset", scope: "Select a run or scenario to load a bounded graph.", virtual: "Virtual time", real: "Artifact time", errors: "Diagnostics", next: "Next", previous: "Previous", noHistory: "No historical data is available.", requests: "Requests", retries: "Retries", rateLimited: "429 / rate limited", passed: "Passed", coverageSummary: "Coverage summary", simulated: "Simulated test data", reports: "Reports", recentRuns: "Recent runs", missing: "missing", excepted: "excepted", mismatch: "mismatch", value: "Value", explanation: "Explanation", related: "Related records", details: "Details", object: "Object", seed: "Seed", provenance: "Provenance", firstDifference: "First difference", differences: "Differences", mutations: "Mutations", runs: "Runs", failureCategories: "Failure categories", replay: "Replay", concurrency: "Concurrency", operations: "Operations", resources: "Resources", edges: "Edges", type: "Type", label: "Label", reason: "Reason", count: "Count", http: "HTTP", operation: "Operation", retryQuota: "Retry / quota", path: "Path", from: "From", to: "To", objectType: "Object type", start: "Start", end: "End", proxy: "Proxy", quota: "Quota", expected: "Expected rejection", failure: "Failure", timeline: "Timeline", openTimeline: "Open timeline", virtualWaitNote: "Virtual waits are simulated; artifact timestamps are wall-clock metadata."
    },
    zh: {
      analysis: "分析概览", coverage: "覆盖矩阵", replays: "回放差异", campaigns: "Campaign", soak: "Soak", evidence: "证据关系", timelineTrend: "时间线与趋势",
      loading: "正在加载服务端生成的分析数据…", apply: "应用筛选", clear: "清除", exportJson: "导出 JSON", exportMarkdown: "导出 Markdown", truncated: "结果已截断。请缩小筛选范围或使用 cursor 继续读取。",
      empty: "没有与当前筛选条件匹配的已保存分析数据。", local: "模拟离线测试数据 · 仅本机只读分析", status: "状态", dimension: "维度", search: "搜索", scenario: "场景", run: "运行 ID", source: "来源", fqdn: "FQDN", verdict: "结论", evidenceType: "证据类型", preset: "预设", category: "差异类别", time: "时间", events: "事件", trends: "趋势", graph: "关系图", table: "表格", zoomIn: "放大", zoomOut: "缩小", reset: "重置", scope: "请选择运行或场景，以加载有范围限制的关系图。", virtual: "虚拟时间", real: "artifact 时间", errors: "诊断", next: "下一页", previous: "上一页", noHistory: "暂无历史数据。", requests: "请求", retries: "重试", rateLimited: "429 / 限流", passed: "通过", coverageSummary: "覆盖摘要", simulated: "模拟测试数据", reports: "报告", recentRuns: "最近运行", missing: "缺失", excepted: "例外", mismatch: "不匹配", value: "值", explanation: "说明", related: "关联记录", details: "详情", object: "对象", seed: "Seed", provenance: "来源信息", firstDifference: "首个差异", differences: "差异", mutations: "变异", runs: "运行", failureCategories: "失败类别", replay: "回放", concurrency: "并发", operations: "操作数", resources: "资源", edges: "边", type: "类型", label: "标签", reason: "原因", count: "数量", http: "HTTP", operation: "操作", retryQuota: "重试 / 额度", path: "路径", from: "起点", to: "终点", objectType: "对象类型", start: "开始", end: "结束", proxy: "代理", quota: "额度", expected: "预期拒绝", failure: "失败", timeline: "时间线", openTimeline: "打开时间线", virtualWaitNote: "虚拟等待是模拟时间；artifact 时间戳为真实墙钟元数据。"
    }
  };
  const endpoints = {
    analysis: "/api/analysis/overview",
    coverage: "/api/analysis/coverage",
    replays: "/api/analysis/replays",
    campaigns: "/api/analysis/campaigns",
    soak: "/api/analysis/soak",
    evidence: "/api/analysis/evidence-graph",
    timelineTrend: "/api/analysis/timeline"
  };

  const context = () => window.FqdnForgeConsole;
  const t = key => labels[context()?.state?.lang || "en"][key] || key;
  const esc = value => context()?.esc?.(value) || String(value ?? "");
  const status = value => `<span class="badge ${/passed|matched|covered|correct/i.test(value) ? "good" : /failed|mismatch|missing|expired/i.test(value) ? "bad" : /partial|excepted|unavailable/i.test(value) ? "warn" : "local"}>${esc(value || "—")}</span>`;
  const value = (document, key, fallback) => document?.[key] ?? fallback;
  const documentFor = page => cache.get(page)?.document || null;
  const paramsFor = page => cache.get(page)?.params || new URLSearchParams();

  function pageTitle(page) { return `<h1 class="page-title">${t(page)}</h1><p class="muted">${t("local")}</p>`; }
  function exportControls(page) { return `<div class="analysis-actions"><button class="secondary small" data-analysis-export="json" data-analysis-page="${page}">${t("exportJson")}</button><button class="secondary small" data-analysis-export="markdown" data-analysis-page="${page}">${t("exportMarkdown")}</button></div>`; }
  function diagnostics(document) { const items = document?.diagnostics || []; return items.length ? `<details class="analysis-diagnostics"><summary>${t("errors")} (${items.length})</summary><ul>${items.map(item => `<li><code>${esc(item.code)}</code> · ${esc(item.object_id)} · ${esc(item.message)}</li>`).join("")}</ul></details>` : ""; }
  function truncated(document) { return document?.truncated ? `<p class="notice" role="status">${t("truncated")}</p>` : ""; }
  function filterInput(page, key, label, type = "text") { const current = paramsFor(page).get(key) || ""; return `<label>${esc(label)} <input type="${type}" data-analysis-filter="${page}" data-analysis-key="${key}" value="${esc(current)}"></label>`; }
  function filterSelect(page, key, label, options) { const current = paramsFor(page).get(key) || ""; return `<label>${esc(label)} <select data-analysis-filter="${page}" data-analysis-key="${key}"><option value="">—</option>${options.map(option => `<option value="${esc(option)}" ${current === option ? "selected" : ""}>${esc(option)}</option>`).join("")}</select></label>`; }
  function filters(page, fields) { return `<div class="toolbar analysis-filters">${fields.join("")}<button class="primary" data-analysis-action="load" data-analysis-page="${page}">${t("apply")}</button><button class="secondary" data-analysis-action="clear" data-analysis-page="${page}">${t("clear")}</button>${exportControls(page)}</div>`; }
  function table(headers, rows) { return rows.length ? `<div class="table-wrap"><table class="table"><thead><tr>${headers.map(header => `<th>${esc(header)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>` : `<div class="empty">${t("empty")}</div>`; }
  function pagination(page, document) { if (!document?.next_cursor && !(paramsFor(page).get("cursor") > 0)) return ""; const cursor = Number(paramsFor(page).get("cursor") || 0); return `<div class="analysis-actions"><button class="secondary small" data-analysis-action="previous" data-analysis-page="${page}" ${cursor === 0 ? "disabled" : ""}>${t("previous")}</button><button class="secondary small" data-analysis-action="next" data-analysis-page="${page}" ${document.next_cursor ? "" : "disabled"}>${t("next")}</button></div>`; }

  function overview(document) {
    const data = value(document, "data", {});
    const coverage = data.coverage || {};
    const counts = coverage.status_counts || {};
    const report = data.reports || {};
    const replay = data.replays || {};
    const failures = Object.entries(data.failure_categories || {}).map(([name, count]) => `${name}: ${count}`).join(", ") || "—";
    const recentCampaigns = data.campaigns?.recent || [];
    const recentSoaks = data.soak?.recent || [];
    return `${pageTitle("analysis")}<section class="notice"><strong>${t("simulated")}</strong><p>${esc(data.simulation_notice || "")}</p></section><div class="grid analysis-grid"><div class="card"><div class="label">${t("reports")}</div><div class="metric">${esc(report.count || 0)}</div></div><div class="card"><div class="label">${t("coverage")}</div><div class="metric">${esc(counts.covered || 0)}</div><div class="muted">${esc(counts.missing || 0)} ${t("missing")} · ${esc(counts.excepted || 0)} ${t("excepted")}</div></div><div class="card"><div class="label">${t("replays")}</div><div class="metric">${esc(replay.count || 0)}</div><div class="muted">${esc(replay.mismatch_count || 0)} ${t("mismatch")}</div></div><div class="card"><div class="label">Campaign / Soak</div><div class="metric">${esc(data.campaigns?.count || 0)} / ${esc(data.soak?.count || 0)}</div></div></div><section class="card"><h2>${t("recentRuns")}</h2>${table([t("scenario"), t("status"), t("time"), t("requests"), t("retries")], (report.recent || []).map(item => `<tr><td class="long-text">${esc(item.scenario_id)}</td><td>${status(item.status)}</td><td>${esc(item.finished_at)}</td><td>${esc(item.request_count)}</td><td>${esc(item.retry_count)}</td></tr>`))}</section><section class="two"><div class="card"><h2>Campaign</h2>${table([t("status"), t("seed"), t("failureCategories")], recentCampaigns.map(item => `<tr><td>${status(item.status)}</td><td>${esc(item.seed)}</td><td class="long-text">${esc(Object.entries(item.failure_categories || {}).map(([name, count]) => `${name}: ${count}`).join(", ") || "—")}</td></tr>`))}</div><div class="card"><h2>Soak</h2>${table([t("status"), t("operations"), t("concurrency")], recentSoaks.map(item => `<tr><td>${status(item.status)}</td><td>${esc(item.operations)}</td><td>${esc(item.concurrency)}</td></tr>`))}</div></section><section class="card"><h2>${t("failureCategories")}</h2><p class="long-text">${esc(failures)}</p></section>${diagnostics(document)}`;
  }

  function coverage(document) {
    const data = value(document, "data", {});
    const summary = data.summary || {};
    const counts = summary.status_counts || {};
    const cells = data.cells || [];
    const detail = cells.find(cell => `${cell.dimension}:${cell.value}` === ui.coverageDetail);
    const detailCard = detail ? `<section class="card"><h2>${t("details")}</h2><div class="kv"><span>${t("dimension")}</span><span>${esc(detail.dimension)}</span><span>${t("value")}</span><span>${esc(detail.value)}</span><span>${t("status")}</span><span>${status(detail.status)}</span><span>${t("related")}</span><span class="long-text">${esc([...(detail.scenario_ids || []), ...(detail.campaign_ids || []), ...(detail.exception_ids || [])].join(", ") || "—")}</span></div><p class="long-text">${esc(detail.description)}</p></section>` : "";
    return `${pageTitle("coverage")}${filters("coverage", [filterInput("coverage", "dimension", t("dimension")), filterSelect("coverage", "status", t("status"), ["covered", "partial", "missing", "excepted", "expired_exception"]), filterInput("coverage", "q", t("search"))])}<div class="grid analysis-grid">${Object.entries(counts).map(([name, count]) => `<div class="card"><div class="label">${esc(name)}</div><div class="metric">${esc(count)}</div></div>`).join("")}</div>${truncated(document)}${table([t("dimension"), t("value"), t("status"), t("related"), t("explanation")], cells.map(cell => `<tr><td>${esc(cell.dimension)}</td><td>${esc(cell.value)}</td><td>${status(cell.status)}</td><td class="long-text">${esc([...(cell.scenario_ids || []), ...(cell.campaign_ids || [])].join(", ") || "—")}</td><td><button class="secondary small" data-analysis-action="coverage-detail" data-analysis-id="${esc(`${cell.dimension}:${cell.value}`)}">${t("details")}</button></td></tr>`))}${detailCard}${pagination("coverage", document)}${diagnostics(document)}`;
  }

  function replays(document) {
    const rows = value(document, "data", {}).comparisons || [];
    return `${pageTitle("replays")}${filters("replays", [filterSelect("replays", "status", t("status"), ["matched", "mismatch", "unavailable"]), filterInput("replays", "scenario", t("scenario")), filterInput("replays", "category", t("category"))])}${truncated(document)}${table([t("status"), t("object"), t("seed"), t("provenance"), t("firstDifference"), t("differences")], rows.map(item => `<tr><td>${status(item.status)}</td><td class="long-text">${esc(item.scenario_or_plan_id)}</td><td>${esc(item.seed)}</td><td>${esc(item.provenance_status)}</td><td class="long-text">${esc(item.first_difference_path || "—")}</td><td><details><summary>${esc(item.difference_count || 0)}</summary><pre class="pre compact">${esc(JSON.stringify(item.differences || [], null, 2))}</pre></details>${item.timeline_run_id ? `<button class="secondary small" data-analysis-action="open-timeline" data-analysis-run="${esc(item.timeline_run_id)}">${t("openTimeline")}</button>` : ""}</td></tr>`))}${pagination("replays", document)}${diagnostics(document)}`;
  }

  function campaigns(document) {
    const rows = value(document, "data", {}).campaigns || [];
    return `${pageTitle("campaigns")}${filters("campaigns", [filterInput("campaigns", "campaign", t("campaigns")), filterSelect("campaigns", "status", t("status"), ["passed", "failed"])])}${truncated(document)}${table([t("campaigns"), t("status"), t("seed"), t("mutations"), t("runs"), t("failureCategories"), t("replay")], rows.map(item => `<tr><td class="long-text">${esc(item.campaign_id)}</td><td>${status(item.status)}</td><td>${esc(item.seed)}</td><td class="long-text">${esc((item.mutation_types || []).join(", "))}</td><td>${esc(item.total_runs)}</td><td class="long-text">${esc(Object.entries(item.failure_categories || {}).map(([key, count]) => `${key}: ${count}`).join(", ") || "—")}</td><td><details><summary>${item.replay_available ? "✓" : "—"}</summary><pre class="pre compact">${esc(JSON.stringify(item, null, 2))}</pre></details>${item.run_id ? `<button class="secondary small" data-analysis-action="open-timeline" data-analysis-run="${esc(item.run_id)}">${t("openTimeline")}</button>` : ""}</td></tr>`))}${pagination("campaigns", document)}${diagnostics(document)}`;
  }

  function soak(document) {
    const rows = value(document, "data", {}).soaks || [];
    return `${pageTitle("soak")}${filters("soak", [filterSelect("soak", "preset", t("preset"), ["smoke", "standard", "release"]), filterSelect("soak", "status", t("status"), ["passed", "failed"])])}<p class="muted">${t("virtualWaitNote")}</p>${truncated(document)}${table([t("preset"), t("status"), t("seed"), t("concurrency"), t("operations"), t("retries"), t("rateLimited"), t("resources")], rows.map(item => `<tr><td>${esc(item.preset)}</td><td>${status(item.status)}</td><td>${esc(item.seed)}</td><td>${esc(item.concurrency)}</td><td>${esc(item.operations)}</td><td>${esc(item.retries)}</td><td>${esc(item.rate_limited)}</td><td><details><summary>${t("details")}</summary><pre class="pre compact">${esc(JSON.stringify({ resources: item.resources, resource_invariants: item.resource_invariants, last_failure: item.last_failure }, null, 2))}</pre></details></td></tr>`))}${pagination("soak", document)}${diagnostics(document)}`;
  }

  function evidence(document) {
    const data = value(document, "data", {});
    const graph = data.nodes || [];
    const edges = data.edges || [];
    const controls = filters("evidence", [filterInput("evidence", "run", t("run")), filterInput("evidence", "scenario", t("scenario")), filterInput("evidence", "source", t("source")), filterInput("evidence", "fqdn", t("fqdn")), filterInput("evidence", "verdict", t("verdict")), filterInput("evidence", "evidence_type", t("evidenceType"))]);
    if (data.scope_required) return `${pageTitle("evidence")}${controls}<div class="empty">${t("scope")}</div>${diagnostics(document)}`;
    const selectedNode = graph.find(node => node.id === ui.graphNodeId);
    const index = new Map(graph.map((node, position) => [node.id, position]));
    const radius = 145 * ui.graphZoom;
    const centerX = 300;
    const centerY = 210;
    const point = node => { const position = index.get(node.id) || 0; const angle = (Math.PI * 2 * position) / Math.max(graph.length, 1) - Math.PI / 2; return { x: centerX + radius * Math.cos(angle), y: centerY + radius * Math.sin(angle) }; };
    const svg = `<svg class="evidence-svg" viewBox="0 0 600 420" role="img" aria-label="${esc(t("evidence"))}"><g>${edges.map(edge => { const from = point({ id: edge.from }); const to = point({ id: edge.to }); return `<line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" class="evidence-edge"/>`; }).join("")}</g><g>${graph.map(node => { const position = point(node); return `<g tabindex="0" role="button" data-analysis-action="graph-node" data-analysis-id="${esc(node.id)}"><circle cx="${position.x}" cy="${position.y}" r="19" class="evidence-node evidence-${esc(node.type)}"/><text x="${position.x}" y="${position.y + 4}" text-anchor="middle">${esc(String(node.label).slice(0, 8))}</text><title>${esc(`${node.type}: ${node.label} — ${node.visibility_reason}`)}</title></g>`; }).join("")}</g></svg>`;
    const tableView = table([t("type"), t("label"), t("reason"), t("count")], graph.map(node => `<tr><td>${esc(node.type)}</td><td class="long-text">${esc(node.label)}</td><td class="long-text">${esc(node.visibility_reason)}</td><td>${esc(node.count)}</td><td><button class="secondary small" data-analysis-action="graph-node" data-analysis-id="${esc(node.id)}">${t("details")}</button></td></tr>`));
    const detail = selectedNode ? `<section class="card"><h2>${t("details")}</h2><div class="kv"><span>${t("type")}</span><span>${esc(selectedNode.type)}</span><span>${t("label")}</span><span class="long-text">${esc(selectedNode.label)}</span><span>${t("reason")}</span><span class="long-text">${esc(selectedNode.visibility_reason)}</span><span>${t("count")}</span><span>${esc(selectedNode.count)}</span></div></section>` : "";
    return `${pageTitle("evidence")}${controls}${truncated(document)}<div class="analysis-actions"><button class="secondary small" data-analysis-action="graph-view">${ui.graphView === "graph" ? t("table") : t("graph")}</button><button class="secondary small" data-analysis-action="graph-zoom" data-analysis-delta="0.2">${t("zoomIn")}</button><button class="secondary small" data-analysis-action="graph-zoom" data-analysis-delta="-0.2">${t("zoomOut")}</button><button class="secondary small" data-analysis-action="graph-reset">${t("reset")}</button></div><section class="card"><h2>${t("simulated")}</h2>${ui.graphView === "graph" ? svg : tableView}<p class="muted">${esc(data.truncation_hint || "")}</p></section>${detail}<section class="card"><h2>${t("edges")}</h2>${table([t("from"), t("to"), t("type")], edges.map(edge => `<tr><td class="long-text">${esc(edge.from)}</td><td class="long-text">${esc(edge.to)}</td><td>${esc(edge.type)}</td></tr>`))}</section>${diagnostics(document)}`;
  }

  function timelineTrend(document) {
    const timeline = document?.timeline || null;
    const trends = document?.trends || null;
    const events = value(timeline, "data", {}).events || [];
    const points = value(trends, "data", {}).points || [];
    const timelineControls = filters("timelineTrend", [filterInput("timelineTrend", "run", t("run")), filterInput("timelineTrend", "scenario", t("scenario")), filterInput("timelineTrend", "source", t("source")), filterInput("timelineTrend", "status", t("status")), filterSelect("timelineTrend", "proxy", t("proxy"), ["true", "false"]), filterSelect("timelineTrend", "retry", t("retries"), ["true", "false"]), filterSelect("timelineTrend", "quota", t("quota"), ["true", "false"]), filterSelect("timelineTrend", "expected", t("expected"), ["true", "false"]), filterSelect("timelineTrend", "failure", t("failure"), ["true", "false"]), filterInput("timelineTrend", "object_type", t("objectType")), filterInput("timelineTrend", "from", t("start"), "datetime-local"), filterInput("timelineTrend", "to", t("end"), "datetime-local")]);
    const maxRequests = Math.max(1, ...points.map(point => Number(point.requests || 0)));
    const coordinates = points.map((point, index) => `${index * (560 / Math.max(points.length - 1, 1))},${180 - (Number(point.requests || 0) * 150 / maxRequests)}`).join(" ");
    const trendChart = points.length ? `<svg class="trend-svg" viewBox="0 0 580 210" role="img" aria-label="${esc(t("trends"))}"><line x1="10" y1="180" x2="570" y2="180" class="trend-axis"/><polyline points="${coordinates}" class="trend-line" fill="none"/></svg>` : `<div class="empty">${t("noHistory")}</div>`;
    const eventTable = table([t("time"), t("virtual"), t("source"), t("http"), t("operation"), t("retryQuota"), t("path")], events.map(event => `<tr><td>${esc(event.timestamp)}</td><td>${esc(event.virtual_time_ms)} ms</td><td>${esc(event.source_id || "—")}</td><td>${esc(event.status)}</td><td>${esc(event.operation)}</td><td>${event.retry ? "retry " : ""}${event.quota_consumed ? "quota " : ""}${event.expected_rejection ? "expected" : ""}</td><td class="long-text">${esc(event.path_summary)}</td></tr>`));
    const eventTimeline = events.length ? `<div class="timeline">${events.map(event => `<div class="event"><strong>${esc(event.operation)} · ${esc(event.status)} · ${esc(event.source_id || "—")}</strong><div class="muted">${t("real")}: ${esc(event.timestamp)} · ${t("virtual")}: ${esc(event.virtual_time_ms)} ms</div><div class="long-text">${esc(event.path_summary)}${event.retry_after ? ` · Retry-After ${esc(event.retry_after)}` : ""}</div></div>`).join("")}</div>` : `<div class="empty">${t("empty")}</div>`;
    const trendTable = table([t("time"), "Type", t("passed"), t("requests"), t("retries"), t("rateLimited"), t("virtual")], points.map(point => `<tr><td>${esc(point.timestamp)}</td><td>${esc(point.object_type)}</td><td>${point.passed ? "✓" : "—"}</td><td>${esc(point.requests)}</td><td>${esc(point.retries)}</td><td>${esc(point.rate_limited)}</td><td>${esc(point.virtual_wait_ms)} ms</td></tr>`));
    return `${pageTitle("timelineTrend")}${timelineControls}${truncated(timeline)}<section class="card"><div class="analysis-heading"><h2>${t("events")}</h2><button class="secondary small" data-analysis-action="timeline-view">${ui.timelineView === "timeline" ? t("table") : t("timeline")}</button></div><p class="muted">${esc(value(timeline, "data", {}).time_note || "")}</p>${ui.timelineView === "timeline" ? eventTimeline : eventTable}</section><section class="card"><div class="analysis-heading"><h2>${t("trends")}</h2><button class="secondary small" data-analysis-action="trend-view">${ui.trendView === "chart" ? t("table") : t("graph")}</button></div>${ui.trendView === "chart" ? trendChart : trendTable}<p class="muted">${esc(value(trends, "data", {}).unavailable?.coverage_gap_history || "")}</p></section>${diagnostics(timeline)}${diagnostics(trends)}`;
  }

  function render(page) {
    const document = documentFor(page);
    if (!document) {
      queueMicrotask(() => load(page).then(() => context()?.render?.({ preserveScroll: false })).catch(error => showError(error)));
      return `${pageTitle(page)}<div class="empty">${t("loading")}</div>`;
    }
    if (page === "analysis") return overview(document);
    if (page === "coverage") return coverage(document);
    if (page === "replays") return replays(document);
    if (page === "campaigns") return campaigns(document);
    if (page === "soak") return soak(document);
    if (page === "evidence") return evidence(document);
    return timelineTrend(document);
  }

  async function load(page, parameters) {
    const active = parameters || new URLSearchParams(paramsFor(page));
    if (page === "timelineTrend") {
      const timeline = new URLSearchParams(active);
      timeline.delete("object_type"); timeline.delete("from"); timeline.delete("to");
      const trends = new URLSearchParams(active);
      trends.delete("source"); trends.delete("status"); trends.delete("run"); trends.delete("proxy"); trends.delete("retry"); trends.delete("quota"); trends.delete("expected"); trends.delete("failure");
      const [timelineDocument, trend] = await Promise.all([request(endpoints.timelineTrend, timeline), request("/api/analysis/trends", trends)]);
      cache.set(page, { document: { timeline: timelineDocument, trends: trend }, params: active });
    } else {
      cache.set(page, { document: await request(endpoints[page], active), params: active });
    }
  }

  async function request(endpoint, parameters, format) {
    const url = new URL(endpoint, location.origin);
    if (url.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(url.hostname)) throw new Error("non-loopback analysis request refused");
    for (const [key, item] of parameters.entries()) url.searchParams.set(key, item);
    if (format) url.searchParams.set("format", format);
    const response = await fetch(url.pathname + url.search, { headers: { "x-fqdn-console-request": "1" } });
    if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.error?.message || body.error || String(response.status)); }
    return format ? response.blob() : response.json();
  }

  function collectParameters(page) {
    const parameters = new URLSearchParams();
    document.querySelectorAll(`[data-analysis-filter="${page}"]`).forEach(control => {
      const key = control.dataset.analysisKey;
      if (key && control.value) parameters.set(key, control.value);
    });
    return parameters;
  }

  async function exportView(page, format) {
    const blob = await request(page === "timelineTrend" ? endpoints.timelineTrend : endpoints[page], paramsFor(page), format);
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `fqdn-forge-${page}.${format === "markdown" ? "md" : "json"}`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(link.href);
  }

  function showError(error) {
    if (context()) { context().state.error = error.message || String(error); context().render?.(); }
  }

  document.addEventListener("click", async event => {
    const exportButton = event.target.closest("[data-analysis-export]");
    const action = event.target.closest("[data-analysis-action]");
    if (!exportButton && !action) return;
    event.preventDefault();
    try {
      if (exportButton) { await exportView(exportButton.dataset.analysisPage, exportButton.dataset.analysisExport); return; }
      const page = action.dataset.analysisPage || context()?.state?.page;
      if (action.dataset.analysisAction === "load") { await load(page, collectParameters(page)); context()?.render?.({ preserveScroll: false }); return; }
      if (action.dataset.analysisAction === "clear") { cache.delete(page); await load(page, new URLSearchParams()); context()?.render?.({ preserveScroll: false }); return; }
      if (action.dataset.analysisAction === "next") { const parameters = new URLSearchParams(paramsFor(page)); const next = documentFor(page)?.next_cursor; if (next) { parameters.set("cursor", next); await load(page, parameters); context()?.render?.({ preserveScroll: false }); } return; }
      if (action.dataset.analysisAction === "previous") { const parameters = new URLSearchParams(paramsFor(page)); const current = Number(parameters.get("cursor") || 0); parameters.set("cursor", String(Math.max(0, current - 200))); await load(page, parameters); context()?.render?.({ preserveScroll: false }); return; }
      if (action.dataset.analysisAction === "coverage-detail") { ui.coverageDetail = action.dataset.analysisId; context()?.render?.(); return; }
      if (action.dataset.analysisAction === "graph-node") { ui.graphNodeId = action.dataset.analysisId; context()?.render?.(); return; }
      if (action.dataset.analysisAction === "open-timeline") { const parameters = new URLSearchParams(); parameters.set("run", action.dataset.analysisRun); await load("timelineTrend", parameters); context().state.page = "timelineTrend"; context()?.render?.({ preserveScroll: false }); return; }
      if (action.dataset.analysisAction === "graph-view") ui.graphView = ui.graphView === "graph" ? "table" : "graph";
      if (action.dataset.analysisAction === "graph-zoom") ui.graphZoom = Math.max(.5, Math.min(1.8, ui.graphZoom + Number(action.dataset.analysisDelta || 0)));
      if (action.dataset.analysisAction === "graph-reset") { ui.graphZoom = 1; ui.graphView = "graph"; ui.graphNodeId = null; }
      if (action.dataset.analysisAction === "timeline-view") ui.timelineView = ui.timelineView === "timeline" ? "table" : "timeline";
      if (action.dataset.analysisAction === "trend-view") ui.trendView = ui.trendView === "chart" ? "table" : "chart";
      context()?.render?.();
    } catch (error) { showError(error); }
  });

  window.FqdnForgeAnalysis = { pages, page: render };
})();
