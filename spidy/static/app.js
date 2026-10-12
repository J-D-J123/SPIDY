"use strict";
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
let config, current = null, timer = null, historyTimer = null, focusTimer = null;
let selectedTab = "findings", refreshVersion = 0;
const draftCache = new Map();

function node(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = String(text);
  return el;
}
function showError(selector, error) {
  const el = $(selector); el.textContent = error.message || String(error); el.classList.remove("hidden");
}
async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST", headers: {"Content-Type": "application/json", "X-Spidy-Token": config.token}, body: JSON.stringify(body)
  };
  let response;
  try {
    response = await fetch(path, opts);
  } catch (e) {
    // A network-layer failure means the request never got a response — commonly a stale
    // keep-alive socket to a just-restarted server. One retry opens a fresh connection.
    // (The server rejects a duplicate mutation, so a retried POST cannot double-run.)
    await new Promise(r => setTimeout(r, 300));
    response = await fetch(path, opts);
  }
  let data; try { data = await response.json(); } catch { data = {}; }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
function friendlyTarget(url) { try { return new URL(url).host; } catch { return url; } }
function empty(container, title, description) {
  const box = node("div", "empty"); box.append(node("div", "", title), node("div", "small", description)); container.append(box);
}
function scopeLabel(scan) {
  // A follow-up is named by the origin it was approved for, so you can see what it is.
  const added = scan.added_origins || [];
  if (!added.length) return "Follow-up";
  return friendlyTarget(added[0]) + (added.length > 1 ? ` and ${added.length - 1} more` : "");
}
function historyItem(scan, nested) {
  const button = node("button", "history-item" + (nested ? " nested" : "") + (current?.id === scan.id ? " selected" : ""));
  button.append(node("strong", "", nested ? scopeLabel(scan) : friendlyTarget(scan.config.target)),
    node("small", "", `${scan.status} · ${new Date(scan.created_at).toLocaleDateString()}`));
  button.addEventListener("click", () => openScan(scan.id).catch(e => showError("#connection-error", e)));
  return button;
}
async function history() {
  const scans = await api("/api/scans"); $("#scan-count").textContent = scans.length;
  const container = $("#history"); container.replaceChildren();
  if (!scans.length) { container.append(node("p", "muted small", "Your scans will appear here.")); return; }
  // Group every approved-origin follow-up under the main domain it came from.
  const byId = new Map(scans.map(s => [s.id, s]));
  const rootOf = (scan) => { let cur = scan, guard = 0; while (cur.parent_id && byId.has(cur.parent_id) && guard++ < 50) cur = byId.get(cur.parent_id); return cur; };
  const groups = new Map();
  scans.forEach(scan => {
    const root = rootOf(scan);
    const group = groups.get(root.id) || {root, children: [], latest: root.created_at};
    if (scan.id !== root.id) group.children.push(scan);
    if (scan.created_at > group.latest) group.latest = scan.created_at;
    groups.set(root.id, group);
  });
  [...groups.values()].sort((a, b) => b.latest.localeCompare(a.latest)).slice(0, 18).forEach(group => {
    container.append(historyItem(group.root, false));
    group.children.sort((a, b) => a.created_at.localeCompare(b.created_at)).forEach(child => container.append(historyItem(child, true)));
  });
}
async function openScan(id) {
  disableAutoApproval();
  const version = ++refreshVersion; clearTimeout(timer);
  const scan = await api(`/api/scans/${id}`);
  if (version !== refreshVersion) return;
  hideCommandLog(); setActiveNav("new-scan-nav");
  current = scan; $("#setup").classList.add("hidden"); $("#results").classList.remove("hidden");
  render(); history().catch(() => {}); scheduleRefresh();
}
function autopilotTaskRunning() { return current?.autopilot?.task?.status === "running"; }
function scheduleRefresh() {
  clearTimeout(timer);
  const shouldPoll = current && (["queued", "running"].includes(current.status) || autopilotTaskRunning());
  if (shouldPoll) timer = setTimeout(async () => {
    const id = current.id, version = refreshVersion;
    const prevTask = current.autopilot?.task;
    try {
      const fresh = await api(`/api/scans/${id}`);
      if (version !== refreshVersion || current?.id !== id) return;
      current = fresh; render(); $("#connection-error").classList.add("hidden"); scheduleRefresh();
      if (!["queued", "running"].includes(current.status)) history().catch(() => {});
      const task = current.autopilot?.task;
      if (prevTask?.status === "running" && task?.status !== "running") autopilotSettled(prevTask);
    } catch (e) { showError("#connection-error", e); scheduleRefresh(); }
  }, autopilotTaskRunning() ? 600 : 1200);  // poll faster while a task streams its output
}
function render() {
  const s = current, running = ["queued", "running"].includes(s.status);
  $("#result-target").textContent = s.config.target;
  const followUp = s.parent_id ? ` · follow-up${(s.added_origins || []).length ? ` on ${friendlyTarget(s.added_origins[0])}` : ""}` : "";
  $("#result-meta").textContent = `${s.id.slice(0, 8)} · ${new Date(s.created_at).toLocaleString()}${followUp}`;
  $("#result-status").textContent = s.status; $("#result-status").className = `badge ${s.status}`;
  $("#stop-scan").classList.toggle("hidden", !running);
  $("#rescan").classList.toggle("hidden", running);
  $("#stop-scan").textContent = s.events.some(e => e.type === "cancel_requested") ? "Stopping…" : "Stop scan";
  $("#result-summary").textContent = s.summary;
  $("#metric-findings").textContent = s.findings.length; $("#metric-pages").textContent = s.pages.length;
  $("#metric-requests").textContent = `${s.events.filter(e => e.type === "request").length} / ${s.config.max_requests} HTTP attempts`;
  const pending = s.pending_origins.filter(p => p.decision === "pending").length;
  $("#metric-pending").textContent = pending; $("#scope-tab-count").textContent = pending;
  $("#metric-ports").textContent = s.config.checks.includes("ports") ? inventoryServices().filter(p => p.state === "open").length : "n/a";
  $("#download-pdf").href = `/api/scans/${s.id}/report.pdf`;
  $("#download-md").href = `/api/scans/${s.id}/report.md`; $("#download-json").href = `/api/scans/${s.id}/report.json`;
  renderFindings(); renderInventory(); renderScope(); renderTools(); renderActivity(); renderCoverage(); renderAssessment(); renderDraft();
}
function renderFindings() {
  const container = $("#findings-list"), openIds = new Set([...container.querySelectorAll("details[open]")].map(e => e.dataset.id));
  container.replaceChildren();
  const rank = {high: 0, medium: 1, low: 2, info: 3}, filter = $("#severity-filter").value;
  const findings = current.findings.filter(f => filter === "all" || f.severity === filter).sort((a, b) => rank[a.severity] - rank[b.severity]);
  if (!findings.length) empty(container, current.status === "running" ? "Spidy is looking into it…" : "No findings in this view.", "Check coverage and activity to see exactly what was tested.");
  findings.forEach(f => {
    const details = node("details", "finding"); details.dataset.id = f.id; details.open = openIds.has(f.id);
    const summary = node("summary"), title = node("div", "finding-title", f.title);
    title.append(node("small", "", `${f.id} · ${f.confidence} confidence · ${f.url}`)); summary.append(node("span", `badge ${f.severity}`, f.severity), title);
    const content = node("div", "finding-detail");
    content.append(node("p", "", f.description), node("h4", "", "Observed evidence"), node("div", "evidence", f.evidence), node("h4", "", "What to do next"), node("p", "", f.remediation));
    if (f.why_tested) content.append(node("h4", "", "Why this was tested"), node("p", "", f.why_tested), node("h4", "", "How to validate"), node("p", "", f.verification));
    const reference = node("a", "text-button", "Read the reference");
    if (["https://owasp.org/", "https://cheatsheetseries.owasp.org/", "https://nvd.nist.gov/", "https://docs.projectdiscovery.io/"].some(prefix => f.reference.startsWith(prefix))) reference.href = f.reference;
    reference.target = "_blank"; reference.rel = "noopener noreferrer"; content.append(reference); details.append(summary, content); container.append(details);
  });
}
function renderScope() {
  const container = $("#scope-list"); container.replaceChildren();
  if (!current.pending_origins.length) empty(container, "No additional origins discovered.", "Spidy stays within the explicitly approved scope.");
  current.pending_origins.forEach(p => {
    const box = node("div", "scope-item"); box.append(node("h4", "", p.origin), node("p", "", p.reason), node("p", "", `Discovered at ${p.source}`));
    if (p.decision !== "pending") box.append(node("span", "badge", p.decision));
    else {
      const controls = node("div", "scope-controls"), label = node("label"), check = node("input"); check.type = "checkbox";
      label.append(check, node("span", "", "I have permission to assess this origin"));
      const approve = node("button", "primary", "Approve & run follow-up"), deny = node("button", "secondary", "Keep blocked");
      approve.disabled = true; const running = ["queued", "running"].includes(current.status); deny.disabled = running; check.disabled = running;
      check.addEventListener("change", () => { approve.disabled = !check.checked; });
      async function decide(allowed) {
        approve.disabled = deny.disabled = true; $("#scope-error").classList.add("hidden");
        try {
          const result = await api(`/api/scans/${current.id}/decisions`, {approve: allowed ? [p.origin] : [], deny: allowed ? [] : [p.origin], authorized: allowed && check.checked});
          await openScan(result.id);
        } catch (e) { showError("#scope-error", e); approve.disabled = !check.checked; deny.disabled = false; }
      }
      approve.addEventListener("click", () => decide(true)); deny.addEventListener("click", () => decide(false)); controls.append(label, approve, deny); box.append(controls);
      if (running) box.append(node("p", "", "Scope decisions become available when this scan finishes."));
    }
    container.append(box);
  });
}
function renderActivity() {
  const container = $("#activity-list"); container.replaceChildren();
  if (!current.events.length) empty(container, "Waiting for the first action.", "Every request and scope decision will be recorded here.");
  current.events.slice().reverse().forEach(e => {
    const row = node("div", "event"), content = node("div", "event-content");
    content.textContent = e.url || e.target || e.purpose || e.reason || e.error || (e.host ? `${e.host}:${e.port} · ${e.state}` : e.status || "");
    const extras = Object.entries(e).filter(([k]) => !["time", "type", "url", "target", "coverage", "approved_origins"].includes(k)).map(([k,v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join(" · ");
    content.append(node("small", "", extras)); row.append(node("time", "", new Date(e.time).toLocaleTimeString([], {hour12:false})), node("span", "event-type", e.type.replaceAll("_", " ")), content); container.append(row);
  });
}
function renderCoverage() {
  const container = $("#coverage-list"); container.replaceChildren(); const grid = node("div", "coverage-grid");
  const coverage = {...current.coverage, selected_checks: current.config.checks.join(", "), active_input_probes: current.config.active, approved_additional_origins: current.approved_origins.join(", ") || "None"};
  Object.entries(coverage).forEach(([key, value]) => { const row = node("div", "coverage-row"); row.append(node("span", "", key.replaceAll("_", " ")), node("strong", "", value)); grid.append(row); }); container.append(grid);
}
// Scans from before 0.3, and scans still running, only have the raw connection results.
function inventoryServices() { return current.inventory?.services?.length ? current.inventory.services : current.ports.map(p => ({...p, evidence: p.evidence || p.note})); }
function table(headers, rows) {
  const el = node("table", "port-table"), head = node("tr"); headers.forEach(t => head.append(node("th", "", t))); el.append(head);
  rows.forEach(cells => {const row = node("tr"); cells.forEach(t => row.append(node("td", "", t ?? ""))); el.append(row);}); return el;
}
function renderInventory() {
  const inventory = current.inventory || {}, advisories = current.advisories || {}, selected = current.config.checks.includes("ports");
  const all = inventoryServices(), open = all.filter(s => s.state === "open");
  $("#inventory-status").textContent = selected ? (inventory.coverage?.status || "in progress").replaceAll("_", " ") : "not selected";
  const services = $("#inventory-services"); services.replaceChildren();
  if (open.length) services.append(table(["Port", "Service", "Software", "Confidence", "Address", "Evidence"], open.map(s => [s.port,
    s.service_verified === false ? `${s.service_hint && s.service_hint !== "unknown" ? s.service_hint + "?" : "unknown"} (unverified)` : s.service || "unknown",
    [s.product, s.version].filter(Boolean).join(" ") || "Not identified", s.confidence || "low", s.ip || "n/a", s.evidence || ""])));
  else services.append(node("p", "inventory-note", !selected ? "The service inventory was not part of this assessment." : all.length ? "No probed port accepted a connection." : "No port results yet."));
  const unopened = new Map();
  all.filter(s => s.state !== "open").forEach(s => { const key = `${s.ip || s.host} · ${s.state}`; unopened.set(key, [...(unopened.get(key) || []), s.port]); });
  unopened.forEach((ports, key) => services.append(node("p", "inventory-note small", `${key} · ${ports.length} port(s): ${ports.join(", ")}`)));
  (inventory.coverage?.limitations || []).forEach(note => services.append(node("p", "inventory-note small", note)));
  const software = $("#inventory-software"); software.replaceChildren();
  const technologies = inventory.technologies || [];
  if (technologies.length) software.append(table(["Product", "Version", "Confidence", "Evidence", "Seen at"], technologies.map(t => [t.product, t.version || "Not disclosed", t.confidence, t.evidence, t.source])));
  else software.append(node("p", "inventory-note", "No product or version was advertised in the inspected responses and banners."));
  (inventory.tls || []).forEach(t => software.append(node("p", "inventory-note small", `TLS on ${t.host}:${t.port} · ${t.tls_version || "?"} · ${t.cipher || "?"} · certificate valid until ${t.certificate_not_after || "not recorded"} · issued by ${t.certificate_issuer || "not recorded"}`)));
  $("#advisory-status").textContent = (advisories.status || "not run").replaceAll("_", " ");
  $("#advisory-note").textContent = advisories.status && advisories.status !== "disabled"
    ? "A version match is a lead to verify with the owner, not a confirmed vulnerability. Distributions often patch without changing the version number."
    : "Lookup was off for this assessment. Enable “Look up known vulnerabilities” when you start one.";
  const list = $("#advisory-list"), openIds = new Set([...list.querySelectorAll("details[open]")].map(e => e.dataset.id)); list.replaceChildren();
  (advisories.queries || []).forEach(q => list.append(node("p", "inventory-note small", `${q.product} ${q.version} · ${q.status} · ${q.count} candidate(s)${q.truncated ? ` of ${q.total_results} published` : ""}${q.reason ? ` · ${q.reason}` : ""}`)));
  const verification = current.advisory_verification;
  if (verification && (advisories.candidates || []).length) {
    list.append(node("h4", "verify-heading", "Did these survive host verification?"));
    list.append(node("p", "inventory-note small", verification.note));
    verification.rows.forEach(row => {
      const badges = {corroborated: "medium", version_differs: "low", not_installed: "info", not_checkable: "info", inconclusive: "info"};
      const line = node("p", "inventory-note small");
      line.append(node("span", `badge ${badges[row.status] || "info"}`, row.status.replaceAll("_", " ")),
        node("span", "", ` ${row.product} ${row.advertised_version}, installed: ${row.installed.join("; ") || "no matching package"} · ${row.cve_ids.slice(0, 8).join(", ")} · ${row.note}`));
      list.append(line);
    });
  }
  (advisories.candidates || []).forEach(c => {
    const details = node("details", "finding"); details.dataset.id = c.id; details.open = openIds.has(c.id);
    const summary = node("summary"), title = node("div", "finding-title", c.id);
    title.append(node("small", "", `${c.product} ${c.version} · candidate, not confirmed`)); summary.append(node("span", `badge ${c.severity === "critical" ? "high" : c.severity || "info"}`, c.severity || "unrated"), title);
    const content = node("div", "finding-detail"); content.append(node("p", "", c.description || "No description published."), node("p", "", c.match_reason));
    const link = node("a", "text-button", "Read the NVD entry");
    if (String(c.url).startsWith("https://nvd.nist.gov/vuln/detail/CVE-")) link.href = c.url;
    link.target = "_blank"; link.rel = "noopener noreferrer"; content.append(link);
    if ((c.references || []).length) {
      content.append(node("h4", "", "Published references (NVD)"));
      c.references.forEach(ref => {
        const row = node("div", "ref-row");
        (ref.tags || []).forEach(tag => row.append(node("span", `badge ${tag === "Exploit" ? "medium" : "info"}`, tag)));
        const refLink = node("a", "text-button", ref.url);
        if (/^https?:\/\//.test(ref.url)) { refLink.href = ref.url; refLink.target = "_blank"; refLink.rel = "noopener noreferrer"; }
        row.append(refLink); content.append(row);
      });
      content.append(node("p", "inventory-note small", "These are pointers NVD publishes. Spidy does not run them. Use only against systems you are authorized to test."));
    }
    details.append(summary, content); list.append(details);
  });
  $("#host-command").textContent = `python3 -m spidy host-inventory ${friendlyTarget(current.config.target).replace(/:\d+$/, "")}`;
  const processes = $("#process-list"), host = inventory.process_inventory || {}; processes.replaceChildren();
  if (host.status === "owner_supplied") {
    processes.append(node("p", "inventory-note", `Owner-supplied inventory from ${new Date(host.collected_at).toLocaleString()} · ${host.platform.system} ${host.platform.release} · ${host.processes.length} processes · ${host.packages.length} packages. ${host.reason}`));
    const groups = new Map();
    const visible = host.processes.filter(p => p.executable);
    visible.forEach(p => { const key = [p.name, p.package, p.package_version].join("\u0000"); groups.set(key, (groups.get(key) || 0) + 1); });
    const rows = [...groups].map(([key, count]) => { const [name, pkg, version] = key.split("\u0000"); return [name, count, pkg || "Not established", version || "n/a"]; })
      .sort((a, b) => (a[3] === "n/a") - (b[3] === "n/a") || a[0].localeCompare(b[0]));
    processes.append(table(["Process", "Running", "Package", "Installed version"], rows.slice(0, 300)));
    processes.append(node("p", "inventory-note small", `${Math.max(0, rows.length - 300)} more distinct processes and ${host.processes.length - visible.length} kernel threads or processes without a readable executable are in the JSON export.`));
  } else processes.append(node("p", "inventory-note", "No host inventory imported yet."));
}
$("#host-inventory-file").addEventListener("change", async event => {
  const file = event.target.files[0], id = current.id; event.target.value = ""; $("#host-inventory-error").classList.add("hidden");
  if (!file) return;
  try {
    if (file.size > 1900000) throw new Error("That file is too large to be a Spidy host inventory.");
    let data; try { data = JSON.parse(await file.text()); } catch { throw new Error("That file is not valid JSON."); }
    await api(`/api/scans/${id}/host-inventory`, data); await openScan(id);
  } catch (e) { showError("#host-inventory-error", e); }
});
function newScan() {
  disableAutoApproval();
  hideCommandLog(); setActiveNav("new-scan-nav");
  ++refreshVersion; clearTimeout(timer); current = null; $("#setup").classList.remove("hidden"); $("#results").classList.add("hidden"); $("#target").focus(); history().catch(() => {});
}
function probeHint() {
  const inputSelected = $$("input[name=checks]:checked").some(e => ["sqli", "reflection", "cors", "redirects", "methods", "nuclei"].includes(e.value));
  $("#probe-hint").classList.toggle("hidden", !inputSelected || $("#active").checked);
  $("#inventory-options").classList.toggle("hidden", !$("input[value=ports]").checked);
  $("#discovery-options").classList.toggle("hidden", !$("input[value=discovery]").checked);
}
$("#scan-form").addEventListener("submit", async event => {
  event.preventDefault(); $("#form-error").classList.add("hidden"); const button = $("#start-button"); button.disabled = true;
  try {
    const scan = await api("/api/scans", {target: $("#target").value, focus: $("#focus").value, checks: $$("input[name=checks]:checked").map(c => c.value), active: $("#active").checked, authorized: $("#authorized").checked, max_pages: Number($("#max-pages").value), max_requests: Number($("#max-requests").value), discovery: $("input[value=discovery]").checked, max_paths: Number($("#max-paths").value), inventory: $("input[value=ports]").checked, port_profile: $("#port-profile").value, custom_ports: $("#custom-ports").value, advisory_lookup: $("#advisories").checked, llm_model: ($("#setup-llm-model") && $("#setup-llm-model").value) || ""});
    await openScan(scan.id);
  } catch (e) {showError("#form-error", e);} finally {button.disabled = false;}
});
$("#focus").addEventListener("input", () => {
  clearTimeout(focusTimer); const text = $("#focus").value;
  focusTimer = setTimeout(async () => { try { const result = await api("/api/focus", {text}); if ($("#focus").value !== text) return; if (result.checks.length) $$("input[name=checks]").forEach(c => {c.checked = result.checks.includes(c.value) || (c.value === "ports" && c.checked);}); probeHint(); } catch {} }, 350);
});
$$("input[name=checks], #active").forEach(c => c.addEventListener("change", probeHint));
$("#new-scan-nav").addEventListener("click", newScan); $("#new-assessment").addEventListener("click", newScan);
$("#refresh-models").addEventListener("click", () => loadModels(true));
$("#stop-scan").addEventListener("click", async () => {try {await api(`/api/scans/${current.id}/cancel`, {}); $("#stop-scan").textContent = "Stopping…";} catch(e) {showError("#connection-error", e);}});
$("#rescan").addEventListener("click", async () => {
  if (!current) return; const c = current.config; $("#rescan").disabled = true;
  try {
    // Re-run the same domain with the same settings as a fresh top-level assessment.
    const scan = await api("/api/scans", {target: c.target, focus: c.focus || "", checks: c.checks, active: !!c.active, authorized: true,
      max_pages: c.max_pages || 15, max_requests: c.max_requests || 80, discovery: !!c.discovery, max_paths: c.max_paths || 12,
      inventory: c.inventory !== false, port_profile: c.port_profile || "common", custom_ports: c.custom_ports || [], advisory_lookup: c.advisory_lookup !== false, llm_model: c.llm_model || ""});
    await openScan(scan.id);
  } catch (e) { showError("#connection-error", e); } finally { $("#rescan").disabled = false; }
});
$("#severity-filter").addEventListener("change", renderFindings);
$$(".tab").forEach(tab => tab.addEventListener("click", () => {
  selectedTab = tab.dataset.tab; $$(".tab").forEach(t => {t.classList.toggle("active", t === tab); t.setAttribute("aria-selected", String(t === tab));}); $$(".tab-panel").forEach(p => p.classList.toggle("hidden", p.id !== `tab-${selectedTab}`));
}));
$("#how-it-works").addEventListener("click", () => $("#about").showModal());
[$("#close-about"), $("#about-done")].forEach(b => b.addEventListener("click", () => $("#about").close()));

// --- Command log: a chat-style transcript of the guide/executor steps for one scan ---
function setActiveNav(id) { $$(".nav-item").forEach(b => b.classList.toggle("active", b.id === id)); }
function hideCommandLog() {
  $("#commandlog-view").classList.add("hidden");
  $("main > .breadcrumb")?.classList.remove("hidden");
  $("main > .page-heading")?.classList.remove("hidden");
}
async function showCommandLog() {
  disableAutoApproval();
  ++refreshVersion; clearTimeout(timer); current = null;
  $("#setup").classList.add("hidden"); $("#results").classList.add("hidden");
  $("main > .breadcrumb")?.classList.add("hidden");
  $("main > .page-heading")?.classList.add("hidden");
  $("#commandlog-view").classList.remove("hidden");
  $("#commandlog-error").classList.add("hidden");
  setActiveNav("command-log-nav");
  await populateCommandLogScans();
}
async function populateCommandLogScans() {
  const select = $("#commandlog-scan");
  try {
    const scans = await api("/api/scans");
    const prev = select.value;
    const placeholder = node("option", "", "Choose an assessment…"); placeholder.value = "";
    select.replaceChildren(placeholder);
    scans.forEach(s => {
      const o = node("option", "", `${friendlyTarget(s.config.target)} · ${s.status} · ${new Date(s.created_at).toLocaleString()}`);
      o.value = s.id; select.append(o);
    });
    if (prev && scans.some(s => s.id === prev)) select.value = prev; else renderCommandLog(null);
  } catch (e) { showError("#commandlog-error", e); }
}
function clogEmpty(text) { return node("div", "chatlog-empty", text); }
function clogCommand(step) {
  if (step.command) return step.command;
  if (step.tool) return `${step.tool} ${JSON.stringify(step.options || {})}`;
  return step.instructions || "";
}
function clogBadgeClass(outcome) {
  if (outcome === "ran") return "completed";
  if (["failed", "error", "timed out", "timed_out", "tool_error"].includes(outcome)) return "failed";
  if (outcome === "running") return "running";
  return "info";
}
function clogRow(kind, who, step, build) {
  const row = node("div", "clog-row clog-" + kind);
  const main = node("div", "clog-main");
  const name = node("div", "clog-name");
  name.append(node("span", "clog-whoname", who));
  if (step?._index) name.append(node("span", "clog-step", "Step " + step._index));
  const content = node("div", "clog-content");
  build(content);
  main.append(name, content);
  row.append(node("div", "clog-avatar", who[0]), main);
  return row;
}
function renderCommandLog(scan) {
  const body = $("#commandlog-body"), meta = $("#commandlog-meta");
  body.replaceChildren();
  if (!scan) { meta.textContent = ""; body.append(clogEmpty("Pick an assessment above to read its guide and executor command log.")); return; }
  const plan = scan.autopilot || {}, steps = plan.steps || [];
  const exec = plan.model || "executor", guide = plan.guide_model;
  meta.textContent = `${friendlyTarget(scan.config.target)} · ${steps.length} step(s)` +
    (guide && guide !== exec ? ` · guide ${guide} → executor ${exec}` : ` · executor ${exec}`);
  if (!steps.length) {
    body.append(clogEmpty("No Autopilot steps recorded for this assessment. Run Autopilot from the Deep scans tab to build a command log."));
    return;
  }
  steps.forEach((step, i) => {
    step._index = i + 1;
    if (step.guidance) body.append(clogRow("guide", "Guide", step, c => c.append(node("div", "clog-text", step.guidance))));
    body.append(clogRow("exec", "Executor", step, c => {
      if (step.reason) c.append(node("div", "clog-text", step.reason));
      const cmd = clogCommand(step), outcome = stepOutcome(step);
      if (cmd) {
        const block = node("div", "clog-command");
        block.append(node("span", "clog-prompt", (step.command || step.tool) ? "$" : "›"), node("code", "", cmd));
        c.append(block);
      }
      const status = node("div", "clog-status");
      status.append(node("span", "badge " + clogBadgeClass(outcome), outcome));
      if (step.added !== undefined) status.append(node("span", "small muted", `+${step.added} finding(s)`));
      if (step.approval_mode === "automatic") status.append(node("span", "small muted", "auto-approved"));
      c.append(status);
      if (step.error) c.append(node("div", "notice error clog-err", step.error));
      if (step.meta && step.meta.output !== undefined) {
        const det = node("details", "clog-output");
        det.append(node("summary", "", `Terminal output · exit ${step.meta.exit_code}${step.meta.timed_out ? " · timed out" : ""}${step.meta.output_truncated ? " · truncated" : ""}`),
                   node("pre", "terminal-output", terminalText(step.meta.output) || "(no output)"));
        c.append(det);
      }
    }));
  });
}
$("#command-log-nav").addEventListener("click", () => showCommandLog().catch(e => showError("#commandlog-error", e)));
$("#commandlog-scan").addEventListener("change", async () => {
  const id = $("#commandlog-scan").value;
  $("#commandlog-error").classList.add("hidden");
  if (!id) { renderCommandLog(null); return; }
  try { renderCommandLog(await api(`/api/scans/${id}`)); } catch (e) { showError("#commandlog-error", e); }
});
$("#load-demo").addEventListener("click", () => {newScan(); $("#target").value = config.demo_target; $$("input[name=checks]").forEach(c => {c.checked = true;}); $("#active").checked = true; $("#max-pages").value = 8; probeHint();});
function renderAssessment() {
  $("#assessment-progress").textContent = current.progress || "No actions recorded yet.";
  const assessment = current.analysis;
  if (!assessment) return;
  $("#assessment-summary").textContent = assessment.executive_summary;
  const container = $("#priority-list"); container.replaceChildren();
  if (!assessment.issue_groups.length) empty(container, "No issue groups yet.", "Use Coverage and Activity to understand the limits of this assessment.");
  for (const priority of ["Fix first", "Validate next", "Hardening", "Context only"]) {
    const groups = assessment.issue_groups.filter(g => g.priority === priority);
    if (!groups.length) continue;
    const section = node("section", "priority-section"); section.append(node("h3", "", `${priority} · ${groups.length}`));
    groups.forEach(g => {
      const item = node("details", "triage-item"), summary = node("summary");
      summary.append(node("span", `badge ${g.severity}`, g.severity), node("strong", "", g.title));
      const detail = node("div", "triage-detail");
      detail.append(node("p", "small", `${g.certainty} · ${g.confidence} confidence · ${g.urls.length} route(s) · ${g.finding_ids.join(", ")}`),
        node("p", "", g.description), node("h4", "", "Why this matters"), node("p", "", g.why_tested),
        node("h4", "", "Observed evidence"), node("div", "evidence", g.evidence_samples.join("\n")),
        node("h4", "", "Recommended action"), node("p", "", g.remediation), node("h4", "", "Verify before making a claim"), node("p", "", g.verification));
      item.append(summary, detail); section.append(item);
    }); container.append(section);
  }
  renderLLM();
  const methods = $("#methodology-list"); methods.replaceChildren();
  assessment.methodology.forEach(m => {
    const box = node("details", "method-item"), summary = node("summary", "", `${m.name}: ${m.state}`);
    box.append(summary, node("p", "", m.why), node("p", "", m.how), node("p", "small", `${m.requests} tagged HTTP attempts · ${m.inspections} inspections`));
    m.skip_reasons.forEach(reason => box.append(node("p", "small", reason))); methods.append(box);
  });
}
let toolsLoaded = false, toolCatalog = [];
async function renderTools() {
  const container = $("#tools-list"); if (!container) return;
  const finished = !["queued", "running"].includes(current.status);
  if (!toolsLoaded) {
    toolsLoaded = true;
    try { toolCatalog = (await api("/api/tools")).tools || []; } catch (e) { toolCatalog = []; }
  }
  renderAutopilot();
  if (container.childElementCount && container.dataset.scan === current.id) { container.querySelectorAll("button.run-tool").forEach(b => b.disabled = !finished || b.dataset.ready === "false"); return; }
  container.replaceChildren(); container.dataset.scan = current.id;
  if (!toolCatalog.length) { empty(container, "No external tools found.", "Run install-tools.sh to add nuclei, naabu, ffuf, and more."); return; }
  toolCatalog.forEach(tool => {
    const ready = tool.installed && tool.ready !== false;
    const card = node("div", "tool-card");
    const head = node("div", "tool-head");
    head.append(node("strong", "", tool.label), node("span", `badge ${ready ? "" : "info"}`, ready ? tool.input : tool.installed ? "needs repair" : "not installed"));
    card.append(head);
    const opts = node("div", "tool-opts");
    const inputs = {};
    Object.entries(tool.options || {}).forEach(([key, val]) => {
      const label = node("label", "", key + " ");
      const input = node("input"); input.value = val; input.className = "tool-opt"; input.size = Math.min(28, Math.max(10, String(val).length + 2));
      inputs[key] = input; label.append(input); opts.append(label);
    });
    card.append(opts);
    const row = node("div", "tool-run-row");
    const run = node("button", "primary run-tool", "Run"); run.disabled = !ready || !finished; run.dataset.ready = String(ready);
    const status = node("span", "muted small", ready ? "" : tool.error || `Needs ${tool.needs}.`);
    run.addEventListener("click", async () => {
      run.disabled = true; status.textContent = `Running ${tool.name}… this can take a while.`;
      const options = {}; Object.entries(inputs).forEach(([k, el]) => options[k] = el.value);
      try {
        const res = await api(`/api/scans/${current.id}/tool`, {tool: tool.name, options});
        status.textContent = `Done — added ${res.added} finding(s). Total: ${res.findings}.`;
        const fresh = await api(`/api/scans/${current.id}`); if (current?.id === fresh.id) { current = fresh; renderFindings(); renderAssessment(); }
      } catch (e) { status.textContent = e.message; }
      finally { run.disabled = !finished; }
    });
    row.append(run, status); card.append(row); container.append(card);
  });
}
let autoApproveScanId = null, autopilotSubmitting = false;
const guideContextDrafts = new Map();
const planningModelDrafts = new Map();
function renderGuideComposer(working) {
  const input = $("#autopilot-guide-context");
  if (!input) return;
  if (input.scanId !== current.id) {
    input.scanId = current.id;
    input.value = guideContextDrafts.get(current.id) ?? current.autopilot?.guide_context ?? "";
    $("#guide-context-status").textContent = "";
  }
  $("#autopilot-send-context").disabled = working || autopilotSubmitting || ["queued", "running"].includes(current.status);
  $("#autopilot-model").disabled = working || autopilotSubmitting;
  $("#autopilot-guide-model").disabled = working || autopilotSubmitting;
  const selection = planningModelDrafts.get(current.id) || current.autopilot || {};
  for (const [selector, key] of [["#autopilot-model", "model"], ["#autopilot-guide-model", "guide_model"]]) {
    const picker = $(selector);
    if (picker.scanId !== current.id && picker.options?.length) {
      if (selection[key] !== undefined && [...picker.options].some(option => option.value === selection[key])) picker.value = selection[key];
      picker.scanId = current.id;
    }
  }
  resizeGuideComposer();
}
function checkBackend(fresh) {
  if (config?.instance_id && fresh.instance_id !== config.instance_id) disableAutoApproval();
  config = fresh;
  const compatible = fresh.planner_protocol === 2 && !fresh.restart_required;
  const message = compatible ? "" : "Spidy’s dashboard and running server are out of sync. Restart Spidy, then refresh this page. Autopilot is paused until the updated server is running.";
  $("#runtime-notice").textContent = message;
  $("#runtime-notice").classList.toggle("hidden", compatible);
  if (!compatible) {
    disableAutoApproval();
    throw new Error(message);
  }
}
async function ensureCurrentBackend() { checkBackend(await api("/api/config")); }
function disableAutoApproval() {
  autoApproveScanId = null;
  $("#autopilot-auto-approve").checked = false;
  $("#autopilot-auto-state").textContent = "Auto-approve off";
}
function autoApprovalEnabled() { return !!current && autoApproveScanId === current.id; }
function autoApprovalStatus() {
  if (!autoApprovalEnabled()) return "Auto-approve off";
  const plan = current.autopilot || {};
  if (autopilotTaskRunning() || autopilotSubmitting) return "Auto-approve on · working";
  if (plan.task?.status === "error") return "Auto-approve on · needs attention";
  if (["done", "stop"].includes(plan.proposal?.action)) return "Auto-approve on · planning finished";
  if (plan.proposal && (plan.proposal.action !== "run" || plan.proposal.needs_preparation || plan.proposal.command === "")) return "Auto-approve on · waiting for a runnable step";
  return "Auto-approve on";
}
async function submitAutopilotRun(p, options, automatic = false) {
  if (!current || autopilotTaskRunning() || autopilotSubmitting) return;
  const scanId = current.id;
  if (automatic && !autoApprovalEnabled()) return;
  const body = {action: "run", proposal_id: p.id, approved: true,
    approval_mode: automatic ? "automatic" : "manual"};
  if (typeof p.command === "string") body.command = p.command;
  else body.options = options || p.options || {};
  autopilotSubmitting = true;
  $("#autopilot-status").textContent = automatic ? "Auto-approved; running action…" : "Running approved action…";
  renderAutopilot();
  try {
    await ensureCurrentBackend();
    if (current?.id !== scanId || (automatic && !autoApprovalEnabled())) return;
    const res = await api(`/api/scans/${scanId}/autopilot`, body);
    if (current?.id !== scanId) return;
    current.autopilot = {...(current.autopilot || {}), task: res.task, proposal: null};
    scheduleRefresh();
  } catch (e) {
    if (current?.id === scanId) {
      $("#autopilot-status").textContent = e.message + (autoApprovalEnabled() ? " Auto-approve remains on; request a new proposal to continue." : "");
    }
  } finally {
    autopilotSubmitting = false;
    if (current?.id === scanId) renderAutopilot();
  }
}
function autoApprovePending() {
  if (!autoApprovalEnabled() || autopilotTaskRunning() || autopilotSubmitting) return;
  const p = current.autopilot?.proposal;
  if (!p) return;
  if (p.action !== "run" || p.needs_preparation || p.command === "") {
    $("#autopilot-status").textContent = p.action === "paused" ? planningPauseMessage(p)
      : "Auto-approve is on, but this step cannot run automatically. " + (p.reason || "Add context or request a new proposal.");
    $("#autopilot-auto-state").textContent = autoApprovalStatus();
    return;
  }
  return submitAutopilotRun(p, p.options, true);
}
function stepOutcome(st) {
  let outcome = st.outcome || st.status || "step";
  if (outcome === "ran" && st.meta?.timed_out) return "timed out";
  if (outcome === "ran" && st.meta?.exit_code != null && st.meta.exit_code !== 0) return "failed";
  return outcome;
}
function planningPauseMessage(proposal) {
  const mode = autoApprovalEnabled() ? "Auto-approve remains on, waiting for a runnable proposal." : "Auto-approve is off.";
  if (proposal.pause_reason === "model_output") return "Planning stopped after the models returned repetitive or incomplete output. The broken responses were discarded. No new command was executed. " + mode;
  return proposal.pause_reason === "repeated_action" || proposal.rejected_repeats?.length
    ? "Next proposal blocked because it repeats recorded work. No new command was executed. " + mode + " Add context or use Propose next step to request different work."
    : "Planning paused before another command could run. " + mode + " " + (proposal.reason || "Review the planning attempts below.");
}
function executionReceipt(plan) {
  const recorded = (plan.steps || []).map((step, index) => ({step, index: index + 1}))
    .filter(({step}) => ["ran", "failed", "timed out", "error", "tool_error", "timed_out"].includes(stepOutcome(step)));
  const last = recorded.at(-1);
  if (!last) return null;
  const {step, index} = last, outcome = stepOutcome(step), meta = step.meta || {};
  const status = outcome === "ran" ? "process completed" : outcome;
  const http = [...String(meta.output || "").matchAll(/^HTTP\/\S+\s+(\d{3})\b/gm)].at(-1)?.[1];
  const receipt = node("details", "execution-receipt");
  receipt.append(node("summary", "", `Last execution #${index}: ${status}${meta.exit_code != null ? ` · exit ${meta.exit_code}` : ""}${http ? ` · HTTP ${http}` : ""} — view output`));
  receipt.append(stepNode(step, index, true));
  return receipt;
}
function stepNode(st, index, open) {
  const line = node("div", "autopilot-step");
  const name = st.command ? "custom command" : st.tool || "manual step";
  const outcome = stepOutcome(st);
  const result = outcome === "ran" ? (st.command ? " · output saved" : st.added !== undefined ? ` → +${st.added} finding(s)` : "") : "";
  line.append(node("strong", "", `${index ? "#" + index + " · " : ""}${outcome} · ${name}${result}`));
  if (st.command) line.append(node("pre", "command-output", st.command));
  else if (Object.keys(st.options || {}).length) line.append(node("pre", "command-output", `${st.tool} ${JSON.stringify(st.options)}`));
  if (st.reason) line.append(node("div", "small muted", st.reason));
  if (st.approval_mode === "automatic") line.append(node("div", "small muted", "Auto-approved for this session"));
  if (st.error) line.append(node("div", "notice error", st.error));
  if (st.discussion?.length) {
    const transcript = node("details", "step-discussion");
    transcript.append(node("summary", "", "Planning conversation"));
    for (const entry of st.discussion) {
      const role = entry.role === "executor" ? "exec" : entry.role;
      const name = {guide: "Guide", exec: "Executor", user: "You", checks: "Spidy checks"}[role] || "Spidy";
      transcript.append(chatBubbleEl(role, name + (entry.model ? ` · ${entry.model}` : ""), entry.text));
    }
    line.append(transcript);
  }
  if (st.meta?.output !== undefined) {
    const details = node("details"); if (open) details.open = true;
    details.append(node("summary", "", `Output · exit ${st.meta.exit_code}${st.meta.timed_out ? " · timed out" : ""}${st.meta.output_truncated ? " · truncated" : ""}`),
                   node("pre", "command-output", st.meta.output || "(no output)"));
    line.append(details);
  }
  return line;
}
function typingDots() {
  // A neutral "typing…" indicator — never fabricated words, just shows a turn is in progress.
  const t = node("span", "typing"); t.append(node("span"), node("span"), node("span")); return t;
}
function chatBubbleEl(kind, who, textOrNode) {
  const b = node("div", "chat-msg " + kind);
  const body = node("span", "chat-text");
  if (typeof textOrNode === "string") body.textContent = textOrNode; else body.append(textOrNode);
  b.append(node("span", "chat-who", who), body);
  return b;
}
function outputControls(panel, output, dark = false) {
  output.tabIndex = 0;
  panel.autoScroll = true;
  const controls = node("div", "output-controls" + (dark ? " output-controls-dark" : ""));
  const label = node("label");
  const follow = node("input"); follow.type = "checkbox"; follow.checked = true;
  label.append(follow, node("span", "", "Auto-scroll"));
  const more = node("button", "", "Show more"); more.type = "button";
  more.setAttribute("aria-expanded", "false");
  more.addEventListener("click", () => {
    panel.expanded = !panel.expanded;
    output.classList.toggle("output-expanded", panel.expanded);
    more.textContent = panel.expanded ? "Show less" : "Show more";
    more.setAttribute("aria-expanded", String(panel.expanded));
    if (panel.autoScroll) output.scrollTop = output.scrollHeight;
  });
  follow.addEventListener("change", () => {
    panel.autoScroll = follow.checked;
    if (panel.autoScroll) output.scrollTop = output.scrollHeight;
  });
  output.addEventListener("scroll", () => {
    if (!output.clientHeight) return; // Hidden tabs have no meaningful scroll position.
    panel.autoScroll = output.scrollHeight - output.scrollTop - output.clientHeight < 24;
    follow.checked = panel.autoScroll;
  });
  controls.append(label, more);
  panel.followCheckbox = follow;
  return controls;
}
function rememberOutput(panel, output) {
  panel.savedScrollTop = output.scrollTop;
  // Measure while still mounted, before new text changes the scroll height.
  if (output.clientHeight && output.scrollHeight - output.scrollTop - output.clientHeight >= 24) {
    panel.autoScroll = false;
    panel.followCheckbox.checked = false;
  }
}
function restoreOutput(panel, output) {
  output.scrollTop = panel.autoScroll ? output.scrollHeight : panel.savedScrollTop || 0;
}
function autopilotFeed(plan, working, runningStep, existing) {
  // A turn-based feed of the models' REAL words: the guide speaks, the executor then responds.
  const feed = existing?.scanId === current.id ? existing : node("section", "autopilot-feed");
  if (!feed.output) {
    feed.scanId = current.id;
    feed.output = node("div", "autopilot-feed-output");
    feed.output.setAttribute("aria-label", "Guide and executor messages");
    feed.append(node("div", "conversation-heading", "Guide ↔ Executor"), outputControls(feed, feed.output), feed.output);
  }
  rememberOutput(feed, feed.output);
  feed.output.replaceChildren();
  let any = false;
  const add = el => { feed.output.append(el); any = true; };
  const task = plan.task || {};
  const discussion = working && task.kind === "plan" ? task.discussion : runningStep?.discussion || plan.proposal?.discussion;
  if (discussion?.length) {
    for (const entry of discussion) {
      const role = entry.role === "executor" ? "exec" : entry.role;
      const name = {guide: "Guide", exec: "Executor", user: "You", checks: "Spidy checks"}[role] || "Spidy";
      add(chatBubbleEl(role, name + (entry.model ? ` · ${entry.model}` : ""), entry.text));
    }
    if (working && task.kind === "plan") {
      const isGuide = ["guide", "guide_review"].includes(task.stage);
      if (task.stage === "guide" && !discussion.some(entry => entry.role === "guide") && task.guide_text)
        add(chatBubbleEl("guide", `Guide · ${task.guide_model || plan.guide_model || ""}`, task.guide_text));
      else if (task.stage !== "validate") add(chatBubbleEl(isGuide ? "guide" : "exec", isGuide ? "Guide" : "Executor", typingDots()));
    } else if (runningStep) add(chatBubbleEl("exec", "Executor", "Running the approved action. Live output is below."));
    else if (["paused", "done", "stop"].includes(plan.proposal?.action) || ["manual_followup", "validated_fallback"].includes(plan.proposal?.source))
      add(chatBubbleEl("checks", "Spidy", plan.proposal.preparation_note || plan.proposal.reason));
    return feed;
  }
  if (working && task.kind === "plan") {
    const stage = task.stage || "exec";
    if (stage === "guide" || task.guide_text) {
      // Guide's turn: show its real streamed words; dots until the first tokens arrive.
      add(chatBubbleEl("guide", "Guide", task.guide_text ? task.guide_text : typingDots()));
    }
    if (stage === "validate" || stage === "guide_review") {
      add(chatBubbleEl("exec", "Checks", task.validation_text || "Checking prerequisites and previous work…"));
    } else if (stage === "exec") {
      // Guide has finished (or there is none) — executor is now responding. Its real words
      // appear as the proposal when ready; until then, a plain typing indicator.
      add(chatBubbleEl("exec", "Executor", typingDots()));
    }
  } else if (runningStep) {
    // Not reasoning here — just state the actual command being executed.
    add(chatBubbleEl("exec", "Executor", "Running " + (runningStep.command || `${runningStep.tool} ${JSON.stringify(runningStep.options || {})}`) + "…"));
  } else {
    const p = plan.proposal;
    if (p) {
      if (p.guidance) add(chatBubbleEl("guide", "Guide", p.guidance));   // the guide's real output
      if (["done", "stop", "paused"].includes(p.action)) add(chatBubbleEl("exec", "Executor", p.reason || "No further steps to propose."));
      else {
        const what = p.command !== undefined ? (p.command || "(needs a runnable command)")
          : p.tool ? `${p.tool} ${JSON.stringify(p.options || {})}` : (p.instructions || "a manual step");
        add(chatBubbleEl("exec", "Executor", (p.reason ? p.reason + " " : "") + "→ proposing: " + what));  // the executor's real words
      }
    }
  }
  if (!any) add(node("div", "conversation-empty", "Start a conversation with your models. Add context below, or propose the next step using the saved assessment evidence."));
  return feed;
}
function terminalText(value) {
  // Treat process output as text, including HTML and terminal escape sequences.
  return String(value || "").replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "").replace(/\r\n/g, "\n")
    .split("\n").map(line => line.split("\r").at(-1)).join("\n")
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");
}
function executorTerminal(step, snapshot, running, existing) {
  const key = `${current.id}:${step.proposal_id || step.time}`;
  const panel = existing?.terminalKey === key ? existing : node("section", "executor-terminal");
  if (!panel.terminalOutput) {
    panel.terminalKey = key;
    panel.terminalStatus = node("span", "terminal-status");
    const title = node("div", "terminal-title");
    title.append(node("strong", "", "Executor terminal"), panel.terminalStatus);
    panel.terminalCommand = node("pre", "terminal-command");
    panel.terminalOutput = node("pre", "terminal-output");
    panel.terminalOutput.tabIndex = 0;
    panel.terminalOutput.setAttribute("aria-label", "Executor terminal output");
    panel.terminalNote = node("div", "terminal-note");
    panel.append(title, outputControls(panel, panel.terminalOutput, true), panel.terminalCommand, panel.terminalOutput, panel.terminalNote);
  }
  const output = panel.terminalOutput;
  rememberOutput(panel, output);
  const state = snapshot.display_state || (running ? "Running" : snapshot.timed_out ? "Timed out"
    : snapshot.exit_code != null ? `Exited ${snapshot.exit_code}` : stepOutcome(step));
  panel.terminalStatus.textContent = state;
  panel.terminalStatus.className = "terminal-status" + (["Paused", "Failed", "Timed out"].includes(state) || (snapshot.exit_code != null && snapshot.exit_code !== 0) ? " terminal-warning" : "");
  const command = snapshot.command || step.command || (step.tool ? `${step.tool} ${JSON.stringify(step.options || {})}` : "");
  panel.terminalCommand.textContent = command ? "$ " + terminalText(command) : "No command running";
  output.textContent = terminalText(snapshot.activity_text ?? snapshot.output_tail ?? snapshot.output) || (running
    ? "Waiting for output… Some tools buffer output or write results to a file."
    : step.error || "Process finished without terminal output.");
  panel.terminalNote.textContent = snapshot.output_truncated ? "Showing the latest output; earlier output was truncated." : "";
  return panel;
}
function terminalView(plan, runningStep) {
  const task = plan.task || {}, p = plan.proposal, steps = plan.steps || [];
  const activity = (id, state, message, action = {}) => ({step: {proposal_id: id, ...action},
    snapshot: {display_state: state, activity_text: message}, running: false});
  if (task.status === "error") return activity(task.id, "Failed", task.error || "The current action failed.");
  if (task.status === "running") {
    if (task.kind === "run") {
      if (runningStep) return {step: runningStep, snapshot: task.terminal || {}, running: true};
      return activity(task.id, "Starting", "Starting the approved action…", task.submitted_action);
    }
    const stage = task.stage || "exec";
    return activity(task.id + ":" + stage, stage === "guide" ? "Planning" : stage === "guide_review" ? "Guide review" : stage === "validate" ? "Checking" : "Preparing",
      stage === "guide" ? "The guide is reviewing the saved results. No command is running."
      : stage === "guide_review" ? "The executor's draft was rejected. The guide is using the validation feedback to prepare a replacement. No command is running."
      : stage === "validate" ? (task.validation_text || "Checking local prerequisites and duplicate work.")
      : "The executor is preparing the next action. No command is running.");
  }
  if (p) {
    const stopped = ["paused", "stop", "done"].includes(p.action);
    const draft = p.needs_preparation || p.action === "manual";
    return activity(p.id, p.action === "paused" ? "Paused" : p.action === "done" ? "Finished"
      : p.action === "stop" ? "Stopped" : draft ? "Needs preparation" : "Awaiting approval",
      p.action === "paused" ? planningPauseMessage(p)
      : p.reason || (draft ? "Prepare a runnable action to continue." : "Ready for approval. Nothing is running."), stopped ? {} : p);
  }
  // Show the latest decision, even when older adapters saved no terminal output.
  const last = steps.at(-1);
  if (!last) return null;
  if (["skipped", "stopped"].includes(last.outcome)) return activity(last.proposal_id,
    last.outcome === "skipped" ? "Skipped" : "Stopped", last.reason || "No command is running.");
  const snapshot = {...(last.meta || {})};
  if (snapshot.output === undefined) snapshot.activity_text = last.error ||
    `No terminal output was saved for this run.${last.added !== undefined ? ` Recorded ${last.added} new finding(s).` : ""}`;
  return {step: last, snapshot, running: false};
}
function renderAutopilot() {
  loadModels();
  const steps = $("#autopilot-steps"); if (!steps) return;
  const finished = !["queued", "running"].includes(current.status);
  const working = autopilotTaskRunning();
  renderGuideComposer(working);
  $("#autopilot-plan").disabled = !finished || working || autopilotSubmitting;
  $("#autopilot-auto-approve").checked = autoApprovalEnabled();
  $("#autopilot-auto-approve").disabled = !finished;
  $("#autopilot-auto-state").textContent = autoApprovalStatus();
  const existingTerminal = [...steps.children].find(el => el.className === "executor-terminal");
  const existingFeed = [...steps.children].find(el => el.className === "autopilot-feed");
  const existingHistory = [...steps.children].find(el => el.className === "step-history");
  const existingReceipt = [...steps.children].find(el => el.className === "execution-receipt");
  const children = [];
  const plan = current.autopilot || {};
  const allSteps = plan.steps || [];
  const lastStep = allSteps.at(-1);
  const runningStep = (working && plan.task?.kind === "run" && lastStep?.outcome === "running") ? lastStep : null;

  const feed = autopilotFeed(plan, working, runningStep, existingFeed);
  if (feed) children.push(feed);

  const view = terminalView(plan, runningStep);
  let terminal;
  if (view) {
    terminal = executorTerminal(view.step, view.snapshot, view.running, existingTerminal);
    children.push(terminal);
  }
  if (!runningStep && (plan.proposal || working || plan.task?.status === "error")) {
    const receipt = executionReceipt(plan);
    if (receipt) {
      receipt.open = existingFeed?.scanId === current.id && !!existingReceipt?.open;
      children.push(receipt);
    }
  }

  // Everything else is hidden in a collapsed log, most-recent first, so you can always come back to it.
  const past = runningStep ? allSteps.slice(0, -1) : allSteps;
  if (past.length) {
    const det = node("details", "step-history");
    det.open = existingFeed?.scanId === current.id && !!existingHistory?.open;
    det.append(node("summary", "", `Previous steps (${past.length}) — newest first`));
    const list = node("div", "step-list");
    past.forEach((st, i) => list.append(stepNode(st, i + 1)));
    list.replaceChildren(...[...list.children].reverse());
    det.append(list); children.push(det);
  }
  // Keep live panels mounted so polling cannot interrupt scrolling or keyboard focus.
  for (const child of [...steps.children]) if (!children.includes(child)) steps.removeChild(child);
  children.forEach((child, index) => {
    if (steps.children[index] !== child) steps.insertBefore(child, steps.children[index] || null);
  });
  if (feed) restoreOutput(feed, feed.output);
  if (terminal) restoreOutput(terminal, terminal.terminalOutput);

  if (working) { $("#autopilot-proposal").replaceChildren(); return; }
  renderProposal(plan.proposal);
}
function autopilotSettled(prevTask) {
  const plan = current.autopilot || {};
  if (plan.task?.status === "error") {
    $("#autopilot-status").textContent = (plan.task.error || "Autopilot could not complete that action.") +
      (autoApprovalEnabled() ? " Auto-approve remains on; add context or request another proposal." : "");
    renderAutopilot(); return;
  }
  if (prevTask.kind === "run") {
    renderFindings(); renderAssessment();
    // Propose the next step whether the command succeeded or failed; after a failure the
    // planner is told what broke and proposes a corrected command for review.
    autopilotPlan(null, false);
  } else {
    const p = plan.proposal || {};
    const needsPrep = p.needs_preparation || p.action === "manual" || p.command === "";
    $("#autopilot-status").textContent = p.action === "paused" ? planningPauseMessage(p)
      : ["done", "stop"].includes(p.action) ? (p.reason || "")
      : needsPrep ? "The draft needs preparation before approval." : "Review the proposed step, then approve.";
    renderAutopilot();
    autoApprovePending();
  }
}
function renderProposal(p) {
  const box = $("#autopilot-proposal"); box.replaceChildren();
  if (p?.planning_attempts?.length) {
    const details = node("details", "planning-attempts");
    details.open = p.action === "paused";
    details.append(node("summary", "", `Planning attempts (${p.planning_attempts.length})`));
    for (const attempt of p.planning_attempts) {
      const entry = node("div", "autopilot-step");
      const candidate = attempt.proposal || {};
      entry.append(node("strong", "", `${attempt.role === "guide" ? "Guide" : "Executor"}: ${attempt.accepted ? "passed proposal checks" : "rejected"}`));
      const action = candidate.command || (candidate.tool ? `${candidate.tool} ${JSON.stringify(candidate.options || {})}` : candidate.instructions || candidate.action);
      if (action) entry.append(node("pre", "command-output", !attempt.accepted && action.length > 1200
        ? `Unusable model output omitted (${action.length} characters). See the rejection reason below.` : action));
      if (attempt.issue) entry.append(node("p", "small", attempt.issue));
      details.append(entry);
    }
    box.append(details);
  }
  if (!p) return;
  if (["done", "stop", "paused"].includes(p.action)) {
    box.append(node("p", "small muted", p.reason || "The model has no further steps to propose."));
    return;
  }
  const scanId = current.id;
  const custom = p.command !== undefined || p.action === "manual";
  const card = node("div", "proposal-card");
  card.append(node("strong", "", custom ? "Proposed action — review before approving" : `Proposed: run ${p.tool} — approve before it executes`));
  if (p.reason && !p.reason.includes("Supply a command below")) card.append(node("p", "small", p.reason));
  if (p.repeat_note) card.append(node("p", "notice", p.repeat_note));
  if (p.preparation_note) card.append(node("p", "small", p.preparation_note));
  if (p.instructions && p.action === "manual") card.append(node("pre", "command-output", p.instructions));
  const inputs = {}; const opts = node("div", "tool-opts");
  const command = typeof p.command === "string" ? p.command : "";
  if (custom) {
    if (command.trim()) card.append(node("pre", "command-output", command));
    else card.append(node("p", "small muted", "This draft needs a runnable command. Prepare it first, then review and approve. Nothing runs during preparation."));
  } else {
    card.append(node("p", "small muted", `Target: ${current.config.target}`));
    Object.entries(p.options || {}).forEach(([k, v]) => {
      const label = node("label", "", k + " "); const input = node("input"); input.value = v; input.className = "tool-opt"; inputs[k] = input; label.append(input); opts.append(label);
    });
    card.append(opts);
  }
  const row = node("div", "tool-run-row");
  const runnable = !custom || !!command.trim();
  const approve = node("button", "primary", runnable ? "Approve & run" : "Prepare runnable action");
  const skip = node("button", "secondary", "Skip this");
  const stop = node("button", "secondary", "Stop");
  const updateButtons = () => {
    const busy = autopilotTaskRunning() || autopilotSubmitting;
    approve.disabled = skip.disabled = stop.disabled = busy;
    $("#autopilot-plan").disabled = busy;
  };
  async function decide(action) {
    if (autopilotTaskRunning() || autopilotSubmitting || current?.id !== scanId) return;
    if (action === "run" && custom && !command.trim()) return;
    if (action === "run") {
      const options = {}; Object.entries(inputs).forEach(([k, el]) => options[k] = el.value);
      return submitAutopilotRun(p, options);
    }
    if (action === "stop") disableAutoApproval();
    const body = {action, proposal_id: p.id};
    $("#autopilot-status").textContent = "Saving decision…";
    try {
      await api(`/api/scans/${scanId}/autopilot`, body);
      if (current?.id !== scanId) return;
      const fresh = await api(`/api/scans/${scanId}`);
      if (current?.id !== scanId) return;
      current = fresh; renderAutopilot();
      if (action === "stop") $("#autopilot-status").textContent = "Stopped. Click “Propose next step” to resume.";
      else await autopilotPlan();
    } catch (e) { if (current?.id === scanId) { $("#autopilot-status").textContent = e.message; renderAutopilot(); } }
  }
  approve.addEventListener("click", () => {
    if (current?.id !== scanId) return;
    return runnable ? decide("run") : autopilotPlan(p.id);
  });
  skip.addEventListener("click", () => decide("skip"));
  stop.addEventListener("click", () => decide("stop"));
  updateButtons(); row.append(approve, skip, stop); card.append(row); box.append(card);
}
async function autopilotPlan(proposalId = null, includeDraft = true) {
  if (!current || autopilotTaskRunning() || autopilotSubmitting) return;
  const scanId = current.id;
  const model = $("#autopilot-model").value;
  if (!model) { $("#autopilot-status").textContent = "Pick a local model first."; return; }
  const guide = $("#autopilot-guide-model")?.value || "";
  const guideContext = includeDraft ? $("#autopilot-guide-context")?.value || "" : current.autopilot?.guide_context || "";
  autopilotSubmitting = true;
  renderGuideComposer(false);
  $("#autopilot-plan").disabled = true;
  $("#autopilot-proposal").replaceChildren();
  $("#autopilot-status").textContent = proposalId
    ? `${model} is preparing a runnable action for review…`
    : guide ? `${guide} is guiding ${model} on the next step…` : `${model} is deciding the next step…`;
  try {
    await ensureCurrentBackend();
    if (current?.id !== scanId) return;
    const res = await api(`/api/scans/${scanId}/autopilot`, {action: proposalId ? "repair" : "plan", model, guide_model: guide, guide_context: guideContext, ...(proposalId ? {proposal_id: proposalId} : {})});
    if (current?.id !== scanId) return;
    // Planning runs in the background; the poll loop renders the proposal when it is ready.
    current.autopilot = {...(current.autopilot || {}), model, guide_model: guide, guide_context: guideContext, task: res.task, proposal: null};
    $("#guide-context-status").textContent = guideContext ? "Context sent. Included in this assessment’s next planning rounds." : "Planning without additional context.";
    renderAutopilot(); scheduleRefresh();
  } catch (e) { if (current?.id === scanId) { $("#autopilot-status").textContent = e.message; renderAutopilot(); } }
  finally { autopilotSubmitting = false; if (current?.id === scanId) renderAutopilot(); }
}
$("#autopilot-plan").addEventListener("click", () => autopilotPlan());
$("#autopilot-guide-context")?.addEventListener("input", event => {
  if (!current) return;
  guideContextDrafts.set(current.id, event.target.value);
  $("#guide-context-status").textContent = "Draft updated. Send context to use it in the next plan.";
  resizeGuideComposer();
});
function resizeGuideComposer() {
  const input = $("#autopilot-guide-context");
  if (!input?.style) return;
  input.style.height = "auto";
  input.style.height = Math.min(180, Math.max(48, input.scrollHeight)) + "px";
}
function sendGuideMessage() {
  if (!current || autopilotTaskRunning() || autopilotSubmitting) return;
  return autopilotPlan();
}
$("#autopilot-send-context")?.addEventListener("click", sendGuideMessage);
$("#autopilot-guide-context")?.addEventListener("keydown", event => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    return sendGuideMessage();
  }
});
$("#autopilot-auto-approve").addEventListener("change", async event => {
  if (!event.target.checked || !current) {
    disableAutoApproval();
    $("#autopilot-status").textContent = "Auto-approval off. Any action already submitted will finish; further runs wait for approval.";
    renderAutopilot();
    return;
  }
  autoApproveScanId = current.id;
  $("#autopilot-status").textContent = "Auto-approval on for this scan and page session.";
  renderAutopilot();
  if (autopilotTaskRunning() || autopilotSubmitting) return;
  const proposal = current.autopilot?.proposal;
  if (proposal?.action === "run" && !proposal.needs_preparation && proposal.command !== "") await autoApprovePending();
  else await autopilotPlan(proposal && (proposal.needs_preparation || proposal.action === "manual") ? proposal.id : null, false);
});
$("#autopilot-guide-model")?.addEventListener("change", guideHint);
for (const selector of ["#autopilot-model", "#autopilot-guide-model"]) $(selector)?.addEventListener("change", () => {
  if (current) planningModelDrafts.set(current.id, {model: $("#autopilot-model").value, guide_model: $("#autopilot-guide-model").value});
});
let llmModelsLoaded = false;
function optionNode(value, label) { const o = node("option", "", label); o.value = value; return o; }
function pickDefaultModel(models) {
  // Prefer a genuinely unrestricted/uncensored model by name; else the first installed one.
  const unrestricted = /uncensor|dolphin|abliterat|storm|wizard|hermes|nous|mytho|airoboros|tiger|solar/i;
  return models.find(name => unrestricted.test(name)) || models[0];
}
function pickGuideModel(detailed, executor) {
  // Size is only a starting point, but a name keyword must not prefer a smaller guide.
  return [...detailed].filter(model => model.name !== executor)
    .sort((a, b) => (b.size || 0) - (a.size || 0))[0]?.name || "";
}
// Uncensored models worth running as the guide; offered even when not yet pulled.
const RECOMMENDED_GUIDES = [
  {name: "dolphin-mistral", note: "uncensored · 7B · 32K ctx"},
  {name: "dolphin-mixtral:8x7b", note: "uncensored · bigger, stronger"},
  {name: "dolphin3:8b", note: "uncensored · newer (Llama 3.1)"},
];
let installedModels = new Set();
function guideHint() {
  const el = $("#autopilot-guide-hint"); if (!el) return;
  const sel = $("#autopilot-guide-model"); const v = sel?.value || "";
  if (v && !installedModels.has(v)) {
    el.textContent = `${v} isn't pulled yet — run:  ollama pull ${v}  (then click ↻ refresh). Until then the executor plans alone.`;
  } else el.textContent = "";
}
async function loadModels(force) {
  if (llmModelsLoaded && !force) return;
  const setup = $("#setup-llm-model"), writeup = $("#llm-model"), status = $("#setup-llm-status");
  let info;
  try { info = await api("/api/llm/models"); }
  catch (e) { info = {available: false, models: [], error: `Spidy could not list models (${e.message}). If you just updated Spidy, restart the server.`}; }
  if (setup) setup.replaceChildren(optionNode("", "No model analysis"));
  if (writeup) writeup.replaceChildren();
  if (info.available && info.models.length) {
    llmModelsLoaded = true;
    info.models.forEach(name => { if (setup) setup.append(optionNode(name, name)); if (writeup) writeup.append(optionNode(name, name)); });
    const chosen = pickDefaultModel(info.models);
    if (setup) setup.value = chosen;            // auto-default to an unrestricted model
    if (writeup) { writeup.value = chosen; $("#llm-run").disabled = false; }
    // Any other model picker (e.g. autopilot executor) gets the same list + default.
    $$(".model-select").forEach(sel => { if (sel !== setup && sel !== writeup) { sel.replaceChildren(); info.models.forEach(n => sel.append(optionNode(n, n))); sel.value = chosen; } });
    // Default to the largest other installed model; the operator can choose any guide.
    const guide = $("#autopilot-guide-model");
    if (guide) {
      const installed = new Set(info.models); installedModels = installed;
      guide.replaceChildren(optionNode("", "None (executor only)"));
      info.models.forEach(n => guide.append(optionNode(n, n)));
      // Recommended uncensored guides you can pull — shown as choices even before they're installed.
      RECOMMENDED_GUIDES.forEach(r => {
        if (!installed.has(r.name)) {
          const o = optionNode(r.name, `${r.name} — ${r.note} · not installed`);
          o.dataset.pull = "1"; guide.append(o);
        }
      });
      guide.value = pickGuideModel(info.detailed || info.models.map(name => ({name})), chosen);
      guideHint();
    }
    if (current) {
      $("#autopilot-model").scanId = null;
      $("#autopilot-guide-model").scanId = null;
      renderGuideComposer(autopilotTaskRunning());
    }
    if (status) status.textContent = (status.textContent || "") + `${info.models.length} local model(s) found. Will analyze with: ${chosen}.`;
  } else {
    const reason = info.error || (info.available ? "Ollama is running but no models are pulled — try: ollama pull dolphin-mistral"
                                                  : "Ollama isn't reachable from Spidy. Start it with: ollama serve, then click refresh.");
    if (status) status.textContent = reason;
    if (writeup) {
      writeup.append(optionNode("", info.available ? "No models pulled" : "Ollama not running"));
      $("#llm-run").disabled = true; $("#llm-status").textContent = reason;
    }
  }
}
function renderLLM() {
  loadModels();
  const running = ["queued", "running"].includes(current.status);
  $("#llm-run").disabled = running || !$("#llm-model").value;
  const output = $("#llm-output"); output.replaceChildren();
  const analysis = current.llm_analysis;
  if (analysis && analysis.text) {
    output.append(node("div", "llm-meta small muted", `${analysis.model} · ${new Date(analysis.generated_at).toLocaleString()} · ${analysis.disclaimer || ""}`));
    output.append(node("div", "llm-text", analysis.text));
  }
}
$("#llm-run").addEventListener("click", async () => {
  const id = current.id, model = $("#llm-model").value; if (!model) return;
  $("#llm-run").disabled = true; $("#llm-status").textContent = `Running ${model} locally… this can take a minute.`;
  try {
    const result = await api(`/api/scans/${id}/analyze`, {model});
    if (current?.id === id) { current.llm_analysis = result; renderLLM(); $("#llm-status").textContent = "Done — analysis below."; }
  } catch (e) { $("#llm-status").textContent = e.message; }
  finally { $("#llm-run").disabled = false; }
});
async function renderDraft() {
  const id = current.id, running = ["queued", "running"].includes(current.status);
  const disabled = running || !draftCache.get(id);
  $("#email-draft").disabled = disabled; $("#save-draft").disabled = disabled; $("#copy-draft").disabled = disabled; $("#download-email").disabled = disabled;
  if (running) { $("#email-draft").value = ""; $("#draft-status").textContent = "Waiting for the assessment to finish."; return; }
  if (!draftCache.has(id)) {
    $("#email-draft").value = ""; $("#draft-status").textContent = "Preparing your draft…";
    draftCache.set(id, null);
    try {
      const response = await fetch(`/api/scans/${id}/email.txt`);
      if (!response.ok) throw new Error("Could not load the email draft.");
      draftCache.set(id, {text: await response.text(), dirty:false});
    } catch (e) {draftCache.delete(id); if (current?.id === id) $("#draft-status").textContent = e.message; return;}
  }
  if (current?.id !== id || !draftCache.get(id)) return;
  const draft = draftCache.get(id);
  $("#email-draft").disabled = false; $("#save-draft").disabled = false; $("#copy-draft").disabled = false; $("#download-email").disabled = false;
  $("#email-draft").value = draft.text; $("#draft-status").textContent = draft.dirty ? "Unsaved edits" : "Local draft; nothing has been sent.";
}
$("#email-draft").addEventListener("input", () => {if (!current) return; draftCache.set(current.id, {text:$("#email-draft").value, dirty:true}); $("#draft-status").textContent = "Unsaved edits";});
$("#save-draft").addEventListener("click", async () => {
  const id = current.id, text = $("#email-draft").value; $("#save-draft").disabled = true;
  try {
    await api(`/api/scans/${id}/draft`, {text});
    const latest = draftCache.get(id), unchanged = !latest || latest.text === text;
    if (unchanged) draftCache.set(id, {text, dirty:false});
    if (current?.id === id) $("#draft-status").textContent = unchanged ? "Draft saved locally. Nothing sent." : "Earlier version saved; your newest edits are unsaved.";
  } catch(e) {if (current?.id === id) $("#draft-status").textContent = e.message;}
  finally {if (current?.id === id) $("#save-draft").disabled = false;}
});
$("#copy-draft").addEventListener("click", async () => {
  try {await navigator.clipboard.writeText($("#email-draft").value); $("#draft-status").textContent = "Draft copied.";}
  catch {$("#email-draft").focus(); $("#email-draft").select(); $("#draft-status").textContent = "Text selected. Use your keyboard to copy.";}
});
$("#download-email").addEventListener("click", () => {
  const url = URL.createObjectURL(new Blob([$("#email-draft").value], {type:"text/plain;charset=utf-8"}));
  const link = node("a"); link.href = url; link.download = `spidy-${current.id.slice(0,8)}.email.txt`; link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
});
async function init() {
  try {
    config = await api("/api/config"); $("#limitations").textContent = config.limitations; $("#about-limitations").textContent = config.limitations;
    try { checkBackend(config); } catch { /* Keep saved reports accessible while showing the restart notice. */ }
    $("#demo-banner").classList.toggle("hidden", !config.demo_target);
    loadModels();
    await history(); historyTimer = setInterval(() => history().catch(() => {}), 10000);
  } catch(e) {showError("#connection-error", new Error(`Cannot reach Spidy. ${e.message}`)); $("#start-button").disabled = true;}
}
init();
