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
  const version = ++refreshVersion; clearTimeout(timer);
  const scan = await api(`/api/scans/${id}`);
  if (version !== refreshVersion) return;
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
  if (container.childElementCount && container.dataset.scan === current.id) { container.querySelectorAll("button.run-tool").forEach(b => b.disabled = !finished); return; }
  container.replaceChildren(); container.dataset.scan = current.id;
  if (!toolCatalog.length) { empty(container, "No external tools found.", "Run install-tools.sh to add nuclei, naabu, ffuf, and more."); return; }
  toolCatalog.forEach(tool => {
    const card = node("div", "tool-card");
    const head = node("div", "tool-head");
    head.append(node("strong", "", tool.label), node("span", `badge ${tool.installed ? "" : "info"}`, tool.installed ? tool.input : "not installed"));
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
    const run = node("button", "primary run-tool", "Run"); run.disabled = !tool.installed || !finished;
    const status = node("span", "muted small", tool.installed ? "" : `Needs ${tool.needs}.`);
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
function stepOutcome(st) {
  let outcome = st.outcome || st.status || "step";
  if (outcome === "ran" && st.meta?.timed_out) return "timed out";
  if (outcome === "ran" && st.meta?.exit_code != null && st.meta.exit_code !== 0) return "failed";
  return outcome;
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
  if (st.error) line.append(node("div", "notice error", st.error));
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
function autopilotFeed(plan, working, runningStep) {
  // A turn-based feed of the models' REAL words: the guide speaks, the executor then responds.
  const feed = node("div", "autopilot-feed"); let any = false;
  const add = el => { feed.append(el); any = true; };
  const task = plan.task || {};
  if (working && task.kind === "plan") {
    const stage = task.stage || "exec";
    if (stage === "guide" || task.guide_text) {
      // Guide's turn: show its real streamed words; dots until the first tokens arrive.
      add(chatBubbleEl("guide", "Guide", task.guide_text ? task.guide_text : typingDots()));
    }
    if (stage === "exec") {
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
  return any ? feed : null;
}
function renderAutopilot() {
  loadModels();
  const steps = $("#autopilot-steps"); if (!steps) return;
  const finished = !["queued", "running"].includes(current.status);
  const working = autopilotTaskRunning();
  $("#autopilot-plan").disabled = !finished || working;
  steps.replaceChildren();
  const plan = current.autopilot || {};
  const allSteps = plan.steps || [];
  const runningStep = (working && plan.task?.kind === "run") ? allSteps[allSteps.length - 1] : null;

  const feed = autopilotFeed(plan, working, runningStep);
  if (feed) steps.append(feed);

  // Show the command running right now in full, so you can see what's happening.
  if (runningStep) { const live = node("div", "autopilot-live"); live.append(stepNode(runningStep, allSteps.length, true)); steps.append(live); }

  // Everything else is hidden in a collapsed log, most-recent first, so you can always come back to it.
  const past = runningStep ? allSteps.slice(0, -1) : allSteps;
  if (past.length) {
    const det = node("details", "step-history");
    det.append(node("summary", "", `Previous steps (${past.length}) — newest first`));
    const list = node("div", "step-list");
    past.forEach((st, i) => list.append(stepNode(st, i + 1)));
    list.replaceChildren(...[...list.children].reverse());
    det.append(list); steps.append(det);
  }

  if (working) { $("#autopilot-proposal").replaceChildren(); return; }
  renderProposal(plan.proposal);
}
function autopilotSettled(prevTask) {
  const plan = current.autopilot || {};
  if (plan.task?.status === "error") {
    $("#autopilot-status").textContent = plan.task.error || "Autopilot could not complete that action.";
    renderAutopilot(); return;
  }
  if (prevTask.kind === "run") {
    renderFindings(); renderAssessment();
    // Propose the next step whether the command succeeded or failed; after a failure the
    // planner is told what broke and proposes a corrected command for review.
    autopilotPlan();
  } else {
    const p = plan.proposal || {};
    const needsPrep = p.needs_preparation || p.action === "manual" || p.command === "";
    $("#autopilot-status").textContent = ["done", "paused", "stop"].includes(p.action) ? (p.reason || "")
      : needsPrep ? "The draft needs preparation before approval." : "Review the proposed step, then approve.";
    renderAutopilot();
  }
}
function renderProposal(p) {
  const box = $("#autopilot-proposal"); box.replaceChildren();
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
    const busy = autopilotTaskRunning();
    approve.disabled = skip.disabled = stop.disabled = busy;
    $("#autopilot-plan").disabled = busy;
  };
  async function decide(action) {
    if (autopilotTaskRunning() || current?.id !== scanId) return;
    if (action === "run" && custom && !command.trim()) return;
    const body = {action, proposal_id: p.id};
    if (action === "run") {
      body.approved = true;
      if (custom) body.command = command;
      else { body.options = {}; Object.entries(inputs).forEach(([k, el]) => body.options[k] = el.value); }
    }
    $("#autopilot-status").textContent = action === "run" ? "Running approved action…" : "Saving decision…";
    try {
      const res = await api(`/api/scans/${scanId}/autopilot`, body);
      if (current?.id !== scanId) return;
      if (action === "run") {
        // Execution runs in the background; polling surfaces the running step and chains the next plan.
        current.autopilot = {...(current.autopilot || {}), task: res.task, proposal: null};
        renderAutopilot(); scheduleRefresh();
      } else {
        const fresh = await api(`/api/scans/${scanId}`);
        if (current?.id !== scanId) return;
        current = fresh; renderAutopilot();
        if (action === "stop") $("#autopilot-status").textContent = "Stopped. Click “Propose next step” to resume.";
        else await autopilotPlan();
      }
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
async function autopilotPlan(proposalId = null) {
  if (!current || autopilotTaskRunning()) return;
  const scanId = current.id;
  const model = $("#autopilot-model").value;
  if (!model) { $("#autopilot-status").textContent = "Pick a local model first."; return; }
  const guide = $("#autopilot-guide-model")?.value || "";
  $("#autopilot-proposal").replaceChildren();
  $("#autopilot-status").textContent = proposalId
    ? `${model} is preparing a runnable action for review…`
    : guide ? `${guide} is guiding ${model} on the next step…` : `${model} is deciding the next step…`;
  try {
    const res = await api(`/api/scans/${scanId}/autopilot`, {action: proposalId ? "repair" : "plan", model, guide_model: guide, ...(proposalId ? {proposal_id: proposalId} : {})});
    if (current?.id !== scanId) return;
    // Planning runs in the background; the poll loop renders the proposal when it is ready.
    current.autopilot = {...(current.autopilot || {}), model, task: res.task, proposal: null};
    renderAutopilot(); scheduleRefresh();
  } catch (e) { if (current?.id === scanId) { $("#autopilot-status").textContent = e.message; renderAutopilot(); } }
}
$("#autopilot-plan").addEventListener("click", () => autopilotPlan());
$("#autopilot-guide-model")?.addEventListener("change", guideHint);
let llmModelsLoaded = false;
function optionNode(value, label) { const o = node("option", "", label); o.value = value; return o; }
function pickDefaultModel(models) {
  // Prefer a genuinely unrestricted/uncensored model by name; else the first installed one.
  const unrestricted = /uncensor|dolphin|abliterat|storm|wizard|hermes|nous|mytho|airoboros|tiger|solar/i;
  return models.find(name => unrestricted.test(name)) || models[0];
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
    // The guide should be bigger and uncensored: prefer the largest uncensored model
    // (the detailed list is largest-first), else the largest overall, never the executor itself.
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
      const detailed = (info.detailed || []).filter(m => m.name !== chosen);
      const uncensored = /uncensor|dolphin|abliterat|storm|wizard|hermes|nous|mytho|airoboros|tiger|solar/i;
      const pick = detailed.find(m => uncensored.test(m.name)) || detailed[0];
      if (pick && info.models.length > 1) guide.value = pick.name;
      guideHint();
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
    $("#demo-banner").classList.toggle("hidden", !config.demo_target);
    loadModels();
    await history(); historyTimer = setInterval(() => history().catch(() => {}), 10000);
  } catch(e) {showError("#connection-error", new Error(`Cannot reach Spidy. ${e.message}`)); $("#start-button").disabled = true;}
}
init();
