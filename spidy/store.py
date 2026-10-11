import copy
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .analysis import advisory_verification, analyze, finding_context, inventory_view
from .progress import assessment_progress


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.scans = {}
        for path in self.directory.glob("*.json"):
            try:
                data = json.loads(path.read_text())
                if not re.fullmatch(r"[a-f0-9]{32}", data["id"]):
                    continue
                if data["status"] in ("running", "queued"):
                    data["status"] = "interrupted"
                    data["summary"] = "The process exited before this scan finished. Results are partial."
                self.scans[data["id"]] = data
            except (ValueError, KeyError, OSError):
                continue

    def save(self, data):
        # Same-directory replace prevents readers seeing partial reports.
        path = self.directory / (data["id"] + ".json")
        temp = path.with_suffix(".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(temp, path)

    def create(self, config, approved=None, parent=None):
        with self.lock:
            data = {"id": uuid.uuid4().hex, "created_at": now(), "finished_at": None,
                    "status": "queued", "config": config, "approved_origins": approved or [],
                    "parent_id": parent, "findings": [], "events": [], "pending_origins": [],
                    "pages": [], "ports": [], "inventory": {}, "advisories": {}, "coverage": {},
                    "added_origins": [], "llm_analysis": None, "autopilot": None, "summary": "Waiting to start."}
            self.scans[data["id"]] = data
            self.save(data)
            return copy.deepcopy(data)

    def get(self, scan_id):
        with self.lock:
            return copy.deepcopy(self.scans[scan_id])

    def list(self):
        with self.lock:
            return [{k: copy.deepcopy(d.get(k)) for k in ("id", "created_at", "status", "config", "summary", "parent_id", "added_origins")}
                    for d in sorted(self.scans.values(), key=lambda d: d["created_at"], reverse=True)]

    def update(self, scan_id, **changes):
        with self.lock:
            self.scans[scan_id].update(changes)
            self.save(self.scans[scan_id])

    def append(self, scan_id, field, item):
        with self.lock:
            self.scans[scan_id][field].append(item)
            self.save(self.scans[scan_id])


def add_external_findings(scan, items, source="external"):
    """Append normalized tool findings to a scan dict (dedup, ids, context). Returns count added."""
    findings = scan.setdefault("findings", [])
    seen = {(f.get("title"), f.get("url"), f.get("evidence")) for f in findings}
    target = (scan.get("config") or {}).get("target", "")
    added = 0
    for item in items:
        url = item.get("url") or target
        evidence = str(item.get("evidence", ""))[:1200]
        key = (item["title"], url, evidence)
        if key in seen:
            continue
        seen.add(key)
        record = {"id": f"SP-{len(findings) + 1:03d}", "title": item["title"], "severity": item.get("severity", "info"),
                  "confidence": item.get("confidence", "medium"), "url": url, "evidence": evidence,
                  "description": item.get("description", ""), "remediation": item.get("remediation", ""),
                  "reference": item.get("reference", ""), "check": item.get("check", "server"), "source": source}
        record.update(finding_context(record))
        findings.append(record)
        added += 1
    return added


def markdown_report(scan):
    def inline(value):
        return str(value).replace("`", "'").replace("\n", " ").replace("\r", " ").replace("<", "&lt;").replace(">", "&gt;")

    config = scan["config"]
    assessment = analyze(scan)
    lines = ["# Spidy security assessment", "", f"- Target: `{inline(config['target'])}`",
             f"- Scan: `{scan['id']}`", f"- Started: {scan['created_at']}",
             f"- Status: {scan['status']}", f"- Focus: {', '.join(config['checks'])}",
             f"- Active input probes: {config['active']}", f"- Approved additional origins: {inline(', '.join(scan['approved_origins']) or 'None')}",
             "", "## Executive assessment", "", assessment["executive_summary"], "", "## What needs attention", ""]
    for priority in ("Fix first", "Validate next", "Hardening", "Context only"):
        groups = [g for g in assessment["issue_groups"] if g["priority"] == priority]
        if not groups:
            continue
        lines += [f"### {priority}", ""]
        for group in groups:
            lines += [f"- **{group['title']}** — {group['confidence']} confidence; {group['certainty']}. "
                      f"{len(group['urls'])} affected route(s), {group['occurrences']} observation(s). "
                      f"Evidence IDs: {', '.join(group['finding_ids'])}. {group['remediation']}"]
        lines.append("")
    if not assessment["issue_groups"]:
        lines += ["No issues were recorded. Check the coverage and errors before drawing conclusions.", ""]
    lines += inventory_lines(scan, inline)
    lines += ["## Why these checks were performed", "", f"Requested focus: `{inline(config.get('focus') or 'Categories selected by the operator')}`", ""]
    for method in assessment["methodology"]:
        lines += [f"### {method['name']}", "", f"- Reason: {method['why']}", f"- Method: {method['how']}",
                  f"- Execution: {method['state']}; {method['requests']} tagged HTTP attempt(s), {method['inspections']} inspection(s)."]
        lines.extend(f"- Limitation: {inline(reason)}" for reason in method["skip_reasons"])
        lines.append("")
    lines += ["## Scan outcome", "", scan["summary"], "", "## Coverage", ""]
    for key, value in scan["coverage"].items():
        lines.append(f"- {key}: {inline(value)}")
    lines += ["", "## Findings", ""]
    if not scan["findings"]:
        lines += ["No findings recorded. This does not establish that the target is secure.", ""]
    for f in scan["findings"]:
        context = finding_context(f)
        lines += [f"### {f['id']}: {f['title']}", "", f"- Severity: **{f['severity']}**",
                  f"- Confidence: {f['confidence']}", f"- URL: `{inline(f['url'])}`",
                  f"- Evidence: `{inline(f['evidence'])}`", f"- Assessment: {f['description']}",
                  f"- Priority: {context['priority']} ({context['certainty']})",
                  f"- Why tested: {context['why_tested']}", f"- Method: {context['method']}",
                  f"- Recommendation: {f['remediation']}", f"- Verification: {context['verification']}",
                  f"- Reference: {f['reference']}", "", "Reproduction / review:", ""]
        lines.extend(f"{index}. {inline(step)}" for index, step in enumerate(context["reproduction"], 1))
        lines.append("")
    lines += ["## Scope decisions", ""]
    for p in scan["pending_origins"]:
        lines.append(f"- {p['decision']}: `{inline(p['origin'])}` — {inline(p['reason'])}. Discovered at `{inline(p['source'])}`.")
    lines += ["", "## Activity log", "", "Each line is an action or decision; response bodies and cookie values are not retained.", ""]
    for e in scan["events"]:
        lines.append(f"- `{inline(json.dumps(e, ensure_ascii=True))}`")
    lines += ["", "## Assessment working record", ""]
    lines += [inline(line) for line in assessment_progress(scan).splitlines()]
    analysis = scan.get("llm_analysis")
    if isinstance(analysis, dict) and analysis.get("text"):
        lines += ["", "## Local model analysis", "",
                  f"Model: `{inline(analysis.get('model', 'unknown'))}` · generated {inline(analysis.get('generated_at', ''))}. {inline(analysis.get('disclaimer', ''))}", ""]
        lines += [inline(line) for line in str(analysis["text"]).splitlines()]
        lines.append("")
    lines += ["", "## Limitations", "", LIMITATIONS, ""]
    return "\n".join(lines)


def inventory_lines(scan, inline):
    view = inventory_view(scan)
    lines = ["## Services and software found", "", "What answers on the target hostname. An open port is an exposure observation, not a vulnerability.", ""]
    for address in view["addresses"]:
        lines.append(f"- Resolved address: `{inline(address.get('ip', '?'))}` ({inline(address.get('family', ''))})")
    for s in view["open"]:
        software = " ".join(filter(None, (s.get("product"), s.get("version")))) or "software not identified"
        lines.append(f"- **{inline(s.get('host', '?'))}:{s.get('port', '?')}** open — {inline(s.get('service') or 'unknown')}"
                     f"{'' if s.get('service_verified', True) else ' (unverified' + ('; port suggests ' + inline(s['service_hint']) if s.get('service_hint', 'unknown') != 'unknown' else '') + ')'}; "
                     f"{inline(software)}; {inline(s.get('confidence', 'low'))} confidence. Address `{inline(s.get('ip') or 'not recorded')}`. {inline(s.get('evidence', ''))}")
    for group in view["unopened"]:
        lines.append(f"- {inline(group['address'])} — {inline(group['state'])} ({len(group['ports'])}): {', '.join(str(port) for port in group['ports'])}")
    if not view["recorded"]:
        lines.append("No service inventory was recorded. This does not mean that no services are exposed.")
    lines += ["", "### Software and versions", ""]
    for t in view["technologies"]:
        lines.append(f"- {inline(t.get('product', '?'))} {inline(t.get('version') or '(version not disclosed)')} — {inline(t.get('evidence', ''))}; "
                     f"{inline(t.get('confidence', 'low'))} confidence; seen at `{inline(t.get('source', ''))}`")
    if not view["technologies"]:
        lines.append("No product or version was advertised in the inspected responses and banners.")
    for tls in view["tls"]:
        lines.append(f"- TLS on {inline(tls.get('host', '?'))}:{tls.get('port', '?')} — {inline(tls.get('tls_version', '?'))}, {inline(tls.get('cipher', '?'))}; "
                     f"certificate valid until {inline(tls.get('certificate_not_after', 'not recorded'))}")
    lines += ["", "### Running processes and installed packages", ""]
    process = view["process"] if isinstance(view["process"], dict) else {}
    if process.get("status") == "owner_supplied":
        lines += [f"Owner-supplied host inventory collected {inline(process.get('collected_at', '?'))}: {len(process.get('processes', []))} processes, "
                  f"{len(process.get('packages', []))} packages. {inline(process.get('reason', ''))}", ""]
        for item in view["processes"][:150]:
            lines.append(f"- {inline(item['name'])}" + (f" ×{item['count']}" if item["count"] > 1 else "")
                         + (f" — package {inline(item['package'])} {inline(item['version'])}" if item["package"] else ""))
        lines.append(f"- {max(0, len(view['processes']) - 150)} more distinct processes and {view['processes_unreadable']} kernel threads "
                     "or processes without a readable executable are in the JSON export.")
    else:
        lines.append(process.get("reason") or "Not available: a remote scan cannot list a server's processes. Run `python3 -m spidy host-inventory` on the server and import the result.")
    lines += ["", "## Known vulnerability candidates", ""]
    advisories = scan.get("advisories") or {}
    lines.append(f"Lookup status: {inline(advisories.get('status', 'not performed'))}. A version match is a lead to verify, not a confirmed vulnerability.")
    lines.append("")
    for query in advisories.get("queries", []):
        lines.append(f"- Queried {inline(query.get('product', '?'))} {inline(query.get('version', '?'))}: {inline(query.get('status', '?'))}, "
                     f"{query.get('count', 0)} candidate(s)" + (f" of {query['total_results']} published" if query.get("truncated") else "")
                     + (f" — {inline(query['reason'])}" if query.get("reason") else ""))
    for c in advisories.get("candidates", []):
        lines.append(f"- **{inline(c.get('id', '?'))}** ({inline(c.get('severity', 'severity not published'))}) — {inline(c.get('product', ''))} {inline(c.get('version', ''))}: "
                     f"{inline(c.get('description', '')[:400])} {inline(c.get('url', ''))}")
        for ref in c.get("references", []):
            tags = ", ".join(ref.get("tags", [])) or "reference"
            lines.append(f"    - {inline(tags)}: {inline(ref.get('url', ''))}")
    verification = advisory_verification(scan)
    lines += ["", "### Did these candidates survive host verification?", "", inline(verification["note"]), ""]
    for row in verification["rows"]:
        installed = "; ".join(row["installed"]) or "no matching package installed"
        lines.append(f"- **{inline(row['product'])} {inline(row['advertised_version'])}** — {inline(row['status'].replace('_', ' '))}: "
                     f"advertised vs installed [{inline(installed)}]. Covers {inline(', '.join(row['cve_ids'][:8]))}. {inline(row['note'])}")
    lines.extend(f"- Limitation: {inline(note)}" for note in advisories.get("limitations", []))
    lines.append("")
    return lines


LIMITATIONS = (
    "Spidy uses local evidence-based analysis and a finite check catalog, not an LLM or a full exploitation framework. It does not execute JavaScript, "
    "authenticate, submit POST forms, brute force credentials, extract database data, or prove backend exploitability. "
    "SQL-error and HTML-reflection signals require manual validation; missing headers and token fields are not proof of exploitation. "
    "The service inventory covers a selected TCP port set on the domain's resolved addresses, which may belong to a CDN or proxy; "
    "products and versions come from banners and headers that can be hidden, spoofed, or backport-patched. "
    "A remote scan cannot list a server's processes; that needs an owner-run host inventory. "
    "Advisory matches are unconfirmed candidates, and the lookup runs only when enabled. "
    "Discovery follows bounded HTML links and, when enabled, at most twelve curated path guesses with signature validation. "
    "CORS and redirect signals need application-specific validation; no requests are made to synthetic test origins. "
    "Dynamic routes, authenticated flows, APIs, and deeper infrastructure may be missed. "
    "A scan with no findings does not establish security. GET requests can still have side effects on poorly designed applications."
)
