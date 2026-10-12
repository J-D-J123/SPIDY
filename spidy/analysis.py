"""Evidence-grounded triage and reporting. No external model or network calls."""
import re
from collections import Counter
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


METHODS = {
    "headers": ("Headers & cookies", "Check browser and session protections that are easy to miss during deployment.", "Inspect headers and cookie attribute names; do not retain cookie values."),
    "forms": ("Forms", "Look for unsafe credential transport and missing visible CSRF defenses.", "Inspect form markup without submitting credentials or POST requests."),
    "sqli": ("SQL injection signals", "See whether changing a query parameter introduces a database-error signature.", "Compare a normal GET response with a single-quote mutation; do not extract data."),
    "reflection": ("Input reflection", "Identify input that reaches an HTML response without encoding.", "Compare a baseline with a unique inert marker; do not send executable script."),
    "server": ("Server exposure", "Find visible deployment mistakes, debug output, and transport problems.", "Inspect response metadata, directory-listing signatures, TLS, and error text."),
    "ports": ("Service inventory", "Identify reachable services and available product/version evidence on the original hostname.", "Probe the selected bounded TCP port set on up to two validated addresses, inspect safe greeting banners, and correlate approved HTTP response metadata."),
    "transport": ("Transport & browser exposure", "Look for TLS expiry, mixed content, weak security policy values, and plaintext authentication prompts.", "Inspect the negotiated TLS connection, certificate metadata, headers, and page resource references; no browser script is executed."),
    "methods": ("HTTP method exposure", "Identify advertised HTTP methods that deserve an authorization review.", "Send OPTIONS once per approved origin and inspect Allow; never attempt state-changing methods."),
    "advisories": ("Known vulnerability lookup", "Find published advisories potentially relevant to observed product/version strings.", "With explicit opt-in, query NIST NVD using product/version identifiers only. Results remain unconfirmed candidates."),
    "discovery": ("Bounded path discovery", "Find forgotten configuration, source-control metadata, backups, and diagnostic endpoints.", "Try a small curated path set, compare a random missing-path control, and require content signatures."),
    "cors": ("Cross-origin policy", "Check whether a site grants read permission to an arbitrary web origin.", "Send an Origin header containing a reserved .invalid hostname; inspect allow-origin and credential response headers."),
    "redirects": ("Redirect validation", "Check whether a destination parameter can redirect users off-site.", "Substitute a reserved .invalid URL in existing redirect-like GET parameters and inspect Location without following it."),
    "waf": ("WAF / CDN detection (wafw00f)", "Identify a web application firewall or CDN in front of the site.", "Run wafw00f against the target: a handful of fingerprinting requests, no exploitation. The tool resolves DNS itself."),
    "nuclei": ("Template vulnerability scan (nuclei)", "Run community detection templates for known CVEs, misconfigurations, exposures, and default credentials.", "Run nuclei against the target with rate limiting and detection templates only; Spidy never enables code-execution templates. The tool resolves DNS itself."),
}
ACTIVE_CHECKS = {"sqli", "reflection", "cors", "redirects", "methods", "nuclei"}
SEVERITY = {"high": 0, "medium": 1, "low": 2, "info": 3}


def safe_url(url):
    """Sharing view: omit every query value and fragment, not just known secret names."""
    try:
        p = urlsplit(url)
        pairs = parse_qsl(p.query, keep_blank_values=True, max_num_fields=100)
        return urlunsplit((p.scheme, p.netloc, p.path, urlencode([(k, "[redacted]") for k, _ in pairs]), ""))
    except ValueError:
        return "[URL omitted]"


def category(finding):
    if finding.get("check") in METHODS:
        return finding["check"]
    title = finding["title"].lower()
    if "sql injection" in title:
        return "sqli"
    if "reflection" in title:
        return "reflection"
    if "form" in title or "csrf" in title:
        return "forms"
    if "cors" in title or "cross-origin" in title:
        return "cors"
    if "redirect" in title:
        return "redirects"
    if any(s in title for s in ("environment file", "git metadata", "backup source", "diagnostic endpoint", "api description")):
        return "discovery"
    if any(s in title for s in ("server", "tls", "unencrypted", "error details", "directory listing")):
        return "server"
    return "headers"


def finding_context(finding):
    check = category(finding)
    certainty = "observed configuration" if finding["confidence"] == "high" else "needs validation"
    if check in ("sqli", "reflection", "redirects", "cors"):
        certainty = "needs validation"
    if finding["severity"] == "info":
        certainty = "informational"
    if finding["severity"] == "high" and certainty == "observed configuration":
        priority = "Fix first"
    elif finding["severity"] in ("high", "medium"):
        priority = "Validate next"
    elif finding["severity"] == "low":
        priority = "Hardening"
    else:
        priority = "Context only"
    context = {"check": check, "why_tested": METHODS[check][1], "method": METHODS[check][2],
            "certainty": certainty, "priority": priority,
            "verification": verification(check),
            "reproduction": [f"Review the recorded activity for {safe_url(finding['url'])} and its matching evidence entry.",
                             "Reproduce only within the approved scope, using a test environment where practical.",
                             "Use the recommendation and verification notes to check whether the behavior is intended and whether the fix works."]}
    if finding.get("source") == "ffuf":
        context.update(method="Request wordlist paths with ffuf and record matching HTTP statuses and response sizes. "
                       "No missing-path control or content-signature validation was performed by this adapter.",
                       certainty="HTTP response observed; exposure unconfirmed", priority="Context only",
                       verification="Review the saved status and response evidence. A 401/403 response does not prove file existence or exposure; "
                       "a 200 response can be an ordinary page or a generic fallback. Confirm content and intended routing before remediation.")
    return context


def verification(check):
    return {
        "sqli": "Repeat the baseline/probe comparison in a test environment. Review server-side query construction; a database error alone does not prove injection.",
        "reflection": "Inspect the HTML context and application rendering. Confirm context-aware encoding; reflection alone does not establish executable XSS.",
        "forms": "Verify actual browser submission, server-side controls, and any Origin/SameSite defenses before concluding that an action is exploitable.",
        "cors": "Confirm whether sensitive authenticated content is accessible in a real browser and whether the policy is intentionally public. No credentialed request was made.",
        "redirects": "Confirm the redirect is not an intentional outbound-link feature and that destination validation matches the intended workflow.",
        "discovery": "Confirm the endpoint is unintentionally public. Restrict it, remove exposed artifacts, review access logs, and rotate any exposed secrets through the owner's process.",
        "server": "Confirm the deployment setting with the owner; remove unnecessary exposure and repeat the relevant request after remediation.",
        "headers": "Verify the control is applicable to this response, deploy an appropriate policy, and inspect headers again after the fix.",
        "ports": "Have the owner verify service identity and intended exposure; an open port alone is not a vulnerability.",
        "transport": "Review the observed certificate/policy/resource settings, fix applicable weaknesses, and retest in a browser. A negotiated TLS connection does not enumerate every supported protocol or cipher.",
        "methods": "Verify server-side authorization for advertised methods in a controlled environment; an Allow header alone does not establish that an operation is permitted.",
        "advisories": "Confirm the exact component, affected version range, deployment conditions, and distribution backports before concluding that a published vulnerability applies.",
        "waf": "Confirm the WAF/CDN with the owner. It shields the origin, so other findings may describe the edge rather than the application; coordinate testing windows or source IPs.",
        "nuclei": "Reproduce the nuclei match manually and confirm it applies to this deployment and version. Detection templates can false-positive, especially behind a CDN.",
    }[check]


# NVD product name -> Debian/Ubuntu package name patterns, for confirming an
# advertised version against what the owner's host inventory actually has installed.
PRODUCT_PACKAGES = {
    "Apache HTTP Server": (r"apache2(?:-bin)?",),
    "nginx": (r"nginx(?:-core|-full|-light|-extras)?",),
    "OpenSSH": (r"openssh-(?:server|client)",),
    "PHP": (r"php\d*(?:\.\d+)?", r"php-\w+", r"libapache2-mod-php\d*"),
    "WordPress": (r"wordpress",),
    "jQuery": (r"libjs-jquery",),
    "Python": (r"python3(?:\.\d+)?(?:-minimal)?", r"libpython3[\w.-]*"),
    "MariaDB": (r"mariadb-server(?:-core)?[\w.-]*",),
    "MySQL": (r"mysql-server(?:-core)?[\w.-]*", r"mysql-community-server"),
}


def _upstream_version(value):
    """Reduce a dpkg version (1:8.1.2-1ubuntu7.3) to its upstream part (8.1.2)."""
    value = str(value).split(":", 1)[-1]
    return re.split(r"[-+~]", value, maxsplit=1)[0]


def _versions_agree(advertised, installed_upstream):
    advertised, installed = advertised.strip(), installed_upstream.strip()
    if not advertised or not installed:
        return False
    return advertised == installed or installed.startswith(advertised + ".") or advertised.startswith(installed + ".")


def advisory_verification(scan):
    """Cross-check advertised-version CVE candidates against the owner's installed packages.

    Render-time and read-only: importing a host inventory after the scan updates
    this without re-running anything, and no exploit or probe is performed.
    """
    advisories = scan.get("advisories") or {}
    products = {}
    for candidate in advisories.get("candidates") or []:
        product, version = candidate.get("product"), candidate.get("version")
        if product and version:
            products.setdefault((product, version), []).append(candidate.get("id", "?"))
    if not products:
        return {"status": "no_candidates", "rows": [], "note": "No advisory candidates to confirm."}
    process = (scan.get("inventory") or {}).get("process_inventory")
    if not isinstance(process, dict) or process.get("status") != "owner_supplied":
        return {"status": "no_host_inventory", "rows": [], "note":
                "Advertised versions are unconfirmed. Run `python3 -m spidy host-inventory <host>` on the server and import it to check these candidates against the installed packages."}
    packages = [p for p in process.get("packages", []) if isinstance(p, dict)]
    rows = []
    for (product, version), cve_ids in sorted(products.items()):
        patterns = PRODUCT_PACKAGES.get(product, ())
        # dpkg multi-arch names carry an ":amd64" suffix; match on the bare package name.
        matches = [p for p in packages if any(re.fullmatch(pattern, str(p.get("name", "")).split(":")[0], re.I) for pattern in patterns)]
        # Surface packages whose version matches the advertised one first, and keep the list short.
        matches.sort(key=lambda p: not _versions_agree(version, _upstream_version(p.get("version", ""))))
        installed = [f"{p.get('name')} {p.get('version')}" for p in matches[:6]]
        if len(matches) > 6:
            installed.append(f"+{len(matches) - 6} more")
        if not patterns:
            status, note = "not_checkable", "No known distribution package name for this product; confirm the installed version manually."
        elif not matches:
            status, note = "not_installed", "No matching package is installed on the host inventory; the advertised service may run from source, a container, or another host (such as a CDN or proxy)."
        elif any(_versions_agree(version, _upstream_version(p.get("version", ""))) for p in matches):
            status, note = "corroborated", "An installed package matches the advertised version. The distribution revision may still carry a backported security fix, so confirm the package changelog before treating the CVEs as applicable."
        else:
            status, note = "version_differs", "The installed package version differs from the advertised one; the banner may be stale or served by a different component. Re-check which version actually handles requests."
        rows.append({"product": product, "advertised_version": version, "status": status,
                     "cve_ids": cve_ids, "installed": installed, "note": note})
    present = {row["status"] for row in rows}
    status = "corroborated" if "corroborated" in present else "differs" if "version_differs" in present else "inconclusive"
    return {"status": status, "rows": rows,
            "note": "Package versions can include backported fixes, so a corroborated version is a reason to verify, not proof of exploitability."}


def inventory_view(scan):
    """Report-ready service inventory: open services in full, everything else as port lists."""
    inventory = scan.get("inventory") or {}
    services = [s for s in inventory.get("services") or [] if isinstance(s, dict)]
    legacy = not services and bool(scan.get("ports"))
    if legacy:
        # Scans made before version identification only stored connection results.
        services = [{**p, "evidence": p.get("note", "")} for p in scan["ports"]]
    unopened = {}
    for service in services:
        if service.get("state") != "open":
            ports = unopened.setdefault((service.get("ip") or service.get("host") or "?", service.get("state", "unknown")), [])
            ports.append(service.get("port", "?"))
    process = inventory.get("process_inventory")
    processes, unreadable = {}, 0
    for item in process.get("processes", []) if isinstance(process, dict) else []:
        if not item.get("executable"):
            # Kernel threads, or another user's processes when collected without root.
            unreadable += 1
            continue
        key = (item.get("name", ""), item.get("package", ""), item.get("package_version", ""))
        processes[key] = processes.get(key, 0) + 1
    return {"legacy": legacy, "recorded": bool(services), "addresses": inventory.get("addresses") or [],
            "open": [s for s in services if s.get("state") == "open"],
            "unopened": [{"address": address, "state": state, "ports": ports} for (address, state), ports in unopened.items()],
            "technologies": inventory.get("technologies") or [], "tls": inventory.get("tls") or [],
            "coverage": inventory.get("coverage") or {}, "process": process, "processes_unreadable": unreadable,
            # Processes with a known package version are the useful ones; list them first.
            "processes": [{"name": name, "package": package, "version": version, "count": count}
                          for (name, package, version), count in sorted(processes.items(), key=lambda p: (not p[0][2], p[0]))]}


def analyze(scan):
    groups = {}
    for finding in scan["findings"]:
        context = finding_context(finding)
        p = urlsplit(finding["url"])
        key = (finding["title"], p.scheme + "://" + p.netloc, finding["severity"], finding["confidence"])
        if key not in groups:
            groups[key] = {**finding, **context, "finding_ids": [], "urls": [], "evidence_samples": [], "occurrences": 0}
        group = groups[key]
        group["finding_ids"].append(finding["id"])
        group["occurrences"] += 1
        url = safe_url(finding["url"])
        if url not in group["urls"]:
            group["urls"].append(url)
        if finding["evidence"] not in group["evidence_samples"] and len(group["evidence_samples"]) < 3:
            group["evidence_samples"].append(finding["evidence"])
    grouped = sorted(groups.values(), key=lambda f: (SEVERITY.get(f["severity"], 4), f["confidence"] != "high", f["title"]))
    counts = Counter(g["priority"] for g in grouped)
    total = len(grouped)
    incomplete = scan["status"] != "completed"
    summary = f"Spidy recorded {len(scan['findings'])} observations across {total} distinct issue groups. "
    if counts["Fix first"]:
        summary += f"{counts['Fix first']} clearly observed configuration issue(s) should be addressed first. "
    if counts["Validate next"]:
        summary += f"{counts['Validate next']} higher-impact signal(s) need validation before making an exploitability claim. "
    if not counts["Fix first"] and not counts["Validate next"]:
        summary += "The recorded findings do not establish a high-impact vulnerability. "
    if incomplete:
        summary += f"This assessment is {scan['status']}; conclusions are provisional. "
    summary += "Coverage is limited to the documented checks and does not establish that the application is secure."
    methods = []
    for check in scan["config"]["checks"]:
        name, why, how = METHODS[check]
        events = [e for e in scan["events"] if e.get("check") == check]
        requests = [e for e in events if e["type"] == "request"]
        checks_run = [e for e in events if e["type"] == "check_run"]
        skip_reasons = list(dict.fromkeys(e["reason"] for e in events if e["type"] == "check_skipped"))
        if check in ACTIVE_CHECKS and not scan["config"].get("active"):
            state = "Skipped: active probes disabled"
        elif check == "discovery" and not scan["config"].get("discovery"):
            state = "Skipped: path discovery disabled"
        elif check == "advisories":
            state = "Lookup status: " + scan.get("advisories", {}).get("status", "not run")
        elif requests or checks_run or (check == "ports" and scan["ports"]):
            state = "Attempted; review errors and coverage"
        else:
            state = "No execution recorded for this check"
        methods.append({"check": check, "name": name, "why": why, "how": how, "state": state,
                        "requests": len(requests), "inspections": len(checks_run), "skip_reasons": skip_reasons})
    return {"generated_by": "Local evidence-based analysis", "executive_summary": summary,
            "issue_groups": grouped, "priorities": dict(counts), "methodology": methods,
            "obvious_fixes": [g for g in grouped if g["priority"] == "Fix first"],
            "validation_queue": [g for g in grouped if g["priority"] == "Validate next"],
            "partial": incomplete}


def email_draft(scan, assessment=None, attachment_name=None):
    assessment = assessment or analyze(scan)
    target = safe_url(scan["config"]["target"])
    host = urlsplit(target).netloc
    brief = f"The assessment recorded {len(assessment['issue_groups'])} distinct issue groups. "
    if assessment["priorities"].get("Fix first"):
        brief += f"{assessment['priorities']['Fix first']} clearly observed configuration issue(s) deserve priority attention."
    else:
        brief += "The findings need review in the context of your application."
    if assessment["partial"]:
        brief += f" The scan is {scan['status']}; this is a preliminary report."
    lines = ["To: [site owner's security contact]", f"Subject: Security assessment observations for {host} — review requested", "",
             "Hello [security team / owner],", "", f"I am sharing observations from an assessment of {target} performed on {scan['created_at']}.",
             "Authorization / engagement reference: [add your authorization or assessment context before sending].", "",
             brief, "", "Top items for review:"]
    groups = assessment["issue_groups"]
    for g in groups[:3]:
        lines += [f"- {g['title']} ({g['severity']}; {g['confidence']} confidence; {g['certainty']}).",
                  f"  Affected route: {g['urls'][0]}"]
    if not groups:
        lines += ["- No findings were recorded. Please review the coverage and limitations in the attachment."]
    if len(groups) > 3:
        lines.append(f"The attached assessment covers {len(groups) - 3} additional issue groups.")
    lines += ["", "The attached report documents why each check was selected, what requests were made, the observed evidence, limitations, and recommended verification steps.",
              "These are assessment observations, not a claim that an account or database was compromised. Query values are omitted from this email draft.",
              "", "Please confirm the appropriate contact and a secure channel for any sensitive technical details. I am happy to coordinate validation and retesting.",
              "", "Thank you,", "[your name]", "[your contact information]", "",
              f"Attachment to add manually: {attachment_name or ('spidy-' + scan['id'][:8] + '.pdf')}", "",
              "[Review this draft, remove placeholders, and check the attachment for sensitive data before sending.]"]
    return "\n".join(lines)
