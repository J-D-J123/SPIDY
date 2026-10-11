"""Self-contained, text-searchable assessment PDFs using only the standard library.

The renderer uses the PDF standard's built-in fonts. It never fetches a URL,
opens a file, or embeds executable content. Unsupported font characters receive
a readable transliteration where possible, otherwise a question mark.
"""

from collections import Counter
import json
import re
import unicodedata

from .analysis import METHODS, advisory_verification, analyze, inventory_view, safe_url
from .progress import assessment_progress


# Widths in thousandths of an em for the standard Helvetica ASCII glyphs.
_WIDTHS = dict(zip(
    (chr(i) for i in range(32, 127)),
    (278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
     556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
     1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
     667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
     333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
     556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584)))
_URL = re.compile(r"https?://[^\s<>\"']+")
_MAX_FIELD = 6000
_ACTIVITY_LIMIT = 120
_PROCESS_LIMIT = 80


def _sharing_text(value):
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    value = str(value if value is not None else "Not recorded")

    def redact(match):
        url = safe_url(match.group())
        # Strip embedded user information as well as query values/fragments.
        return re.sub(r"^(https?://)[^/]*@", r"\1", url)

    value = _URL.sub(redact, value)
    if len(value) > _MAX_FIELD:
        value = value[:_MAX_FIELD] + " [truncated; see the JSON export]"
    return value


def _font_text(value):
    """Produce printable WinAnsi text without PDF control characters."""
    output = []
    for char in str(value):
        if unicodedata.category(char).startswith("C"):
            output.append(" ")
            continue
        try:
            char.encode("cp1252")
            output.append(char)
        except UnicodeEncodeError:
            fallback = unicodedata.normalize("NFKD", char).encode("ascii", "ignore").decode()
            output.append(fallback or "?")
    return "".join(output)


def _literal(value):
    value = _font_text(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return b"(" + value.encode("cp1252") + b")"


def _width(value, size, font):
    if font == "F3":
        return len(value) * size * 0.6
    # A conservative bound also covers wider bold glyphs and WinAnsi accents.
    factor = 1.14 if font == "F2" else 1.0
    return sum(_WIDTHS.get(char, 1000) for char in value) * size * factor / 1000


def _wrap(value, width, size, font):
    """Wrap long unbroken URLs as well as ordinary prose within the page."""
    line = ""
    for word in _font_text(value).split():
        trial = (line + " " + word).lstrip()
        if _width(trial, size, font) <= width:
            line = trial
            continue
        if line:
            yield line
            line = ""
        while _width(word, size, font) > width:
            end = 1
            while end < len(word) and _width(word[:end + 1], size, font) <= width:
                end += 1
            yield word[:end]
            word = word[end:]
        line = word
    if line:
        yield line


class _Document:
    width = 612
    height = 792
    margin = 46
    bottom = 62

    def __init__(self, target, scan_id):
        self.target = _sharing_text(target)
        self.scan_id = str(scan_id)
        self.pages = []
        self._new_page()

    def _draw(self, text, x, y, size=10, font="F1", color="0.15 0.19 0.25"):
        self.pages[-1].append(
            f"BT /{font} {size:g} Tf {color} rg 1 0 0 1 {x:g} {y:g} Tm ".encode()
            + _literal(text) + b" Tj ET\n")

    def _new_page(self):
        self.pages.append([])
        self._draw("SPIDY", self.margin, 759, 15, "F2", "0.08 0.23 0.35")
        self._draw("SECURITY ASSESSMENT", 370, 761, 8, "F2", "0.30 0.37 0.43")
        target_lines = list(_wrap(self.target, 520, 8, "F1"))
        self._draw(target_lines[0] if target_lines else "Target not recorded", self.margin, 742, 8)
        self.pages[-1].append(b"0.78 0.84 0.88 RG 0.6 w 46 732 m 566 732 l S\n")
        self.y = 711

    def _space(self, height):
        if self.y - height < self.bottom:
            self._new_page()

    def paragraph(self, value, *, size=10, font="F1", indent=0, after=7, color="0.15 0.19 0.25"):
        value = _sharing_text(value)
        leading = size * 1.38
        for raw in value.splitlines() or [""]:
            lines = list(_wrap(raw, self.width - 2 * self.margin - indent, size, font)) or [""]
            for line in lines:
                self._space(leading)
                self._draw(line, self.margin + indent, self.y, size, font, color)
                self.y -= leading
        self.y -= after

    def heading(self, text, *, level=1):
        self._space(65)
        self.y -= 6
        self.paragraph(text, size=14 if level == 1 else 11, font="F2", after=8,
                       color="0.08 0.29 0.40")

    def field(self, name, value):
        self.paragraph(f"{name}: {_sharing_text(value)}", size=9, after=4)

    def finish(self):
        total = len(self.pages)
        for index in range(total):
            page = self.pages[index]
            page.append(b"0.78 0.84 0.88 RG 0.5 w 46 48 m 566 48 l S\n")
            page.append(b"BT /F1 8 Tf 0.36 0.41 0.46 rg 1 0 0 1 46 33 Tm "
                        + _literal("Spidy | Assessment " + self.scan_id[:12]) + b" Tj ET\n")
            page.append(b"BT /F1 8 Tf 0.36 0.41 0.46 rg 1 0 0 1 477 33 Tm "
                        + _literal(f"Page {index + 1} of {total}") + b" Tj ET\n")
        objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"",
                   b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
                   b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
                   b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"]
        page_ids = []
        for commands in self.pages:
            page_id = len(objects) + 1
            content_id = page_id + 1
            page_ids.append(page_id)
            objects.append((f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> "
                            f"/Contents {content_id} 0 R >>").encode())
            content = b"".join(commands)
            objects.append(f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"endstream")
        kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
        objects[1] = f"<< /Type /Pages /Count {total} /Kids [{kids}] >>".encode()
        objects.append(b"<< /Title (Spidy security assessment) /Author (Spidy) "
                       b"/Creator (Spidy standard-library PDF renderer) >>")
        result = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for index, obj in enumerate(objects, 1):
            offsets.append(len(result))
            result.extend(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
        xref = len(result)
        result.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
        for offset in offsets[1:]:
            result.extend(f"{offset:010d} 00000 n \n".encode())
        result.extend((f"trailer\n<< /Size {len(offsets)} /Root 1 0 R /Info {len(objects)} 0 R >>\n"
                       f"startxref\n{xref}\n%%EOF\n").encode())
        return bytes(result)


def _list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _normalized(scan):
    """Adapt historical records without changing the stored assessment."""
    config = {"target": "Target not recorded", "checks": [], "active": False, **scan.get("config", {})}
    config["checks"] = [check for check in config["checks"] if check in METHODS]
    findings = []
    for index, finding in enumerate(scan.get("findings", []), 1):
        findings.append({"id": f"SP-{index:03d}", "title": "Untitled observation", "severity": "info",
                         "confidence": "low", "url": config["target"], "evidence": "Not recorded",
                         "description": "Not recorded", "remediation": "Review with the system owner.",
                         "reference": "Not recorded", **finding})
    return {"id": "unknown", "status": "unknown", "created_at": "Not recorded", "summary": "",
            "events": [], "ports": [], "coverage": {}, "approved_origins": [], "pending_origins": [],
            **scan, "config": config, "findings": findings}


def _pairs(record):
    """Readable 'key: value' text for a stored record of unknown shape."""
    if not isinstance(record, dict):
        return _sharing_text(record)
    return "; ".join(f"{str(key).replace('_', ' ')}: {_sharing_text(value)}" for key, value in record.items() if value not in ("", None, []))


def _software(record):
    return " ".join(filter(None, (record.get("product") or record.get("name"), record.get("version")))) or "Unidentified"


def _inventory(document, scan):
    view = inventory_view(scan)
    document.heading("Exposed services and software")
    document.paragraph("This inventory describes externally visible endpoints on approved hosts. An open port "
                       "is an exposure observation; it does not establish a vulnerability or reveal every backend system.")
    for address in view["addresses"]:
        document.field("Resolved address", _pairs(address))
    coverage = view["coverage"]
    if coverage:
        document.field("Port coverage", f"{coverage.get('profile', 'selected')} profile; {len(_list(coverage.get('ports_selected')))} ports; "
                       f"{coverage.get('connections_completed', 0)} connection attempts; status {coverage.get('status', 'not recorded')}")
    for service in view["open"]:
        label = service.get("service") or "unidentified service"
        if service.get("service_verified") is False and service.get("service_hint", "unknown") != "unknown":
            label = f"unverified ({service['service_hint']} by port number)"
        host = service.get("host") or service.get("ip") or "Unknown host"
        document.heading(f"{host}:{service.get('port', '?')} | open | {label}", level=2)
        document.field("Address", service.get("ip") or "Not recorded")
        document.field("Product / observed version", f"{service.get('product') or 'Unidentified'} / "
                       f"{service.get('version') or 'Not disclosed'}")
        document.field("Confidence", service.get("confidence") or "Not recorded")
        document.field("Evidence", service.get("evidence") or "No identifying banner recorded")
    if view["recorded"] and not view["open"]:
        document.paragraph("No probed port accepted a connection.")
    if view["unopened"]:
        document.heading("Ports that did not accept a connection", level=2)
    for group in view["unopened"]:
        document.field(f"{group['address']} | {group['state']} ({len(group['ports'])})", ", ".join(str(port) for port in group["ports"]))
    if view["legacy"]:
        document.paragraph("This older assessment has TCP results without software/version identification.")
    if not view["recorded"]:
        document.paragraph("No service inventory was recorded. This does not mean that no services are exposed.")
    document.heading("Software and versions", level=2)
    for record in _list(view["technologies"]):
        if isinstance(record, dict):
            detail = {key: value for key, value in record.items() if key not in ("product", "name", "version")}
            document.field(_software(record), _pairs(detail) or "No further detail recorded")
        else:
            document.paragraph(record, size=9)
    if not view["technologies"]:
        document.paragraph("No product or version was advertised in the inspected responses and banners.", size=9)
    document.heading("TLS observations", level=2)
    for record in _list(view["tls"]):
        document.paragraph(_pairs(record), size=9)
    if not view["tls"]:
        document.paragraph("No observations recorded.", size=9)
    document.heading("Running processes and installed packages", level=2)
    process = view["process"] if isinstance(view["process"], dict) else {}
    if process.get("status") == "owner_supplied":
        document.field("Source", f"Owner-supplied host inventory for {process.get('target_host', 'the target')}, collected {process.get('collected_at', 'at an unrecorded time')}")
        document.field("Platform", _pairs(process.get("platform")) or "Not recorded")
        document.field("Totals", f"{len(_list(process.get('processes')))} processes; {len(_list(process.get('packages')))} installed packages")
        document.paragraph(process.get("reason", ""), size=9)
        for item in view["processes"][:_PROCESS_LIMIT]:
            document.paragraph(item["name"] + (f" x{item['count']}" if item["count"] > 1 else "")
                               + (f" | package {item['package']} {item['version']}" if item["package"] else " | package not established"),
                               size=8, font="F3", after=2)
        document.paragraph(f"{max(0, len(view['processes']) - _PROCESS_LIMIT)} more distinct processes, {view['processes_unreadable']} kernel threads "
                           "or processes without a readable executable, and the package list are in the JSON export.", size=9)
    else:
        document.paragraph(process.get("reason") or "Unavailable: a remote external assessment "
                           "cannot enumerate operating-system processes. An authenticated host inventory from the owner "
                           "is required to identify process names, IDs, packages, and internal listeners.")
    for limitation in _list(coverage.get("limitations")):
        document.field("Inventory limitation", limitation)


def _advisories(document, scan):
    advisories = scan.get("advisories") or {}
    document.heading("Known vulnerability candidates")
    document.field("Lookup status", advisories.get("status", "Not performed in this assessment"))
    if advisories.get("provider"):
        document.field("Source", advisories["provider"])
    document.paragraph("A product/version match is a lead, not proof of exploitability. Banners can be inaccurate; "
                       "vendor backports, edition, configuration, and affected-version ranges require verification. "
                       "No match, missing versions, or an unavailable advisory source does not establish security.")
    document.paragraph("Reference links below, including any tagged Exploit, are pointers NVD publishes. Spidy does not fetch "
                       "or run them. Use them only against systems you are authorized to test.", size=9)
    for query in _list(advisories.get("queries")):
        document.field(f"Queried {_software(query)}", f"{query.get('status', 'not recorded')}; {query.get('count', 0)} candidate(s)"
                       + (f" of {query.get('total_results')} published" if query.get("truncated") else "")
                       + (f"; {query['reason']}" if query.get("reason") else ""))
    candidates = advisories.get("candidates") or []
    # The rationale is the same sentence for most candidates; state each distinct one once.
    for reason in dict.fromkeys(candidate.get("match_reason", "Not recorded") for candidate in candidates):
        document.field("Match rationale", reason)
    if candidates:
        document.paragraph("Severities below are the published ratings, not a severity confirmed for this target.", size=9)
    for candidate in candidates:
        document.heading(f"{candidate.get('id', 'Candidate')} | {_software(candidate)} | "
                         f"{candidate.get('severity') or 'unrated'} | {candidate.get('status', 'candidate')}", level=2)
        summary = candidate.get("description") or candidate.get("title") or "No description published."
        document.field("Summary", summary[:420] + ("..." if len(summary) > 420 else ""))
        document.field("NVD entry", candidate.get("url", "Not recorded"))
        for ref in _list(candidate.get("references"))[:8]:
            if isinstance(ref, dict) and ref.get("url"):
                document.field(", ".join(ref.get("tags") or []) or "Reference", ref["url"])
    if not candidates:
        document.paragraph("No advisory candidates were recorded; review the lookup status and version coverage.")
    verification = advisory_verification(scan)
    if candidates:
        document.heading("Host verification of these candidates", level=2)
        document.paragraph(verification["note"])
        for row in verification["rows"]:
            installed = "; ".join(row["installed"]) or "no matching package installed"
            document.field(f"{_software({'product': row['product'], 'version': row['advertised_version']})} | {row['status'].replace('_', ' ')}",
                           f"Installed: {installed}. Covers {', '.join(row['cve_ids'][:8])}. {row['note']}")
    for caveat in _list(advisories.get("limitations")):
        document.field("Lookup limitation", caveat)


def _event_line(event):
    """One readable line per activity entry; the JSON export keeps every field."""
    if not isinstance(event, dict):
        return _sharing_text(event)
    subject = event.get("url") or event.get("target") or (f"{event.get('host', '?')}:{event['port']}" if event.get("port") else "")
    outcome = next((event[key] for key in ("error", "status", "state", "reason") if event.get(key) not in (None, "")), "")
    parts = [str(event.get("time", ""))[11:19], event.get("type", "event"), event.get("check"), event.get("method"), subject,
             f"-> {outcome}" if outcome != "" else ""]
    return " ".join(_sharing_text(part) for part in parts if part)


def pdf_report(scan):
    """Return a complete PDF snapshot of a current or historical scan as bytes."""
    scan = _normalized(scan)
    assessment = analyze(scan)
    document = _Document(scan["config"]["target"], scan["id"])
    document.paragraph("Security assessment", size=25, font="F2", after=12, color="0.08 0.23 0.35")
    document.field("Target", scan["config"]["target"])
    document.field("Assessment ID", scan["id"])
    document.field("Status", scan["status"])
    document.field("Started / finished", f"{scan['created_at']} / {scan.get('finished_at') or 'Not finished'}")
    document.field("Requested focus", scan["config"].get("focus") or ", ".join(scan["config"]["checks"]) or "Not recorded")
    document.field("Active probes", "Enabled" if scan["config"]["active"] else "Disabled")
    document.heading("Executive assessment")
    document.paragraph(assessment["executive_summary"])
    counts = Counter(group["severity"] for group in assessment["issue_groups"])
    document.field("Distinct issue groups", " | ".join(f"{severity}: {counts[severity]}" for severity in ("high", "medium", "low", "info")))
    view = inventory_view(scan)
    software = list(dict.fromkeys(_software(t) for t in view["technologies"] if isinstance(t, dict)))
    document.field("Open services", (", ".join(f"{s.get('port', '?')}/{s.get('service') or 'unknown'}" for s in view["open"][:20]) or "None observed")
                   if view["recorded"] else "Service inventory not recorded")
    document.field("Software identified", ", ".join(software[:12]) or "None advertised")
    document.field("Vulnerability candidates", f"{len((scan.get('advisories') or {}).get('candidates') or [])} "
                   f"(lookup {(scan.get('advisories') or {}).get('status', 'not performed')})")
    if scan.get("summary"):
        document.field("Scan outcome", scan["summary"])
    document.heading("Priority actions")
    for group in assessment["issue_groups"][:6]:
        document.heading(f"{group['priority']} | {group['title']}", level=2)
        document.paragraph(group["remediation"])
    if not assessment["issue_groups"]:
        document.paragraph("No findings were recorded. Review coverage, execution errors, and the limitations before drawing conclusions.")
    elif len(assessment["issue_groups"]) > 6:
        document.paragraph("Additional issue groups appear in the detailed findings below.")
    _inventory(document, scan)
    _advisories(document, scan)
    document.heading("Assessment working record")
    for line in assessment_progress(scan).splitlines():
        document.paragraph(line, size=9)
    analysis = scan.get("llm_analysis")
    if isinstance(analysis, dict) and analysis.get("text"):
        document.heading("Local model analysis")
        document.field("Model", f"{analysis.get('model', 'unknown')} (local, open)")
        document.paragraph(analysis.get("disclaimer", ""), size=9)
        for paragraph in str(analysis["text"]).split("\n\n"):
            if paragraph.strip():
                document.paragraph(paragraph.strip())
    document.heading("Coverage and methodology")
    for key, value in scan.get("coverage", {}).items():
        document.field(key.replace("_", " ").capitalize(), value)
    if not scan.get("coverage"):
        document.paragraph("No coverage metrics were recorded.")
    for method in assessment["methodology"]:
        document.heading(method["name"], level=2)
        document.field("Why tested", method["why"])
        document.field("Method", method["how"])
        document.field("Execution", f"{method['state']}; {method['requests']} HTTP attempts, {method['inspections']} inspections")
        for reason in method["skip_reasons"]:
            document.field("Skipped", reason)
    document.heading("Detailed findings")
    for index, group in enumerate(assessment["issue_groups"], 1):
        document.heading(f"{index}. [{group['severity'].upper()}] {group['title']}", level=2)
        document.field("Assessment", f"{group['priority']}; {group['confidence']} confidence; {group['certainty']}")
        document.field("Evidence IDs", ", ".join(group["finding_ids"]))
        document.field("Occurrences", group["occurrences"])
        for url in group["urls"]:
            document.field("Affected route", url)
        for evidence in group["evidence_samples"]:
            document.field("Evidence sample", evidence)
        document.field("Impact / interpretation", group["description"])
        document.field("Recommendation", group["remediation"])
        document.field("Verification", group["verification"])
        if group.get("reference"):
            document.field("Reference", group["reference"])
    if not assessment["issue_groups"]:
        document.paragraph("No issue groups recorded.")
    document.heading("Scope decisions")
    document.field("Initial target", scan["config"]["target"])
    document.field("Approved additional origins", ", ".join(scan.get("approved_origins", [])) or "None")
    document.paragraph("Additional origins require operator approval before contact. A link or shared address is not authorization to assess another domain.")
    for decision in scan.get("pending_origins", []):
        document.field(decision.get("decision", "pending").capitalize(), decision.get("origin", "Not recorded"))
        document.field("Reason", decision.get("reason", "Not recorded"))
        document.field("Discovered at", decision.get("source", "Not recorded"))
    if not scan.get("pending_origins"):
        document.paragraph("No additional scope decisions were recorded.")
    document.heading("Limitations and interpretation")
    document.paragraph("This is a bounded external assessment using recorded evidence and a finite check catalog. "
                       "It cannot enumerate all websites, host processes, private services, authenticated workflows, or hidden backends. "
                       "A public address may terminate at a proxy or CDN. Service labels and version banners need owner verification. "
                       "Checks may be skipped, blocked, rate limited, or incomplete; absence of findings does not establish security.")
    document.paragraph("Signals such as SQL errors, reflected input, missing headers, or visible form fields require "
                       "application-specific validation. Findings are not claims of account access, data extraction, or successful exploitation. "
                       "This PDF is a snapshot; retain the JSON export for the complete structured evidence and activity record.")
    document.paragraph("Query values, URL user information, and fragments are removed in this sharing view. "
                       "Evidence may still contain sensitive operational details; review the document before sharing. "
                       "Characters unsupported by the built-in PDF font are transliterated or replaced with question marks.", size=9)
    document.heading("Activity appendix")
    events = scan.get("events", [])
    document.paragraph(f"{len(events)} recorded activities, one line each. Response bodies and cookie values are not retained; the JSON export has every field.")
    if len(events) > _ACTIVITY_LIMIT:
        document.paragraph(f"Showing the first 80 and last 40 activities; {len(events) - _ACTIVITY_LIMIT} middle entries "
                           "are omitted from this PDF. The JSON export contains the complete activity log.")
        indexed_events = list(enumerate(events[:80], 1)) + list(enumerate(events[-40:], len(events) - 39))
    else:
        indexed_events = enumerate(events, 1)
    for index, event in indexed_events:
        document.paragraph(f"{index}. {_event_line(event)}", size=7, font="F3", after=2)
    if not events:
        document.paragraph("No activity entries were recorded.")
    return document.finish()
