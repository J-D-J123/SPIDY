"""Run installed external security tools (nuclei, wafw00f) and fold results in.

Tools are found in ./tools/bin (the bundled installer's output) or on PATH, and
are invoked only against the authorized target. Unlike Spidy's own HTTP client,
these tools resolve DNS themselves, so Spidy's strict address pinning does not
cover them — they are meant for targets you are clearly authorized to assess.

nuclei is run with detection templates and rate limiting; Spidy never passes the
flags that let nuclei execute code templates, keeping this to scanning, not
exploitation.
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from contextvars import ContextVar

from .process_output import capture

_output_observer = ContextVar("tool_output_observer", default=None)


def _run_process(args, **kwargs):
    observer = _output_observer.get()
    if observer is None:
        return subprocess.run(args, **kwargs)
    meta, stdout = capture(args, timeout=kwargs["timeout"], on_output=observer, separate_stdout=True)
    observer({**meta, "output": meta["output_tail"]})
    if kwargs.get("text"):
        stdout = stdout.decode("utf-8", "replace")
    if meta["timed_out"]:
        raise subprocess.TimeoutExpired(args, kwargs["timeout"], output=stdout)
    return subprocess.CompletedProcess(args, meta["exit_code"], stdout=stdout)

_BIN = Path(__file__).resolve().parent.parent / "tools" / "bin"


class ToolError(Exception):
    """A sanitized failure from an external tool, safe to show the operator."""


def tool_path(name):
    local = _BIN / name
    if local.exists():
        return str(local)
    return shutil.which(name)


def available(name):
    return tool_path(name) is not None


def tool_readiness(name):
    """Check local prerequisites only; never contact the assessment target."""
    spec = TOOLS.get(name)
    if not spec or not available(spec["needs"]):
        return {"ready": False, "error": f"{name} is not installed."}
    if name == "nikto":
        try:
            result = subprocess.run([tool_path("nikto"), "-Version"], capture_output=True,
                                    text=True, timeout=5, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ready": False, "error": f"Nikto could not start locally: {exc}"}
        if result.returncode != 0:
            return {"ready": False, "error": (result.stderr or result.stdout or "Nikto startup failed.").strip()[:500]}
    return {"ready": True, "error": ""}


def run_wafw00f(url, timeout=60):
    """Return the WAFs/CDNs wafw00f fingerprints in front of the URL."""
    path = tool_path("wafw00f")
    if not path:
        raise ToolError("wafw00f is not installed (run install-tools.sh).")
    tmp = tempfile.mkdtemp()
    out = os.path.join(tmp, "waf.json")
    try:
        _run_process([path, "-f", "json", "-o", out, url], capture_output=True, timeout=timeout, check=False)
        with open(out) as handle:
            data = json.load(handle)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ToolError("wafw00f did not return parseable results.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    detected = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict) and item.get("detected"):
            name = str(item.get("firewall", "unknown")).strip()[:120] or "unknown"
            maker = str(item.get("manufacturer", "")).strip()[:120]
            detected.append({"firewall": name, "manufacturer": maker})
    return detected


def _parse_nuclei(output):
    findings = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        severity = str(info.get("severity", "info")).lower()
        if severity not in ("info", "low", "medium", "high", "critical"):
            severity = "info"
        references = info.get("reference")
        reference = ""
        if isinstance(references, list):
            reference = next((r for r in references if isinstance(r, str) and r.startswith("http")), "")
        elif isinstance(references, str) and references.startswith("http"):
            reference = references
        tags = info.get("tags")
        findings.append({
            "template": str(row.get("template-id", ""))[:120],
            "name": str(info.get("name") or row.get("template-id") or "nuclei match")[:200],
            "severity": severity,
            "matched_at": str(row.get("matched-at") or row.get("host") or "")[:400],
            "description": str(info.get("description") or "")[:600],
            "remediation": str(info.get("remediation") or "")[:600],
            "reference": reference[:300],
            "tags": [t for t in tags if isinstance(t, str)][:10] if isinstance(tags, list) else [],
        })
    return findings


def run_nuclei(url, rate=15, concurrency=10, request_timeout=10, overall_timeout=300,
               severities="low,medium,high,critical", tags=""):
    """Run nuclei detection templates against the URL; return (findings, timed_out)."""
    path = tool_path("nuclei")
    if not path:
        raise ToolError("nuclei is not installed (run install-tools.sh).")
    args = [path, "-u", url, "-jsonl", "-silent", "-no-color", "-disable-update-check",
            "-rate-limit", str(rate), "-concurrency", str(concurrency),
            "-timeout", str(request_timeout), "-retries", "1", "-severity", severities]
    if tags:
        args += ["-tags", tags]
    try:
        proc = _run_process(args, capture_output=True, text=True, timeout=overall_timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        # Keep whatever nuclei produced before the deadline.
        partial = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        return _parse_nuclei(partial), True
    except OSError as exc:
        raise ToolError(f"nuclei could not be started ({exc.errno}).")
    return _parse_nuclei(proc.stdout), False


# ---------------------------------------------------------------------------
# On-demand "deep scan" tools: run after the main scan, adjust parameters, and
# fold normalized findings back into the assessment. Detection/fingerprinting
# only — no tool is given exploitation flags.
# ---------------------------------------------------------------------------
import re as _re
from urllib.parse import urlsplit as _urlsplit

WAF_REF = "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework/"
TLS_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
DISCOVERY_REF = "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/"
_WORDLIST = _BIN.parent / "wordlists" / "common.txt"


def _int(value, default, low, high):
    try:
        return max(low, min(high, int(str(value).strip())))
    except (TypeError, ValueError):
        return default


def _exec(args, timeout):
    try:
        return _run_process(args, capture_output=True, text=True, timeout=timeout, check=False).stdout or ""
    except subprocess.TimeoutExpired as exc:
        return (exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")) or ""
    except OSError as exc:
        raise ToolError(f"could not run {args[0]} ({exc.errno})")


def _norm(title, severity, confidence, evidence, description, remediation, reference, check):
    return {"title": title[:200], "severity": severity, "confidence": confidence, "evidence": str(evidence)[:1000],
            "description": description[:600], "remediation": remediation[:400], "reference": reference, "check": check}


def _nuclei_tool(target, opts, cancelled=None):
    matches, timed_out = run_nuclei(target, rate=_int(opts.get("rate"), 15, 1, 500),
                                    severities=(opts.get("severity") or "low,medium,high,critical").strip(),
                                    tags=(opts.get("tags") or "").strip())
    smap = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "info"}
    items = []
    for m in matches:
        ref = m["reference"] if m["reference"].startswith("http") else "https://docs.projectdiscovery.io/tools/nuclei/overview"
        evidence = f"template {m['template']}; matched at {m['matched_at']}" + (f"; tags {', '.join(m['tags'])}" if m["tags"] else "")
        items.append(_norm(f"nuclei: {m['name']}", smap.get(m["severity"], "info"), "medium", evidence,
                           m["description"] or "A nuclei detection template matched (a signal, not confirmed exploitation).",
                           m["remediation"] or "Reproduce the match manually and remediate per the template reference.", ref, "nuclei"))
    return items, {"timed_out": timed_out, "matches": len(items)}


def _wafw00f_tool(target, opts, cancelled=None):
    detected = run_wafw00f(target)
    if not detected:
        return [], {"detected": False}
    names = ", ".join(d["firewall"] + (f" ({d['manufacturer']})" if d["manufacturer"] else "") for d in detected)
    return [_norm("Web application firewall or CDN detected", "info", "high", f"wafw00f fingerprinted: {names}",
                  "A WAF/CDN sits in front of this site. It shields the origin and can block or alter automated requests.",
                  "Confirm with the owner; coordinate testing windows or allowlisted source IPs.", WAF_REF, "waf")], {"detected": True}


def _httpx_tool(target, opts, cancelled=None):
    path = tool_path("httpx")
    out = _exec([path, "-u", target, "-json", "-silent", "-no-color", "-title", "-status-code",
                 "-tech-detect", "-web-server", "-timeout", "10"], 60)
    items = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        techs = row.get("tech") if isinstance(row.get("tech"), list) else []
        evidence = (f"status {row.get('status_code', '?')}; server {row.get('webserver') or 'n/a'}; "
                    f"title {str(row.get('title', ''))[:120]!r}; tech: {', '.join(techs[:15]) or 'none'}")
        items.append(_norm("HTTP fingerprint (httpx)", "info", "medium", evidence,
                           "httpx fingerprinted the HTTP response: server, title, and detected technologies.",
                           "Use the detected stack to check for known vulnerable versions (enable the NVD lookup).", "", "server"))
    return items, {"count": len(items)}


def _naabu_tool(host, opts, cancelled=None):
    path = tool_path("naabu")
    ports = (opts.get("ports") or "top-1000").strip()
    args = [path, "-host", host, "-silent", "-json", "-s", "c", "-rate", str(_int(opts.get("rate"), 1000, 10, 5000))]
    if ports.startswith("top-") and ports[4:].isdigit():
        args += ["-top-ports", ports[4:]]
    elif _re.fullmatch(r"[0-9,\-]+", ports):
        args += ["-p", ports]
    open_ports = []
    for line in _exec(args, 180).splitlines():
        try:
            open_ports.append(int(json.loads(line).get("port")))
        except (ValueError, TypeError):
            pass
    ordered = sorted(set(p for p in open_ports if isinstance(p, int)))
    if not ordered:
        return [], {"open": 0}
    return [_norm("Open TCP ports (naabu)", "info", "medium", "Open: " + ", ".join(map(str, ordered)),
                  "naabu found these TCP ports open on the host. Open does not mean vulnerable, and a CDN/WAF may answer many ports.",
                  "Confirm intended exposure with the owner; restrict management and data-store ports to trusted networks.", "", "ports")], {"open": len(ordered)}


def _subfinder_tool(domain, opts, cancelled=None):
    path = tool_path("subfinder")
    subs = sorted({l.strip() for l in _exec([path, "-d", domain, "-silent"], 150).splitlines() if l.strip()})[:300]
    if not subs:
        return [], {"count": 0}
    sample = ", ".join(subs[:30]) + (" …" if len(subs) > 30 else "")
    return [_norm(f"Subdomains discovered ({len(subs)}) — subfinder", "info", "medium", f"{len(subs)} names: {sample}",
                  "Passive subdomain enumeration found these names. Each is a separate asset/scope.",
                  "Confirm which subdomains are in your engagement scope before assessing them.", "", "discovery")], {"count": len(subs)}


def _katana_tool(target, opts, cancelled=None):
    path = tool_path("katana")
    out = _exec([path, "-u", target, "-silent", "-d", str(_int(opts.get("depth"), 2, 1, 4)), "-timeout", "10"], 180)
    urls = sorted({l.strip() for l in out.splitlines() if l.strip().startswith("http")})[:500]
    if not urls:
        return [], {"count": 0}
    return [_norm(f"Crawled endpoints ({len(urls)}) — katana", "info", "low",
                  f"{len(urls)} URLs discovered. Sample: " + ", ".join(urls[:20]),
                  "katana crawled the site (including JavaScript) and mapped these endpoints — useful for finding sensitive functionality.",
                  "Review discovered endpoints for forms, APIs, or admin areas worth testing.", "", "discovery")], {"count": len(urls)}


def _ffuf_tool(target, opts, cancelled=None):
    path = tool_path("ffuf")
    wordlist = (opts.get("wordlist") or str(_WORDLIST)).strip()
    if not os.path.isfile(wordlist):
        raise ToolError(f"wordlist not found: {wordlist}")
    tmp = tempfile.mkdtemp()
    outp = os.path.join(tmp, "ffuf.json")
    args = [path, "-u", target.rstrip("/") + "/FUZZ", "-w", wordlist, "-mc", "200,204,301,302,307,401,403",
            "-of", "json", "-o", outp, "-s", "-t", "20", "-rate", "30"]
    extensions = (opts.get("extensions") or "").strip()
    if _re.fullmatch(r"[.,\w]+", extensions or "x"):
        if extensions:
            args += ["-e", extensions]
    try:
        _exec(args, 300)
        with open(outp) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = {}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    items = []
    for row in (data.get("results") or [])[:100]:
        if not isinstance(row, dict):
            continue
        status = row.get("status")
        url = str(row.get("url", ""))
        denied = status in (401, 403)
        label = "Access restricted" if denied else "Path response observed"
        item = _norm(f"{label}: {_urlsplit(url).path or '/'}", "info", "medium",
                           f"ffuf: {url} -> HTTP {status} ({row.get('length', '?')} bytes)",
                           ("The server denied access or required authentication. This does not establish that the requested file exists or is exposed."
                            if denied else "A requested path returned an HTTP response. Status and size alone do not establish sensitive content or a vulnerability."),
                           "Review existing response evidence and intended routing with the owner before treating this as an exposure.", DISCOVERY_REF, "discovery")
        item["url"] = url
        items.append(item)
    return items, {"count": len(items)}


def _testssl_tool(target, opts, cancelled=None):
    path = tool_path("testssl.sh")
    tmp = tempfile.mkdtemp()
    outp = os.path.join(tmp, "t.json")
    args = [path, "--jsonfile", outp, "--quiet", "--color", "0", "--severity", "LOW"]
    if str(opts.get("fast", "true")).lower() in ("true", "1", "yes"):
        args.append("--fast")
    args.append(target)
    try:
        _exec(args, 320)
        with open(outp) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    smap = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "WARN": "low"}
    items = []
    for entry in data if isinstance(data, list) else []:
        severity = smap.get(str(entry.get("severity", "")).upper())
        if not severity:
            continue
        items.append(_norm(f"TLS: {entry.get('id', 'issue')}", severity, "medium", str(entry.get("finding", ""))[:300],
                           "testssl.sh flagged a TLS/SSL configuration weakness.",
                           "Review the TLS configuration and remediate per current best practice.", TLS_REF, "transport"))
    return items, {"count": len(items)}


def _nikto_tool(target, opts, cancelled=None):
    path = tool_path("nikto")
    tmp = tempfile.mkdtemp()
    outp = os.path.join(tmp, "nikto.json")
    try:
        _exec([path, "-h", target, "-Format", "json", "-output", outp, "-maxtime", "120s", "-nointeractive"], 200)
        with open(outp) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = {}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    vulns = []
    for block in (data if isinstance(data, list) else [data]):
        if isinstance(block, dict) and isinstance(block.get("vulnerabilities"), list):
            vulns.extend(block["vulnerabilities"])
    items = []
    for vuln in vulns[:100]:
        if not isinstance(vuln, dict):
            continue
        message = str(vuln.get("msg", ""))[:300]
        items.append(_norm(f"nikto: {message[:80]}", "low", "medium",
                           f"{vuln.get('method', 'GET')} {vuln.get('url', '')}: {message}",
                           "nikto flagged a potential web-server issue (dangerous file, misconfiguration, or outdated component).",
                           "Review and remediate the flagged item; nikto results include false positives.", "", "server"))
    return items, {"count": len(items)}


def _gau_tool(domain, opts, cancelled=None):
    path = tool_path("gau")
    # Bounded so unreachable archive providers can never hang the UI; returns partial on timeout.
    urls = sorted({l.strip() for l in _exec([path, "--threads", "5", "--timeout", "10", domain], 75).splitlines() if l.strip().startswith("http")})[:1000]
    if not urls:
        return [], {"count": 0}
    return [_norm(f"Historical URLs ({len(urls)}) — gau", "info", "medium",
                  f"{len(urls)} URLs from public archives (no requests sent to the target). Sample: " + ", ".join(urls[:20]),
                  "gau pulled these URLs from web archives and certificate logs — a passive view of the site's historical endpoints, including ones no longer linked.",
                  "Review archived endpoints (old admin pages, APIs, parameters) that may still be live.", "", "discovery")], {"count": len(urls)}


TOOLS = {
    "nuclei":    {"label": "nuclei — template vuln scan", "input": "url", "needs": "nuclei", "run": _nuclei_tool,
                  "options": {"severity": "low,medium,high,critical", "tags": "", "rate": "15"}},
    "wafw00f":   {"label": "wafw00f — WAF / CDN detection", "input": "url", "needs": "wafw00f", "run": _wafw00f_tool, "options": {}},
    "httpx":     {"label": "httpx — HTTP tech / title / server", "input": "url", "needs": "httpx", "run": _httpx_tool, "options": {}},
    "naabu":     {"label": "naabu — fast port scan", "input": "host", "needs": "naabu", "run": _naabu_tool,
                  "options": {"ports": "top-1000", "rate": "1000"}},
    "subfinder": {"label": "subfinder — subdomain discovery", "input": "domain", "needs": "subfinder", "run": _subfinder_tool, "options": {}},
    "katana":    {"label": "katana — deep crawl", "input": "url", "needs": "katana", "run": _katana_tool, "options": {"depth": "2"}},
    "ffuf":      {"label": "ffuf — content / path discovery", "input": "url", "needs": "ffuf", "run": _ffuf_tool,
                  "options": {"wordlist": str(_WORDLIST), "extensions": ""}},
    "testssl":   {"label": "testssl.sh — TLS / SSL audit", "input": "url", "needs": "testssl.sh", "run": _testssl_tool, "options": {"fast": "true"}},
    "nikto":     {"label": "nikto — web server scanner", "input": "url", "needs": "nikto", "run": _nikto_tool, "options": {}},
    "gau":       {"label": "gau — historical URLs (passive, archives)", "input": "domain", "needs": "gau", "run": _gau_tool, "options": {}},
}


def tools_status():
    return [{"name": name, "label": spec["label"], "input": spec["input"],
             "installed": available(spec["needs"]), "needs": spec["needs"], "options": spec["options"],
             **tool_readiness(name)}
            for name, spec in TOOLS.items()]


def validate_options(name, options):
    if name == "ffuf":
        extensions = [item.strip() for item in str(options.get("extensions") or "").split(",") if item.strip()]
        if len(extensions) != len(set(extensions)):
            raise ToolError("ffuf extensions contain repeated entries. Supply each extension once; repetitions add no new coverage.")
    if name == "nuclei":
        tags = str(options.get("tags") or "").strip()
        if tags.casefold() in {"none", "null", "n/a"}:
            raise ToolError("nuclei tags must name real template tags. To omit the tag filter, use an empty string; 'none' is a literal tag, not no filter.")
        severity = str(options.get("severity") or "").strip()
        if severity and not set(severity.split(",")) <= {"info", "low", "medium", "high", "critical", "unknown"}:
            raise ToolError("nuclei severity must be a comma-separated list of info, low, medium, high, critical, or unknown.")


def run_tool(name, target, options=None, cancelled=None, on_output=None):
    spec = TOOLS.get(name)
    if not spec:
        raise ToolError(f"Unknown tool: {name}")
    validate_options(name, options or {})
    readiness = tool_readiness(name)
    if not readiness["ready"]:
        raise ToolError(readiness["error"] + " Repair the local tool installation before retrying.")
    terminal = {}

    def observe(snapshot):
        terminal.update(snapshot)
        on_output(snapshot)

    token = _output_observer.set(observe if on_output else None)
    try:
        items, meta = spec["run"](target, options or {}, cancelled)
        return items, {**meta, **terminal}
    finally:
        _output_observer.reset(token)
