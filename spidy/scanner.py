import re
import ssl
import threading
import uuid
from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .scope import Scope, ScopeError, normalize_url, origin
from .store import now
from .transport import Transport
from .analysis import METHODS, analyze, finding_context, safe_url
from .advisories import lookup_advisories
from .baseline import BaselineChecks
from .checks import AdditionalChecks
from .inventory import Inventory, port_options


CHECKS = tuple(METHODS)
DEFAULT_CHECKS = ["headers", "forms", "server", "transport"]
ADVISORY_REF = "https://nvd.nist.gov/vuln/search"
WAF_REF = "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework/"
NUCLEI_REF = "https://docs.projectdiscovery.io/tools/nuclei/overview"
HEADER_REF = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
SQL_REF = "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection"
XSS_REF = "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting"
FORM_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
SQL_ERRORS = re.compile(r"SQL syntax.*?MySQL|You have an error in your SQL syntax|SQLSTATE\[[A-Z0-9]+\]|ORA-\d{5}|PostgreSQL.*?ERROR|pg_query\(\).*?Warning|sqlite3?\.(?:OperationalError|DatabaseError)|unclosed quotation mark after the character string", re.I | re.S)
UNSAFE_PATH = re.compile(r"(?:^|[/_.?=&-])(logout|logoff|delete|remove|destroy|unsubscribe|purchase|checkout|reset|signout)(?:$|[/_.?=&-])", re.I)
SENSITIVE_PARAM = re.compile(r"pass|token|csrf|secret|session|auth|key|email|phone", re.I)


def validate_config(raw):
    if not isinstance(raw, dict):
        raise ValueError("Scan configuration must be an object.")
    if raw.get("authorized") is not True:
        raise ValueError("Confirm permission to assess this target.")
    target = normalize_url(str(raw.get("target", "")))
    checks = raw.get("checks", DEFAULT_CHECKS)
    if not isinstance(checks, list) or not checks or any(c not in CHECKS for c in checks):
        raise ValueError("Choose at least one supported check.")
    for key in ("active", "discovery", "inventory", "advisory_lookup", "use_nmap"):
        if key in raw and not isinstance(raw[key], bool):
            raise ValueError(f"{key} must be true or false.")
    # The service inventory runs in every assessment unless the operator opts out.
    inventory, advisory_lookup = raw.get("inventory", True), raw.get("advisory_lookup", True)
    checks = [c for c in dict.fromkeys(checks) if c != "ports"]
    if inventory:
        checks.append("ports")
    if advisory_lookup and "advisories" not in checks:
        checks.append("advisories")
    def number(key, default, low, high):
        value = raw.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"{key} must be an integer from {low} to {high}.")
        return value
    llm_model = raw.get("llm_model", "") or ""
    if not isinstance(llm_model, str) or (llm_model and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}", llm_model)):
        raise ValueError("Choose a valid local model, or none.")
    return {"target": target, "checks": checks, "active": raw.get("active", False),
            "max_pages": number("max_pages", 15, 1, 5000), "max_requests": number("max_requests", 80, 1, 50000),
            "discovery": raw.get("discovery", False), "max_paths": number("max_paths", 12, 1, 12),
            "inventory": inventory, **port_options(raw), "advisory_lookup": advisory_lookup,
            "use_nmap": raw.get("use_nmap", True), "llm_model": llm_model, "llm_host": str(raw.get("llm_host", "") or ""),
            "authorized": True, "focus": str(raw.get("focus", ""))[:1000]}


def focus_checks(text):
    """Transparent keyword routing; explicit UI categories remain authoritative."""
    text = text.lower()
    mapping = {"headers": r"header|csp|hsts|cookie", "forms": r"form|csrf|login",
               "sqli": r"sql|database|injection", "reflection": r"xss|reflect|cross.site.script",
               "server": r"server|backend|back.end|tls|stack|directory", "ports": r"\bports?\b|service|network",
               "transport": r"tls|ssl|certificate|https|encrypt|mixed.content", "methods": r"\bmethods?\b|\bverbs?\b",
               "waf": r"waf|firewall|cdn", "nuclei": r"nuclei|template|cve.scan|vuln.*scan|deep.scan",
               "discovery": r"brute|discover|backup|config|uncommon|hidden|expos", "cors": r"cors|cross.origin",
               "redirects": r"redirect|forward"}
    return [key for key, pattern in mapping.items() if re.search(pattern, text)]


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.resources, self.forms = [], [], []
        self.current = None
        self.base = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "base" and self.base is None and a.get("href"):
            self.base = a["href"]
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag in ("script", "img", "iframe", "source", "video", "audio") and a.get("src"):
            self.resources.append(a["src"])
        if tag == "link" and a.get("href"):
            self.resources.append(a["href"])
        if tag == "form":
            self.current = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "fields": []}
            self.forms.append(self.current)
        if tag in ("input", "textarea", "select") and self.current is not None:
            self.current["fields"].append({"name": a.get("name", ""), "type": a.get("type", "text").lower(), "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class Scanner:
    def __init__(self, store, scan_id, allow_private=False, stop=None):
        self.store, self.id = store, scan_id
        self.data = store.get(scan_id)
        self.config = self.data["config"]
        self.scope = Scope(self.config["target"], self.data["approved_origins"], allow_private)
        self.stop = stop or threading.Event()
        self.transport = Transport(self.scope, self.record, self.stop.is_set, budget=self.config["max_requests"])
        self.seen, self.pending, self.finding_keys = set(), set(), set()
        self.probed = set()
        self.denied = set(self.data.get("denied_origins", []))
        self.pages, self.errors, self.probes = 0, 0, 0
        self.first_error = None
        self.bounded = False
        self.additional = AdditionalChecks(self)
        self.baseline = BaselineChecks(self)
        self.inventory = Inventory(self)

    def record(self, kind, **details):
        self.store.append(self.id, "events", {"time": now(), "type": kind, **details})

    def finding(self, title, severity, confidence, url, evidence, description, remediation, reference=HEADER_REF, check=None, scope="url"):
        # Origin-level issues (headers, cookies, server config, TLS) are the same on
        # every page, so record them once per origin — the origin encodes the port, so
        # the same issue on a different port stays a separate finding.
        try:
            key_url = origin(url) if scope == "origin" else url
        except ValueError:
            key_url = url
        key = (title, key_url, evidence)
        if key in self.finding_keys:
            return
        self.finding_keys.add(key)
        item = {"id": f"SP-{len(self.finding_keys):03}", "title": title,
            "severity": severity, "confidence": confidence, "url": url, "evidence": evidence[:1200],
            "description": description, "remediation": remediation, "reference": reference, "check": check}
        item.update(finding_context(item))
        self.store.append(self.id, "findings", item)

    def discover(self, url, source, reason):
        try:
            # Reject non-web schemes before normalize_url can interpret them as domains.
            if urlsplit(url).scheme not in ("http", "https"):
                return None
            url = normalize_url(url)
            if not self.scope.permits(url):
                o = origin(url)
                if o not in self.pending and len(self.pending) < 100:
                    self.pending.add(o)
                    self.store.append(self.id, "pending_origins", {"origin": o, "url": url, "source": source,
                        "reason": reason, "decision": "denied" if o in self.denied else "pending"})
                    self.record("scope_block", url=url, source=source, reason=reason)
                return None
            return url
        except (ValueError, UnicodeError):
            return None

    def get(self, url, purpose, check=None, headers=None, method="GET"):
        try:
            response = self.transport.get(url, purpose, check=check, headers=headers, method=method)
            self.inventory.observe_response(response)
            return response
        except InterruptedError:
            raise
        except Exception as exc:
            self.errors += 1
            if self.first_error is None:
                self.first_error = str(exc) or type(exc).__name__
            self.record("check_error", url=url, purpose=purpose, check=check, error=str(exc))
            if isinstance(exc, ssl.SSLCertVerificationError) and "server" in self.config["checks"]:
                self.finding("TLS certificate validation failed", "medium", "high", url, str(exc),
                    "The certificate could not be verified for this hostname using the system trust store. The HTTPS request was stopped.",
                    "Check certificate expiration, hostname coverage, and the served certificate chain.", scope="origin")
            return None

    def inspect_headers(self, response):
        self.record("check_run", check="headers", url=response.url, reason=METHODS["headers"][1])
        url = response.url
        html = "text/html" in response.header("Content-Type").lower()
        rules = [("X-Content-Type-Options", "nosniff", "low", "Set X-Content-Type-Options: nosniff.")]
        if urlsplit(url).scheme == "https":
            rules.append(("Strict-Transport-Security", "", "low", "Enable HSTS after verifying HTTPS coverage for the intended hosts."))
        if html:
            rules.append(("Content-Security-Policy", "", "low", "Deploy a restrictive Content Security Policy appropriate to the application."))
        for header, expected, severity, fix in rules:
            value = response.header(header)
            if not value or (expected and value.lower().strip() != expected):
                self.finding(f"Missing or ineffective {header}", severity, "high", url, f"{header}: {value or '(absent)'}",
                             "A browser hardening control is missing or has an unexpected value. This alone does not demonstrate an exploitable vulnerability.", fix, scope="origin")
        if html and not response.header("X-Frame-Options") and "frame-ancestors" not in response.header("Content-Security-Policy").lower():
            self.finding("No framing restriction observed", "low", "high", url, "Neither X-Frame-Options nor CSP frame-ancestors was present.",
                         "The response may be embeddable by other sites. Clickjacking impact depends on the page's functionality.", "Use CSP frame-ancestors to restrict framing.", scope="origin")
        for key, value in response.headers:
            if key.lower() != "set-cookie":
                continue
            parts = value.split(";")
            name = parts[0].split("=", 1)[0].strip()
            attrs = {part.strip().split("=", 1)[0].lower() for part in parts[1:]}
            missing = [a for a in ("secure", "httponly", "samesite") if a not in attrs]
            if missing:
                self.finding("Cookie attributes need review", "low", "medium", url, f"Cookie {name}: missing {', '.join(missing)} (value omitted)",
                             "Sensitive session cookies need transport and browser protections. Some non-sensitive cookies intentionally allow JavaScript access.",
                             "For session cookies, set Secure, HttpOnly, and a suitable SameSite policy.", scope="origin")

    def inspect_server(self, response):
        self.record("check_run", check="server", url=response.url, reason=METHODS["server"][1])
        if urlsplit(response.url).scheme == "http":
            self.finding("Page served over unencrypted HTTP", "low", "high", response.url, f"HTTP {response.status} over plaintext transport",
                "This response was served without TLS. Network intermediaries can read or modify plaintext traffic.",
                "Serve the application over HTTPS and redirect HTTP requests to HTTPS.", scope="origin")
        for key in ("Server", "X-Powered-By", "X-AspNet-Version"):
            if response.header(key):
                self.finding("Server technology disclosed", "info", "high", response.url, f"{key}: {response.header(key)}",
                             "The server advertises technology metadata. This is an observation, not proof that the software is vulnerable.",
                             "Remove unnecessary version headers and verify supported, patched versions through an authenticated inventory.", scope="origin")
        match = re.search(r"Traceback \(most recent call last\)|Stack trace:|Fatal error:|Exception in thread|at [\w.]+\([^\n]*\.java:\d+\)", response.body)
        if match:
            self.finding("Application error details exposed", "medium", "medium", response.url, match.group(0),
                         "An error or stack-trace signature appears in the response. It could also be documentation or example text.",
                         "Confirm context, disable public debug output, and keep detailed errors in private logs.")

    def inspect_forms(self, response, parser, base):
        if "forms" in self.config["checks"]:
            self.record("check_run", check="forms", url=response.url, forms_seen=len(parser.forms), reason=METHODS["forms"][1])
        for form in parser.forms[:30]:
            action = urljoin(base, form["action"]) if form["action"] else response.url
            allowed = self.discover(action, response.url, "Form submits to another origin")
            password = any(f["type"] == "password" for f in form["fields"])
            if "forms" in self.config["checks"]:
                if password and (urlsplit(action).scheme == "http" or urlsplit(response.url).scheme == "http" or form["method"] == "get"):
                    self.finding("Password form uses an unsafe transport or method", "high", "high", response.url,
                        f"method={form['method'].upper()}, action={action}, password field present",
                        "Credentials may travel over plaintext or appear in URLs and access logs. No credentials were submitted.",
                        "Serve and submit password forms over HTTPS using POST.", FORM_REF)
                if form["method"] == "post" and not any(re.search(r"csrf|xsrf|authenticity|requestverification", f["name"], re.I) for f in form["fields"]):
                    self.finding("POST form has no recognizable CSRF token field", "info", "low", response.url,
                        f"POST form action={action}; no conventional CSRF field name",
                        "This is a review item, not a confirmed CSRF vulnerability. Origin checks, SameSite cookies, or custom tokens may provide protection.",
                        "Manually verify CSRF protection for state-changing actions.", FORM_REF)
            if allowed and form["method"] == "get" and not password and not UNSAFE_PATH.search(action):
                fields = [(f["name"], f["value"] or "spidy") for f in form["fields"]
                          if f["name"] and f["type"] in ("text", "search", "number") and not SENSITIVE_PARAM.search(f["name"])]
                # Do not submit a partial credential/token-bearing form.
                if fields and not any(SENSITIVE_PARAM.search(f["name"]) for f in form["fields"]):
                    p = urlsplit(allowed)
                    candidate = urlunsplit((p.scheme, p.netloc, p.path, urlencode(fields[:5]), ""))
                    self.probe(candidate)

    def probe(self, url):
        checks = self.config["checks"]
        if not self.config["active"] or not ({"sqli", "reflection"} & set(checks)) or UNSAFE_PATH.search(url):
            return
        p = urlsplit(url)
        params = parse_qsl(p.query, keep_blank_values=True, max_num_fields=100)
        signature = (origin(url), p.path, tuple(k for k, _ in params))
        if not params or signature in self.probed or len(self.probed) >= 10:
            return
        self.probed.add(signature)
        baseline = self.get(url, "Input-probe baseline")
        if not baseline or baseline.status >= 400 or 300 <= baseline.status < 400:
            return
        for i, (key, value) in enumerate(params[:3]):
            if SENSITIVE_PARAM.search(key):
                continue
            payloads = []
            if "sqli" in checks:
                payloads.append(("sqli", value + "'"))
            if "reflection" in checks:
                payloads.append(("reflection", "spidy_" + uuid.uuid4().hex[:12] + '<spidy-probe data-check="1">'))
            for kind, payload in payloads:
                modified = list(params)
                modified[i] = (key, payload)
                probe_url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(modified), ""))
                response = self.get(probe_url, f"{kind} probe for parameter {key}", check=kind)
                self.probes += 1
                if not response:
                    continue
                if 300 <= response.status < 400 and response.header("Location"):
                    self.discover(urljoin(probe_url, response.header("Location")), probe_url, "Input probe redirected to another origin")
                if kind == "sqli":
                    match = SQL_ERRORS.search(response.body)
                    if match and not SQL_ERRORS.search(baseline.body):
                        self.finding("Possible SQL injection: new database error after quote probe", "medium", "medium", probe_url,
                            f"Parameter {key}; baseline HTTP {baseline.status}; probe HTTP {response.status}; signature={match.group(0)[:180]}",
                            "A single quote introduced a database-error signature absent from the baseline. This suggests unsafe query handling but does not prove SQL injection or data access.",
                            "Reproduce in a test environment, use parameterized queries, and remove public database errors.", SQL_REF)
                elif payload in response.body and payload not in baseline.body and "text/html" in response.header("Content-Type").lower():
                    self.finding("Unescaped HTML input reflection", "medium", "medium", probe_url,
                        f"Parameter {key}; literal inert marker reflected: {payload}",
                        "HTML metacharacters were reflected without encoding. No executable script was sent; context and browser testing are needed to determine XSS exploitability.",
                        "Apply context-aware output encoding and validate the rendering context manually.", XSS_REF)

    def advisories(self, inventory):
        """Optional NVD lookup of advertised versions; candidates stay unconfirmed."""
        enabled = self.config.get("advisory_lookup") is True
        if enabled:
            self.store.update(self.id, summary="Looking up published advisories for the advertised software versions.")
            self.record("check_run", check="advisories", url=self.config["target"], reason=METHODS["advisories"][1])

        def record(event):
            event = dict(event)
            self.record(event.pop("type"), **event)
        # Prefer server products over lower-confidence markup hints within the lookup cap.
        technologies = sorted(inventory["technologies"], key=lambda t: t["confidence"] == "low")
        try:
            result = lookup_advisories(technologies, enabled, record, self.stop.is_set)
        except Exception as exc:
            self.record("check_error", check="advisories", purpose="Advisory lookup", error=type(exc).__name__)
            result = lookup_advisories([], False)
            result["status"] = "unavailable"
        for query in result["queries"]:
            matches = [c for c in result["candidates"] if (c["product"], c["version"]) == (query["product"], query["version"])]
            if not matches:
                continue
            serious = any(c.get("severity") in ("high", "critical") for c in matches)
            with_exploit = sum(1 for c in matches if any("Exploit" in r.get("tags", []) for r in c.get("references", [])))
            self.finding(f"Published advisories may apply to advertised {query['product']} {query['version']}",
                "medium" if serious else "low", "low", self.config["target"],
                f"{len(matches)} NVD candidate(s) for the advertised version" + ("; more exist than were retrieved" if query.get("truncated") else "")
                + (f"; {with_exploit} list a published exploit/PoC reference" if with_exploit else "")
                + ": " + ", ".join(c["id"] for c in matches[:8]) + ("…" if len(matches) > 8 else ""),
                "The advertised product and version match vulnerable configurations in published advisories. Version strings can be spoofed, and distributions backport fixes without changing them, so applicability is unconfirmed.",
                "Have the owner confirm the installed package and patch level, then update where an advisory applies.", ADVISORY_REF, check="advisories")
        return result

    def run_waf(self):
        """Fingerprint a WAF/CDN in front of the target with wafw00f."""
        from . import externals
        if self.stop.is_set():
            return
        if not externals.available("wafw00f"):
            self.record("check_skipped", check="waf", reason="wafw00f not installed; run install-tools.sh")
            return
        self.record("check_run", check="waf", url=self.config["target"], reason=METHODS["waf"][1])
        try:
            detected = externals.run_wafw00f(self.config["target"])
        except externals.ToolError as exc:
            self.errors += 1
            self.record("check_error", check="waf", purpose="wafw00f", error=str(exc))
            return
        self.inventory.data["waf"] = detected
        if detected:
            names = ", ".join(f"{d['firewall']}" + (f" ({d['manufacturer']})" if d['manufacturer'] else "") for d in detected)
            self.finding("Web application firewall or CDN detected", "info", "high", self.config["target"],
                f"wafw00f fingerprinted: {names}",
                "A WAF/CDN sits in front of this site. It can block or alter automated requests and shields the real origin, so other findings may describe the edge rather than the application.",
                "Confirm with the owner. For assessment, coordinate testing windows or allowlisted source IPs; for defense, verify the WAF ruleset actually covers the application's risks.", WAF_REF, check="waf")
        else:
            self.record("check_skipped", check="waf", url=self.config["target"], reason="No WAF/CDN fingerprinted (does not prove none is present)")

    def run_nuclei(self):
        """Run nuclei detection templates against the target (rate-limited, detection only)."""
        from . import externals
        if self.stop.is_set():
            return
        if not externals.available("nuclei"):
            self.record("check_skipped", check="nuclei", reason="nuclei not installed; run install-tools.sh")
            return
        self.store.update(self.id, summary="Running nuclei detection templates (rate-limited)…")
        self.record("check_run", check="nuclei", url=self.config["target"], reason=METHODS["nuclei"][1])
        try:
            matches, timed_out = externals.run_nuclei(self.config["target"])
        except externals.ToolError as exc:
            self.errors += 1
            self.record("check_error", check="nuclei", purpose="nuclei", error=str(exc))
            return
        severity_map = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        for match in matches:
            reference = match["reference"] if match["reference"].startswith("http") else NUCLEI_REF
            evidence = f"nuclei template {match['template']}; matched at {safe_url(match['matched_at'])}" + (f"; tags {', '.join(match['tags'])}" if match["tags"] else "")
            self.finding(f"nuclei: {match['name']}", severity_map.get(match["severity"], "info"), "medium",
                self.config["target"], evidence,
                (match["description"] or "A nuclei detection template matched. This is a detection signal, not confirmed exploitation.")[:600],
                match["remediation"] or "Reproduce the match manually and remediate per the template reference.", reference, check="nuclei")
        self.record("nuclei_summary", check="nuclei", matches=len(matches), timed_out=timed_out)

    def _crawl(self, queue):
        """Fetch and inspect pages within scope until the page or request budget is spent."""
        while queue and len(self.seen) < self.config["max_pages"]:
                url = queue.popleft()
                if url in self.seen:
                    continue
                if UNSAFE_PATH.search(url):
                    self.record("skip", url=url, reason="Potentially state-changing route")
                    continue
                self.seen.add(url)
                response = self.get(url, "Page discovery and passive checks")
                if not response:
                    continue
                self.pages += 1
                self.store.append(self.id, "pages", {"url": url, "status": response.status, "truncated": response.truncated})
                self.baseline.observe(response)
                if response.status in (301, 302, 303, 307, 308) and response.header("Location"):
                    if "redirects" in self.config["checks"] and self.config["active"]:
                        self.additional.redirects(response)
                    dest = self.discover(urljoin(url, response.header("Location")), url, "Redirect to another origin")
                    if dest and dest not in self.seen:
                        queue.appendleft(dest)
                    continue
                if "headers" in self.config["checks"]:
                    self.inspect_headers(response)
                if "server" in self.config["checks"]:
                    self.inspect_server(response)
                self.additional.run(response)
                self.baseline.methods(response)
                if "text/html" not in response.header("Content-Type").lower():
                    self.probe(url)
                    continue
                parser = PageParser()
                parser.feed(response.body)
                base = urljoin(url, parser.base) if parser.base else url
                self.inspect_forms(response, parser, base)
                self.baseline.inspect_page(response, parser, base)
                self.probe(url)
                for link in parser.resources[:200]:
                    self.discover(urljoin(base, link), url, "Third-party page resource (not fetched)")
                for link in parser.links[:200]:
                    dest = self.discover(urljoin(base, link), url, "Link to another origin")
                    if dest and dest not in self.seen and len(queue) < 300:
                        if not re.search(r"\.(?:png|jpe?g|gif|svg|webp|ico|pdf|zip|mp4|css|js|woff2?)(?:\?|$)", dest, re.I):
                            queue.append(dest)
        if queue:
            self.bounded = True

    def run(self):
        self.store.update(self.id, status="running", summary="Inspecting the approved scope.")
        self.record("start", target=self.config["target"], approved_origins=sorted(self.scope.origins),
                    checks=self.config["checks"], active=self.config["active"], authorization_confirmed=True)
        for check in self.config["checks"]:
            self.record("check_plan", check=check, reason=METHODS[check][1], method=METHODS[check][2])
        queue = deque([self.config["target"]])
        # Explicitly approved discoveries become seeds in the continuation scan.
        for u in self.data.get("seed_urls", []):
            if self.scope.permits(u):
                queue.append(u)
        status = "completed"
        reason = ""
        try:
            # Crawl the approved scope first, on a clean connection, so that a later
            # port scan cannot throttle the target and block page retrieval.
            self._crawl(queue)
            if "ports" in self.config["checks"]:
                self.store.update(self.id, summary="Building the service inventory for the target hostname.")
                try:
                    self.inventory.run()
                    self.inventory.report_exposure()
                except InterruptedError:
                    raise
                except Exception as exc:
                    self.errors += 1
                    if self.first_error is None:
                        self.first_error = str(exc) or type(exc).__name__
                    self.record("check_error", check="ports", purpose="Service inventory", error=str(exc) or type(exc).__name__)
                self.store.update(self.id, inventory=self.inventory.snapshot(), summary="Reviewing discovered services.")
                # Crawl any in-scope web services the inventory newly discovered.
                self._crawl(deque(u for u in self.inventory.web_urls if u not in self.seen))
            if "waf" in self.config["checks"]:
                self.run_waf()
            if "nuclei" in self.config["checks"] and self.config["active"]:
                self.run_nuclei()
            if self.stop.is_set():
                status, reason = "cancelled", "Scan stopped by user."
            elif self.errors:
                status, reason = ("partial" if self.pages else "failed"), "Some network or scope checks failed; see activity log."
        except InterruptedError as exc:
            status = "cancelled" if self.stop.is_set() else "partial"
            reason = str(exc) + "."
        except Exception as exc:
            status, reason = "failed", str(exc)
            self.record("error", error=reason)
        inventory = self.inventory.snapshot()
        advisories = self.advisories(inventory)
        self.store.update(self.id, inventory=inventory, advisories=advisories)
        open_services = [s for s in inventory["services"] if s["state"] == "open"]
        versions = {(t["product"], t["version"]) for t in inventory["technologies"] if t["version"]}
        findings = self.store.get(self.id)["findings"]
        pending_count = sum(p["decision"] == "pending" for p in self.store.get(self.id)["pending_origins"])
        coverage = {"pages_received": self.pages, "page_limit": self.config["max_pages"],
                    "http_attempts": self.transport.count, "http_budget": self.config["max_requests"],
                    "input_probes": self.probes, "input_probe_mode": "enabled" if self.config["active"] else "disabled",
                    "discovery_paths_attempted": self.additional.path_attempts, "discovery_path_budget": self.config.get("max_paths", 12),
                    "technology_hints": ", ".join(sorted(self.additional.fingerprints)) or "None",
                    "service_inventory": inventory["coverage"]["status"] if "ports" in self.config["checks"] else "not selected",
                    "tcp_endpoints_probed": inventory["coverage"]["connections_completed"], "open_services": len(open_services),
                    "software_versions_identified": len(versions),
                    "advisory_lookup": advisories["status"], "advisory_candidates": len(advisories["candidates"]),
                    "network_errors": self.errors, "crawl_limit_reached": self.bounded,
                    "pending_origins": pending_count, "blocked_origins": len(self.pending), "javascript_execution": "not supported", "authenticated_testing": "not performed"}
        summary = f"Received {self.pages} pages; recorded {len(findings)} findings and review items. "
        if "ports" in self.config["checks"]:
            summary += f"The service inventory saw {len(open_services)} open service(s) and {len(versions)} advertised software version(s). "
        summary += f"{pending_count} additional origins were blocked pending your decision. "
        summary += reason or "Review evidence and confidence before treating signals as confirmed vulnerabilities."
        if self.pages == 0 and open_services and "ports" in self.config["checks"]:
            summary += " No page was retrieved even though ports answered — a WAF, CDN, or rate limit is probably blocking automated requests. Try again later, from another network, or with a smaller request budget."
        if status in ("failed", "partial") and self.first_error:
            summary += f" First error encountered: {self.first_error}."
        self.record("finish", status=status, coverage=coverage)
        self.store.update(self.id, coverage=coverage, finished_at=now())
        model = self.config.get("llm_model")
        if model and status in ("completed", "partial") and not self.stop.is_set():
            # Keep the scan marked active so the dashboard shows the analysis when it lands.
            self.store.update(self.id, summary=f"Assessment complete; analyzing the findings with {model}…",
                              analysis=analyze(self.store.get(self.id)))
            try:
                from . import llm
                result = llm.analyze_scan(self.store.get(self.id), model, self.config.get("llm_host") or llm.DEFAULT_HOST)
                self.store.update(self.id, llm_analysis=result)
            except Exception as exc:
                self.record("check_error", purpose="local model analysis", error=str(exc)[:200])
        self.store.update(self.id, status=status, summary=summary, analysis=analyze(self.store.get(self.id)))
        return self.store.get(self.id)
