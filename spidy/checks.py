"""Bounded additional checks using the scanner's single scope-checked transport."""
import json
import re
import uuid
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .scope import origin

DISCOVERY_REF = "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
CORS_REF = "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"
REDIRECT_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
PROBE_ORIGIN = "https://spidy-probe.invalid"
BASE_PATHS = [("/.git/HEAD", "git"), ("/.env", "env"), ("/config.php.bak", "backup"),
              ("/backup/", "listing"), ("/openapi.json", "api"), ("/swagger.json", "api")]
EXTRA_PATHS = [("/server-status?auto", "apache"), ("/nginx_status", "nginx"),
               ("/actuator/health", "actuator"), ("/actuator/info", "actuator"),
               ("/wp-config.php.bak", "backup"), ("/web.config.bak", "backup")]


def signatures(body):
    return bool(re.search(r"<title>\s*Index of\b|<h1>\s*Index of\b", body, re.I)) and bool(re.search(r"Parent Directory|href=[\"'](?:\.\./|\?C=)", body, re.I))


def normalize_control(body, path):
    return re.sub(r"\s+", " ", body.replace(path, "[requested-path]").strip())[:16000]


class AdditionalChecks:
    def __init__(self, scanner):
        self.scanner = scanner
        self.discovered = set()
        self.cors_tested = set()
        self.redirect_tested = set()
        self.path_attempts = 0
        self.fingerprints = set()

    def run(self, response):
        s = self.scanner
        metadata = " ".join((response.header("Server"), response.header("X-Powered-By"), response.body[:32000])).lower()
        for technology in ("nginx", "apache", "php", "wordpress", "spring", "asp.net"):
            if technology in metadata and technology not in self.fingerprints:
                self.fingerprints.add(technology)
                s.record("technology_hint", technology=technology, url=response.url,
                         reason="Response metadata or markup hint; version and vulnerability not established")
        if "server" in s.config["checks"] and signatures(response.body):
            self.directory_finding(response)
        if "discovery" in s.config["checks"] and s.config.get("discovery"):
            self.discover_paths(response)
        if "cors" in s.config["checks"] and s.config["active"]:
            self.cors(response)
        if "redirects" in s.config["checks"] and s.config["active"]:
            self.redirects(response)

    def directory_finding(self, response):
        self.scanner.finding("Directory listing is publicly visible", "low", "high", response.url,
            "Directory-index heading and parent/sorting link markers both present; file names not retained.",
            "The response resembles an automatically generated directory listing. Its sensitivity depends on the files exposed; no listed files were fetched.",
            "Disable directory indexing where unintended and remove non-public files from the web root.", DISCOVERY_REF, check="server")

    def handle_redirect(self, response, purpose):
        if response and 300 <= response.status < 400 and response.header("Location"):
            try:
                self.scanner.discover(urljoin(response.url, response.header("Location")), response.url, purpose)
            except ValueError:
                self.scanner.record("check_skipped", url=response.url, reason="Malformed redirect destination")
            return True
        return False

    def discover_paths(self, page):
        s = self.scanner
        site = origin(page.url)
        if site in self.discovered or self.path_attempts >= s.config.get("max_paths", 12):
            return
        self.discovered.add(site)
        control_path = "/spidy-missing-" + uuid.uuid4().hex
        control = s.get(site + control_path, "Discovery: random missing-path control", check="discovery")
        if not control or control.status in (401, 403, 429) or control.status >= 500 or self.handle_redirect(control, "Missing-path control redirected to another origin"):
            s.record("check_skipped", check="discovery", url=site, reason="Missing-path baseline was blocked, redirected, or unavailable")
            return
        ordered = list(BASE_PATHS)
        # Technology hints prioritize the finite list; they never authorize a new host.
        hints = self.fingerprints
        priority = {"apache": "apache", "nginx": "nginx", "spring": "actuator", "php": "backup", "wordpress": "backup", "asp.net": "backup"}
        preferred = {priority[h] for h in hints}
        ordered += sorted(EXTRA_PATHS, key=lambda p: p[1] not in preferred)
        s.record("check_plan", check="discovery", url=site,
                 reason="Use content signatures and a missing-path control to reduce catch-all/soft-404 false positives",
                 technology_hints=sorted(hints), candidates=[path for path, _ in ordered], remaining_path_budget=s.config.get("max_paths", 12) - self.path_attempts)
        for path, kind in ordered:
            if self.path_attempts >= s.config.get("max_paths", 12):
                break
            self.path_attempts += 1
            response = s.get(site + path, f"Discovery: inspect {kind} signature at curated path", check="discovery")
            if not response or self.handle_redirect(response, "Discovery path redirected to another origin"):
                continue
            if response.status == 429:
                s.record("check_skipped", check="discovery", url=site, reason="Server rate limited discovery; stopping path guesses")
                break
            if response.status != 200:
                continue
            expected = normalize_control(control.body, control_path)
            actual = normalize_control(response.body, urlsplit(response.url).path)
            if control.status == response.status and (expected == actual or SequenceMatcher(None, expected, actual).ratio() > 0.94):
                s.record("check_skipped", check="discovery", url=response.url, reason="Response matches the missing-path control; suppressing soft-404/catch-all finding")
                continue
            self.inspect_discovery(response, kind)

    def inspect_discovery(self, response, kind):
        s = self.scanner
        body = response.body
        if kind == "git" and re.fullmatch(r"(?:ref: refs/(?:heads|tags)/[^\s]+|[a-f0-9]{40,64})\s*", body):
            s.finding("Git metadata is publicly readable", "medium", "high", response.url,
                "HTTP 200 with a valid Git HEAD structure; branch name/hash omitted.",
                "A source-control metadata file is publicly readable. This alone does not establish that repository contents can be recovered; no objects were requested.",
                "Deny web access to .git directories and deploy release artifacts without repository metadata.", DISCOVERY_REF, check="discovery")
        elif kind == "env":
            fields = re.findall(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,80})\s*=\s*[^\r\n]+", body)
            if not re.search(r"<(?:html|body|pre|code)\b", body, re.I) and len(set(fields)) >= 2 and any(re.search(r"(?:PASSWORD|SECRET|TOKEN|API_KEY|DATABASE_URL|DB_HOST|APP_KEY)", field) for field in fields):
                s.finding("Environment file appears publicly readable", "high", "high", response.url,
                    f"HTTP 200; {len(set(fields))} environment-style assignments including sensitive configuration keys. All keys and values omitted.",
                    "The response contains structured application configuration with sensitive-key patterns. Values may be placeholders; their validity was not tested or retained.",
                    "Block access to environment files, remove them from the web root, and have the owner assess exposure and rotate affected secrets.", DISCOVERY_REF, check="discovery")
        elif kind == "backup" and (re.match(r"\s*<\?php\b", body) and re.search(r"\$[\w]+\s*=|define\s*\(", body) or re.match(r"\s*(?:<\?xml[^>]*>\s*)?<configuration[\s>]", body) and "connectionStrings" in body):
            s.finding("Backup source or configuration file is publicly readable", "high", "high", response.url,
                "HTTP 200 with source/configuration syntax at a backup extension; content omitted.",
                "A backup path returned source or configuration syntax rather than an executed page. No secrets were validated and no file contents were retained.",
                "Remove backup files from the web root, deny backup extensions, and assess whether exposed configuration requires secret rotation.", DISCOVERY_REF, check="discovery")
        elif kind == "listing" and signatures(body):
            self.directory_finding(response)
        elif kind in ("apache", "nginx"):
            valid = ("Total Accesses:" in body and "BusyWorkers:" in body) if kind == "apache" else ("Active connections:" in body and "server accepts handled requests" in body)
            if valid:
                s.finding("Server diagnostic endpoint is publicly visible", "low", "high", response.url,
                    f"HTTP 200 with {kind} status field signatures; operational values omitted.",
                    "A diagnostic status endpoint is readable without authentication. Operational metadata may aid reconnaissance; no administrative capability was tested.",
                    "Restrict diagnostic endpoints to intended operators or monitoring networks.", DISCOVERY_REF, check="discovery")
        elif kind in ("api", "actuator"):
            try:
                data = json.loads(body)
            except ValueError:
                return
            if not isinstance(data, dict):
                return
            if kind == "api" and ("openapi" in data or "swagger" in data) and isinstance(data.get("paths"), dict):
                s.finding("API description is publicly discoverable", "info", "high", response.url,
                    "HTTP 200 with OpenAPI/Swagger version and paths fields; endpoint contents omitted.",
                    "An API description is publicly available. This may be intentional and is not proof of unauthorized API access; described routes were not invoked.",
                    "Confirm whether the API description is intended to be public and enforce authorization on the actual API routes.", DISCOVERY_REF, check="discovery")
            elif kind == "actuator" and (isinstance(data.get("components"), dict) or isinstance(data.get("build"), dict) or isinstance(data.get("git"), dict)):
                s.finding("Detailed application diagnostic endpoint is publicly visible", "low", "medium", response.url,
                    "HTTP 200 with build, repository, or component detail fields; field contents omitted.",
                    "Detailed diagnostic metadata was returned without authentication. A minimal health status alone would not be flagged.",
                    "Restrict diagnostic details to authenticated operators and expose only necessary health status publicly.", DISCOVERY_REF, check="discovery")

    def cors(self, page):
        s = self.scanner
        site = origin(page.url)
        if site in self.cors_tested or len(self.cors_tested) >= 3 or not 200 <= page.status < 300:
            return
        self.cors_tested.add(site)
        response = s.get(page.url, "CORS: compare arbitrary Origin against normal response", check="cors", headers={"Origin": PROBE_ORIGIN})
        if not response or self.handle_redirect(response, "CORS probe redirected to another origin") or not 200 <= response.status < 300:
            return
        allowed = response.header("Access-Control-Allow-Origin").strip()
        credentials = response.header("Access-Control-Allow-Credentials").strip().lower() == "true"
        if allowed == PROBE_ORIGIN and page.header("Access-Control-Allow-Origin").strip() != PROBE_ORIGIN:
            s.finding("CORS reflects an arbitrary origin" + (" with credentials enabled" if credentials else ""),
                "medium" if credentials else "low", "medium", response.url,
                f"Baseline ACAO={page.header('Access-Control-Allow-Origin') or '(absent)'}; probe ACAO={PROBE_ORIGIN}; credentials={credentials}",
                "The response permits the supplied arbitrary origin. Sensitive authenticated content was not requested, so cross-origin data exposure remains unproven.",
                "Use an explicit trusted-origin allowlist; enable credentialed CORS only where required and verify with authenticated browser tests.", CORS_REF, check="cors")

    def redirects(self, page):
        s = self.scanner
        p = urlsplit(page.url)
        try:
            pairs = parse_qsl(p.query, keep_blank_values=True, max_num_fields=100)
        except ValueError:
            return
        signature = (origin(page.url), p.path, tuple(k for k, _ in pairs))
        if signature in self.redirect_tested or len(self.redirect_tested) >= 5:
            return
        indexes = [i for i, (k, _) in enumerate(pairs) if k.lower() in ("url", "next", "return", "returnurl", "return_to", "redirect", "redirect_uri", "redirect_url", "continue", "destination")]
        if not indexes:
            return
        self.redirect_tested.add(signature)
        for index in indexes[:2]:
            modified = list(pairs)
            modified[index] = (pairs[index][0], PROBE_ORIGIN + "/redirect-check")
            url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(modified), ""))
            response = s.get(url, f"Redirect: test destination parameter {pairs[index][0]} without following", check="redirects")
            if not response or not 300 <= response.status < 400 or not response.header("Location"):
                continue
            try:
                location = urljoin(response.url, response.header("Location"))
                destination = origin(location)
            except ValueError:
                s.record("check_skipped", check="redirects", url=response.url, reason="Redirect destination was not a valid HTTP(S) URL")
                continue
            if destination == PROBE_ORIGIN:
                s.record("scope_block", check="redirects", url=location, source=url,
                         reason="Synthetic redirect destination was observed only; never resolved or contacted")
                s.finding("Possible open redirect through a destination parameter", "medium", "medium", url,
                    f"HTTP {response.status}; Location points to reserved test origin {PROBE_ORIGIN}; parameter={pairs[index][0]}",
                    "A supplied external destination was accepted in a redirect response. No request was made to that destination. Intended outbound-link behavior must be reviewed.",
                    "Validate redirect destinations against intended routes or a trusted allowlist; review whether the behavior is intentional.", REDIRECT_REF, check="redirects")
            else:
                self.handle_redirect(response, "Redirect probe produced a different external destination")
