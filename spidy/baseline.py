"""Additional low-impact configuration checks and observed TLS assessment."""
import re
import ssl
import time
from urllib.parse import urljoin, urlsplit

from .analysis import METHODS
from .scope import origin


REF = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"


class BaselineChecks:
    def __init__(self, scanner):
        self.scanner = scanner
        self.methods_seen = set()
        self.certificates_seen = set()

    def observe(self, response):
        s = self.scanner
        if "transport" not in s.config["checks"]:
            return
        s.record("check_run", check="transport", url=response.url, reason=METHODS["transport"][1])
        if urlsplit(response.url).scheme == "http" and re.search(r"\bbasic\b", response.header("WWW-Authenticate"), re.I):
            s.finding("Basic authentication advertised over plaintext HTTP", "medium", "high", response.url,
                "HTTP response includes a Basic WWW-Authenticate challenge; no credentials submitted.",
                "A client could send reusable credentials over an unencrypted connection if it answers this challenge.",
                "Require HTTPS before issuing or accepting authentication challenges.", REF, check="transport", scope="origin")
        hsts = response.header("Strict-Transport-Security")
        if urlsplit(response.url).scheme == "https" and hsts:
            match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
            if not match or int(match[1]) == 0:
                s.finding("HSTS header does not enable a valid policy", "low", "high", response.url,
                    "Strict-Transport-Security has no valid positive max-age directive.",
                    "The header is present but does not enable a persistent HTTPS-only policy in browsers.",
                    "Set a valid positive max-age after confirming HTTPS coverage.", REF, check="transport", scope="origin")
        csp = response.header("Content-Security-Policy")
        directives = {part.split()[0].lower(): part.split()[1:] for part in csp.split(";") if part.split()}
        scripts = directives.get("script-src", directives.get("default-src", []))
        has_nonce_or_hash = any(value.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for value in scripts)
        if scripts and ("'unsafe-eval'" in scripts or ("'unsafe-inline'" in scripts and not has_nonce_or_hash)):
            s.finding("Content Security Policy permits broad script execution", "low", "medium", response.url,
                "Effective script policy contains unsafe-eval or unsafe-inline without a nonce/hash exception.",
                "The observed policy weakens a browser defense. This does not prove a script injection vulnerability.",
                "Review inline/eval dependencies and deploy nonce/hash based script policies where practical.", check="transport", scope="origin")
        expires = response.network.get("certificate_not_after")
        if expires and origin(response.url) not in self.certificates_seen:
            self.certificates_seen.add(origin(response.url))
            try:
                days = (ssl.cert_time_to_seconds(expires) - time.time()) / 86400
                if 0 <= days <= 30:
                    s.finding("TLS certificate expires within 30 days", "low", "high", response.url,
                        f"Certificate notAfter={expires}; approximately {int(days)} days remaining.",
                        "The currently served certificate is approaching expiry. Automated renewal may already be configured.",
                        "Verify renewal and deployment monitoring before the certificate expires.", REF, check="transport")
            except (ValueError, OverflowError):
                pass
        # Names in a certificate are discoveries, never automatic scan targets.
        for name in response.network.get("certificate_dns_names", [])[:16]:
            if "*" not in name:
                s.discover("https://" + name + "/", response.url, "Hostname advertised in the TLS certificate")

    def inspect_page(self, response, parser, base):
        s = self.scanner
        if "transport" not in s.config["checks"] or urlsplit(response.url).scheme != "https":
            return
        resources = [urljoin(base, value) for value in parser.resources[:200]]
        insecure = [value for value in resources if urlsplit(value).scheme == "http"]
        if insecure:
            s.finding("HTTPS page references plaintext resources", "low", "high", response.url,
                f"{len(insecure)} HTTP resource reference(s) in HTTPS page markup; resources were not fetched.",
                "Browsers may block or upgrade mixed content. Plaintext resource references should be reviewed for tampering risks and breakage.",
                "Serve all page resources over HTTPS and verify browser mixed-content warnings.", REF, check="transport")

    def methods(self, page):
        s = self.scanner
        if "methods" not in s.config["checks"] or not s.config["active"] or origin(page.url) in self.methods_seen or len(self.methods_seen) >= 3:
            return
        self.methods_seen.add(origin(page.url))
        response = s.get(page.url, "Inspect advertised methods without performing state changes", check="methods", method="OPTIONS")
        if not response:
            return
        if 300 <= response.status < 400 and response.header("Location"):
            s.discover(urljoin(page.url, response.header("Location")), page.url, "OPTIONS redirected to another origin")
        methods = {m.strip().upper() for m in response.header("Allow").split(",")}
        sensitive = sorted(methods & {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"})
        if sensitive:
            s.finding("Potentially sensitive HTTP methods advertised", "info", "high", response.url,
                "Allow advertises: " + ", ".join(sensitive) + "; these methods were not executed.",
                "The server advertises methods that deserve an authorization review. They may be intentional and access-controlled.",
                "Verify method-specific authorization and disable methods that the application does not need.", check="methods")
