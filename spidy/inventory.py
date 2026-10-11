"""Bounded external inventory. A reachable service is not proof of a vulnerability.

All sockets use addresses authorized and validated by Scope.resolve. Only the
original target hostname receives TCP probes; approving another web origin never
implicitly authorizes a port scan of that host. No authentication or application
commands are sent to non-HTTP services.
"""
import copy
import re
import socket
import ssl
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from html.parser import HTMLParser
from urllib.parse import urlsplit

from . import portscan
from .transport import connect_pinned, readable_name


COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
                465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000,
                3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017)
EXPANDED_PORTS = tuple(sorted(set(COMMON_PORTS) | {
    20, 26, 49, 79, 81, 88, 111, 113, 119, 161, 179, 199, 264, 427, 444,
    500, 512, 513, 514, 515, 548, 554, 631, 873, 902, 989, 990, 1000,
    1080, 1099, 1434, 1723, 1883, 1900, 2000, 2082, 2083, 2086, 2087,
    2181, 2222, 2483, 2484, 3001, 3128, 3268, 3269, 4000, 4369, 5000,
    5001, 5060, 5061, 5222, 5601, 5671, 5672, 5985, 5986, 6000, 6443,
    6667, 7001, 7443, 8008, 8009, 8081, 8088, 8090, 8161, 8883, 8888,
    9000, 9090, 9092, 9300, 9418, 11211, 15672,
}))
PORT_PROFILES = {"common": COMMON_PORTS, "expanded": EXPANDED_PORTS}
MAX_PORTS, MAX_ADDRESSES, MAX_CONNECTIONS = 128, 2, 256
MAX_WORKERS, CONNECT_TIMEOUT, BANNER_TIMEOUT = 4, 0.65, 0.25
PORT_HINTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "smtp-submission", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1099: "java-rmi", 1433: "mssql", 1521: "oracle",
    1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 2222: "ssh", 2375: "docker-api",
    2376: "docker-api-tls", 3000: "http", 3128: "http-proxy", 3306: "mysql",
    3389: "rdp", 5000: "http", 5432: "postgresql", 5601: "http", 5672: "amqp",
    5900: "vnc", 5985: "winrm", 5986: "winrm-tls", 6379: "redis", 6443: "https",
    8000: "http", 8008: "http", 8009: "ajp", 8080: "http", 8081: "http",
    8443: "https", 8888: "http", 9092: "kafka", 9200: "elasticsearch-http",
    9300: "elasticsearch-transport", 11211: "memcached", 15672: "http", 27017: "mongodb",
}
HTTP_PORTS = {80, 81, 3000, 3001, 4000, 5000, 5601, 5985, 7001, 8000,
              8008, 8080, 8081, 8088, 8090, 8161, 8888, 9000, 9090, 9200, 15672}
HTTPS_PORTS = {443, 2083, 2087, 2376, 5001, 5986, 6443, 7443, 8443}
GREETING_PORTS = {21, 22, 25, 110, 143, 587, 2222, 3306}
# Ports Spidy will try an implicit-TLS handshake on, to confirm an HTTPS/TLS service
# and read its presented certificate without sending any HTTP request.
TLS_PORTS = HTTPS_PORTS | {465, 636, 990, 993, 995}
TLS_TIMEOUT = 0.8
# Data stores that are essentially never all exposed together on one real host; several
# answering on one edge address is a strong sign a proxy/CDN is completing the handshakes.
MUTEX_SERVICES = {1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                  9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB"}
VERSION = r"[0-9]+(?:\.[0-9]+){0,3}(?:p[0-9]+)?"
HEADER_PRODUCTS = (
    ("Apache HTTP Server", rf"\bApache(?:/({VERSION}))?"),
    ("nginx", rf"\bnginx(?:/({VERSION}))?"),
    ("OpenResty", rf"\bopenresty(?:/({VERSION}))?"),
    ("Microsoft IIS", rf"\bMicrosoft-IIS(?:/({VERSION}))?"),
    ("PHP", rf"\bPHP(?:/({VERSION}))?"),
    ("Caddy", rf"\bCaddy(?:/({VERSION}))?"),
    ("LiteSpeed", rf"\bLiteSpeed(?:/({VERSION}))?"),
    ("Express", rf"\bExpress(?:/({VERSION}))?"),
    ("ASP.NET", rf"\bASP\.NET(?:[ /]({VERSION}))?"),
    ("Python", rf"\bPython/({VERSION})"),
)
EXPOSURE_REF = "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration"
# Reachability categories worth an owner review. Nothing is sent to these services.
EXPOSURES = (
    ("Database, cache, or message-queue port reachable", "medium",
     {1433, 1434, 1521, 2181, 2483, 2484, 3306, 5432, 5672, 6379, 9092, 9200, 9300, 11211, 27017},
     "Data services are normally reachable only from application servers. Exposure invites credential guessing and, where authentication is absent or weak, direct data access. No authentication or query was attempted.",
     "Restrict these ports to the application network or a VPN, and confirm authentication and encryption are required."),
    ("Remote administration or file-sharing port reachable", "medium",
     {111, 135, 139, 445, 873, 1099, 2049, 2375, 2376, 3389, 5900, 5985, 5986, 8009},
     "Administrative and file-sharing protocols are frequent targets for credential guessing and protocol-level vulnerabilities. No login or protocol command was attempted.",
     "Limit access to trusted management networks or a VPN and disable services the host does not need."),
    ("Plaintext legacy service port reachable", "low",
     {21, 23, 110, 143, 512, 513, 514},
     "These protocols can carry credentials and content without encryption unless an upgrade such as STARTTLS is enforced. No credentials were submitted.",
     "Retire the plaintext protocol or require an encrypted equivalent (SFTP/SSH, IMAPS, POP3S)."),
)
PORT_HELP = f"Use up to {MAX_PORTS} ports from 1 to 65535, such as 22, 80, 8000-8010."


def parse_ports(text):
    """Parse '22, 80, 8000-8010' into a bounded list of distinct ports."""
    ports = []
    for part in filter(None, re.split(r"[,\s]+", text.strip())):
        match = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", part)
        low, high = (int(match[1]), int(match[2] or match[1])) if match else (0, 0)
        if not 1 <= low <= high <= 65535 or high - low >= MAX_PORTS:
            raise ValueError(PORT_HELP)
        ports.extend(range(low, high + 1))
    return list(dict.fromkeys(ports))


def port_options(raw):
    """Return validated config fields for reuse by the API and CLI."""
    profile = raw.get("port_profile", "common")
    if not isinstance(profile, str) or profile not in PORT_PROFILES:
        raise ValueError("port_profile must be common or expanded.")
    custom = raw.get("custom_ports", [])
    if isinstance(custom, str):
        custom = parse_ports(custom)
    if (not isinstance(custom, list) or len(custom) > MAX_PORTS or
            any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in custom)):
        raise ValueError(PORT_HELP)
    timeout = raw.get("inventory_timeout", 30)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 5 <= timeout <= 60:
        raise ValueError("inventory_timeout must be an integer from 5 to 60 seconds.")
    return {"port_profile": profile, "custom_ports": list(dict.fromkeys(custom)), "inventory_timeout": timeout}


def selected_ports(config):
    options = port_options(config)
    ports = list(options["custom_ports"] or PORT_PROFILES[options["port_profile"]])
    target = urlsplit(config["target"])
    target_port = target.port or (443 if target.scheme == "https" else 80)
    # Preserve the hard cap while always including the explicitly supplied port.
    return list(dict.fromkeys([target_port] + ports))[:MAX_PORTS]


def clean(value, limit=200):
    return re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f]", " ", str(value))).strip()[:limit]


class MarkupProducts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.products = []

    def handle_starttag(self, tag, attrs):
        if len(self.products) >= 30:
            return
        attrs = dict(attrs)
        if tag == "meta" and attrs.get("name", "").lower() == "generator":
            match = re.fullmatch(rf"WordPress(?:\s+({VERSION}))?", attrs.get("content", "").strip(), re.I)
            if match:
                version = match.group(1) or ""
                self.products.append(("WordPress", version, "HTML generator: WordPress" + (" " + version if version else "")))
        if tag == "script":
            src = attrs.get("src", "")
            match = re.search(r"(?:^|/)jquery[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js(?:[?#]|$)", src, re.I)
            if match:
                self.products.append(("jQuery", match.group(1), "Script filename advertises jQuery " + match.group(1)))


def identify_greeting(data, port):
    """Return only recognized protocol/product tokens, never raw banner text."""
    text = data[:512].decode("ascii", errors="replace")
    if port in {22, 2222}:
        match = re.search(r"(?:^|\r?\n)SSH-(2\.0|1\.99)-([A-Za-z0-9_.+-]{1,80})", text)
        if match:
            software = re.fullmatch(rf"OpenSSH_({VERSION})(?:[-_][A-Za-z0-9_.+-]+)?", match.group(2))
            return {"service": "ssh", "product": "OpenSSH" if software else "", "version": software.group(1) if software else "",
                    "evidence": "SSH protocol greeting" + (f"; OpenSSH {software.group(1)}" if software else "")}
    if port == 3306 and len(data) > 5 and data[3] == 0 and data[4] == 10:
        version_data = data[5:].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        if re.fullmatch(r"[0-9][A-Za-z0-9_.+~:-]{0,95}", version_data):
            maria = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)-MariaDB", version_data, re.I)
            mysql = re.match(r"[0-9]+\.[0-9]+\.[0-9]+", version_data)
            if maria or mysql:
                product, version = ("MariaDB", maria.group(1)) if maria else ("MySQL", mysql.group(0))
                return {"service": "mysql", "product": product, "version": version,
                        "evidence": f"MySQL protocol 10 greeting; {product} {version}"}
    if port == 21 and re.match(r"^220[ -]", text):
        for product, pattern in (("vsFTPd", rf"\bvsFTPd\s+({VERSION})"),
                                 ("ProFTPD", rf"\bProFTPD\s+({VERSION})"),
                                 ("Pure-FTPd", rf"\bPure-FTPd(?:[ /]({VERSION}))?")):
            match = re.search(pattern, text, re.I)
            if match:
                version = match.group(1) or ""
                return {"service": "ftp", "product": product, "version": version,
                        "evidence": f"FTP greeting; {product}" + (" " + version if version else "")}
    if port in {25, 587} and re.match(r"^220[ -].*\bE?SMTP\b", text, re.I):
        return {"service": "smtp", "product": "", "version": "", "evidence": "SMTP greeting with explicit SMTP protocol marker"}
    if port == 110 and re.match(r"^\+OK\b", text):
        return {"service": "pop3", "product": "", "version": "", "evidence": "POP3-style +OK greeting on a POP3 candidate port"}
    if port == 143 and re.match(r"^\* OK\b", text, re.I):
        return {"service": "imap", "product": "", "version": "", "evidence": "IMAP-style untagged OK greeting"}
    return None


class Inventory:
    def __init__(self, scanner):
        self.scanner = scanner
        self.options = port_options(scanner.config)
        self.target = urlsplit(scanner.config["target"])
        # In-scope web URLs on open ports; the scanner may crawl these without new approval.
        self.web_urls = []
        self.data = {
            "addresses": [], "services": [], "technologies": [], "tls": [],
            "process_inventory": {"status": "unavailable", "reason":
                "A remote domain assessment cannot enumerate internal operating-system processes, installed packages, or the origin server behind a CDN. An owner-provided authenticated host inventory is required."},
            "coverage": {"status": "not_started", "profile": "custom" if self.options["custom_ports"] else self.options["port_profile"],
                "ports_selected": selected_ports(scanner.config), "address_limit": MAX_ADDRESSES,
                "connection_limit": MAX_CONNECTIONS, "time_limit_seconds": self.options["inventory_timeout"],
                "connections_scheduled": 0, "connections_completed": 0, "addresses_omitted": 0,
                "scope": "TCP probes cover only the original target hostname; approved additional origins receive HTTP assessment only.",
                "limitations": ["Selected TCP ports only; UDP and all 65,535 ports are not covered.",
                    "A banner can be hidden, forged, proxied, or reflect a vendor build with backported fixes.",
                    "Timeouts cannot distinguish filtering from a slow or unreachable service.",
                    "Alternate web origins require approval before HTTP requests; no credentials or database commands are sent."]}}

    def snapshot(self):
        return copy.deepcopy(self.data)

    def _technology(self, product, version, source, evidence, confidence="medium"):
        item = {"product": product, "version": version, "source": source,
                "evidence": clean(evidence), "confidence": confidence}
        # One entry per product, version, and endpoint; the first URL showing it is kept as the source.
        key = (product, version, urlsplit(source).netloc, item["evidence"])
        if key not in {(t["product"], t["version"], urlsplit(t["source"]).netloc, t["evidence"]) for t in self.data["technologies"]} and len(self.data["technologies"]) < 200:
            self.data["technologies"].append(item)

    def _merge_service(self, result):
        key = (result["host"], result["ip"], result["port"])
        for existing in self.data["services"]:
            if (existing["host"], existing["ip"], existing["port"]) == key:
                # An observed HTTP response is stronger identification evidence
                # than a TCP connection-only result, and the first one stands
                # unless a later response names the server product.
                verified = existing.get("service_verified")
                if verified and not result.get("service_verified"):
                    existing["tcp_state"] = result["state"]
                elif not verified or (result.get("product") and not existing.get("product")):
                    existing.update(result)
                return
        self.data["services"].append(result)

    def observe_response(self, response):
        """Collect metadata from already authorized requests without more traffic."""
        p = urlsplit(response.url)
        network = getattr(response, "network", None) or {}
        port = p.port or (443 if p.scheme == "https" else 80)
        products = []
        for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
            value = response.header(name)[:512]
            if name == "X-AspNet-Version" and re.fullmatch(VERSION, value.strip()):
                products.append(("ASP.NET", value.strip(), f"{name}: {value.strip()}"))
            for product, pattern in HEADER_PRODUCTS:
                match = re.search(pattern, value, re.I)
                if match:
                    products.append((product, match.group(1) or "", f"{name}: {match.group(0)}"))
        for product, version, evidence in products:
            self._technology(product, version, response.url, evidence)
        if "html" in response.header("Content-Type").lower():
            markup = MarkupProducts()
            try:
                markup.feed(response.body[:524288])
                for product, version, evidence in markup.products:
                    self._technology(product, version, response.url, evidence, "low" if product == "jQuery" else "medium")
            except (ValueError, AssertionError):
                pass
        server = next((t for t in products if t[0] in {"Apache HTTP Server", "nginx", "OpenResty", "Microsoft IIS", "Caddy", "LiteSpeed"}), None)
        self._merge_service({"host": p.hostname, "ip": clean(network.get("ip", ""), 64), "port": port,
            "state": "open", "service": p.scheme, "service_hint": p.scheme, "service_verified": True,
            "product": server[0] if server else "", "version": server[1] if server else "",
            "evidence": f"HTTP {response.status} response received" + (f"; {server[2]}" if server else ""),
            "confidence": "medium" if server else "high"})
        if p.scheme == "https" and network.get("tls_version"):
            tls = {"host": p.hostname, "ip": clean(network.get("ip", ""), 64), "port": port}
            for field in ("tls_version", "cipher", "certificate_not_after", "certificate_subject", "certificate_issuer"):
                if field in network:
                    tls[field] = clean(network[field], 300)
            if tls not in self.data["tls"]:
                self.data["tls"].append(tls)

    def _probe(self, address, port, deadline):
        if self.scanner.stop.is_set() or time.monotonic() >= deadline:
            return None
        family, socktype, proto, _, addr = address
        pinned = (addr[0], port, *addr[2:])
        hint = PORT_HINTS.get(port, "unknown")
        result = {"host": self.target.hostname, "ip": addr[0], "port": port,
            "state": "unknown", "service": "unknown", "service_hint": hint,
            "service_verified": False, "product": "", "version": "", "confidence": "low"}
        sock = None
        try:
            sock = connect_pinned([(family, socktype, proto, "", pinned)], min(CONNECT_TIMEOUT, max(0.001, deadline - time.monotonic())))
            convention = f" Port {port} conventionally serves {hint}." if hint != "unknown" else ""
            result.update(state="open", evidence="TCP handshake succeeded." + convention
                          + " Service identity is unverified: no banner was read and no TLS or HTTP response was confirmed on this port.")
            if not self.scanner.stop.is_set() and time.monotonic() < deadline:
                if port in TLS_PORTS:
                    sock = self._identify_tls(sock, port, result, deadline) or sock
                elif port in GREETING_PORTS:
                    try:
                        sock.settimeout(min(BANNER_TIMEOUT, max(0.001, deadline - time.monotonic())))
                        identification = identify_greeting(sock.recv(512), port)
                        if identification:
                            result.update(identification, service_verified=True, confidence="medium")
                    except OSError:
                        pass
        except ConnectionRefusedError:
            result.update(state="closed", evidence="TCP connection refused")
        except (socket.timeout, TimeoutError):
            result.update(state="filtered/unknown", evidence="TCP connection timed out; filtering and reachability are not distinguishable")
        except OSError as exc:
            result.update(state="unknown", evidence=f"TCP connection failed (OS error {exc.errno if exc.errno is not None else 'unspecified'})")
        finally:
            if sock:
                sock.close()
        return result

    def _identify_tls(self, sock, port, result, deadline):
        """Confirm a TLS service and read its presented certificate. No HTTP request is sent."""
        try:
            sock.settimeout(min(TLS_TIMEOUT, max(0.001, deadline - time.monotonic())))
            tls = ssl.create_default_context().wrap_socket(sock, server_hostname=self.target.hostname)
        except ssl.SSLCertVerificationError:
            # A certificate was presented but does not validate for this hostname (for
            # example a self-signed internal service): the service speaks TLS regardless.
            result.update(service="tls", service_verified=True, confidence="low",
                evidence="A TLS service is present, but its certificate did not validate for this hostname, so the service identity is not confirmed.")
            return None
        except (ssl.SSLError, OSError):
            return None
        cert = tls.getpeercert() or {}
        result.update(service="https" if port in HTTPS_PORTS else "tls", service_verified=True, confidence="medium",
            evidence=f"TLS {tls.version()} handshake succeeded; certificate subject {readable_name(cert.get('subject', ())) or 'not disclosed'}, "
                     f"issuer {readable_name(cert.get('issuer', ())) or 'not disclosed'}, valid until {cert.get('notAfter', 'unknown')}.")
        return tls

    def _identify_web(self, deadline):
        """Confirm the target's in-scope HTTP origin(s) so the web service is always identified.

        HTTPS ports are already identified by the TLS handshake in _probe; this covers plain
        HTTP. Only the target hostname's in-scope origins are requested, and observe_response
        records the service and any Server header from the response.
        """
        authority = f"[{self.target.hostname}]" if ":" in self.target.hostname else self.target.hostname
        for service in list(self.data["services"]):
            if self.scanner.stop.is_set() or time.monotonic() >= deadline:
                break
            if service["host"] != self.target.hostname or service["state"] != "open" or service.get("service_verified"):
                continue
            if service["port"] not in (80, 8080):
                continue
            url = f"http://{authority}" + (f":{service['port']}" if service["port"] != 80 else "") + "/"
            if not self.scanner.scope.permits(url):
                continue
            try:
                self.scanner.get(url, "Service inventory: confirm the web service on an in-scope port", check="ports")
            except InterruptedError:
                break

    def _record_result(self, result):
        self._merge_service(result)
        self.data["coverage"]["connections_completed"] += 1
        self.scanner.store.append(self.scanner.id, "ports", {**result, "note": result["evidence"]})
        self.scanner.record("port", check="ports", **result)
        if result["state"] != "open":
            return
        authority = f"[{self.target.hostname}]" if ":" in self.target.hostname else self.target.hostname
        if result["product"]:
            self._technology(result["product"], result["version"], f"tcp://{authority}:{result['port']}", result["evidence"])
        port = result["port"]
        scheme = "https" if port in HTTPS_PORTS else "http" if port in HTTP_PORTS else None
        if scheme:
            url = f"{scheme}://{authority}:{port}/"
            permitted = self.scanner.discover(url, self.scanner.config["target"], "Open TCP port may provide a web service; HTTP inspection needs origin authorization")
            if permitted and permitted not in self.web_urls:
                self.web_urls.append(permitted)

    def report_exposure(self):
        """Turn reachable sensitive ports into review findings, one per category."""
        probed = [s for s in self.data["services"] if "service_hint" in s and s["host"] == self.target.hostname]
        opened = [s for s in probed if s["state"] == "open"]
        datastores = sorted({MUTEX_SERVICES[s["port"]] for s in opened if s["port"] in MUTEX_SERVICES})
        everything_open = len(probed) >= 16 and len(opened) >= 0.8 * len(probed)
        if len(datastores) >= 3 or everything_open:
            detail = (f"{len(opened)} of {len(probed)} probed ports completed a TCP handshake" if everything_open
                      else f"{len(opened)} ports are open, including {len(datastores)} data services that are not normally exposed together ({', '.join(datastores)})")
            self.data["coverage"]["limitations"].append(
                "Open results probably reflect a proxy, CDN, or load balancer in front of the target rather than services on the origin host, so individual ports were not reported as exposures.")
            self.scanner.finding("Open ports likely answered by a proxy, CDN, or load balancer, not real services", "info", "high", self.scanner.config["target"],
                detail + ".",
                "A device in front of the target appears to accept connections on these ports regardless of what the origin runs, so an open handshake does not show the service is reachable on the real host. Behind a CDN the origin's own ports are usually not visible from the internet at all.",
                "Confirm exposure against the owner's firewall and listening-socket list, or run the inventory from inside the hosting network. Approve the target's web origins so Spidy can confirm HTTP/TLS services through the edge.", EXPOSURE_REF, check="ports")
            return
        for title, severity, ports, description, remediation in EXPOSURES:
            matches = [s for s in opened if s["port"] in ports]
            if not matches:
                continue
            labels = list(dict.fromkeys(f"{s['port']} ({s['service'] if s['service_verified'] else s['service_hint'] + ', port-based guess'})" for s in matches))
            self.scanner.finding(title, severity, "medium" if any(s["service_verified"] for s in matches) else "low", self.scanner.config["target"],
                "TCP handshake succeeded on port " + ", ".join(labels) + ".",
                description + " A completed handshake does not confirm which software is listening.", remediation, EXPOSURE_REF, check="ports")

    def run(self):
        coverage = self.data["coverage"]
        if coverage["status"] != "not_started":
            return self.snapshot()
        started = time.monotonic()
        deadline = started + self.options["inventory_timeout"]
        coverage["status"] = "running"
        try:
            if self.scanner.stop.is_set():
                raise InterruptedError("Scan stopped by user")
            self.scanner.record("check_run", check="ports", url=self.scanner.config["target"],
                reason="Inventory reachable TCP services and advertised versions before assessing possible vulnerabilities.")
            # Scope validates EVERY DNS answer before the two-address cap, so a
            # mixed public/private DNS response cannot bypass address policy.
            resolved = self.scanner.scope.resolve(self.scanner.config["target"])
            unique, seen = [], set()
            for address in resolved:
                if address[4][0] not in seen:
                    seen.add(address[4][0])
                    unique.append(address)
            coverage["addresses_omitted"] = max(0, len(unique) - MAX_ADDRESSES)
            addresses = unique[:MAX_ADDRESSES]
            self.data["addresses"] = [{"host": self.target.hostname, "ip": a[4][0],
                "family": "IPv6" if a[0] == socket.AF_INET6 else "IPv4", "source": "validated target DNS"} for a in addresses]
            # Prefer nmap for real service/version detection; fall back to the built-in scan.
            if portscan.available() and self.scanner.config.get("use_nmap", True):
                coverage["scanner"] = "nmap " + portscan.version()
                try:
                    self._nmap_ports(addresses, deadline)
                except portscan.NmapError as exc:
                    coverage["scanner"] = "built-in connect scan (nmap unavailable)"
                    self.scanner.record("check_error", check="ports", purpose="nmap service scan", error=str(exc)[:200])
                    self._probe_ports(addresses, deadline)
            else:
                coverage["scanner"] = "built-in connect scan"
                self._probe_ports(addresses, deadline)
            self._identify_web(deadline)
            if coverage["status"] == "running":
                coverage["status"] = "completed"
        except InterruptedError:
            coverage["status"] = "cancelled"
            raise
        except Exception:
            coverage["status"] = "failed"
            raise
        finally:
            coverage["elapsed_seconds"] = round(time.monotonic() - started, 2)
            coverage["open_services"] = sum(s["state"] == "open" for s in self.data["services"])
            self.data["services"].sort(key=lambda s: (s["host"], s["port"], s["ip"]))
        return self.snapshot()

    def _nmap_ports(self, addresses, deadline):
        """Run nmap -sV against the validated target address; versions feed the CVE lookup."""
        coverage = self.data["coverage"]
        # One representative address keeps nmap fast; service identity rarely differs by address.
        for address in addresses[:1]:
            if self.scanner.stop.is_set():
                raise InterruptedError("Scan stopped by user")
            remaining = int(deadline - time.monotonic())
            if remaining <= 0:
                coverage["status"] = "time_limited"
                break
            results = portscan.scan(address[4][0], coverage["ports_selected"],
                                    min(remaining, self.options["inventory_timeout"]), address[0] == socket.AF_INET6)
            coverage["connections_scheduled"] += len(coverage["ports_selected"])
            for result in results:
                if self.scanner.stop.is_set():
                    raise InterruptedError("Scan stopped by user")
                result["host"] = self.target.hostname
                self._record_result(result)

    def _probe_ports(self, addresses, deadline):
        """Built-in bounded TCP connect scan used when nmap is not available."""
        coverage = self.data["coverage"]
        executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="spidy-inventory")
        pending = set()
        try:
            tasks = iter([(address, port) for port in coverage["ports_selected"] for address in addresses][:MAX_CONNECTIONS])
            exhausted = False
            while pending or not exhausted:
                if self.scanner.stop.is_set():
                    raise InterruptedError("Scan stopped by user")
                if time.monotonic() >= deadline:
                    coverage["status"] = "time_limited"
                    break
                while len(pending) < MAX_WORKERS and not exhausted:
                    item = next(tasks, None)
                    if item is None:
                        exhausted = True
                        break
                    pending.add(executor.submit(self._probe, *item, deadline))
                    coverage["connections_scheduled"] += 1
                if pending:
                    done, pending = wait(pending, timeout=min(0.1, max(0, deadline - time.monotonic())), return_when=FIRST_COMPLETED)
                    for future in done:
                        result = future.result()
                        if result:
                            self._record_result(result)
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
