import json
import socket
import ssl
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from spidy import advisories, portscan
from spidy.advisories import AdvisoryError, lookup_advisories
from spidy.analysis import advisory_verification
from spidy.host_inventory import collect_host, validate_host_inventory
from spidy.inventory import identify_greeting, parse_ports, selected_ports
from spidy.pdf_report import pdf_report
from spidy.scanner import Scanner, validate_config
from spidy.store import Store, markdown_report
from spidy.transport import Response


def nvd_item(cve, severity="HIGH", end="1.20.0"):
    return {"cve": {"id": cve, "descriptions": [{"lang": "en", "value": "Example flaw."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": severity}}]},
                    "references": [{"url": "https://lists.nginx.org/advisory", "tags": ["Vendor Advisory"]},
                                   {"url": f"https://github.com/example/{cve}-poc", "tags": ["Exploit", "Third Party Advisory"]},
                                   {"url": "ftp://skip/this"}],
                    "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "versionEndExcluding": end,
                        "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"}]}]}]}}


class ScannerCase(unittest.TestCase):
    def scanner(self, target="https://example.test/", **config):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = Store(temp.name)
        scan = self.store.create(validate_config({"target": target, "authorized": True, "advisory_lookup": False, "use_nmap": False, **config}))
        scanner = Scanner(self.store, scan["id"], allow_private=True)
        scanner.transport.delay = 0
        return scanner

    def result(self, scanner):
        return self.store.get(scanner.id)


class PortSelectionTests(unittest.TestCase):
    def test_ranges_lists_and_limits(self):
        self.assertEqual(parse_ports("443, 22 8000-8002,22"), [443, 22, 8000, 8001, 8002])
        for bad in ("0", "70000", "90-80", "1-500", "http"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_ports(bad)

    def test_target_port_is_always_probed(self):
        config = validate_config({"target": "https://example.test:9443/", "authorized": True, "custom_ports": [22]})
        self.assertEqual(selected_ports(config), [9443, 22])


class GreetingTests(unittest.TestCase):
    def test_recognized_banners_yield_product_and_version(self):
        ssh = identify_greeting(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n", 22)
        self.assertEqual((ssh["product"], ssh["version"]), ("OpenSSH", "8.9p1"))
        mysql = identify_greeting(b"\x4a\x00\x00\x00\x0a5.5.5-10.6.12-MariaDB\x00rest", 3306)
        self.assertEqual((mysql["product"], mysql["version"]), ("MariaDB", "10.6.12"))
        self.assertEqual(identify_greeting(b"220 (vsFTPd 3.0.5)\r\n", 21)["version"], "3.0.5")

    def test_unrecognized_data_is_not_retained(self):
        self.assertIsNone(identify_greeting(b"internal-secret-banner build 7\r\n", 22))
        self.assertIsNone(identify_greeting(b"SSH-2.0-OpenSSH_8.9\r\n", 21))


class InventoryTests(ScannerCase):
    def listen(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        self.addCleanup(server.close)
        return server.getsockname()[1]

    def test_open_and_closed_ports_are_recorded_with_unverified_identity(self):
        open_port = self.listen()
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
        closed.close()
        scanner = self.scanner(f"http://127.0.0.1:{open_port}/", custom_ports=[closed_port])
        inventory = scanner.inventory.run()
        states = {s["port"]: s for s in inventory["services"]}
        self.assertEqual(states[open_port]["state"], "open")
        self.assertFalse(states[open_port]["service_verified"])
        self.assertEqual(states[closed_port]["state"], "closed")
        self.assertEqual(inventory["coverage"]["status"], "completed")
        self.assertEqual(inventory["coverage"]["connections_completed"], 2)
        self.assertEqual(len(self.result(scanner)["ports"]), 2)
        self.assertEqual(inventory["process_inventory"]["status"], "unavailable")

    def test_only_the_original_hostname_is_probed(self):
        scanner = self.scanner("http://127.0.0.1:8000/", custom_ports=[8001])
        scanner.scope.origins.add("http://other.test")
        with patch("spidy.inventory.connect_pinned", side_effect=ConnectionRefusedError()) as connect:
            scanner.inventory.run()
        self.assertEqual({call.args[0][0][4][0] for call in connect.call_args_list}, {"127.0.0.1"})

    def test_private_addresses_are_refused_before_any_connection(self):
        scanner = self.scanner("http://127.0.0.1:8000/")
        scanner.scope.allow_private = False
        with patch("spidy.inventory.connect_pinned") as connect:
            result = scanner.run()
        connect.assert_not_called()
        self.assertEqual(result["inventory"]["coverage"]["status"], "failed")
        self.assertEqual(result["status"], "failed")

    def test_cancelled_scan_makes_no_connections(self):
        scanner = self.scanner("http://127.0.0.1:8000/")
        scanner.stop.set()
        with patch("spidy.inventory.connect_pinned") as connect:
            result = scanner.run()
        connect.assert_not_called()
        self.assertEqual(result["status"], "cancelled")

    def test_open_web_port_on_another_origin_needs_approval(self):
        scanner = self.scanner("https://example.test/")
        scanner.inventory._record_result({"host": "example.test", "ip": "192.0.2.1", "port": 8080, "state": "open", "service": "unknown",
            "service_hint": "http", "service_verified": False, "product": "", "version": "", "confidence": "low", "evidence": "TCP handshake succeeded"})
        scanner.inventory._record_result({"host": "example.test", "ip": "192.0.2.1", "port": 80, "state": "open", "service": "unknown",
            "service_hint": "http", "service_verified": False, "product": "", "version": "", "confidence": "low", "evidence": "TCP handshake succeeded"})
        self.assertEqual([p["origin"] for p in self.result(scanner)["pending_origins"]], ["http://example.test:8080"])
        self.assertEqual(scanner.inventory.web_urls, ["http://example.test/"])

    def service(self, port, verified=False):
        return {"host": "example.test", "ip": "192.0.2.1", "port": port, "state": "open", "service": "mysql" if verified else "unknown",
                "service_hint": "mysql", "service_verified": verified, "product": "", "version": "", "confidence": "low", "evidence": "x"}

    def test_reachable_data_and_admin_ports_become_review_findings(self):
        scanner = self.scanner()
        scanner.inventory.data["services"] = [self.service(3306, True), self.service(3389), self.service(443)]
        scanner.inventory.report_exposure()
        findings = {f["title"]: f for f in self.result(scanner)["findings"]}
        self.assertEqual(len(findings), 2)
        database = findings["Database, cache, or message-queue port reachable"]
        self.assertEqual((database["severity"], database["confidence"], database["check"]), ("medium", "medium", "ports"))
        self.assertEqual(findings["Remote administration or file-sharing port reachable"]["confidence"], "low")
        self.assertEqual(database["priority"], "Validate next")

    def test_everything_open_is_reported_as_one_caveat(self):
        scanner = self.scanner()
        scanner.inventory.data["services"] = [self.service(port) for port in range(3300, 3320)]
        scanner.inventory.report_exposure()
        findings = self.result(scanner)["findings"]
        self.assertEqual([f["severity"] for f in findings], ["info"])
        self.assertIn("likely answered by a proxy", findings[0]["title"])

    def test_several_exclusive_datastores_look_like_a_proxy_not_exposures(self):
        scanner = self.scanner()
        scanner.inventory.data["services"] = [self.service(3306, True), self.service(5432), self.service(6379), self.service(443)]
        scanner.inventory.report_exposure()
        findings = self.result(scanner)["findings"]
        # One proxy caveat, and no per-service database/admin exposure finding.
        self.assertEqual([f["title"] for f in findings], ["Open ports likely answered by a proxy, CDN, or load balancer, not real services"])
        self.assertIn("MySQL, PostgreSQL, Redis", findings[0]["evidence"])

    def test_tls_identification_reads_certificate_and_notes_untrusted_certs(self):
        scanner = self.scanner()
        class FakeTLS:
            def version(self):
                return "TLSv1.3"
            def getpeercert(self):
                return {"subject": ((("commonName", "campus.example"),),),
                        "issuer": ((("organizationName", "Example CA"),),),
                        "notAfter": "Jan  1 00:00:00 2030 GMT"}
        with patch("spidy.inventory.ssl.create_default_context") as context:
            context.return_value.wrap_socket.return_value = FakeTLS()
            good = {}
            scanner.inventory._identify_tls(Mock(), 8443, good, time.monotonic() + 5)
        self.assertEqual((good["service"], good["service_verified"], good["confidence"]), ("https", True, "medium"))
        self.assertIn("campus.example", good["evidence"])
        self.assertIn("Example CA", good["evidence"])
        with patch("spidy.inventory.ssl.create_default_context") as context:
            context.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError("bad cert")
            untrusted = {}
            self.assertIsNone(scanner.inventory._identify_tls(Mock(), 8443, untrusted, time.monotonic() + 5))
        self.assertEqual((untrusted["service"], untrusted["service_verified"]), ("tls", True))
        self.assertIn("did not validate", untrusted["evidence"])
        with patch("spidy.inventory.ssl.create_default_context") as context:
            context.return_value.wrap_socket.side_effect = ssl.SSLError("not tls")
            plain = {}
            self.assertIsNone(scanner.inventory._identify_tls(Mock(), 8443, plain, time.monotonic() + 5))
        self.assertEqual(plain, {})  # a non-TLS port keeps its TCP-only result

    def test_web_identification_confirms_the_in_scope_http_service(self):
        scanner = self.scanner("http://127.0.0.1/")
        scanner.inventory.data["services"] = [{"host": "127.0.0.1", "ip": "127.0.0.1", "port": 80, "state": "open",
            "service": "unknown", "service_hint": "http", "service_verified": False, "product": "", "version": "", "confidence": "low", "evidence": "x"}]
        with patch.object(scanner, "get") as get:
            scanner.inventory._identify_web(time.monotonic() + 5)
        get.assert_called_once()
        self.assertEqual(get.call_args.args[0], "http://127.0.0.1/")

    def test_web_identification_skips_verified_and_out_of_scope_ports(self):
        scanner = self.scanner("http://127.0.0.1/")
        scanner.inventory.data["services"] = [
            {"host": "127.0.0.1", "ip": "127.0.0.1", "port": 80, "state": "open", "service": "http", "service_hint": "http", "service_verified": True, "product": "", "version": "", "confidence": "high", "evidence": "x"},
            {"host": "127.0.0.1", "ip": "127.0.0.1", "port": 8080, "state": "open", "service": "unknown", "service_hint": "http", "service_verified": False, "product": "", "version": "", "confidence": "low", "evidence": "x"}]
        with patch.object(scanner, "get") as get:
            scanner.inventory._identify_web(time.monotonic() + 5)
        get.assert_not_called()

    def test_response_metadata_identifies_software_without_extra_requests(self):
        scanner = self.scanner()
        page = Response("https://example.test/", 200, [("Server", "nginx/1.18.0 (Ubuntu)"), ("X-Powered-By", "PHP/8.1.2"), ("Content-Type", "text/html")],
                        '<meta name="generator" content="WordPress 6.4.2"><script src="/js/jquery-3.6.0.min.js"></script>',
                        network={"ip": "192.0.2.1", "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"})
        with patch.object(scanner.transport, "get", return_value=page) as request:
            scanner.get(page.url, "test")
        self.assertEqual(request.call_count, 1)
        inventory = scanner.inventory.snapshot()
        self.assertEqual({(t["product"], t["version"]) for t in inventory["technologies"]},
                         {("nginx", "1.18.0"), ("PHP", "8.1.2"), ("WordPress", "6.4.2"), ("jQuery", "3.6.0")})
        self.assertEqual((inventory["services"][0]["product"], inventory["services"][0]["version"]), ("nginx", "1.18.0"))
        self.assertEqual(inventory["tls"][0]["tls_version"], "TLSv1.3")


NMAP_XML = b"""<?xml version="1.0"?><nmaprun><host><address addr="203.0.113.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.18.0" method="probed" conf="10" tunnel="ssl"><cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe></service></port>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1" method="probed" conf="10"/></port>
<port protocol="tcp" portid="3306"><state state="closed" reason="conn-refused"/></port>
<port protocol="tcp" portid="9200"><state state="open" reason="syn-ack"/><service name="wap-wsp" method="table" conf="3"/></port>
</ports></host></nmaprun>"""


class NmapParseTests(unittest.TestCase):
    def test_parses_services_versions_and_states(self):
        services = {s["port"]: s for s in portscan.parse(NMAP_XML)}
        https = services[443]
        self.assertEqual((https["service"], https["product"], https["version"]), ("https", "nginx", "1.18.0"))
        self.assertTrue(https["service_verified"])
        self.assertEqual(https["confidence"], "high")
        self.assertIn("cpe:/a:igor_sysoev:nginx:1.18.0", https["evidence"])
        self.assertEqual((services[22]["product"], services[22]["version"]), ("OpenSSH", "8.9p1"))
        self.assertEqual(services[3306]["state"], "closed")
        # A table (port-based) guess is not treated as verified.
        self.assertFalse(services[9200]["service_verified"])
        self.assertEqual(services[9200]["confidence"], "low")

    def test_bad_output_raises(self):
        with self.assertRaises(portscan.NmapError):
            portscan.parse(b"not xml at all")

    def test_scan_refuses_non_numeric_address(self):
        with self.assertRaises(portscan.NmapError):
            portscan.scan("example.com", [80], 10)


class NmapInventoryTests(ScannerCase):
    def test_nmap_results_populate_services_versions_and_feed_cve_lookup(self):
        scanner = self.scanner("https://target.test/", use_nmap=True)
        address = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.5", 443))]
        with patch.object(scanner.scope, "resolve", return_value=address), \
                patch("spidy.portscan.available", return_value=True), \
                patch("spidy.portscan.version", return_value="7.94"), \
                patch("spidy.portscan.scan", return_value=portscan.parse(NMAP_XML)) as nmap, \
                patch("spidy.inventory.Inventory._identify_web"):
            inventory = scanner.inventory.run()
        nmap.assert_called_once()
        self.assertTrue(inventory["coverage"]["scanner"].startswith("nmap 7.94"))
        services = {s["port"]: s for s in inventory["services"]}
        self.assertEqual((services[443]["product"], services[443]["version"]), ("nginx", "1.18.0"))
        # nmap-detected versions become technology entries the advisory lookup can use.
        techs = {(t["product"], t["version"]) for t in inventory["technologies"]}
        self.assertIn(("nginx", "1.18.0"), techs)
        self.assertIn(("OpenSSH", "8.9p1"), techs)

    def test_nmap_failure_falls_back_to_builtin_scan(self):
        scanner = self.scanner("https://target.test/", use_nmap=True)
        address = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.5", 443))]
        with patch.object(scanner.scope, "resolve", return_value=address), \
                patch("spidy.portscan.available", return_value=True), \
                patch("spidy.portscan.version", return_value="7.94"), \
                patch("spidy.portscan.scan", side_effect=portscan.NmapError("boom")), \
                patch("spidy.inventory.Inventory._probe_ports") as builtin, \
                patch("spidy.inventory.Inventory._identify_web"):
            inventory = scanner.inventory.run()
        builtin.assert_called_once()
        self.assertIn("built-in", inventory["coverage"]["scanner"])
        self.assertTrue(any(e.get("purpose") == "nmap service scan" for e in self.result(scanner)["events"]))


class AdvisoryTests(ScannerCase):
    TECH = [{"product": "nginx", "version": "1.18.0", "confidence": "medium"}]

    def test_disabled_lookup_never_connects(self):
        with patch("spidy.advisories.http.client.HTTPSConnection") as connection:
            result = lookup_advisories(self.TECH)
        connection.assert_not_called()
        self.assertEqual(result["status"], "disabled")

    def test_only_product_and_version_leave_the_machine(self):
        with patch("spidy.advisories._request_json", return_value={"vulnerabilities": [nvd_item("CVE-2021-23017")], "totalResults": 1}) as request:
            result = lookup_advisories(self.TECH + [{"product": "Internal CMS", "version": "2.0"}, {"product": "PHP", "version": ""}], enabled=True)
        self.assertEqual([call.args[0] for call in request.call_args_list], ["cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["candidates"][0]["status"], "candidate")
        references = result["candidates"][0]["references"]
        # Exploit-tagged links surface first; the non-HTTP reference is dropped.
        self.assertEqual(references[0]["tags"], ["Exploit", "Third Party Advisory"])
        self.assertTrue(references[0]["url"].startswith("https://github.com/example/"))
        self.assertEqual(len(references), 2)
        self.assertEqual(result["skipped"]["unsupported_product"], 1)
        self.assertEqual(result["skipped"]["missing_version"], 1)

    def test_fixed_versions_and_malformed_records_are_dropped(self):
        data = {"vulnerabilities": [nvd_item("CVE-2020-00001", end="1.16.0"), {"cve": {"id": "not-a-cve"}}, "junk", nvd_item("CVE-2021-23017")], "totalResults": 4}
        with patch("spidy.advisories._request_json", return_value=data):
            result = lookup_advisories(self.TECH, enabled=True)
        self.assertEqual([c["id"] for c in result["candidates"]], ["CVE-2021-23017"])

    def test_provider_failure_is_reported_not_raised(self):
        with patch("spidy.advisories._request_json", side_effect=AdvisoryError("NVD rate limit reached; no automatic retry was made.")):
            result = lookup_advisories(self.TECH, enabled=True)
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("rate limit", result["queries"][0]["reason"])

    def test_request_targets_only_the_fixed_nvd_endpoint(self):
        class Reply:
            status = 200
            def getheader(self, name, default=None):
                return default
            def read1(self, size):
                data, self.data = getattr(self, "data", b'{"vulnerabilities": [], "totalResults": 0}'), b""
                return data
        with patch("spidy.advisories.http.client.HTTPSConnection") as connection, patch.object(advisories, "REQUEST_INTERVAL", 0):
            connection.return_value.getresponse.return_value = Reply()
            connection.return_value.sock = None
            advisories._request_json("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")
        self.assertEqual(connection.call_args.args[0], "services.nvd.nist.gov")
        method, path = connection.return_value.request.call_args.args
        self.assertEqual(method, "GET")
        self.assertTrue(path.startswith("/rest/json/cves/2.0?cpeName=cpe%3A2.3%3Aa%3Anginx%3Anginx%3A1.18.0"))
        self.assertNotIn("example", path)

    def test_scan_records_candidates_as_unconfirmed_finding(self):
        scanner = self.scanner("http://127.0.0.1:9/", inventory=False, advisory_lookup=True, checks=["headers"])
        scanner.inventory._technology("nginx", "1.18.0", "http://127.0.0.1:9/", "Server: nginx/1.18.0")
        with patch("spidy.advisories._request_json", return_value={"vulnerabilities": [nvd_item("CVE-2021-23017")], "totalResults": 1}):
            result = scanner.run()
        finding = next(f for f in result["findings"] if f["check"] == "advisories")
        self.assertEqual((finding["severity"], finding["confidence"], finding["certainty"]), ("medium", "low", "needs validation"))
        self.assertIn("CVE-2021-23017", finding["evidence"])
        self.assertEqual(result["coverage"]["advisory_candidates"], 1)
        self.assertIn("CVE-2021-23017", markdown_report(result))
        self.assertIn("github.com/example/CVE-2021-23017-poc", markdown_report(result))
        self.assertIn(b"CVE-2021-23017", pdf_report(result))
        self.assertIn(b"github.com/example/CVE-2021-23017-poc", pdf_report(result))
        self.assertIn("1 list a published exploit/PoC reference", finding["evidence"])

    def test_configured_model_runs_automatically_after_the_scan(self):
        scanner = self.scanner("http://127.0.0.1/", inventory=False, checks=["headers"], llm_model="llama3.1:8b")
        self.assertEqual(scanner.config["llm_model"], "llama3.1:8b")
        page = Response("http://127.0.0.1/", 200, [("Content-Type", "text/html")], "<h1>ok</h1>")
        with patch.object(scanner, "get", return_value=page), \
                patch("spidy.llm.analyze_scan", return_value={"model": "llama3.1:8b", "text": "Focus on X.",
                      "generated_at": "2026-10-11T00:00:00+00:00", "disclaimer": "verify"}) as analyze:
            result = scanner.run()
        analyze.assert_called_once()
        self.assertEqual(result["llm_analysis"]["text"], "Focus on X.")
        self.assertEqual(result["status"], "completed")

    def test_no_model_configured_means_no_analysis(self):
        scanner = self.scanner("http://127.0.0.1:9/", inventory=False, checks=["headers"])
        with patch("spidy.llm.analyze_scan") as analyze:
            result = scanner.run()
        analyze.assert_not_called()
        self.assertIsNone(result["llm_analysis"])

    def test_scan_without_opt_in_does_no_lookup(self):
        scanner = self.scanner("http://127.0.0.1:9/", inventory=False, checks=["headers"])
        with patch("spidy.advisories._request_json") as request:
            result = scanner.run()
        request.assert_not_called()
        self.assertEqual(result["advisories"]["status"], "disabled")


class AdvisoryVerificationTests(unittest.TestCase):
    def scan(self, candidates, packages=None):
        inventory = {}
        if packages is not None:
            inventory = {"process_inventory": {"status": "owner_supplied", "packages": packages}}
        return {"advisories": {"candidates": candidates}, "inventory": inventory}

    def test_without_host_inventory_it_asks_for_one(self):
        result = advisory_verification(self.scan([{"product": "nginx", "version": "1.18.0", "id": "CVE-1"}]))
        self.assertEqual(result["status"], "no_host_inventory")
        self.assertIn("host-inventory", result["note"])

    def test_matching_installed_version_is_corroborated_with_backport_caveat(self):
        result = advisory_verification(self.scan(
            [{"product": "nginx", "version": "1.18.0", "id": "CVE-1"}],
            [{"name": "nginx-core", "version": "1.18.0-6ubuntu14.4"}]))
        row = result["rows"][0]
        self.assertEqual((result["status"], row["status"]), ("corroborated", "corroborated"))
        self.assertIn("backported", row["note"])
        self.assertEqual(row["installed"], ["nginx-core 1.18.0-6ubuntu14.4"])

    def test_different_installed_version_is_flagged(self):
        result = advisory_verification(self.scan(
            [{"product": "nginx", "version": "1.25.0", "id": "CVE-2"}],
            [{"name": "nginx-core", "version": "1.18.0-6"}]))
        self.assertEqual(result["rows"][0]["status"], "version_differs")

    def test_absent_package_means_not_installed_here(self):
        result = advisory_verification(self.scan(
            [{"product": "nginx", "version": "1.18.0", "id": "CVE-3"}],
            [{"name": "apache2", "version": "2.4.58-1"}]))
        self.assertEqual(result["rows"][0]["status"], "not_installed")

    def test_multiarch_suffix_still_matches(self):
        result = advisory_verification(self.scan(
            [{"product": "Python", "version": "3.12.3", "id": "CVE-9"}],
            [{"name": "libpython3.12-minimal:amd64", "version": "3.12.3-1ubuntu0.17"}]))
        self.assertEqual(result["rows"][0]["status"], "corroborated")

    def test_no_candidates_is_not_an_error(self):
        self.assertEqual(advisory_verification({})["status"], "no_candidates")


class BaselineTests(ScannerCase):
    def test_transport_observations(self):
        scanner = self.scanner(checks=["transport"], inventory=False)
        page = Response("https://example.test/", 200, [("Strict-Transport-Security", "max-age=0"),
            ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")], "",
            network={"certificate_not_after": "Jan  1 00:00:00 2000 GMT", "certificate_dns_names": ["example.test", "shop.example.test", "*.example.test"]})
        with patch("spidy.baseline.time.time", return_value=946684800 - 10 * 86400):
            scanner.baseline.observe(page)
        scanner.baseline.observe(Response("http://example.test/admin", 401, [("WWW-Authenticate", 'Basic realm="x"')], ""))
        data = self.result(scanner)
        self.assertEqual({f["title"] for f in data["findings"]}, {"HSTS header does not enable a valid policy",
            "Content Security Policy permits broad script execution", "TLS certificate expires within 30 days",
            "Basic authentication advertised over plaintext HTTP"})
        # Certificate names are offered for approval, never scanned automatically.
        self.assertEqual([p["origin"] for p in data["pending_origins"]], ["https://shop.example.test"])

    def test_methods_probe_needs_active_mode_and_never_sends_state_changes(self):
        page = Response("https://example.test/", 200, [], "")
        passive = self.scanner(checks=["methods"], inventory=False)
        with patch.object(passive.transport, "get") as request:
            passive.baseline.methods(page)
        request.assert_not_called()
        active = self.scanner(checks=["methods"], inventory=False, active=True)
        with patch.object(active.transport, "get", return_value=Response(page.url, 200, [("Allow", "GET, PUT, DELETE")], "")) as request:
            active.baseline.methods(page)
            active.baseline.methods(page)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.kwargs["method"], "OPTIONS")
        self.assertIn("DELETE, PUT", self.result(active)["findings"][0]["evidence"])


class ExternalToolTests(ScannerCase):
    def test_nuclei_output_is_parsed(self):
        from spidy import externals
        out = "\n".join([
            '{"template-id":"tech","info":{"name":"Nginx","severity":"info","tags":["tech"]},"matched-at":"https://t/"}',
            '{"template-id":"CVE-2021-1","info":{"name":"Bad thing","severity":"critical","description":"d","reference":["https://ref.example"]},"matched-at":"https://t/a?x=SECRET"}',
            "garbage line",
        ])
        found = externals._parse_nuclei(out)
        self.assertEqual(len(found), 2)
        self.assertEqual(found[1]["severity"], "critical")
        self.assertEqual(found[1]["reference"], "https://ref.example")

    def test_run_nuclei_creates_findings_maps_critical_and_redacts(self):
        scanner = self.scanner("https://t.test/", inventory=False, checks=["nuclei"], active=True)
        matches = [{"template": "CVE-x", "name": "Thing", "severity": "critical",
                    "matched_at": "https://t.test/a?token=SECRETVAL", "description": "d",
                    "remediation": "fix", "reference": "https://ref", "tags": ["cve"]}]
        with patch("spidy.externals.available", return_value=True), patch("spidy.externals.run_nuclei", return_value=(matches, False)):
            scanner.run_nuclei()
        finding = self.result(scanner)["findings"][0]
        self.assertEqual((finding["check"], finding["severity"]), ("nuclei", "high"))
        self.assertNotIn("SECRETVAL", json.dumps(self.result(scanner)))

    def test_run_waf_records_detected_firewall(self):
        scanner = self.scanner("https://t.test/", inventory=False, checks=["waf"])
        with patch("spidy.externals.available", return_value=True), \
                patch("spidy.externals.run_wafw00f", return_value=[{"firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}]):
            scanner.run_waf()
        self.assertIn("Web application firewall or CDN detected", [f["title"] for f in self.result(scanner)["findings"]])
        self.assertEqual(scanner.inventory.snapshot()["waf"][0]["firewall"], "Cloudflare")

    def test_missing_external_tool_skips_without_error(self):
        scanner = self.scanner("https://t.test/", inventory=False, checks=["nuclei"], active=True)
        with patch("spidy.externals.available", return_value=False):
            scanner.run_nuclei()
        data = self.result(scanner)
        self.assertEqual(data["findings"], [])
        self.assertTrue(any(e.get("check") == "nuclei" and e["type"] == "check_skipped" for e in data["events"]))


class DeepScanToolTests(unittest.TestCase):
    def test_registry_and_status(self):
        from spidy import externals
        names = {t["name"] for t in externals.tools_status()}
        self.assertTrue({"nuclei", "wafw00f", "httpx", "naabu", "subfinder", "katana", "ffuf", "testssl"} <= names)

    def test_run_tool_dispatches_and_normalizes(self):
        from spidy import externals
        with patch("spidy.externals.available", return_value=True), \
                patch("spidy.externals.run_wafw00f", return_value=[{"firewall": "Cloudflare", "manufacturer": "CF"}]):
            items, meta = externals.run_tool("wafw00f", "https://t.test/")
        self.assertEqual(items[0]["check"], "waf")
        self.assertTrue(meta["detected"])

    def test_run_tool_unknown_and_missing(self):
        from spidy import externals
        with self.assertRaises(externals.ToolError):
            externals.run_tool("notatool", "https://t.test/")
        with patch("spidy.externals.available", return_value=False):
            with self.assertRaises(externals.ToolError):
                externals.run_tool("nuclei", "https://t.test/")

    def test_add_external_findings_dedups_and_assigns_ids(self):
        from spidy.store import add_external_findings
        scan = {"config": {"target": "https://t.test/"}, "findings": []}
        items = [{"title": "X", "severity": "high", "confidence": "medium", "evidence": "e",
                  "description": "d", "remediation": "r", "reference": "https://ref", "check": "nuclei"}]
        self.assertEqual(add_external_findings(scan, items, source="nuclei"), 1)
        self.assertEqual(add_external_findings(scan, items, source="nuclei"), 0)  # dedup on re-run
        self.assertEqual(scan["findings"][0]["source"], "nuclei")
        self.assertEqual(scan["findings"][0]["priority"], "Validate next")  # high + needs-validation

    def test_naabu_parsing(self):
        from spidy import externals
        out = '\n'.join(['{"ip":"1.2.3.4","port":443}', '{"ip":"1.2.3.4","port":22}', 'junk'])
        with patch("spidy.externals._exec", return_value=out), patch("spidy.externals.tool_path", return_value="/x/naabu"):
            items, meta = externals._naabu_tool("t.test", {})
        self.assertEqual(meta["open"], 2)
        self.assertIn("22", items[0]["evidence"])

    def test_gau_parsing(self):
        from spidy import externals
        out = "https://t.test/a\nhttps://t.test/old-admin\nnot-a-url\nhttps://t.test/a"
        with patch("spidy.externals._exec", return_value=out), patch("spidy.externals.tool_path", return_value="/x/gau"):
            items, meta = externals._gau_tool("t.test", {})
        self.assertEqual(meta["count"], 2)  # deduped, only http(s)
        self.assertEqual(items[0]["check"], "discovery")

    def test_nikto_parsing(self):
        import json as _json
        from unittest.mock import mock_open
        from spidy import externals
        payload = _json.dumps([{"vulnerabilities": [{"method": "GET", "url": "/admin", "msg": "Admin page found"}]}])
        with patch("spidy.externals._exec", return_value=""), patch("spidy.externals.tool_path", return_value="/x/nikto"), \
                patch("builtins.open", mock_open(read_data=payload)):
            items, meta = externals._nikto_tool("https://t.test/", {})
        self.assertEqual(meta["count"], 1)
        self.assertIn("Admin page found", items[0]["evidence"])
        self.assertEqual(items[0]["check"], "server")


class AutopilotTests(unittest.TestCase):
    def setUp(self):
        readiness = patch("spidy.externals.tool_readiness", return_value={"ready": True, "error": ""})
        readiness.start(); self.addCleanup(readiness.stop)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        from spidy.store import Store
        from spidy.scanner import validate_config
        self.store = Store(self.temp.name)
        self.scan = self.store.create(validate_config({"target": "https://t.test/", "authorized": True, "checks": ["headers"]}))
        self.store.update(self.scan["id"], status="completed")

    def test_extract_json_handles_prose_wrapped_objects(self):
        from spidy import agent
        self.assertEqual(agent._extract_json('sure: {"action":"done","reason":"x"} ok')["action"], "done")
        self.assertIsNone(agent._extract_json("no json here"))

    def test_manual_scan_is_memory_for_both_models_and_duplicate_guard(self):
        from spidy import agent
        self.store.append(self.scan["id"], "events", {"type": "deep_scan", "tool": "httpx",
                          "target": "https://t.test/", "added": 0})
        scan = self.store.get(self.scan["id"])
        replies = ["Use httpx again", '{"action":"run","tool":"httpx"}',
                   '{"action":"run","tool":"gau"}']
        with patch("spidy.agent.llm.generate", side_effect=replies) as generate:
            proposal = agent.propose_next(scan, "executor", None, [], guide_model="guide")
        self.assertEqual(proposal["tool"], "gau")
        self.assertEqual(proposal["rejected_repeats"][0]["matched_steps"], ["manual event 1"])
        for call in generate.call_args_list:
            self.assertIn("manual event 1", call.args[1])
        self.assertNotIn("Use httpx again", generate.call_args_list[-1].args[1])
        self.assertNotIn("The junior is stalling", generate.call_args_list[0].args[1])
        self.assertEqual(generate.call_args_list[-1].args[0], "guide")
        self.assertIn("REJECTED DUPLICATE", generate.call_args_list[-1].args[1])
        self.assertEqual(proposal["source"], "guide_repair")
        self.assertNotIn("guidance", proposal, "rejected initial guidance is not shown as current advice")

    def test_guide_correction_is_validated_and_bounded(self):
        from spidy import agent
        history = [{"outcome": "ran", "tool": name} for name in agent.externals.TOOLS]
        reply = '{"action":"run","tool":"wafw00f","reason":"inspect CSP"}'
        with patch("spidy.agent.llm.generate", return_value=reply) as generate, \
                patch("spidy.agent._run_command") as command, patch("spidy.externals.run_tool") as builtin:
            p = agent.propose_next(self.store.get(self.scan["id"]), "executor", None, history, guide_model="guide")
        self.assertEqual(p["action"], "paused")
        self.assertIn("No unused built-in fallback", p["reason"])
        self.assertEqual([c.args[0] for c in generate.call_args_list], ["guide", "executor", "guide", "executor", "executor"])
        self.assertEqual(len(p["planning_attempts"]), agent.MAX_PROPOSAL_ATTEMPTS + 1)
        self.assertIn("REJECTED DUPLICATE", p["planning_attempts"][1]["issue"])
        self.assertNotIn("guidance", p)
        command.assert_not_called()
        builtin.assert_not_called()

    def test_guide_outage_does_not_stop_executor_correction(self):
        from spidy import agent, llm
        replies = ["Use httpx", '{"action":"run","tool":"httpx"}', llm.LLMError("guide offline"),
                   '{"action":"run","command":"printf evidence","reason":"local review"}']
        with patch("spidy.agent.llm.generate", side_effect=replies):
            p = agent.propose_next(self.store.get(self.scan["id"]), "executor", None,
                                   [{"tool": "httpx", "outcome": "ran"}], guide_model="guide")
        self.assertEqual(p["command"], "printf evidence")
        self.assertEqual(p["planning_attempts"][1]["issue"], "guide offline")

    def test_runaway_guide_does_not_poison_executor_retry(self):
        from spidy import agent, llm
        replies = ["Review saved work", '{"action":"run","tool":"ffuf"}',
                   llm.GenerationRejected("Model output repeated the same sequence eight times. Runaway output was stopped and discarded."),
                   '{"action":"run","command":"printf reviewed","reason":"local review"}']
        with patch("spidy.agent.llm.generate", side_effect=replies) as generate, patch("spidy.agent._run_command") as run:
            p = agent.propose_next(self.store.get(self.scan["id"]), "executor", None,
                                   [{"tool":"ffuf","outcome":"ran"}], guide_model="guide")
        self.assertEqual(p["command"], "printf reviewed")
        self.assertIn("Runaway output", generate.call_args.args[1])
        self.assertNotIn("partial output", p["command"])
        self.assertTrue(p["planning_attempts"][1]["proposal"]["generation_rejected"])
        run.assert_not_called()

    def test_runaway_models_stop_without_queuing_a_draft(self):
        from spidy import agent, llm
        history = [{"tool":name,"outcome":"ran"} for name in agent.externals.TOOLS]
        with patch("spidy.agent.llm.generate", side_effect=llm.GenerationRejected("Runaway output was discarded")) as generate:
            p = agent.propose_next(self.store.get(self.scan["id"]), "executor", None, history, guide_model="guide")
        self.assertEqual(p["action"], "paused")
        self.assertNotIn("command", p)
        self.assertEqual(generate.call_count, agent.MAX_PROPOSAL_ATTEMPTS + 2)

    def test_guide_can_prepare_a_command_after_executor_defers_to_manual(self):
        from spidy import agent
        replies = ["Review local tool startup", '{"action":"manual","instructions":"Check curl version","reason":"Check local availability"}',
                   '{"action":"run","command":"curl --version","reason":"Check local availability"}']
        with patch("spidy.agent.llm.generate", side_effect=replies) as generate, patch("spidy.agent._run_command") as run:
            p = agent.propose_next(self.store.get(self.scan["id"]), "executor", None, [], guide_model="guide")
        self.assertEqual(p["source"], "guide_repair")
        self.assertEqual(p["command"], "curl --version")
        self.assertIn("deferred to manual", generate.call_args.args[1])
        run.assert_not_called()

    def test_operator_context_reaches_guide_executor_and_correction_round(self):
        from spidy import agent
        replies = ["Review the recorded headers", '{"action":"run","tool":"ffuf","options":{}}',
                   '{"action":"manual","instructions":"Review owner configuration","reason":"Need owner access"}']
        events = []
        with patch("spidy.agent.llm.generate", side_effect=replies) as generate, patch("spidy.agent._run_command") as run:
            proposal = agent.propose_next(self.store.get(self.scan["id"]), "executor", None,
                [{"tool": "ffuf", "outcome": "ran"}], guide_model="guide",
                guide_context="Focus on cookie configuration; the deployment changed yesterday.",
                progress=lambda field, value: events.append((field, value)))
        self.assertEqual(generate.call_count, 3)
        for call in generate.call_args_list:
            self.assertIn("the deployment changed yesterday", call.args[1])
        self.assertEqual([entry["role"] for entry in proposal["discussion"]],
                         ["user", "guide", "executor", "checks", "guide"])
        self.assertEqual(proposal["discussion"][1]["model"], "guide")
        self.assertTrue(any(field == "discussion" for field, _ in events))
        run.assert_not_called()

    def test_guide_context_is_saved_reused_and_can_be_cleared(self):
        from spidy import agent
        body = {"action": "plan", "model": "local", "guide_context": "Check the saved cookie evidence."}
        with patch("spidy.agent.llm.generate", return_value='{"action":"done","reason":"Review"}') as generate:
            agent.autopilot_action(self.store, self.scan["id"], body)
            self.assertEqual(self.store.get(self.scan["id"])["autopilot"]["guide_context"], body["guide_context"])
            agent.autopilot_action(self.store, self.scan["id"], {"action": "plan"})
            self.assertIn(body["guide_context"], generate.call_args.args[1])
            agent.autopilot_action(self.store, self.scan["id"], {"action": "plan", "guide_context": ""})
            self.assertEqual(self.store.get(self.scan["id"])["autopilot"]["guide_context"], "")
            self.assertNotIn(body["guide_context"], generate.call_args.args[1])
        for invalid in (None, {}, "x" * 4001, "bad\x00context"):
            with self.assertRaisesRegex(ValueError, "4,000"):
                agent.autopilot_action(self.store, self.scan["id"], {"action": "plan", "guide_context": invalid})

    def test_manual_access_followup_survives_unusable_guide_replacements(self):
        from spidy import agent
        history = [{"tool": name, "outcome": "ran"} for name in agent.externals.TOOLS]
        manual = {"action": "manual", "instructions": "Request owner access to the WAF configuration.",
                  "reason": "The configuration is not publicly available."}
        replies = ["Review the saved results", json.dumps(manual)] + ['{"action":"run","tool":"ffuf","options":{}}'] * 3
        with patch("spidy.agent.llm.generate", side_effect=replies) as generate, patch("spidy.agent._run_command") as run:
            proposal = agent.propose_next(self.store.get(self.scan["id"]), "executor", None, history, guide_model="guide")
        self.assertEqual(proposal["action"], "manual")
        self.assertEqual(proposal["instructions"], manual["instructions"])
        self.assertEqual(proposal["source"], "manual_followup")
        self.assertNotIn("command", proposal)
        self.assertIn(manual["instructions"], generate.call_args_list[2].args[1])
        self.assertEqual(len(proposal["rejected_repeats"]), 3)
        run.assert_not_called()

    def test_header_probe_does_not_treat_a_missing_header_as_execution_failure(self):
        from spidy import agent
        p, issue = agent._normalize_reply(json.dumps({"action": "run", "command": "curl -s -I https://t.test/ | grep -i 'Content-Security-Policy'"}))
        self.assertIsNone(issue)
        self.assertEqual(p["command"], "curl --silent --show-error --max-time 20 --head -- https://t.test/")
        self.assertIn("missing header is evidence", p["preparation_note"])
        # Custom request semantics and additional shell commands must never be discarded.
        for command in ["curl -X POST https://t.test/ | grep -i Content-Security-Policy",
                        "curl -I -H 'Cookie: session=example' https://t.test/ | grep -i Content-Security-Policy",
                        "curl -s -I https://t.test/ | grep -i Content-Security-Policy; printf next",
                        "curl -I https://t.test/ | grep -i 'Content-Security-Policy.*'"]:
            self.assertIsNone(agent._prepare_header_probe(command))

    def test_successful_repair_retires_stale_failure_advice(self):
        from spidy import agent
        history = [{"command": "nikto -z https://t.test/", "outcome": "failed"},
                   {"tool": "nikto", "outcome": "ran"}]
        self.assertEqual(agent._failed_commands(history), [])
        history.append({"tool": "nikto", "outcome": "failed", "error": "new failure"})
        failures = agent._failed_commands(history)
        self.assertEqual(len(failures), 1)
        self.assertIn("new failure", failures[0])

    def test_exhausted_scans_switch_to_findings_instead_of_old_command_examples(self):
        from spidy import agent
        history = [{"tool": name, "outcome": "ran"} for name in agent.externals.TOOLS]
        history.append({"command": "nikto -z https://t.test/", "outcome": "failed"})
        scan = self.store.get(self.scan["id"])
        scan["findings"] = [{"id": "f-1", "title": "Cookie attributes need review", "url": "https://t.test/", "severity": "low", "confidence": "high",
                             "evidence": "cookie lacks Secure", "description": "Cookie requires review", "remediation": "Review cookie settings",
                             "verification": "Determine whether this cookie is used for authentication"}]
        with patch("spidy.agent.llm.generate", return_value='{"action":"manual","instructions":"Identify which cookie is a session cookie with the owner","reason":"Assess cookie risk"}') as generate:
            proposal = agent.propose_next(scan, "executor", None, history, guide_model="guide")
        self.assertEqual(proposal["action"], "manual")
        for call in generate.call_args_list:
            self.assertIn("Cookie attributes need review", call.args[1])
            self.assertIn("no unused built-in fallback", call.args[1])
            self.assertNotIn("nikto -z", call.args[1])
            self.assertNotIn("default options", call.args[1])

    def test_compact_planning_keeps_custom_targets_and_observed_header_results(self):
        from spidy import agent
        history = [{"tool": name, "outcome": "ran"} for name in agent.externals.TOOLS]
        history += [
            {"command":"curl --head https://t.test/", "outcome":"ran", "meta":{"exit_code":0,
              "output":"HTTP/2 200\r\nserver: local\r\nset-cookie: secret=private-value;Secure;Path=/\r\n\r\n"}},
            {"command":"curl --head https://t.test/.env.local", "outcome":"ran", "meta":{"exit_code":0,
              "output":"HTTP/2 403\r\nserver: local\r\n\r\n"}}]
        scan = self.store.get(self.scan["id"])
        with patch("spidy.agent.llm.generate", return_value='{"action":"done","reason":"Review saved results"}') as generate:
            agent.propose_next(scan, "executor", None, history, guide_model="guide")
        for call in generate.call_args_list:
            prompt = call.args[1]
            self.assertIn('"http_status": 200', prompt)
            self.assertIn('"http_status": 403', prompt)
            self.assertIn('https://t.test/.env.local', prompt)
            self.assertIn('No enforced Content-Security-Policy', prompt)
            self.assertIn('Secure;Path=/', prompt)
            self.assertNotIn('private-value', prompt)
            self.assertIn('not proof a sensitive file was exposed', prompt)

    def test_truncated_capture_does_not_assert_header_absence(self):
        from spidy import agent
        rows = [{"command":"curl --head https://t.test/", "outcome":"ran",
                 "meta":{"exit_code":0,"output":"HTTP/2 200\r\nserver: local", "output_truncated":True}}]
        result = agent._followup_evidence(rows)[0]
        self.assertFalse(result["headers_complete"])
        self.assertNotIn("observation", result)

    def test_manual_scan_after_planning_blocks_execution(self):
        proposal = self.plan({"action": "run", "tool": "httpx"})
        self.store.append(self.scan["id"], "events", {"type": "deep_scan", "tool": "httpx",
                          "target": "https://t.test/", "options": {}})
        with patch("spidy.externals.run_tool") as execute:
            with self.assertRaisesRegex(ValueError, "manual event"):
                self.decide(proposal, approved=True)
        execute.assert_not_called()

    def test_manual_options_are_respected_and_unknown_legacy_options_not_invented(self):
        from spidy.action_memory import recorded_actions, repeated_steps
        scan = self.store.get(self.scan["id"])
        scan["events"] = [{"type": "deep_scan", "tool": "katana", "target": scan["config"]["target"]}]
        self.assertEqual(repeated_steps({"tool": "katana"}, recorded_actions(scan), scan["config"]["target"]), [])
        scan["events"][0]["options"] = {"depth": "2"}
        self.assertEqual(repeated_steps({"tool": "katana"}, recorded_actions(scan), scan["config"]["target"]), ["manual event 1"])
        self.assertEqual(repeated_steps({"tool": "katana", "options": {"depth": "3"}}, recorded_actions(scan), scan["config"]["target"]), [])

    def test_main_scan_tools_are_recorded_only_when_attempted(self):
        from spidy.action_memory import recorded_actions, repeated_steps
        scan = self.store.get(self.scan["id"])
        scan["events"] = [{"type": "check_skipped", "check": "waf"},
                          {"type": "nuclei_summary", "timed_out": False}]
        self.assertEqual(repeated_steps({"tool": "wafw00f"}, recorded_actions(scan), scan["config"]["target"]), [])
        self.assertEqual(repeated_steps({"tool": "nuclei"}, recorded_actions(scan), scan["config"]["target"]), ["main scan event 2"])

    def test_equivalent_custom_command_and_adapter_share_memory(self):
        from spidy.action_memory import repeated_steps
        history = [{"command": "wafw00f https://t.test/", "outcome": "ran"}]
        self.assertEqual(repeated_steps({"tool": "wafw00f"}, history, "https://t.test/"), [1])
        self.assertEqual(repeated_steps({"tool": "wafw00f"}, history, "https://different.test/"), [])

    def test_auto_approval_is_audited_and_still_single_use(self):
        proposal = self.plan({"action": "run", "command": "printf test"})
        with patch("spidy.agent._run_command", return_value={"exit_code": 0}) as execute:
            self.decide(proposal, approved=True, command="printf test", approval_mode="automatic")
            with self.assertRaisesRegex(ValueError, "no longer pending"):
                self.decide(proposal, approved=True, command="printf test", approval_mode="automatic")
        execute.assert_called_once()
        self.assertEqual(self.store.get(self.scan["id"])["autopilot"]["steps"][0]["approval_mode"], "automatic")

    def test_bare_reason_key_is_recovered_without_changing_command(self):
        from spidy import agent
        command = "printf '{keep:this,exact:text}'"
        reply = 'Please review: {"action":"run","command":' + json.dumps(command) + ',reason:"local check"}'
        proposal, issue = agent._normalize_reply(reply)
        self.assertIsNone(issue)
        self.assertEqual(proposal["command"], command)
        self.assertEqual(proposal["reason"], "local check")

    def test_pasted_ffuf_example_is_repaired_before_approval(self):
        from spidy import agent
        bad = 'Target: https://t.test/\n{"action":"run","command":"ffuf -h https://t.test/ --exts=.html --rate=100",reason:"discover paths"}\nPlease approve.'
        corrected = '{"action":"run","tool":"ffuf","options":{"extensions":".html"},"reason":"discover paths"}'
        with patch("spidy.agent.llm.generate", side_effect=[bad, corrected]) as generate, \
                patch("spidy.agent._run_command") as execute, patch("spidy.externals.run_tool") as builtin:
            proposal = agent.propose_next(self.store.get(self.scan["id"]), "local", None, [])
        self.assertEqual(proposal["tool"], "ffuf")
        self.assertEqual(proposal["options"], {"extensions": ".html"})
        self.assertEqual(generate.call_count, 2)
        self.assertIn("ffuf -h prints help", generate.call_args.args[1])
        execute.assert_not_called()
        builtin.assert_not_called()

    def test_unsuccessful_repair_keeps_reviewable_draft(self):
        from spidy import agent, llm
        with patch("spidy.agent.llm.generate", side_effect=["Investigate the site", llm.LLMError("offline")]):
            proposal = agent.propose_next(self.store.get(self.scan["id"]), "local", None, [])
        self.assertTrue(proposal["needs_preparation"])
        self.assertEqual(proposal["instructions"], "Investigate the site")

    def test_ffuf_scan_without_wordlist_needs_preparation(self):
        from spidy import agent
        draft = {"action": "run", "command": "ffuf -u https://t.test/ -e .html -rate 100"}
        proposal, issue = agent._normalize_reply(json.dumps(draft))
        self.assertTrue(proposal["needs_preparation"])
        self.assertIn("missing a wordlist", issue)
        self.assertIn("tools/wordlists/common.txt", issue)
        help_proposal, issue = agent._normalize_reply('{"action":"run","command":"ffuf -h"}')
        self.assertIsNone(issue)
        self.assertEqual(help_proposal["command"], "ffuf -h")
        no_marker = {"action": "run", "command": "ffuf -u https://t.test/ -w /tmp/words.txt"}
        proposal, issue = agent._normalize_reply(json.dumps(no_marker))
        self.assertIsNone(issue)
        self.assertEqual(proposal["action"], "run")
        self.assertIn("https://t.test/FUZZ", proposal["command"])
        self.assertIn("Added the missing FUZZ", proposal["preparation_note"])
        valid = {"action": "run", "command": "ffuf -u https://t.test/ -H 'X-Test: KEY' -w /tmp/words.txt:KEY"}
        self.assertIsNone(agent._normalize_reply(json.dumps(valid))[1])
        pipeline = {"action": "run", "command": "ffuf -u https://t.test/ -w /tmp/words.txt | tee results.txt"}
        self.assertEqual(agent._normalize_reply(json.dumps(pipeline))[0]["command"], pipeline["command"])

    def test_angle_bracketed_url_is_stripped_so_the_command_runs(self):
        from spidy import agent
        proposal, issue = agent._normalize_reply('{"action":"run","command":"nikto -host <https://t.test/>","reason":"scan"}')
        self.assertIsNone(issue)
        self.assertEqual(proposal["action"], "run")
        self.assertEqual(proposal["command"], "nikto -host https://t.test/")
        self.assertIn("Removed angle brackets", proposal["preparation_note"])
        # A redirection (> file) is legitimate shell syntax and must be left alone.
        self.assertIsNone(agent._normalize_reply('{"action":"run","command":"ffuf -u https://t.test/FUZZ -w /tmp/w > out.txt"}')[1])

    def test_failed_command_triggers_a_repair_directive(self):
        from spidy import agent
        self.assertEqual(agent._repair_directive([]), "")
        self.assertEqual(agent._repair_directive([{"outcome": "ran", "tool": "nuclei", "added": 0}]), "")
        history = [{"outcome": "ran", "command": "nikto -z <https://t.test/>", "meta": {"exit_code": 2, "output": "unknown option -z"}}]
        directive = agent._repair_directive(history)
        self.assertIn("FAILED", directive)
        self.assertIn("nikto -z", directive)
        self.assertIn("Exit code 2", directive)
        self.assertIn("unknown option -z", directive)
        self.assertIn("use -host, not -z", directive)          # correct-usage template for nikto
        self.assertIn('"tool":"nikto"', directive)             # points at the built-in shortcut
        # The repair guidance is embedded in the planning prompt.
        scan = self.store.get(self.scan["id"])
        with patch("spidy.agent.llm.generate", return_value='{"action":"run","tool":"nikto","options":{}}') as generate:
            agent.propose_next(scan, "local", None, history)
        self.assertIn("your last command FAILED", generate.call_args.args[1])

    def test_botched_no_option_tool_command_runs_via_correct_builtin(self):
        from spidy import agent
        # The exact invented-flag commands the executor kept failing on become the correct adapter call.
        for cmd, tool in [("gau --rate=100 --target https://t.test/", "gau"),
                          ("httpx --rate=100 --reason", "httpx"),
                          ("nikto -z https://t.test/", "nikto")]:
            proposal, issue = agent._normalize_reply(json.dumps({"action": "run", "command": cmd, "reason": "x"}))
            self.assertIsNone(issue)
            self.assertEqual(proposal["tool"], tool)
            self.assertEqual(proposal["options"], {})
            self.assertIn("built-in", proposal["preparation_note"])
            self.assertNotIn("command", proposal)  # it is a tool call now, not a raw command
        # A no-option tool run as the correct adapter is NOT blocked as a repeat of the failed raw command.
        from spidy.action_memory import repeated_steps
        failed = [{"outcome": "ran", "command": "gau --rate=100 --target https://t.test/", "meta": {"exit_code": 2}}]
        self.assertEqual(repeated_steps({"tool": "gau", "options": {}}, failed, "https://t.test/"), [])
        # Tools with real options and shell pipelines are left as the author wrote them.
        self.assertEqual(agent._normalize_reply('{"action":"run","command":"nuclei -u https://t.test/ -severity high"}')[0]["command"],
                         "nuclei -u https://t.test/ -severity high")
        self.assertEqual(agent._normalize_reply('{"action":"run","command":"gau t.test | tee out.txt"}')[0]["command"],
                         "gau t.test | tee out.txt")

    def test_tool_option_keys_are_normalized_to_the_adapter_schema(self):
        from spidy import agent, externals
        from spidy.action_memory import repeated_steps
        wl = externals.TOOLS["ffuf"]["options"]["wordlist"]
        # Invented ffuf keys (u/e/w/rate) map to real options; unknown keys and the target are dropped.
        p, _ = agent._normalize_reply(json.dumps({"action": "run", "tool": "ffuf",
                                                   "options": {"u": "https://t.test/FUZZ", "e": ".html,.css", "w": wl, "rate": "1000"}}))
        self.assertEqual(p["options"], {"extensions": ".html,.css", "wordlist": wl})
        # With real option values, an equivalent prior ffuf run is now caught as a repeat.
        hist = [{"outcome": "ran", "tool": "ffuf", "options": {"extensions": ".html,.css"}}]
        self.assertEqual(repeated_steps(p, hist, "https://t.test/"), [1])
        self.assertEqual(agent._normalize_reply('{"action":"run","tool":"nuclei","options":{"sev":"high","bogus":"1"}}')[0]["options"],
                         {"severity": "high"})

    def test_guide_directive_feeds_authoritative_usage_and_failures(self):
        from spidy import agent
        history = [{"outcome": "ran", "command": "gau --rate=100 --target https://t.test/", "meta": {"exit_code": 2, "output": "unknown flag"}}]
        scan = self.store.get(self.scan["id"])
        with patch("spidy.agent.llm.generate", return_value="* use the built-in gau shortcut") as generate:
            directive = agent._guide_directive(scan, "big-guide", None, history)
        prompt = generate.call_args.args[1]
        self.assertIn("AUTHORITATIVE correct command usage", prompt)
        self.assertIn("gau DOMAIN", prompt)                       # correct usage is supplied to the guide
        self.assertIn("ALREADY FAILED", prompt)
        self.assertIn("gau --rate=100 --target", prompt)          # the failed command is named
        self.assertEqual(directive, "* use the built-in gau shortcut")
        # No guide model configured → no guide call, empty directive.
        self.assertEqual(agent._guide_directive(scan, "", None, history), "")

    def test_preparing_pending_draft_does_not_execute_or_reuse_approval(self):
        from spidy import agent
        old = self.plan({"action": "manual", "instructions": "Check local version"})
        with patch("spidy.agent.llm.generate", return_value='{"action":"run","command":"printf version"}'), \
                patch("spidy.agent._run_command") as execute:
            result = agent.autopilot_action(self.store, self.scan["id"], {"action": "repair", "proposal_id": old["id"]})
            execute.assert_not_called()
            new = result["proposal"]
            self.assertNotEqual(new["id"], old["id"])
            with self.assertRaisesRegex(ValueError, "no longer pending"):
                self.decide(old, approved=True, command="printf version")
            with self.assertRaisesRegex(ValueError, "Human approval"):
                self.decide(new, command="printf version")

    def test_nonzero_exit_is_recorded_as_failed(self):
        proposal = self.plan({"action": "run", "command": "exit 7"})
        with patch("spidy.agent._run_command", return_value={"exit_code": 7, "output": "bad arguments"}):
            self.decide(proposal, approved=True, command="exit 7")
        from spidy.progress import assessment_progress
        scan = self.store.get(self.scan["id"])
        self.assertEqual(scan["autopilot"]["steps"][0]["outcome"], "failed")
        self.assertIn("do not treat it as a completed check", assessment_progress(scan))

    def test_working_record_survives_reload_and_reaches_both_model_modes_and_reports(self):
        from spidy import agent, llm
        from spidy.progress import assessment_progress
        steps = [{"outcome": "ran", "command": "bad-old-command", "meta": {"exit_code": 127, "output": "old tool missing"}}]
        steps += [{"outcome": "ran", "tool": "nuclei", "options": {"tags": "none"}, "added": 0} for _ in range(14)]
        steps.append({"outcome": "ran", "tool": "ffuf", "added": 79})
        self.store.update(self.scan["id"], autopilot={"model": "local", "steps": steps})
        scan = Store(self.temp.name).get(self.scan["id"])
        record = assessment_progress(scan)
        self.assertIn("failed — bad-old-command", record)
        self.assertIn("Added 0 finding(s) across 14 run(s)", record)
        self.assertIn("Added 79 finding(s)", record)
        self.assertIn("old tool missing", llm._brief(scan))
        with patch("spidy.agent.llm.generate", return_value='{"action":"done","reason":"review results"}') as generate:
            agent.propose_next(scan, "local", None, steps)
        self.assertIn("old tool missing", generate.call_args.args[1])
        self.assertIn("Added 79 finding(s)", markdown_report(scan))
        self.assertIn(b"Assessment working record", pdf_report(scan))

    def test_repeated_proposals_pause_after_bounded_attempts(self):
        from spidy import agent
        history = [{"outcome": "ran", "tool": "nuclei", "options": {"tags": "misconfig"}, "added": 0}]
        history += [{"outcome": "ran", "tool": name} for name in agent.externals.TOOLS if name != "nuclei"]
        with patch("spidy.agent.llm.generate", return_value='{"action":"run","tool":"nuclei","options":{"tags":"misconfig"}}') as generate:
            proposal = agent.propose_next(self.store.get(self.scan["id"]), "local", None, history)
        self.assertEqual(proposal["action"], "paused")
        self.assertEqual(generate.call_count, agent.MAX_PROPOSAL_ATTEMPTS)
        self.assertEqual(len(proposal["rejected_repeats"]), agent.MAX_PROPOSAL_ATTEMPTS)
        self.assertNotIn("command", proposal)
        self.assertIn("REJECTED DUPLICATE", generate.call_args.args[1])

    def test_duplicate_is_replanned_into_different_work(self):
        from spidy import agent
        command = "ffuf -u https://t.test/FUZZ -e .html -w /tmp/words"
        history = [{"outcome": "ran", "command": command, "meta": {"exit_code": 0}}] * 3
        replies = [json.dumps({"action": "run", "command": command}),
                   '{"action":"run","command":"custom-tls-tool https://t.test/","reason":"new evidence"}']
        with patch("spidy.agent.llm.generate", side_effect=replies) as generate, patch("spidy.agent._run_command") as execute:
            proposal = agent.propose_next(self.store.get(self.scan["id"]), "local", None, history)
        self.assertEqual(proposal["command"], "custom-tls-tool https://t.test/")
        self.assertEqual(proposal["rejected_repeats"][0]["matched_steps"], [1, 2, 3])
        self.assertEqual(generate.call_count, 2)
        execute.assert_not_called()

    def test_duplicate_then_model_failure_never_returns_runnable_duplicate(self):
        from spidy import agent, llm
        history = [{"outcome": "ran", "command": "printf test"}]
        with patch("spidy.agent.llm.generate", side_effect=['{"action":"run","command":"printf test"}', llm.LLMError("offline")]):
            proposal = agent.propose_next(self.store.get(self.scan["id"]), "local", None, history)
        self.assertEqual(proposal["action"], "paused")

    def test_duplicate_followed_by_broken_command_selects_ready_fallback(self):
        from spidy import agent
        history = [{"outcome": "ran", "command": "printf test"}]
        bad = json.dumps({"action": "run", "command": "ffuf --exts=.html --reason:review site's files"})
        replies = ['{"action":"run","command":"printf test"}', bad, bad]
        with patch("spidy.agent.llm.generate", side_effect=replies):
            proposal = agent.propose_next(self.store.get(self.scan["id"]), "local", None, history)
        self.assertEqual(proposal["action"], "run")
        self.assertEqual(proposal["source"], "validated_fallback")
        self.assertNotIn("command", proposal)

    def test_missing_dependency_diagnosis_does_not_recommend_scan_flags(self):
        from spidy import agent
        step = {"outcome": "failed", "command": "nikto -host https://t.test/",
                "meta": {"exit_code": 1, "output": "ERROR: Required module not found: XML::Writer"}}
        directive = agent._repair_directive([step])
        self.assertIn("Missing local dependency", directive)
        self.assertNotIn("Correct usage", directive)
        self.assertNotIn("Simplest reliable fix", directive)
        failures = "\n".join(agent._failed_commands([step]))
        self.assertIn("XML::Writer", failures)
        self.assertNotIn("correct usage", failures)
        proposal, issue = agent._normalize_reply('{"action":"run","command":"nikto -Version"}')
        self.assertIsNone(issue)
        self.assertEqual(proposal["command"], "nikto -Version", "local startup checks must not become target scans")

    def test_blocked_tool_is_replaced_with_ready_untried_fallback(self):
        from spidy import agent
        def readiness(name):
            return {"ready": name == "gau", "error": "Missing XML::Writer" if name == "nikto" else "not installed"}
        with patch("spidy.externals.tool_readiness", side_effect=readiness), \
                patch("spidy.agent.llm.generate", return_value='{"action":"run","tool":"nikto"}') as generate:
            proposal = agent.propose_next(self.store.get(self.scan["id"]), "local", None, [])
        self.assertEqual(proposal["tool"], "gau")
        self.assertEqual(proposal["source"], "validated_fallback")
        self.assertEqual(generate.call_count, agent.MAX_PROPOSAL_ATTEMPTS)
        self.assertIn("Missing XML::Writer", generate.call_args.args[1])

    def test_placeholder_nuclei_tags_cannot_be_queued_or_executed(self):
        from spidy import agent, externals
        history = [{"outcome": "ran", "tool": name} for name in externals.TOOLS if name != "gau"]
        with patch("spidy.agent.llm.generate", return_value='{"action":"run","tool":"nuclei","options":{"tags":"none"}}'):
            proposal = agent.propose_next(self.store.get(self.scan["id"]), "local", None, history)
        self.assertEqual(proposal["tool"], "gau")
        self.assertIn("literal tag", proposal["rejected_invalid"][0])
        valid = self.plan({"action": "run", "tool": "nuclei", "options": {"tags": ""}})
        with patch("spidy.externals.run_tool") as run:
            with self.assertRaisesRegex(externals.ToolError, "literal tag"):
                self.decide(valid, approved=True, options={"tags": "none"})
        run.assert_not_called()

    def test_fallback_does_not_rerun_completed_or_declined_tools(self):
        from spidy import agent
        readiness = {name: {"ready": True} for name in agent.externals.TOOLS}
        history = [{"outcome": "skipped", "tool": name} for name in agent.externals.TOOLS]
        self.assertEqual(agent._ready_candidates(self.store.get(self.scan["id"]), history, readiness), [])

    def test_ffuf_reordering_and_rate_changes_do_not_repeat_same_work(self):
        from spidy.action_memory import repeated_steps
        history = [{"outcome": "ran", "command": "ffuf -u https://t.test/FUZZ -e .html,.css -w /tmp/words"}]
        proposal = {"command": "ffuf  -w '/tmp/words' -e .css,.html -rate 20 -u 'https://t.test/FUZZ'"}
        self.assertEqual(repeated_steps(proposal, history, "https://t.test/"), [1])
        proposal["command"] += " -H 'X-Test: 1'"
        self.assertEqual(repeated_steps(proposal, history, "https://t.test/"), [])
        proposal["command"] = "ffuf -u https://other.test/FUZZ -e .html,.css -w /tmp/words"
        self.assertEqual(repeated_steps(proposal, history, "https://t.test/"), [])

    def test_curl_presentation_flags_do_not_evade_completed_header_request(self):
        from spidy.action_memory import repeated_steps
        history = [{"outcome":"ran", "command":"curl --silent --show-error --max-time 20 --head -- https://t.test/.env.local"}]
        for command in ("curl -s -I https://t.test/.env.local", "curl -IsS --max-time=30 https://t.test/.env.local",
                        "curl --url https://t.test/.env.local --head", "/usr/bin/curl -I -m10 https://t.test/.env.local"):
            self.assertEqual(repeated_steps({"command":command}, history, "https://t.test/"), [1])
        for command in ("curl -s https://t.test/.env.local", "curl -I https://t.test/other", "curl -IL https://t.test/.env.local",
                        "curl -I -H 'Accept: application/json' https://t.test/.env.local",
                        "curl -I https://t.test/.env.local > saved-headers.txt"):
            self.assertEqual(repeated_steps({"command":command}, history, "https://t.test/"), [])

    def test_automatic_approval_cannot_run_shortened_completed_curl_command(self):
        from spidy import agent
        p = self.plan({"action":"run", "command":"curl -s -I https://t.test/"})
        state = self.store.get(self.scan["id"])["autopilot"]
        state["steps"].append({"outcome":"ran", "command":"curl --silent --show-error --max-time 20 --head -- https://t.test/"})
        self.store.update(self.scan["id"], autopilot=state)
        with patch("spidy.agent._run_command") as run:
            with self.assertRaisesRegex(ValueError, "already attempted"):
                self.decide(p, approved=True, command=p["command"], approval_mode="automatic")
        run.assert_not_called()

    def test_duplicates_include_skips_failures_and_default_builtin_options(self):
        from spidy.action_memory import repeated_steps
        for outcome in ("ran", "skipped", "failed", "error", "timed_out", "stopped"):
            history = [{"outcome": outcome, "tool": "nuclei", "options": {}}]
            self.assertEqual(repeated_steps({"tool": "nuclei", "options": {"rate": "15", "ignored": "value"}}, history, "https://t.test/"), [1])
        self.assertEqual(repeated_steps({"command": "printf 'same'"}, [{"outcome": "ran", "command": "printf   same"}], ""), [1])
        self.assertEqual(repeated_steps({"command": "echo '$VAR'"}, [{"outcome": "ran", "command": 'echo "$VAR"'}], ""), [])

    def test_rate_only_change_does_not_escape_repeat_guard(self):
        from spidy.action_memory import repeated_steps
        hist = [{"outcome": "ran", "tool": "nuclei", "options": {"rate": "1000", "severity": "low", "tags": "none"}}]
        # Changing only throughput is the same scan.
        self.assertEqual(repeated_steps({"tool": "nuclei", "options": {"rate": "100", "severity": "low", "tags": "none"}}, hist, "https://t.test/"), [1])
        # A different scope (severity) is genuinely new work.
        self.assertEqual(repeated_steps({"tool": "nuclei", "options": {"rate": "100", "severity": "critical", "tags": "none"}}, hist, "https://t.test/"), [])

    def test_builtin_ffuf_matches_equivalent_custom_command(self):
        from spidy.action_memory import repeated_steps
        from spidy import externals
        wordlist = externals.TOOLS["ffuf"]["options"]["wordlist"]
        cmd = f"ffuf -u https://t.test/FUZZ -e .html,.css -w {wordlist}"
        hist = [{"outcome": "ran", "command": cmd}]
        # The built-in shortcut and a hand-typed command for the same discovery are one task,
        # despite differing default -mc filters and -rate.
        self.assertEqual(repeated_steps({"tool": "ffuf", "options": {"rate": "100", "extensions": ".html,.css"}}, hist,
                                        "https://t.test/"), [1])

    def test_stale_pending_duplicate_is_blocked_at_execution(self):
        proposal = self.plan({"action": "run", "command": "printf test"})
        state = self.store.get(self.scan["id"])["autopilot"]
        state["steps"] = [{"outcome": "ran", "command": "printf test", "meta": {"exit_code": 0}}]
        self.store.update(self.scan["id"], autopilot=state)
        with patch("spidy.agent._run_command") as execute:
            with self.assertRaisesRegex(ValueError, "already attempted"):
                self.decide(proposal, approved=True, command="printf test")
        execute.assert_not_called()
        saved = self.store.get(self.scan["id"])["autopilot"]
        self.assertEqual(len(saved["steps"]), 1)
        self.assertEqual(saved["proposal"]["action"], "paused")

    def test_edited_command_cannot_bypass_repeat_guard(self):
        proposal = self.plan({"action": "run", "command": "printf different"})
        state = self.store.get(self.scan["id"])["autopilot"]
        state["steps"] = [{"outcome": "ran", "command": "printf old"}]
        self.store.update(self.scan["id"], autopilot=state)
        with patch("spidy.agent._run_command") as execute:
            with self.assertRaisesRegex(ValueError, "already attempted"):
                self.decide(proposal, approved=True, command="printf old")
        execute.assert_not_called()

    def plan(self, reply):
        from spidy import agent
        with patch("spidy.agent.llm.generate", return_value=json.dumps(reply)):
            return agent.autopilot_action(self.store, self.scan["id"], {"action": "plan", "model": "local"})["proposal"]

    def decide(self, proposal, **body):
        from spidy import agent
        return agent.autopilot_action(self.store, self.scan["id"], {"action": "run", "proposal_id": proposal["id"], **body})

    def test_legacy_autopilot_only_proposes(self):
        from spidy import agent
        with patch("spidy.agent.llm.generate", return_value='{"action":"run","tool":"httpx"}'), \
                patch("spidy.agent.externals.run_tool") as run_tool, patch("spidy.agent._run_command") as command:
            result = agent.run_autopilot(self.store, self.scan["id"], "local")
        run_tool.assert_not_called()
        command.assert_not_called()
        self.assertEqual(result["proposal"]["tool"], "httpx")
        self.assertEqual(result["history"], [])

    def test_unknown_tool_remains_reviewable(self):
        proposal = self.plan({"action": "run", "tool": "custom-analyzer", "reason": "investigate"})
        self.assertEqual(proposal["action"], "run")
        self.assertEqual(proposal["tool"], "custom-analyzer")
        with self.assertRaisesRegex(ValueError, "complete command"):
            self.decide(proposal, approved=True)

    def test_json_parser_preserves_braces_inside_commands(self):
        from spidy import agent
        action = {"action": "run", "command": "printf 'unmatched { and escaped \" quote'"}
        self.assertEqual(agent._extract_json("```json\n" + json.dumps(action) + "\n```"), action)

    def test_free_text_response_is_reviewable_and_never_executed(self):
        from spidy import agent
        with patch("spidy.agent.llm.generate", return_value="Inspect the session flow manually."), \
                patch("spidy.agent._run_command") as command:
            result = agent.propose_next(self.store.get(self.scan["id"]), "local", None, [])
        command.assert_not_called()
        self.assertEqual(result["action"], "manual")
        self.assertIn("session flow", result["instructions"])

    def test_model_cannot_self_approve(self):
        from spidy import agent
        with patch("spidy.agent._run_command") as command:
            proposal = self.plan({"action": "run", "command": "printf test", "approved": True})
            with self.assertRaisesRegex(ValueError, "Human approval"):
                self.decide(proposal, command="printf test")
        command.assert_not_called()
        self.assertNotIn("approved", proposal)

    def test_both_model_modes_send_permission_rules_without_executing_output(self):
        from spidy import agent, llm
        reply = '{"action":"run","command":"custom-tool --inspect https://t.test/"}'
        with patch("spidy.llm._request", return_value={"response": reply}) as request, \
                patch("spidy.llm._generate_stream", return_value=reply) as stream, \
                patch("spidy.agent._run_command") as command, patch("spidy.externals.run_tool") as tool:
            proposal = agent.propose_next(self.store.get(self.scan["id"]), "local", None, [])
            analysis = llm.analyze_scan(self.store.get(self.scan["id"]), "local")
        self.assertEqual(proposal["command"], "custom-tool --inspect https://t.test/")
        self.assertEqual(analysis["text"], reply)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(stream.call_args.args[1]["format"], agent.PROPOSAL_SCHEMA)
        self.assertTrue(stream.call_args.args[1]["stream"])
        self.assertIs(stream.call_args.args[3], agent._guard_proposal_output)
        self.assertNotIn("format", request.call_args.args[2])
        self.assertFalse(request.call_args.args[2]["stream"])
        for payload in (stream.call_args.args[1], request.call_args.args[2]):
            self.assertIn(llm.PROPOSAL_RULES, payload["system"])
            self.assertEqual(payload["options"]["num_ctx"], 16384)
        command.assert_not_called()
        tool.assert_not_called()

    def test_previous_approval_does_not_authorize_the_next_action(self):
        first = self.plan({"action": "run", "command": "printf first"})
        with patch("spidy.agent._run_command", return_value={"output": "first", "exit_code": 0}) as command:
            self.decide(first, approved=True, command="printf first")
            second = self.plan({"action": "run", "command": "printf second", "approved": True})
            with self.assertRaisesRegex(ValueError, "Human approval"):
                self.decide(second, command="printf second")
            command.assert_called_once_with("printf first")
        self.assertEqual(self.store.get(self.scan["id"])["autopilot"]["proposal"]["id"], second["id"])

    def test_direct_step_requires_explicit_approval(self):
        from spidy import agent, externals
        with patch("spidy.agent._run_command") as command, patch("spidy.externals.run_tool") as builtin:
            for approval in (False, None, "true", 1):
                with self.assertRaises(externals.ToolError):
                    agent.run_step(self.store, self.scan["id"], command="printf test", approved=approval)
            with self.assertRaises(externals.ToolError):
                agent.run_step(self.store, self.scan["id"], "httpx", {})
        command.assert_not_called()
        builtin.assert_not_called()

    def test_edited_command_runs_exactly_once_and_persists_output(self):
        from spidy import agent
        proposal = self.plan({"action": "run", "command": "printf original"})
        result = self.decide(proposal, approved=True, command="printf 'reviewed {output}'")
        self.assertEqual(result["meta"]["output"], "reviewed {output}")
        self.assertEqual(result["meta"]["exit_code"], 0)
        self.assertEqual(result["added"], 0)
        with patch("spidy.agent._run_command") as command:
            with self.assertRaisesRegex(ValueError, "no longer pending"):
                self.decide(proposal, approved=True, command="printf duplicate")
        command.assert_not_called()
        state = self.store.get(self.scan["id"])["autopilot"]
        self.assertIsNone(state["proposal"])
        self.assertEqual(state["steps"][0]["command"], "printf 'reviewed {output}'")
        self.assertIn("approved_at", state["steps"][0])
        reloaded = Store(self.temp.name).get(self.scan["id"])
        self.assertEqual(reloaded["autopilot"], state)

    def test_stale_skipped_and_stopped_proposals_cannot_run(self):
        from spidy import agent
        old = self.plan({"action": "run", "command": "printf old"})
        new = self.plan({"action": "run", "command": "printf new"})
        with self.assertRaisesRegex(ValueError, "no longer pending"):
            self.decide(old, approved=True, command="printf old")
        for action in ("skip", "stop"):
            agent.autopilot_action(self.store, self.scan["id"], {"action": action, "proposal_id": new["id"]})
            with self.assertRaisesRegex(ValueError, "no longer pending"):
                self.decide(new, approved=True, command="printf new")
            new = self.plan({"action": "run", "command": "printf new"})

    def test_failed_execution_consumes_approval_and_records_error(self):
        from spidy import externals
        proposal = self.plan({"action": "run", "command": "printf test"})
        with patch("spidy.agent._run_command", side_effect=externals.ToolError("cannot start")):
            with self.assertRaises(externals.ToolError):
                self.decide(proposal, approved=True, command="printf test")
        state = self.store.get(self.scan["id"])["autopilot"]
        self.assertIsNone(state["proposal"])
        self.assertEqual(state["steps"][0]["outcome"], "error")
        self.assertEqual(state["steps"][0]["error"], "cannot start")

    def test_builtin_shortcut_retains_findings(self):
        proposal = self.plan({"action": "run", "tool": "httpx"})
        with patch("spidy.externals.run_tool", return_value=([{"title": "T", "severity": "info", "confidence": "medium",
                   "evidence": "e", "description": "d", "remediation": "r", "reference": "", "check": "server"}], {})) as run_tool:
            result = self.decide(proposal, approved=True, options={})
        self.assertEqual(result["added"], 1)
        self.assertEqual(run_tool.call_args.args, ("httpx", "https://t.test/", {}))

    def test_manual_proposal_can_be_edited_into_a_command(self):
        proposal = self.plan({"action": "manual", "instructions": "Inspect the result"})
        result = self.decide(proposal, approved=True, command="printf manual")
        self.assertEqual(result["meta"]["output"], "manual")

    def test_invalid_commands_do_not_consume_approval(self):
        proposal = self.plan({"action": "run", "command": "printf test"})
        for command in ("", "   ", None, [], "bad\x00command"):
            with self.assertRaises(ValueError):
                self.decide(proposal, approved=True, command=command)
        self.assertEqual(self.store.get(self.scan["id"])["autopilot"]["proposal"], proposal)

    def test_output_exit_status_truncation_and_timeout(self):
        from spidy import agent
        meta = agent._run_command("printf failure >&2; exit 7")
        self.assertEqual(meta["exit_code"], 7)
        self.assertEqual(meta["output"], "failure")
        with patch("spidy.agent.OUTPUT_LIMIT", 4):
            meta = agent._run_command("printf abcdef")
        self.assertTrue(meta["output_truncated"])
        self.assertEqual(meta["output"], "abcd")
        with patch("spidy.agent.COMMAND_TIMEOUT", 0.05):
            meta = agent._run_command("printf started; sleep 5")
        self.assertTrue(meta["timed_out"])
        self.assertEqual(meta["output"], "started")

    def test_recent_results_and_skips_are_in_model_context(self):
        from spidy import agent
        history = [{"outcome": "ran", "command": "printf first", "meta": {"output": "some evidence", "output_tail": "UI_ONLY_TAIL", "exit_code": 0}},
                   {"outcome": "skipped", "tool": "httpx", "options": {"foo": "bar"}}]
        with patch("spidy.agent.llm.generate", return_value='{"action":"done","reason":"enough"}') as generate:
            agent.propose_next(self.store.get(self.scan["id"]), "local", None, history)
        prompt = generate.call_args.args[1]
        self.assertIn("some evidence", prompt)
        self.assertNotIn("UI_ONLY_TAIL", prompt)
        self.assertIn('"skipped"', prompt)
        self.assertIn("not a limit on proposals", prompt)


class HostInventoryTests(unittest.TestCase):
    def test_collection_reads_names_only_and_round_trips(self):
        with tempfile.TemporaryDirectory() as temp:
            for pid, name in ((1, "systemd"), (42, "nginx")):
                process = Path(temp, str(pid))
                process.mkdir()
                (process / "comm").write_text(name + "\n")
                (process / "cmdline").write_text("nginx\x00--password=NEVER_COLLECT")
                (process / "environ").write_text("SECRET=NEVER_COLLECT")
            Path(temp, "self").mkdir()
            collected = collect_host("https://Example.test/", proc_root=temp, include_packages=False)
        self.assertEqual([p["name"] for p in collected["processes"]], ["systemd", "nginx"])
        self.assertNotIn("NEVER_COLLECT", json.dumps(collected))
        validated = validate_host_inventory(json.loads(json.dumps(collected)), "https://example.test/login")
        self.assertEqual(validated["status"], "owner_supplied")
        self.assertEqual(len(validated["processes"]), 2)

    def test_import_rejects_other_hosts_and_malformed_documents(self):
        good = {"format": "spidy-host-inventory-v1", "target_host": "example.test", "collected_at": "2026-10-11T00:00:00+00:00"}
        for bad in ({**good, "target_host": "other.test"}, {**good, "format": "x"}, {**good, "collected_at": "yesterday"},
                    {**good, "processes": [{"pid": "1"}]}, {**good, "processes": [{"pid": 1, "name": "a" * 500}]},
                    {**good, "packages": [{}] * 2001}, []):
            with self.subTest(bad=str(bad)[:60]), self.assertRaises(ValueError):
                validate_host_inventory(bad, "example.test")


class EndToEndTests(ScannerCase):
    def test_scan_reports_inventory_in_every_format(self):
        class Handler(BaseHTTPRequestHandler):
            server_version, sys_version = "nginx/1.18.0", ""
            def log_message(self, *_):
                pass
            def do_GET(self):
                # Most real servers send Content-Length; the transport must read such bodies.
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", "16")
                self.end_headers()
                self.wfile.write(b"<h1>Fixture</h1>")
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_port
        scanner = self.scanner(f"http://127.0.0.1:{port}/", custom_ports=[port])
        result = scanner.run()
        self.assertEqual(result["status"], "completed")
        service = next(s for s in result["inventory"]["services"] if s["port"] == port)
        self.assertEqual((service["state"], service["product"], service["version"], service["service_verified"]), ("open", "nginx", "1.18.0", True))
        self.assertEqual(result["coverage"]["open_services"], 1)
        self.assertEqual(result["coverage"]["software_versions_identified"], 1)
        self.assertEqual(result["coverage"]["network_errors"], 0)
        self.assertEqual(len(result["inventory"]["technologies"]), 1)
        self.assertIn("1 open service(s)", result["summary"])
        report = markdown_report(result)
        self.assertIn("## Services and software found", report)
        self.assertIn("nginx 1.18.0", report)
        pdf = pdf_report(result)
        self.assertIn(f"127.0.0.1:{port} | open | http".encode(), pdf)
        self.assertIn(b"nginx / 1.18.0", pdf)


if __name__ == "__main__":
    unittest.main()
