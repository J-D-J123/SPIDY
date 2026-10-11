import http.client
import json
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from spidy.scanner import Scanner, focus_checks, validate_config
from spidy.scope import Scope, ScopeError, normalize_url, origin
from spidy.server import ScanManager, create_server
from spidy.store import Store, markdown_report
from spidy.transport import Response, Transport


class ScopeTests(unittest.TestCase):
    def test_normalizes_target(self):
        self.assertEqual(normalize_url("EXAMPLE.com."), "https://example.com/")
        self.assertEqual(normalize_url("https://example.com:443/x#frag"), "https://example.com/x")
        self.assertEqual(normalize_url("http://[::1]:8080/"), "http://[::1]:8080/")

    def test_rejects_bad_urls(self):
        for url in ("", "https://u:p@example.com", "https://example.com\\@evil.com", "ftp://example.com", "http://example.com:0", "https://example.com/\nhello", "http://[fe80::1%eth0]/", "https://example.com:65536"):
            with self.subTest(url=url), self.assertRaises(ScopeError):
                normalize_url(url)

    def test_exact_scope_no_implicit_subdomains(self):
        scope = Scope("example.com")
        self.assertTrue(scope.permits("http://example.com/path"))
        for url in ("https://www.example.com", "https://example.com.evil.net", "https://example.com:8443", "https://evil.com"):
            self.assertFalse(scope.permits(url))

    def test_explicit_origin_does_not_expand_to_sibling_scheme(self):
        scope = Scope("example.com", ["https://cdn.example.net:8443"])
        self.assertTrue(scope.permits("https://cdn.example.net:8443/a"))
        self.assertFalse(scope.permits("http://cdn.example.net:8443/a"))

    def test_no_dns_for_out_of_scope(self):
        with patch("spidy.scope.socket.getaddrinfo") as dns:
            with self.assertRaises(ScopeError):
                Scope("example.com").resolve("https://third-party.test")
            dns.assert_not_called()

    def test_private_mixed_and_mapped_answers_blocked(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1"):
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                       (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]
            with self.subTest(address=address), patch("spidy.scope.socket.getaddrinfo", return_value=answers):
                with self.assertRaises(ScopeError):
                    Scope("example.com").resolve("https://example.com")


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hits, cls.external_hits = [], []
        owner = cls

        class Outside(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                owner.external_hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>Outside origin</h1>")

        cls.outside = ThreadingHTTPServer(("127.0.0.1", 0), Outside)
        cls.external = f"http://127.0.0.1:{cls.outside.server_port}"

        class Target(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                owner.hits.append(self.path)
                p = urlsplit(self.path)
                q = parse_qs(p.query).get("q", [""])[0]
                if p.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", owner.external + "/redirected")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", "session=NEVER_LOG_THIS_COOKIE; Path=/")
                self.end_headers()
                if p.path == "/query":
                    body = "SQLSTATE[42000]: syntax error" if "'" in q else f"<h1>{q}</h1>"
                elif p.path == "/base":
                    body = f'<base href="{owner.external}/"><a href="base-link">Outside</a>'
                elif p.path == "/clean":
                    body = "<p>No input surface here</p>"
                else:
                    body = f'''<a href="/query?q=hello">Query</a><a href="/redirect">Redirect</a>
                    <a href="{owner.external}/third-party">Outside</a><img src="{owner.external}/image.png">
                    <a href="/logout">Do not follow</a><form action="/update" method="post"><input name="name"></form>
                    <form action="/login" method="get"><input name="password" type="password"></form>'''
                self.wfile.write(body.encode())

        cls.target_server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        cls.target = f"http://127.0.0.1:{cls.target_server.server_port}"
        for server in (cls.target_server, cls.outside):
            threading.Thread(target=server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.target_server, cls.outside):
            server.shutdown()
            server.server_close()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.hits.clear()
        self.external_hits.clear()

    def scanner(self, path="/", **kwargs):
        # The inventory would probe whatever else listens on this machine; it has its own tests.
        config = validate_config({"target": self.target + path, "authorized": True, "inventory": False, "advisory_lookup": False,
            "use_nmap": False, "checks": ["headers", "forms", "server", "sqli", "reflection"], **kwargs})
        scan = self.store.create(config)
        scanner = Scanner(self.store, scan["id"], allow_private=True)
        scanner.transport.delay = 0
        return scanner

    def test_active_signals_and_scope(self):
        result = self.scanner(active=True).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("SQL injection" in t for t in titles))
        self.assertIn("Unescaped HTML input reflection", titles)
        self.assertIn("Password form uses an unsafe transport or method", titles)
        self.assertEqual(result["pending_origins"][0]["origin"], self.external)
        self.assertEqual(self.external_hits, [])
        self.assertNotIn("/logout", self.hits)
        self.assertFalse(any(h.startswith("/login") or h.startswith("/update") for h in self.hits))
        self.assertNotIn("NEVER_LOG_THIS_COOKIE", json.dumps(result))
        self.assertEqual(result["status"], "completed")

    def test_origin_level_findings_are_deduped_across_pages(self):
        result = self.scanner(active=False).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertGreaterEqual(result["coverage"]["pages_received"], 2)
        # The same header/cookie issue on every page collapses to one finding per origin.
        self.assertEqual(titles.count("Missing or ineffective X-Content-Type-Options"), 1)
        self.assertEqual(titles.count("Cookie attributes need review"), 1)

    def test_passive_mode_sends_no_payloads(self):
        result = self.scanner(active=False).run()
        self.assertEqual(result["coverage"]["input_probes"], 0)
        self.assertFalse(any("%27" in h or "spidy-probe" in h for h in self.hits))

    def test_redirect_never_contacts_outside(self):
        result = self.scanner("/redirect").run()
        self.assertEqual(self.external_hits, [])
        self.assertEqual(result["coverage"]["http_attempts"], 1)
        self.assertEqual(len(result["pending_origins"]), 1)

    def test_external_base_is_respected_but_blocked(self):
        result = self.scanner("/base").run()
        self.assertEqual(result["pending_origins"][0]["url"], self.external + "/base-link")
        self.assertEqual(self.external_hits, [])

    def test_request_budget_hard_limit(self):
        result = self.scanner(active=True, max_requests=2).run()
        self.assertEqual(result["coverage"]["http_attempts"], 2)
        self.assertEqual(len(self.hits), 2)
        self.assertEqual(result["status"], "partial")

    def test_page_limit(self):
        result = self.scanner(max_pages=1).run()
        self.assertEqual(result["coverage"]["pages_received"], 1)
        self.assertTrue(result["coverage"]["crawl_limit_reached"])

    def test_cancellation_prevents_requests(self):
        scanner = self.scanner()
        scanner.stop.set()
        result = scanner.run()
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(self.hits, [])

    def test_failed_scan_summary_names_the_first_error(self):
        result = self.scanner("/clean", max_requests=5).run()
        # Sanity: a healthy scan should not carry an error note.
        self.assertNotIn("First error encountered", result["summary"])

    def test_default_private_address_block(self):
        scanner = self.scanner()
        scanner.scope.allow_private = False
        result = scanner.run()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.hits, [])

    def test_transport_resolves_once_and_ignores_proxy_environment(self):
        scope = Scope(self.target, allow_private=True)
        with patch.object(scope, "resolve", wraps=scope.resolve) as resolver, patch.dict("os.environ", {"HTTP_PROXY": self.external}):
            response = Transport(scope, lambda *a, **k: None, lambda: False, delay=0).get(self.target + "/clean", "Test")
        self.assertEqual(response.status, 200)
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(self.external_hits, [])

    def test_approval_starts_followup_and_preserves_parent(self):
        result = self.scanner("/redirect").run()
        manager = ScanManager(self.store, allow_private=True)
        followup = manager.decide(result["id"], {"approve": [self.external], "authorized": True})
        manager.worker.join(timeout=10)
        self.assertFalse(manager.worker.is_alive())
        child = self.store.get(followup["id"])
        self.assertEqual(child["parent_id"], result["id"])
        self.assertIn(self.external, child["approved_origins"])
        # The follow-up records exactly which origin it was approved for, for grouping under the root.
        self.assertEqual(child["added_origins"], [self.external])
        listed = {row["id"]: row for row in self.store.list()}
        self.assertEqual(listed[child["id"]]["parent_id"], result["id"])
        self.assertEqual(listed[child["id"]]["added_origins"], [self.external])
        self.assertIsNone(listed[result["id"]]["parent_id"])
        self.assertTrue(self.external_hits)
        self.assertEqual(self.store.get(result["id"])["pending_origins"][0]["decision"], "approved")

    def test_denial_does_not_start_network_work(self):
        result = self.scanner("/redirect").run()
        manager = ScanManager(self.store, allow_private=True)
        decided = manager.decide(result["id"], {"deny": [self.external]})
        self.assertEqual(decided["pending_origins"][0]["decision"], "denied")
        self.assertIsNone(manager.worker)
        self.assertEqual(self.external_hits, [])

    def test_cannot_approve_undiscovered_origin_or_without_permission(self):
        result = self.scanner("/redirect").run()
        manager = ScanManager(self.store, allow_private=True)
        for body in ({"approve": ["https://arbitrary.example"], "authorized": True}, {"approve": [self.external]}):
            with self.assertRaises(ValueError):
                manager.decide(result["id"], body)
        self.assertEqual(self.external_hits, [])

    def test_report_and_restart_persistence(self):
        result = self.scanner("/clean").run()
        report = markdown_report(result)
        self.assertIn("## Activity log", report)
        self.assertIn("## Limitations", report)
        self.assertNotIn("NEVER_LOG_THIS_COOKIE", report)
        reopened = Store(self.temp.name)
        self.assertEqual(reopened.get(result["id"])["findings"], result["findings"])

    def test_restart_marks_running_scan_interrupted(self):
        scanner = self.scanner()
        self.store.update(scanner.id, status="running")
        self.assertEqual(Store(self.temp.name).get(scanner.id)["status"], "interrupted")

    def test_baseline_database_error_is_not_new_signal(self):
        scanner = self.scanner(active=True)
        response = Response(self.target + "/query?q=x", 200, [("Content-Type", "text/html")], "SQLSTATE[42000]: old error")
        with patch.object(scanner, "get", return_value=response):
            scanner.probe(response.url)
        self.assertFalse(any("SQL injection" in f["title"] for f in self.store.get(scanner.id)["findings"]))

    def test_denied_origins_remain_denied_in_followup(self):
        scanner = self.scanner()
        self.store.update(scanner.id, denied_origins=[self.external])
        scanner = Scanner(self.store, scanner.id, allow_private=True)
        scanner.transport.delay = 0
        result = scanner.run()
        self.assertEqual(result["pending_origins"][0]["decision"], "denied")
        self.assertEqual(result["coverage"]["pending_origins"], 0)
        self.assertEqual(self.external_hits, [])

    def test_tls_verification_error_is_reported_without_retry(self):
        import ssl
        scanner = self.scanner()
        with patch.object(scanner.transport, "get", side_effect=ssl.SSLCertVerificationError("Certificate expired")) as request:
            self.assertIsNone(scanner.get(self.target, "TLS test"))
        self.assertEqual(request.call_count, 1)
        self.assertIn("TLS certificate validation failed", [f["title"] for f in self.store.get(scanner.id)["findings"]])


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.server = create_server(self.store, port=0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_port
        self.token = self.request("GET", "/api/config")[1]["token"]

    def tearDown(self):
        if self.server.manager.stop:
            self.server.manager.stop.set()
        if self.server.manager.worker:
            self.server.manager.worker.join(timeout=6)
        self.server.shutdown()
        self.server.server_close()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        h = {"Content-Type": "application/json", **(headers or {})}
        conn.request(method, path, json.dumps(body) if body is not None else None, h)
        response = conn.getresponse()
        data = response.read()
        status = response.status
        conn.close()
        try:
            data = json.loads(data)
        except ValueError:
            data = data.decode()
        return status, data

    def _await_autopilot(self, scan_id, timeout=5):
        """Planning and execution run in the background; wait for the task marker to settle."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.store.get(scan_id).get("autopilot") or {}
            task = state.get("task")
            if not task or task.get("status") != "running":
                return state
            time.sleep(0.01)
        self.fail("autopilot task did not settle in time")

    def test_autopilot_api_requires_session_approval_and_single_use_proposal(self):
        scan = self.store.create(validate_config({"target": "https://example.test/", "authorized": True}))
        self.store.update(scan["id"], status="completed")
        path = f"/api/scans/{scan['id']}/autopilot"
        headers = {"X-Spidy-Token": self.token}
        with patch("spidy.agent.llm.generate", return_value='{"action":"run","command":"printf proposed"}'), \
                patch("spidy.agent._run_command", return_value={"output": "edited", "exit_code": 0}) as execute:
            status, planned = self.request("POST", path, {"action": "plan", "model": "local"}, headers)
            self.assertEqual(status, 200)
            self.assertEqual(planned["status"], "working")
            proposal_id = self._await_autopilot(scan["id"])["proposal"]["id"]
            execute.assert_not_called()
            # A run without approval is accepted for processing but fails in the background.
            body = {"action": "run", "proposal_id": proposal_id, "command": "printf edited"}
            self.assertEqual(self.request("POST", path, body, headers)[0], 200)
            self.assertIn("approval", self._await_autopilot(scan["id"])["task"]["error"].lower())
            execute.assert_not_called()
            # The token is still enforced synchronously before any work is scheduled.
            body["approved"] = True
            self.assertEqual(self.request("POST", path, body)[0], 403)
            execute.assert_not_called()
            # Approved and authenticated: the command runs in the background exactly once.
            self.assertEqual(self.request("POST", path, body, headers)[0], 200)
            settled = self._await_autopilot(scan["id"])
            self.assertIsNone(settled["task"])
            self.assertEqual(settled["steps"][-1]["meta"]["output"], "edited")
            execute.assert_called_once_with("printf edited")
            # The proposal is single-use: replaying it fails (no second execution).
            self.assertEqual(self.request("POST", path, body, headers)[0], 200)
            self.assertIn("no longer pending", self._await_autopilot(scan["id"])["task"]["error"].lower())
            execute.assert_called_once()

    def test_autopilot_concurrent_execution_is_rejected(self):
        scan = self.store.create(validate_config({"target": "https://example.test/", "authorized": True}))
        self.store.update(scan["id"], status="completed")
        path = f"/api/scans/{scan['id']}/autopilot"
        headers = {"X-Spidy-Token": self.token}
        with patch("spidy.agent.llm.generate", return_value='{"action":"run","command":"printf test"}'):
            self.request("POST", path, {"action": "plan", "model": "local"}, headers)
            # Keep the patch active until the background planner has produced its proposal.
            proposal_id = self._await_autopilot(scan["id"])["proposal"]["id"]
        entered, release = threading.Event(), threading.Event()
        def execute(command):
            entered.set()
            release.wait(timeout=5)
            return {"output": "test", "exit_code": 0}
        body = {"action": "run", "proposal_id": proposal_id, "command": "printf test", "approved": True}
        with patch("spidy.agent._run_command", side_effect=execute) as command:
            # The run returns immediately; execution continues on a background worker.
            self.assertEqual(self.request("POST", path, body, headers)[0], 200)
            try:
                self.assertTrue(entered.wait(timeout=2))
                # While that worker is executing, a second run and a new plan are both rejected.
                self.assertEqual(self.request("POST", path, body, headers)[0], 400)
                self.assertEqual(self.request("POST", path, {"action": "plan", "model": "local"}, headers)[0], 400)
            finally:
                release.set()
                self._await_autopilot(scan["id"])
            command.assert_called_once()

    def test_dashboard_and_static_assets(self):
        for path in ("/", "/app.js", "/style.css"):
            self.assertEqual(self.request("GET", path)[0], 200)

    def test_dns_rebinding_host_blocked(self):
        self.assertEqual(self.request("GET", "/api/config", headers={"Host": "evil.example"})[0], 403)

    def test_cross_origin_requests_blocked(self):
        self.assertEqual(self.request("GET", "/api/config", headers={"Origin": "https://evil.example"})[0], 403)

    def test_post_requires_token(self):
        status, _ = self.request("POST", "/api/scans", {"target": "example.com", "authorized": True})
        self.assertEqual(status, 403)
        self.assertEqual(self.store.list(), [])

    def test_permission_and_body_validation(self):
        for body in ({"target": "example.com"}, [], {"target": "example.com", "authorized": True, "max_pages": 99999}):
            self.assertEqual(self.request("POST", "/api/scans", body, {"X-Spidy-Token": self.token})[0], 400)

    def test_focus_routing(self):
        status, body = self.request("POST", "/api/focus", {"text": "SQL forms backend and ports"}, {"X-Spidy-Token": self.token})
        self.assertEqual(status, 200)
        self.assertEqual(set(body["checks"]), {"sqli", "forms", "server", "ports"})

    def test_pdf_report_download(self):
        data = self.store.create(validate_config({"target": "example.com", "authorized": True}))
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", f"/api/scans/{data['id']}/report.pdf")
        response = conn.getresponse()
        body = response.read()
        conn.close()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "application/pdf")
        self.assertIn(".pdf", response.getheader("Content-Disposition"))
        self.assertTrue(body.startswith(b"%PDF-1.4"))

    def test_host_inventory_import_is_validated_and_stored(self):
        data = self.store.create(validate_config({"target": "example.com", "authorized": True}))
        path = f"/api/scans/{data['id']}/host-inventory"
        inventory = {"format": "spidy-host-inventory-v1", "target_host": "example.com", "collected_at": "2026-10-11T00:00:00+00:00",
                     "platform": {"system": "Linux", "release": "6.1", "machine": "x86_64"},
                     "processes": [{"pid": 1, "name": "nginx", "executable": "nginx", "package": "nginx-core", "package_version": "1.18.0-6", "version_note": ""}],
                     "packages": [{"name": "nginx-core", "version": "1.18.0-6", "source": "dpkg-query"}]}
        headers = {"X-Spidy-Token": self.token}
        self.assertEqual(self.request("POST", path, inventory, headers)[0], 400)  # still queued
        self.store.update(data["id"], status="completed")
        self.assertEqual(self.request("POST", path, {**inventory, "target_host": "other.example"}, headers)[0], 400)
        self.assertEqual(self.request("POST", path, inventory)[0], 403)
        self.assertEqual(self.request("POST", path, inventory, headers)[0], 200)
        stored = self.store.get(data["id"])["inventory"]["process_inventory"]
        self.assertEqual(stored["status"], "owner_supplied")
        self.assertEqual(stored["processes"][0]["package_version"], "1.18.0-6")
        status, report = self.request("GET", f"/api/scans/{data['id']}/report.md")
        self.assertIn("nginx — package nginx-core 1.18.0-6", report)

    def test_report_download(self):
        data = self.store.create(validate_config({"target": "example.com", "authorized": True}))
        status, body = self.request("GET", f"/api/scans/{data['id']}/report.md")
        self.assertEqual(status, 200)
        self.assertIn("# Spidy security assessment", body)

    def test_email_draft_export_and_local_save(self):
        data = self.store.create(validate_config({"target": "example.com", "authorized": True}))
        self.store.update(data["id"], status="completed")
        path = f"/api/scans/{data['id']}"
        status, body = self.request("GET", path + "/email.txt")
        self.assertEqual(status, 200)
        self.assertIn("Subject:", body)
        self.assertIn("[your name]", body)
        status, _ = self.request("POST", path + "/draft", {"text": "My reviewed draft"}, {"X-Spidy-Token": self.token})
        self.assertEqual(status, 200)
        self.assertEqual(self.request("GET", path + "/email.txt")[1], "My reviewed draft")
        self.assertEqual(Store(self.temp.name).get(data["id"])["email_draft"], "My reviewed draft")

    def test_running_scan_draft_cannot_be_saved(self):
        data = self.store.create(validate_config({"target": "example.com", "authorized": True}))
        status, _ = self.request("POST", f"/api/scans/{data['id']}/draft", {"text": "Too early"}, {"X-Spidy-Token": self.token})
        self.assertEqual(status, 400)


class ConfigTests(unittest.TestCase):
    def test_limits_and_categories(self):
        for extra in ({"max_requests": 999999}, {"max_pages": False}, {"checks": ["rce"]}, {"active": "true"}, {"checks": []}, {"llm_model": "bad name; rm"}):
            with self.assertRaises(ValueError):
                validate_config({"target": "example.com", "authorized": True, **extra})

    def test_inventory_and_advisory_lookup_are_on_by_default(self):
        config = validate_config({"target": "example.com", "authorized": True, "checks": ["headers"]})
        self.assertEqual(config["checks"], ["headers", "ports", "advisories"])
        self.assertTrue(config["advisory_lookup"])
        self.assertEqual(validate_config({"target": "example.com", "authorized": True, "checks": ["headers", "ports"], "inventory": False})["checks"], ["headers", "advisories"])
        off = validate_config({"target": "example.com", "authorized": True, "advisory_lookup": False})
        self.assertNotIn("advisories", off["checks"])
        self.assertFalse(off["advisory_lookup"])
        self.assertEqual(validate_config({"target": "example.com", "authorized": True, "custom_ports": "22, 8000-8002"})["custom_ports"], [22, 8000, 8001, 8002])
        for extra in ({"port_profile": "everything"}, {"custom_ports": "1-65535"}, {"custom_ports": "ssh"}, {"custom_ports": [0]}, {"advisory_lookup": "yes"}):
            with self.assertRaises(ValueError):
                validate_config({"target": "example.com", "authorized": True, **extra})

    def test_keyword_routing(self):
        self.assertEqual(focus_checks("Check SQL injection and forms"), ["forms", "sqli"])
        self.assertEqual(focus_checks("something vague"), [])
        self.assertNotIn("ports", focus_checks("write a report about SQL injection"))


if __name__ == "__main__":
    unittest.main()
