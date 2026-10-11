import json
import tempfile
import unittest
from unittest.mock import patch

from spidy.analysis import analyze, email_draft, safe_url
from spidy.checks import PROBE_ORIGIN
from spidy.scanner import Scanner, validate_config
from spidy.store import Store, markdown_report
from spidy.transport import Response


class AnalysisAndCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.config = validate_config({"target": "https://example.test/", "authorized": True,
                                      "checks": ["discovery", "cors", "redirects"], "active": True, "discovery": True})
        self.scan = self.store.create(self.config)
        self.scanner = Scanner(self.store, self.scan["id"])
        self.page = Response(self.config["target"], 200, [("Content-Type", "text/html")], "<h1>Home</h1>")

    def result(self):
        return self.store.get(self.scan["id"])

    def test_secret_exposure_retains_no_secret_values(self):
        r = Response("https://example.test/.env", 200, [], "DB_HOST=localhost\nAPP_SECRET=NEVER_RETAIN_THIS_VALUE\n")
        self.scanner.additional.inspect_discovery(r, "env")
        data = self.result()
        self.assertEqual(data["findings"][0]["severity"], "high")
        self.assertNotIn("NEVER_RETAIN_THIS_VALUE", json.dumps(data))
        self.assertNotIn("NEVER_RETAIN_THIS_VALUE", markdown_report(data))
        self.assertNotIn("NEVER_RETAIN_THIS_VALUE", email_draft(data))

    def test_html_documentation_is_not_an_exposed_env_file(self):
        r = Response("https://example.test/.env", 200, [], "<html><pre>Example\nDB_HOST=localhost\nAPP_SECRET=example\n</pre></html>")
        self.scanner.additional.inspect_discovery(r, "env")
        self.assertEqual(self.result()["findings"], [])

    def test_discovery_requires_signature_not_status_alone(self):
        for kind in ("env", "git", "backup", "api", "actuator", "apache", "nginx", "listing"):
            self.scanner.additional.inspect_discovery(Response("https://example.test/file", 200, [], "<h1>Welcome to our application</h1>"), kind)
        self.assertEqual(self.result()["findings"], [])

    def test_soft_404_suppression_even_with_signatures(self):
        body = "DB_HOST=localhost\nAPP_SECRET=public-example\n"
        with patch.object(self.scanner, "get", side_effect=lambda url, *a, **k: Response(url, 200, [], body)):
            self.scanner.additional.discover_paths(self.page)
        self.assertEqual(self.result()["findings"], [])
        self.assertTrue(any("catch-all" in e.get("reason", "") for e in self.result()["events"]))

    def test_path_budget_includes_no_more_than_configured_guesses(self):
        self.scanner.config["max_paths"] = 2
        with patch.object(self.scanner, "get", side_effect=lambda url, *a, **k: Response(url, 404, [], "missing")) as request:
            self.scanner.additional.discover_paths(self.page)
        self.assertEqual(request.call_count, 3)  # two paths plus the control
        self.assertEqual(self.scanner.additional.path_attempts, 2)

    def test_control_redirect_aborts_guesses_and_records_scope_request(self):
        with patch.object(self.scanner, "get", return_value=Response(self.page.url, 302, [("Location", "https://external.test/")], "")) as request:
            self.scanner.additional.discover_paths(self.page)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(self.result()["pending_origins"][0]["origin"], "https://external.test")

    def test_rate_limited_discovery_stops(self):
        with patch.object(self.scanner, "get", side_effect=[Response(self.page.url, 404, [], "missing"), Response(self.page.url, 429, [], "slow down")]) as request:
            self.scanner.additional.discover_paths(self.page)
        self.assertEqual(request.call_count, 2)

    def test_discovery_disabled_does_not_guess_paths(self):
        self.scanner.config.update(discovery=False, active=False)
        with patch.object(self.scanner, "get") as request:
            self.scanner.additional.run(self.page)
        request.assert_not_called()

    def test_cors_compares_baseline_and_records_uncertainty(self):
        response = Response(self.page.url, 200, [("Access-Control-Allow-Origin", PROBE_ORIGIN), ("Access-Control-Allow-Credentials", "true")], "ok")
        with patch.object(self.scanner, "get", return_value=response) as request:
            self.scanner.additional.cors(self.page)
        self.assertEqual(request.call_args.kwargs["headers"], {"Origin": PROBE_ORIGIN})
        finding = self.result()["findings"][0]
        self.assertEqual(finding["check"], "cors")
        self.assertEqual(finding["certainty"], "needs validation")
        self.assertEqual(finding["priority"], "Validate next")

    def test_wildcard_cors_is_not_reported_as_credential_theft(self):
        response = Response(self.page.url, 200, [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")], "public")
        with patch.object(self.scanner, "get", return_value=response):
            self.scanner.additional.cors(self.page)
        self.assertEqual(self.result()["findings"], [])

    def test_redirect_probe_never_resolves_synthetic_destination(self):
        page = Response("https://example.test/go?next=/", 302, [("Location", "/")], "")
        response = Response(page.url, 302, [("Location", PROBE_ORIGIN + "/redirect-check")], "")
        with patch.object(self.scanner, "get", return_value=response) as request, patch("spidy.scope.socket.getaddrinfo") as dns:
            self.scanner.additional.redirects(page)
        request.assert_called_once()
        dns.assert_not_called()
        self.assertEqual(len(self.result()["findings"]), 1)
        self.assertEqual(self.result()["pending_origins"], [])
        self.assertEqual(self.result()["events"][-1]["type"], "scope_block")

    def test_invalid_redirect_does_not_crash_scan(self):
        page = Response("https://example.test/go?next=/", 200, [], "")
        with patch.object(self.scanner, "get", return_value=Response(page.url, 302, [("Location", "http://[invalid")], "")):
            # Malformed target content is handled by the check, not followed.
            self.scanner.additional.redirects(page)
        self.assertEqual(self.result()["findings"], [])

    def test_related_findings_are_grouped_with_evidence_ids(self):
        for path in ("/a", "/b"):
            self.scanner.finding("Missing or ineffective Content-Security-Policy", "low", "high", "https://example.test" + path,
                                 "CSP absent", "Hardening is missing.", "Set a policy.")
        assessment = analyze(self.result())
        self.assertEqual(len(assessment["issue_groups"]), 1)
        self.assertEqual(assessment["issue_groups"][0]["finding_ids"], ["SP-001", "SP-002"])
        self.assertEqual(assessment["priorities"]["Hardening"], 1)

    def test_report_explains_rationale_and_reproduction(self):
        self.scanner.finding("Unescaped HTML input reflection", "medium", "medium", "https://example.test/?q=secret-value", "Inert marker reflected", "Potential issue.", "Encode output.")
        report = markdown_report(self.result())
        self.assertIn("## Executive assessment", report)
        self.assertIn("## Why these checks were performed", report)
        self.assertIn("Reproduction / review:", report)
        self.assertIn("- Verification:", report)
        self.assertIn("Validate next", report)

    def test_email_is_draft_with_context_and_query_redaction(self):
        self.scanner.finding("Possible SQL injection", "medium", "medium", "https://example.test/search?token=SECRET123&q=PRIVATE456", "SQL error", "Possible issue.", "Use parameterization.")
        email = email_draft(self.result())
        self.assertNotIn("SECRET123", email)
        self.assertNotIn("PRIVATE456", email)
        self.assertIn("[your name]", email)
        self.assertIn("[add your authorization", email)
        self.assertIn("needs validation", email)
        self.assertIn("Attachment to add manually:", email)

    def test_empty_and_partial_reports_do_not_claim_security(self):
        self.store.update(self.scan["id"], status="failed")
        assessment = analyze(self.result())
        self.assertTrue(assessment["partial"])
        self.assertIn("failed", assessment["executive_summary"])
        self.assertIn("does not establish", assessment["executive_summary"])
        self.assertIn("No findings were recorded", email_draft(self.result()))

    def test_safe_url_removes_unknown_parameter_values(self):
        url = safe_url("https://example.test/p?unusual=SECRET&q=hello#private")
        self.assertNotIn("SECRET", url)
        self.assertNotIn("hello", url)
        self.assertNotIn("private", url)

    def test_cli_attachment_name_matches_the_requested_report(self):
        draft = email_draft(self.result(), attachment_name="assessment.json")
        self.assertIn("Attachment to add manually: assessment.json", draft)


if __name__ == "__main__":
    unittest.main()
