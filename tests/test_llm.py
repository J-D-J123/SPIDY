import json
import unittest
from unittest.mock import patch

from spidy import llm


def sample_scan():
    return {
        "id": "a" * 32, "status": "completed", "created_at": "2026-10-11T00:00:00+00:00",
        "config": {"target": "https://shop.example/login?token=SECRET_TOKEN", "checks": ["headers", "ports"], "active": False},
        "findings": [{"id": "SP-001", "title": "Missing Content-Security-Policy", "severity": "low", "confidence": "high",
                      "url": "https://shop.example/?q=SECRET_QUERY", "evidence": "absent", "description": "Policy missing.",
                      "remediation": "Add one.", "reference": "x"}],
        "events": [], "ports": [], "coverage": {"pages_received": 3, "scanner": "nmap 7.94"},
        "inventory": {"services": [{"host": "shop.example", "ip": "203.0.113.5", "port": 443, "state": "open",
                                    "service": "https", "product": "nginx", "version": "1.18.0", "service_verified": True, "confidence": "high", "evidence": "x"}],
                      "technologies": [{"product": "nginx", "version": "1.18.0", "source": "x", "evidence": "x", "confidence": "high"}]},
        "advisories": {"status": "completed", "candidates": [{"id": "CVE-2021-23017", "product": "nginx", "version": "1.18.0", "severity": "high"}]},
        "approved_origins": [], "pending_origins": [], "summary": "done",
    }


class LLMTests(unittest.TestCase):
    def test_models_parses_names_and_rejects_junk(self):
        payload = {"models": [{"name": "llama3.1:8b"}, {"name": "mistral:latest"}, {"nope": 1}, {"name": 5}]}
        with patch("spidy.llm._request", return_value=payload) as request:
            self.assertEqual(llm.models(), ["llama3.1:8b", "mistral:latest"])
        self.assertEqual(request.call_args.args[1], "/api/tags")

    def test_available_is_false_when_ollama_is_down(self):
        with patch("spidy.llm._request", side_effect=llm.LLMError("down")):
            self.assertFalse(llm.available())

    def test_brief_redacts_target_query_values(self):
        brief = llm._brief(sample_scan())
        self.assertNotIn("SECRET_TOKEN", brief)
        self.assertNotIn("SECRET_QUERY", brief)
        self.assertIn("nginx 1.18.0", brief)
        self.assertIn("CVE-2021-23017", brief)

    def test_analyze_scan_returns_text_and_metadata(self):
        with patch("spidy.llm._request", return_value={"response": "  Prioritize the nginx CVE.  "}) as request:
            result = llm.analyze_scan(sample_scan(), "llama3.1:8b")
        self.assertEqual(request.call_args.args[1], "/api/generate")
        sent = request.call_args.kwargs.get("payload") or request.call_args.args[2]
        self.assertEqual(sent["model"], "llama3.1:8b")
        self.assertFalse(sent["stream"])
        self.assertEqual(result["model"], "llama3.1:8b")
        self.assertEqual(result["text"], "Prioritize the nginx CVE.")
        self.assertIn("local open model", result["disclaimer"])

    def test_analyze_rejects_bad_model_name(self):
        with self.assertRaises(llm.LLMError):
            llm.analyze_scan(sample_scan(), "bad name; rm -rf")

    def test_empty_model_response_is_an_error(self):
        with patch("spidy.llm._request", return_value={"response": "   "}):
            with self.assertRaises(llm.LLMError):
                llm.analyze_scan(sample_scan(), "llama3.1:8b")

    def test_invalid_host_is_rejected_before_any_request(self):
        with self.assertRaises(llm.LLMError):
            llm.models("ftp://evil.example")

    def test_report_includes_model_analysis_when_present(self):
        from spidy.store import markdown_report
        from spidy.pdf_report import pdf_report
        scan = sample_scan()
        scan["llm_analysis"] = {"model": "llama3.1:8b", "generated_at": "2026-10-11T00:00:00+00:00",
                                "text": "Line one.\n\nLine two about nginx.", "disclaimer": "verify this"}
        report = markdown_report(scan)
        self.assertIn("## Local model analysis", report)
        self.assertIn("llama3.1:8b", report)
        self.assertIn("Line two about nginx.", report)
        self.assertIn(b"Local model analysis", pdf_report(scan))


if __name__ == "__main__":
    unittest.main()
