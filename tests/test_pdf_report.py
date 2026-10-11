import copy
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spidy.pdf_report import _width, _wrap, pdf_report


def sample_scan():
    return {
        "id": "abcdef0123456789abcdef0123456789", "status": "completed",
        "created_at": "2026-10-11T12:00:00+00:00", "finished_at": "2026-10-11T12:01:00+00:00",
        "config": {"target": "https://example.test/?token=PRIVATE_TOKEN#private-fragment",
                   "checks": ["headers", "ports"], "active": False},
        "findings": [{"id": "SP-001", "title": "Missing Content-Security-Policy", "severity": "low",
                      "confidence": "high", "url": "https://example.test/?q=PRIVATE_QUERY",
                      "evidence": "Header was absent", "description": "Browser policy is missing.",
                      "remediation": "Configure a suitable policy.", "reference": "https://example.test/docs"}],
        "events": [{"type": "request", "check": "headers", "url": "https://example.test/?secret=PRIVATE_EVENT"}],
        "ports": [], "coverage": {"pages_received": 1}, "approved_origins": [], "pending_origins": [],
        "summary": "Assessment finished.",
    }


class PDFReportTests(unittest.TestCase):
    def assert_valid_structure(self, data):
        self.assertTrue(data.startswith(b"%PDF-1.4\n"))
        self.assertTrue(data.endswith(b"%%EOF\n"))
        offset = int(re.search(rb"startxref\n(\d+)\n", data).group(1))
        self.assertEqual(data[offset:offset + 5], b"xref\n")
        xref = data[offset:].splitlines()
        count = int(xref[1].split()[1])
        for number, entry in enumerate(xref[3:count + 2], 1):
            object_offset = int(entry[:10])
            self.assertTrue(data[object_offset:].startswith(f"{number} 0 obj\n".encode()))
        for match in re.finditer(rb"<< /Length (\d+) >>\nstream\n", data):
            end = match.end() + int(match.group(1))
            self.assertEqual(data[end:end + 9], b"endstream")
        page_count = int(re.search(rb"/Type /Pages /Count (\d+)", data).group(1))
        self.assertEqual(len(re.findall(rb"/Type /Page ", data)), page_count)
        for page in range(1, page_count + 1):
            self.assertIn(f"Page {page} of {page_count}".encode(), data)

    def test_historical_scan_is_valid_and_unchanged(self):
        scan = sample_scan()
        original = copy.deepcopy(scan)
        data = pdf_report(scan)
        self.assert_valid_structure(data)
        self.assertEqual(scan, original)
        self.assertIn(b"Security assessment", data)
        self.assertIn(b"No service inventory was recorded", data)
        self.assertIn(b"No advisory candidates were recorded", data)
        self.assertIn(b"Configure a suitable policy", data)

    def test_minimal_scan_remains_readable(self):
        data = pdf_report({})
        self.assert_valid_structure(data)
        self.assertIn(b"Target not recorded", data)
        self.assertIn(b"No activity entries were recorded", data)
        self.assertIn(b"conclusions are provisional", data)

    def test_inventory_candidates_scope_and_evidence_are_included(self):
        scan = sample_scan()
        scan["inventory"] = {
            "addresses": [{"host": "example.test", "ip": "192.0.2.12"}],
            "services": [{"host": "example.test", "ip": "192.0.2.12", "port": 443,
                          "state": "open", "service": "https", "product": "nginx", "version": "1.2.3",
                          "confidence": "medium", "evidence": "Server: nginx/1.2.3"}],
            "technologies": [{"name": "PHP", "version": "8.1"}],
            "tls": [{"protocol": "TLSv1.3", "issuer": "Example CA"}],
            "process_inventory": {"status": "unavailable", "reason": "External scans cannot see host processes."},
        }
        scan["advisories"] = {"status": "completed", "candidates": [{"id": "CVE-2026-12345", "title": "Example advisory",
            "product": "nginx", "version": "1.2.3", "status": "needs_validation", "match_reason": "Product and version signal",
            "url": "https://example.test/advisory/CVE-2026-12345"}]}
        scan["pending_origins"] = [{"origin": "https://external.test", "decision": "pending",
                                    "source": "https://example.test", "reason": "Cross-origin link"}]
        data = pdf_report(scan)
        for text in (b"192.0.2.12", b"nginx/1.2.3", b"TLSv1.3", b"CVE-2026-12345", b"Product and version signal",
                     b"https://external.test", b"Cross-origin link", b"not proof of exploitability"):
            self.assertIn(text, data)
        self.assert_valid_structure(data)

    def test_sharing_view_redacts_queries_fragments_and_credentials(self):
        scan = sample_scan()
        scan["approved_origins"] = ["https://private-user:PRIVATE_PASSWORD@approved.test/?key=PRIVATE_APPROVED"]
        data = pdf_report(scan)
        for private in (b"PRIVATE_TOKEN", b"private-fragment", b"PRIVATE_QUERY", b"PRIVATE_EVENT", b"PRIVATE_PASSWORD",
                        b"PRIVATE_APPROVED", b"private-user"):
            self.assertNotIn(private, data)
        self.assertIn(b"%5Bredacted%5D", data)

    def test_text_escaping_and_unicode_fallback(self):
        scan = sample_scan()
        scan["findings"][0]["evidence"] = "Literal (parentheses) \\ server; café — 東京 🕷\x00\x1b"
        data = pdf_report(scan)
        self.assertIn(b"Literal \\(parentheses\\) \\\\ server", data)
        self.assertIn(b"caf\xe9", data)
        self.assertNotIn(b"\x00", data)
        self.assert_valid_structure(data)

    def test_long_tokens_wrap_inside_page_width(self):
        for font in ("F1", "F2", "F3"):
            lines = list(_wrap("W" * 1000 + " " + "é" * 100, 520, 10, font))
            self.assertGreater(len(lines), 5)
            self.assertTrue(all(_width(line, 10, font) <= 520 for line in lines))

    def test_large_audit_is_bounded_and_reports_omissions(self):
        scan = sample_scan()
        scan["status"] = "failed"
        scan["events"] = [{"type": "request", "url": f"https://example.test/event-{i}", "check": "headers"} for i in range(200)]
        data = pdf_report(scan)
        self.assertIn(b"first 80 and last 40", data)
        self.assertIn(b"80 middle entries", data)
        self.assertNotIn(b"event-100", data)
        self.assertIn(b"event-199", data)
        self.assertIn(b"conclusions are provisional", data)
        self.assert_valid_structure(data)

    @unittest.skipUnless(shutil.which("pdfinfo") and shutil.which("pdftotext"), "Poppler tools not available")
    def test_poppler_opens_and_extracts_generated_report(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "assessment.pdf"
            path.write_bytes(pdf_report(sample_scan()))
            info = subprocess.run(["pdfinfo", str(path)], capture_output=True, text=True, check=True)
            self.assertIn("PDF version:", info.stdout)
            self.assertEqual(info.stderr, "")
            content = subprocess.run(["pdftotext", str(path), "-"], capture_output=True, text=True, check=True)
            self.assertIn("Executive assessment", content.stdout)
            self.assertIn("Scope decisions", content.stdout)
            self.assertIn("Header was absent", content.stdout)
            self.assertNotIn("PRIVATE_TOKEN", content.stdout)
            self.assertEqual(content.stderr, "")


if __name__ == "__main__":
    unittest.main()
