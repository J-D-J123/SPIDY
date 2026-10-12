import json
from pathlib import Path
import unittest
from unittest.mock import patch

from spidy import agent, externals
from spidy.store import add_external_findings


class PlannerEvidenceTests(unittest.TestCase):
    def test_legacy_denied_paths_are_grouped_without_exposure_claims(self):
        scan = {"config": {"target": "https://t.test/"}, "findings": [
            {"source": "ffuf", "title": "Discovered path: " + path,
             "evidence": f"ffuf: https://t.test/{path} -> HTTP 403 (1454 bytes)"}
            for path in (".env", ".git", "config.php")
        ]}
        before = json.dumps(scan)
        context = agent._investigation_context(scan, [])
        self.assertIn('"saved_observations": 3', context)
        self.assertIn('"http_status": 403', context)
        self.assertIn("Does not establish that these files exist", context)
        self.assertNotIn("Discovered path", context)
        self.assertEqual(json.dumps(scan), before)

    def test_compact_evidence_includes_builtin_results_and_retires_resolved_failures(self):
        rows = [
            {"command": "nikto -host https://t.test/", "outcome": "failed",
             "meta": {"output": "Required module not found: XML::Writer"}},
            {"tool": "nikto", "outcome": "ran", "meta": {"count": 0}},
            {"tool": "ffuf", "outcome": "ran", "record_id": 30,
             "meta": {"command": "ffuf -u https://t.test/FUZZ -w words",
                      "exit_code": 0, "output": ".env\n.git\n", "count": 2}},
        ]
        evidence = agent._followup_evidence(rows)
        self.assertNotIn("XML::Writer", json.dumps(evidence))
        self.assertEqual(evidence[0]["result"], {"count": 0})
        self.assertEqual(evidence[-1]["record"], 30)
        self.assertEqual(evidence[-1]["program"], "ffuf")
        self.assertEqual(evidence[-1]["output_excerpt"], ".env\n.git\n")
        rows.append({"command": "nikto -host https://t.test/", "outcome": "failed",
                     "meta": {"output": "new startup failure"}})
        self.assertIn("new startup failure", json.dumps(agent._followup_evidence(rows)))

    def test_denial_headers_do_not_become_a_csp_investigation(self):
        rows = [{"command": "curl --head https://t.test/.env", "outcome": "ran",
                 "meta": {"output": "HTTP/2 403\r\nserver: test\r\n\r\n", "exit_code": 0}}]
        observation = agent._followup_evidence(rows)[0]["observation"]
        self.assertIn("denial response", observation)
        self.assertNotIn("Content-Security-Policy", observation)

    def test_manual_review_keeps_bounded_access_requirement_but_not_broken_generations(self):
        manual = {"action": "manual", "instructions": "Ask the owner for WAF configuration access.",
                  "reason": "Configuration is not available through public HTTP."}
        feedback = json.loads(agent._retry_feedback([{"role": "executor", "proposal": manual, "issue": "Review"}]))[0]
        self.assertEqual(feedback["manual_request"], manual["instructions"])
        manual["generation_rejected"] = True
        self.assertNotIn("manual_request", agent._retry_feedback([{"role": "executor", "proposal": manual}]))

    def test_ffuf_adapter_records_observations_without_claiming_validation(self):
        def fake_exec(args, timeout):
            Path(args[args.index("-o") + 1]).write_text(json.dumps({"results": [
                {"url": "https://t.test/.env", "status": 403, "length": 1454},
                {"url": "https://t.test/cart", "status": 200, "length": 1000},
            ]}))
            return ""

        with patch("spidy.externals._exec", side_effect=fake_exec), patch("spidy.externals.tool_path", return_value="ffuf"):
            items, meta = externals._ffuf_tool("https://t.test/", {})
        self.assertEqual(meta["count"], 2)
        self.assertEqual(items[0]["title"], "Access restricted: /.env")
        self.assertTrue(all(item["severity"] == "info" for item in items))
        self.assertEqual(items[0]["url"], "https://t.test/.env")
        scan = {"config": {"target": "https://t.test/"}}
        add_external_findings(scan, items, "ffuf")
        self.assertIn("No missing-path control", scan["findings"][0]["method"])
        self.assertIn("does not prove file existence", scan["findings"][0]["verification"])


if __name__ == "__main__":
    unittest.main()
