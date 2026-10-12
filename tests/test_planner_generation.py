import json
import unittest
from unittest.mock import patch

from spidy import agent, llm, externals


class Stream:
    status = 200

    def __init__(self, chunks):
        self.chunks = chunks
        self.read = 0
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def __iter__(self):
        for chunk in self.chunks:
            self.read += 1
            yield json.dumps(chunk).encode()


class PlannerGenerationTests(unittest.TestCase):
    def test_runaway_stream_is_closed_before_reading_the_rest(self):
        stream = Stream([{"response": '{"action":"run","tool":"ffuf","options":{"extensions":"'}] +
                        [{"response": ".gitignore,.gitattributes,.gitmodules,.gitconfig,.gitkeep,"}] * 200)
        with patch("spidy.llm.urllib.request.urlopen", return_value=stream):
            with self.assertRaisesRegex(llm.GenerationRejected, "repeated"):
                llm.generate("local", "one proposal", response_format=agent.PROPOSAL_SCHEMA,
                             output_guard=agent._guard_proposal_output)
        self.assertTrue(stream.closed)
        self.assertLess(stream.read, 20)

    def test_length_stop_discards_partial_json(self):
        stream = Stream([{"response": '{"action":"run","command":"curl', "done": True, "done_reason": "length"}])
        with patch("spidy.llm.urllib.request.urlopen", return_value=stream):
            with self.assertRaisesRegex(llm.GenerationRejected, "token limit"):
                llm.generate("local", "proposal", output_guard=agent._guard_proposal_output)
        self.assertTrue(stream.closed)

    def test_complete_stream_still_returns_a_proposal(self):
        reply = '{"action":"run","command":"printf test","reason":"local check"}'
        stream = Stream([{"response": reply[:30]}, {"response": reply[30:], "done": True, "done_reason": "stop"}])
        with patch("spidy.llm.urllib.request.urlopen", return_value=stream):
            self.assertEqual(llm.generate("local", "proposal", output_guard=agent._guard_proposal_output), reply)

    def test_interrupted_stream_discards_even_parseable_output(self):
        stream = Stream([{"response": '{"action":"run","command":"printf test"}'}])
        with patch("spidy.llm.urllib.request.urlopen", return_value=stream):
            with self.assertRaisesRegex(llm.GenerationRejected, "before completion"):
                llm.generate("local", "proposal", output_guard=agent._guard_proposal_output)
        self.assertTrue(stream.closed)

    def test_malformed_and_oversized_output_never_survives_in_diagnostics(self):
        for reply in ('{"action":"run","options":{"extensions":"' + '.gitignore,.gitattributes,' * 200,
                      '{"action":"run","command":"private-marker',
                      'x' * (agent.MAX_PROPOSAL_CHARS + 1)):
            proposal, issue = agent._normalize_reply(reply)
            self.assertTrue(proposal["generation_rejected"])
            self.assertTrue(issue)
            self.assertLess(len(json.dumps(proposal)), 500)
            self.assertNotIn('private-marker', json.dumps(proposal))

    def test_retry_feedback_does_not_include_bad_options_or_partial_instructions(self):
        feedback = agent._retry_feedback([{"role":"guide", "issue":"Malformed JSON",
            "proposal":{"instructions":"private-marker" * 1000, "options":{"extensions":".git," * 1000}}}])
        self.assertNotIn('private-marker', feedback)
        self.assertNotIn('.git', feedback)
        self.assertLess(len(feedback), 300)

    def test_complete_json_with_repeated_extensions_is_not_runnable(self):
        with self.assertRaisesRegex(externals.ToolError, "repeated entries"):
            externals.validate_options("ffuf", {"extensions":".env,.git,.env,.git"})
        externals.validate_options("ffuf", {"extensions":".env,.git,.html"})


if __name__ == "__main__":
    unittest.main()
