import json
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spidy import agent, externals
from spidy.process_output import capture


class ProcessOutputTests(unittest.TestCase):
    def test_nikto_readiness_detects_missing_dependency_without_a_target(self):
        import subprocess
        with patch("spidy.externals.tool_path", return_value="/local/nikto"), \
                patch("spidy.externals.subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 1, "", "ERROR: Required module not found: XML::Writer")) as run:
            status = externals.tool_readiness("nikto")
        self.assertFalse(status["ready"])
        self.assertIn("XML::Writer", status["error"])
        self.assertEqual(run.call_args.args[0], ["/local/nikto", "-Version"])

    def test_shell_output_arrives_before_completion_including_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory, "release")
            script = ("import pathlib,time,sys; print('started',flush=True); "
                      "print('stderr line',file=sys.stderr,flush=True); "
                      f"p=pathlib.Path({str(release)!r})\n"
                      "while not p.exists(): time.sleep(0.01)\n"
                      "print('finished',flush=True)")
            updates = []

            def output(snapshot):
                updates.append(dict(snapshot))
                if "started" in snapshot["output"] and snapshot["exit_code"] is None:
                    release.touch()

            with patch("spidy.agent.COMMAND_TIMEOUT", 3):
                meta = agent._run_command(shlex.join([sys.executable, "-c", script]), on_output=output)
            self.assertTrue(release.exists(), "the child must receive release before it can exit")
            self.assertFalse(meta["timed_out"])
            self.assertIn("stderr line", meta["output"])
            self.assertIn("finished", updates[-1]["output"])
            self.assertEqual(updates[-1]["exit_code"], 0)

    def test_builtin_stream_keeps_stderr_out_of_parser_and_records_exit(self):
        script = "import sys; print('{\"result\": 42}'); print('diagnostic',file=sys.stderr); sys.exit(7)"

        def adapter(target, options, cancelled):
            data = json.loads(externals._exec([sys.executable, "-c", script], 3))
            return [], {"result": data["result"]}

        spec = {"probe": {"needs": "probe", "run": adapter}}
        updates = []
        with patch.dict(externals.TOOLS, spec), patch.object(externals, "available", return_value=True):
            _, meta = externals.run_tool("probe", "unused", on_output=updates.append)
        self.assertEqual(meta["result"], 42)
        self.assertEqual(meta["exit_code"], 7)
        self.assertIn("diagnostic", meta["output"])
        self.assertGreaterEqual(len(updates), 2)
        self.assertIsNone(externals._output_observer.get())

    def test_output_tail_is_bounded_and_timeout_is_published(self):
        updates = []
        meta, _ = capture([sys.executable, "-c", "import time; print('abcdefghij',flush=True); time.sleep(5)"],
                          timeout=0.3, limit=5, on_output=updates.append)
        self.assertTrue(meta["timed_out"])
        self.assertTrue(meta["output_truncated"])
        self.assertEqual(meta["output"], "abcde")
        self.assertEqual(meta["output_tail"], "ghij\n")
        self.assertTrue(updates[-1]["timed_out"])
        self.assertTrue(all(len(update["output"]) <= 5 for update in updates))

    def test_unicode_output_and_empty_success(self):
        meta, _ = capture([sys.executable, "-c", "print('✓ ready')"], timeout=3)
        self.assertEqual(meta["output"], "✓ ready\n")
        empty, _ = capture([sys.executable, "-c", "pass"], timeout=3)
        self.assertEqual(empty["output"], "")
        self.assertEqual(empty["exit_code"], 0)
