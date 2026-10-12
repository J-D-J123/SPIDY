"""Capture subprocess output while publishing bounded terminal snapshots."""
import os
import shlex
import signal
import subprocess
import tempfile
import time
from pathlib import Path


def capture(args, *, timeout, on_output=None, shell=False, cwd=None, env=None,
            limit=64000, separate_stdout=False):
    command = args if isinstance(args, str) else shlex.join(args)
    head, tail = bytearray(), bytearray()
    total = 0
    timed_out = False
    with tempfile.TemporaryDirectory(prefix="spidy-output-") as directory:
        stdout_path, stderr_path = Path(directory, "stdout"), Path(directory, "stderr")
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            proc = subprocess.Popen(args, shell=shell, cwd=cwd, env=env,
                                    stdin=subprocess.DEVNULL, stdout=stdout,
                                    stderr=stderr if separate_stdout else subprocess.STDOUT,
                                    start_new_session=(os.name == "posix"))
            deadline = time.monotonic() + timeout

            def stop():
                if os.name == "posix":
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                elif proc.poll() is None:
                    proc.kill()
                proc.wait()

            def publish(final=False):
                if on_output:
                    on_output({"command": command, "output": tail.decode("utf-8", "replace"),
                               "output_truncated": total > limit, "timed_out": timed_out,
                               "exit_code": proc.returncode if final else None})

            try:
                with stdout_path.open("rb") as out, stderr_path.open("rb") as err:
                    def drain(final=False):
                        nonlocal total
                        changed = False
                        for stream in (out, err) if separate_stdout else (out,):
                            # Snapshot the size: a noisy process cannot keep this loop from timing out.
                            remaining = os.fstat(stream.fileno()).st_size - stream.tell()
                            if not final:
                                remaining = min(remaining, 262144)
                            while remaining > 0:
                                chunk = stream.read(min(remaining, 65536))
                                if not chunk:
                                    break
                                remaining -= len(chunk)
                                total += len(chunk)
                                head.extend(chunk[:max(0, limit - len(head))])
                                tail.extend(chunk)
                                del tail[:-limit]
                                changed = True
                        return changed

                    publish()
                    while proc.poll() is None:
                        if drain():
                            publish()
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            timed_out = True
                            stop()
                            break
                        try:
                            proc.wait(timeout=min(0.15, remaining))
                        except subprocess.TimeoutExpired:
                            pass
                    drain(final=True)
                    publish(final=True)
            finally:
                if proc.poll() is None:
                    stop()
        meta = {"command": command, "exit_code": proc.returncode, "timed_out": timed_out,
                "output": head.decode("utf-8", "replace"), "output_tail": tail.decode("utf-8", "replace"),
                "output_truncated": total > limit}
        # Tool parsers still receive stdout alone, without terminal truncation or stderr contamination.
        parsed_stdout = stdout_path.read_bytes() if separate_stdout else b""
        return meta, parsed_stdout
