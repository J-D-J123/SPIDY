"""Compare planned work with saved decisions without rewriting executable commands."""
import json
import re
import shlex
from pathlib import Path

from . import externals
from .progress import step_outcome

_ROOT = Path(__file__).resolve().parent.parent
_TERMINAL = {"ran", "failed", "error", "tool_error", "timed_out", "skipped", "stopped"}


def _wordlist(value):
    path = Path(value)
    return str((path if path.is_absolute() else _ROOT / path).resolve())


def _ffuf_signature(options):
    # Same URL + wordlist + extensions is the same discovery task. Throughput (-rate)
    # and the displayed status-code filter (-mc) differ between the built-in shortcut
    # and a hand-typed command for identical work, so they are not part of the identity.
    return ("ffuf", options["-u"], _wordlist(options["-w"]),
            tuple(sorted(filter(None, options.get("-e", "").split(",")))))


def action_signature(row, target):
    command = row.get("command")
    if isinstance(command, str) and command.strip():
        # Preserve shell syntax/expansions verbatim; only tokenize simple invocations.
        if re.search(r"[|;&<>`$\n*?\[\]~#\\]", command):
            return ("shell", command.strip())
        try:
            args = shlex.split(command)
        except ValueError:
            return ("shell", command.strip())
        if args and args[0] in ("ffuf", str(_ROOT / "tools/bin/ffuf")):
            options = {}
            allowed = {"-u", "-w", "-e", "-mc", "-rate", "-t", "-timeout"}
            for index in range(1, len(args), 2):
                if args[index] not in allowed or index + 1 >= len(args) or args[index] in options:
                    break
                options[args[index]] = args[index + 1]
            else:
                if options.get("-u") and options.get("-w"):
                    # Throughput and option order do not constitute a new discovery task.
                    return _ffuf_signature(options)
        return ("command", tuple(args))
    tool = row.get("tool")
    if not tool:
        return None
    spec = externals.TOOLS.get(tool)
    options = {str(k): str(v) for k, v in (row.get("options") or {}).items()}
    if spec:
        options = {k: options.get(k, str(v)) for k, v in spec["options"].items()}
    if tool == "ffuf":
        return _ffuf_signature({"-u": target.rstrip("/") + "/FUZZ",
                                "-w": options.get("wordlist") or externals.TOOLS["ffuf"]["options"]["wordlist"],
                                "-e": options.get("extensions", ""),
                                "-mc": "200,204,301,302,307,401,403"})
    # "rate" is throughput, not scope: re-running nuclei/naabu faster or slower is the
    # same scan. Drop it so the model cannot escape the repeat guard by changing rate.
    scope = {k: v for k, v in options.items() if k != "rate"}
    return ("tool", tool, target, json.dumps(scope, sort_keys=True))


def repeated_steps(proposal, history, target):
    signature = action_signature(proposal, target)
    if signature is None:
        return []
    return [index for index, step in enumerate(history or [], 1)
            if step_outcome(step) in _TERMINAL and action_signature(step, target) == signature]
