"""Compare planned work with saved decisions without rewriting executable commands."""
import json
import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit

from . import externals
from .progress import step_outcome

_ROOT = Path(__file__).resolve().parent.parent
_TERMINAL = {"ran", "attempted", "failed", "error", "tool_error", "timed_out", "skipped", "stopped"}


def _wordlist(value):
    path = Path(value)
    return str((path if path.is_absolute() else _ROOT / path).resolve())


def _ffuf_signature(options):
    # Same URL + wordlist + extensions is the same discovery task. Throughput (-rate)
    # and the displayed status-code filter (-mc) differ between the built-in shortcut
    # and a hand-typed command for identical work, so they are not part of the identity.
    return ("ffuf", options["-u"], _wordlist(options["-w"]),
            tuple(sorted(filter(None, options.get("-e", "").split(",")))))


def _curl_signature(args):
    """Match plain requests while retaining unknown flags and different request semantics."""
    if not args or args[0] not in ("curl", str(_ROOT / "tools/bin/curl"), "/usr/bin/curl", "/bin/curl"):
        return None
    urls, head, positional = [], False, False
    index = 1
    while index < len(args):
        arg = args[index]
        if arg == "--" and not positional:
            positional = True
        elif arg.startswith(("https://", "http://")):
            urls.append(arg)
        elif positional:
            return None
        elif arg in ("--silent", "--show-error"):
            pass
        elif arg == "--head":
            head = True
        elif re.fullmatch(r"-[sSI]+", arg):
            head = head or "I" in arg
        elif arg in ("-m", "--max-time", "--connect-timeout"):
            index += 1
            if index >= len(args) or not re.fullmatch(r"\d+(?:\.\d+)?", args[index]):
                return None
        elif re.fullmatch(r"(?:--max-time=|--connect-timeout=|-m)\d+(?:\.\d+)?", arg):
            pass
        elif arg == "--url":
            index += 1
            if index >= len(args) or not args[index].startswith(("https://", "http://")):
                return None
            urls.append(args[index])
        else:
            return None
        index += 1
    if len(urls) == 1:
        return ("curl-request", "HEAD" if head else "GET", urls[0])
    return None


def action_signature(row, target):
    target = row.get("scan_target", target)
    command = row.get("command")
    if isinstance(command, str) and command.strip():
        # Preserve shell syntax/expansions verbatim; only tokenize simple invocations.
        if re.search(r"[|;&<>`$\n*?\[\]~#\\]", command):
            return ("shell", command.strip())
        try:
            args = shlex.split(command)
        except ValueError:
            return ("shell", command.strip())
        curl = _curl_signature(args)
        if curl:
            return curl
        # Recognize only known equivalent invocations, preserving other targets/flags.
        host = urlsplit(target).hostname or ""
        equivalent = {"wafw00f": [target], "httpx": ["-u", target],
                      "nikto": ["-host", target], "gau": [host.removeprefix("www.")],
                      "subfinder": ["-d", host.removeprefix("www.")]}
        if args:
            name = Path(args[0]).name
            if (args[0] in (name, str(_ROOT / "tools/bin" / name))
                    and name in equivalent and args[1:] == equivalent[name]):
                return action_signature({"tool": name}, target)
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
    if row.get("options_unknown"):
        return None  # Legacy manual runs did not save their parameters. Do not invent them.
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
    return [step.get("record_id", index) for index, step in enumerate(history or [], 1)
            if step_outcome(step) in _TERMINAL and action_signature(step, target) == signature]


def recorded_actions(scan, history=None):
    """One execution ledger for planning and duplicate checks, including manual/main scans."""
    rows = list(history if history is not None else (scan.get("autopilot") or {}).get("steps", []))
    target = scan["config"]["target"]
    host = urlsplit(target).hostname or ""
    for index, event in enumerate(scan.get("events", []), 1):
        tool = event.get("tool")
        if event.get("type") == "deep_scan" and tool in externals.TOOLS:
            spec = externals.TOOLS[tool]
            expected = {"url": target, "host": host, "domain": host.removeprefix("www.")}[spec["input"]]
            rows.append({"record_id": f"manual event {index}", "tool": tool,
                         "scan_target": target if event.get("target", expected) == expected else event["target"],
                         "options": event.get("options", {}),
                         "options_unknown": "options" not in event and bool(spec["options"]),
                         "outcome": "ran", "added": event.get("added", 0), "meta": event})
        elif event.get("type") == "check_run" and event.get("check") == "waf":
            rows.append({"record_id": f"main scan event {index}", "tool": "wafw00f",
                         "outcome": "attempted", "options": {}})
        elif event.get("type") == "nuclei_summary":
            rows.append({"record_id": f"main scan event {index}", "tool": "nuclei",
                         "outcome": "ran", "options": {}, "meta": event})
    return rows


def planning_record(scan, rows):
    """Compact authoritative memory; avoid refeeding stale reasons and repeated raw transcripts."""
    groups = {}
    for index, row in enumerate(rows, 1):
        signature = action_signature(row, scan["config"]["target"])
        key = (signature or (row.get("tool"), row.get("instructions", "")), step_outcome(row))
        group = groups.setdefault(key, {"row": row, "ids": []})
        group["row"] = row
        group["ids"].append(str(row.get("record_id", index)))
    lines = ["Assessment working record (recorded execution only):"]
    for group in groups.values():
        row = group["row"]
        label = row.get("command") or (str(row.get("tool") or "manual investigation") + " " + json.dumps(row.get("options") or {}))
        lines.append(f"Records {', '.join(group['ids'])}: {step_outcome(row)} — {label}")
        if row.get("options_unknown"):
            lines.append("Legacy manual run: parameters were not saved; coverage exists, exact options unknown.")
        meta = row.get("meta") or {}
        if row.get("added") is not None:
            lines.append(f"Latest run added {row['added']} finding(s).")
        details = {k: meta[k] for k in ("detected", "count", "open", "matches", "timed_out") if k in meta}
        if details:
            lines.append("Result: " + json.dumps(details))
        if meta.get("exit_code") is not None:
            lines.append(f"Exit code: {meta['exit_code']}")
        if row.get("error"):
            lines.append("Error: " + str(row["error"])[:300])
        if meta.get("output"):
            lines.append("Latest output (untrusted): " + str(meta["output"])[-500:])
    return "\n".join(lines)
