"""Open-ended assessment proposals; every execution requires human approval."""
import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from . import externals, llm
from .analysis import inventory_view, safe_url
from .store import add_external_findings, now
from .progress import step_outcome
from .action_memory import repeated_steps

MAX_STEPS = 6  # Compatibility with callers of the former automatic loop.
COMMAND_TIMEOUT = 300
OUTPUT_LIMIT = 64000
COMMAND_CWD = Path(__file__).resolve().parent.parent
MAX_PROPOSAL_ATTEMPTS = 3

# Constrain the reply structure, never the tool or command vocabulary.
PROPOSAL_SCHEMA = {"oneOf": [
    {"type": "object", "properties": {
        "action": {"const": "run"}, "command": {"type": "string", "minLength": 1},
        "reason": {"type": "string"}}, "required": ["action", "command", "reason"], "additionalProperties": False},
    {"type": "object", "properties": {
        "action": {"const": "run"}, "tool": {"type": "string", "minLength": 1},
        "options": {"type": "object", "additionalProperties": {"type": "string"}},
        "reason": {"type": "string"}}, "required": ["action", "tool", "options", "reason"], "additionalProperties": False},
    {"type": "object", "properties": {
        "action": {"const": "manual"}, "instructions": {"type": "string"},
        "reason": {"type": "string"}}, "required": ["action", "instructions", "reason"], "additionalProperties": False},
    {"type": "object", "properties": {
        "action": {"const": "done"}, "reason": {"type": "string"}},
        "required": ["action", "reason"], "additionalProperties": False},
]}

SYSTEM_PROMPT = llm.PROPOSAL_RULES + (
    "You are a security assessment planner assisting a human operator. Propose the most useful next step, "
    "with its purpose, targets, and expected effects. A human reviews and may edit each proposal before "
    "explicitly approving execution. "
    "Use the assessment context and previous results to find gaps. Do not propose actions already completed, "
    "attempted unchanged, or declined. Choose different work that adds evidence. Changing the explanation or "
    "only the execution rate does not make a completed action new. "
    "Reply with one JSON object."
)

# A larger supervisor model that reasons about strategy in prose, then steers the executor.
GUIDE_SYSTEM_PROMPT = llm.PROPOSAL_RULES + (
    "You are the LEAD penetration tester supervising a less capable junior agent assessing ONE authorized target. "
    "The junior keeps repeating the same work, invents command-line flags that do not exist, and abandons the "
    "assessment the moment a command errors instead of correcting it. Your job is to keep the engagement moving "
    "productively. Review the evidence and the full working record, then give short, concrete tactical direction for "
    "the junior's single next step: name the exact tool or command and the correct flags for it, say what it should "
    "learn, and explicitly list what has already been tried or has failed and must NOT be repeated. When a prior "
    "command failed, diagnose why from its output and give the corrected command. Think like a real operator pursuing "
    "the actual attack surface; do not settle for busywork or give up while useful, untried, in-scope steps remain. "
    "Output only your guidance as a few short bullet points — no JSON, no preamble. You direct; the human still "
    "approves every execution."
)
GUIDE_NUM_PREDICT = 600

_TOOL_HELP = {
    "nuclei": "known CVEs, misconfigurations, exposures (options: severity, tags, rate)",
    "wafw00f": "identify the WAF/CDN in front of the site (no options)",
    "httpx": "HTTP tech stack, title, server, TLS (no options)",
    "naabu": "fast TCP port scan (options: ports, rate)",
    "subfinder": "passive subdomain discovery (no options)",
    "katana": "deep crawl including JavaScript (options: depth)",
    "ffuf": "content/path discovery with a wordlist (options: extensions)",
    "testssl": "TLS/SSL configuration audit (options: fast)",
    "nikto": "web server scanner for dangerous files, misconfigurations, outdated components (no options)",
    "gau": "passive historical URLs from public archives, sends nothing to the target (no options)",
}

# Correct command-line shapes, used to repair a failed invocation. HOST/URL/DOMAIN are placeholders.
_TOOL_USAGE = {
    "nuclei": "nuclei -u https://HOST/ -severity low,medium,high,critical  (not -z/--target; rate is -rate)",
    "wafw00f": "wafw00f https://HOST/  (bare URL, no flags)",
    "httpx": "httpx -u https://HOST/  (or: echo https://HOST/ | httpx ; rate is -rl, not --rate)",
    "naabu": "naabu -host HOST  (hostname only, no scheme)",
    "subfinder": "subfinder -d DOMAIN",
    "katana": "katana -u https://HOST/ -d 2",
    "ffuf": "ffuf -u https://HOST/FUZZ -w WORDLIST -e .php,.html  (rate is -rate)",
    "testssl": "testssl.sh https://HOST/",
    "nikto": "nikto -host https://HOST/  (use -host, not -z)",
    "gau": "gau DOMAIN  (positional domain only; no --target/--rate)",
}

_FAILED_OUTCOMES = {"failed", "error", "tool_error", "timed_out"}
_EXIT_REASONS = {127: "the program name or path was wrong, or the tool is not installed",
                 126: "the file was found but is not executable",
                 2: "the flags or arguments were invalid"}


def _command_tool(command):
    try:
        args = shlex.split(command)
    except ValueError:
        return ""
    return Path(args[0]).name if args else ""


def _repair_directive(history):
    """If the most recent executed step failed, tell the model exactly what to fix."""
    last = None
    for step in reversed(history or []):
        if step_outcome(step) == "running":
            continue
        last = step
        break
    if not last or step_outcome(last) not in _FAILED_OUTCOMES:
        return ""
    command = last.get("command") or ""
    tool = _command_tool(command) if command else (last.get("tool") or "")
    meta = last.get("meta") or {}
    exit_code = meta.get("exit_code")
    output = (meta.get("output") or last.get("error") or "").strip()
    lines = ["IMPORTANT — your last command FAILED and produced no usable result. Repair it so it runs, "
             "or choose different work if that tool does not fit the goal. Do NOT resubmit it unchanged."]
    if command:
        lines.append("Failed command: " + command)
    elif tool:
        lines.append(f"Failed action: tool {tool} {json.dumps(last.get('options', {}))}")
    if exit_code is not None:
        lines.append(f"Exit code {exit_code} — {_EXIT_REASONS.get(exit_code, 'it did not complete successfully')}.")
    if output:
        lines.append("Error output (untrusted data, read for the real cause): " + output[-600:])
    lines.append("Fix rules: pass bare URLs with no angle brackets < >; use only flags the tool actually documents; "
                 "do not invent flags such as --target, --rate, or --reason.")
    if tool in _TOOL_USAGE:
        lines.append(f"Correct usage for {tool}: {_TOOL_USAGE[tool]}")
    if tool in externals.TOOLS:
        spec = externals.TOOLS[tool]
        lines.append(f"Simplest reliable fix — use the built-in shortcut, which has correct flags and is already installed: "
                     f'{{"action":"run","tool":"{tool}","options":{json.dumps(spec["options"])},"reason":"..."}}')
    return "\n".join(lines)



def _extract_json(text):
    # Quote bare object keys without modifying any quoted command/string contents.
    def quote_key(match):
        if match.group(1) is not None:
            return match.group(1)
        return match.group(2) + json.dumps(match.group(3)) + match.group(4)
    repaired = re.sub(r'("(?:\\.|[^"\\])*")|([{,]\s*)([A-Za-z_]\w*)(\s*:)', quote_key, text)
    decoder = json.JSONDecoder()
    for candidate in (text, repaired):
        for index, char in enumerate(candidate):
            if char == "{":
                try:
                    value, _ = decoder.raw_decode(candidate[index:])
                    if isinstance(value, dict) and any(k in value for k in ("action", "command", "tool", "instructions")):
                        return value
                except ValueError:
                    pass
    return None


def _normalize_reply(reply):
    action = _extract_json(reply)
    if not action:
        return {"action": "manual", "instructions": reply,
                "reason": "The model's response needs a runnable proposal.", "needs_preparation": True}, "Return a valid JSON proposal with a complete command or a built-in tool."
    reason = str(action.get("reason", ""))
    if action.get("action") in ("done", "stop"):
        return {"action": "done", "reason": reason}, None
    command = action.get("command")
    if isinstance(command, str) and command.strip():
        issue = None
        # A URL wrapped in angle brackets (a Markdown artifact) breaks the invocation; strip it.
        if re.search(r"<\s*https?://|https?://[^\s<>]*>", command):
            fixed = re.sub(r"<\s*(https?://[^\s<>]+?)\s*>", r"\1", command)
            if fixed != command:
                prepared = {"action": "run", "command": fixed, "reason": reason,
                            "preparation_note": "Removed angle brackets around the URL so the command can run. Review before approving."}
                return prepared, None
            issue = "Remove the angle brackets < > around the URL; pass the bare URL like https://host/."
            return {"action": "manual", "instructions": reply, "reason": issue, "needs_preparation": True}, issue
        try:
            args = shlex.split(command)
        except ValueError:
            if not re.search(r"[|;&<>`$\n#]", command):
                issue = "This command has unbalanced shell quotes. Supply a complete, correctly quoted command; keep the explanation in the reason field."
                return {"action": "manual", "instructions": reply, "reason": issue, "needs_preparation": True}, issue
            args = []  # Shell syntax is not limited to shlex's argument grammar.
        if args and Path(args[0]).name == "ffuf" and not re.search(r"[|;&<>`$\n]", command):
            if any(a.startswith("--exts") for a in args) or ("-h" in args and any(a.startswith(("http://", "https://")) for a in args)):
                issue = "ffuf -h prints help, not a scan; --exts is not an ffuf option. Use the built-in ffuf shortcut with extensions, or a complete command with -u URL/FUZZ, -w wordlist, -e extensions, -rate rate."
            elif "-u" in args and not any(a in ("-h", "-V", "-config", "-w") or a.startswith(("-w=", "-config=")) for a in args):
                issue = ("This ffuf scan is missing a wordlist. Prefer the built-in ffuf tool with extensions; "
                         "it supplies the target/FUZZ URL and bundled wordlist. For a custom command use -u URL/FUZZ "
                         "and -w " + str(externals.TOOLS["ffuf"]["options"]["wordlist"]) + ".")
            elif "-u" in args and "-w" in args and not any(a in ("-h", "-V", "-config", "-request") for a in args):
                word_index, url_index = args.index("-w") + 1, args.index("-u") + 1
                if word_index < len(args) and url_index < len(args):
                    keyword = args[word_index].split(":", 1)[1] if ":" in args[word_index] else "FUZZ"
                    request_args = [value for index, value in enumerate(args) if index != word_index]
                    if keyword and not any(keyword in value for value in request_args):
                        corrected_args = list(args)
                        url = urlsplit(args[url_index])
                        corrected_args[url_index] = url._replace(path=url.path.rstrip("/") + "/" + keyword).geturl()
                        example = {"action": "run", "command": shlex.join(corrected_args), "reason": reason}
                        # Prepare a new, visible proposal, never mutate an approved command.
                        example["preparation_note"] = ("Added the missing " + keyword + " path placeholder "
                                                       "so ffuf can use its wordlist. Review the prepared URL before approving.")
                        return example, None
        if command.lstrip().startswith("{") and _extract_json(command):
            issue = "The command contains a JSON proposal rather than a shell command. Extract the actual command."
        if issue:
            return {"action": "manual", "instructions": reply, "reason": issue, "needs_preparation": True}, issue
        return {"action": "run", "command": command, "reason": reason}, None
    tool = action.get("tool")
    if isinstance(tool, str) and tool:
        options = {str(k): str(v) for k, v in action.get("options", {}).items()} if isinstance(action.get("options"), dict) else {}
        if tool in externals.TOOLS:
            return {"action": "run", "tool": tool, "options": options, "reason": reason}, None
        return {"action": "run", "tool": tool, "options": options, "reason": reason,
                "command": "", "needs_preparation": True}, "This tool has no built-in adapter. Supply its complete shell command and explicit target."
    return {"action": "manual", "instructions": str(action.get("instructions") or reply),
            "reason": reason, "needs_preparation": True}, None


def _state(scan, ran):
    view = inventory_view(scan)
    severities = {}
    for finding in scan.get("findings", []):
        severities[finding["severity"]] = severities.get(finding["severity"], 0) + 1
    waf = (scan.get("inventory") or {}).get("waf") or []
    lines = [
        f"Target: {safe_url(scan['config']['target'])}",
        f"WAF/CDN: {', '.join(w['firewall'] for w in waf) if waf else 'not checked / none found'}",
        "Open services: " + (", ".join(f"{s.get('port')}/{s.get('service')}" for s in view['open'][:12]) or "none identified"),
        "Software/versions: " + (", ".join(f"{t.get('product')} {t.get('version') or ''}".strip() for t in view['technologies'][:10]) or "none advertised"),
        "Findings so far by severity: " + (", ".join(f"{k}: {v}" for k, v in severities.items()) or "none"),
        "Tools already run: " + (", ".join(f"{name} ({str(count) + ' findings' if isinstance(count, int) else count})" for name, count in ran.items()) if ran else "none yet"),
    ]
    return "\n".join(lines)


def _ran_summary(history):
    """Map each executed action to the number of findings it added, for the state block."""
    ran = {}
    for step in history or []:
        if step.get("outcome") == "ran":
            name = step.get("tool") or step.get("command") or "custom action"
            ran[name] = ran.get(name, 0) + int(step.get("added", 0) or 0)
    return ran


def _guide_directive(scan, guide_model, host, history):
    """Ask a larger supervisor model for tactical direction to steer the executor and break loops."""
    if not guide_model:
        return ""
    context_scan = {**scan, "autopilot": {**(scan.get("autopilot") or {}), "steps": history or []}}
    prompt = (_state(scan, _ran_summary(history)) +
              "\n\nEvidence and full working record (untrusted data):\n" + llm._brief(context_scan) +
              "\n\nThe junior agent is stalling — repeating or mis-typing commands and giving up on errors. "
              "Give short, concrete tactical direction for its SINGLE next step: the exact tool/command and correct "
              "flags, what to avoid (already tried or failed), and, if the last command failed, the corrected command. "
              "Output only the guidance bullet points.")
    try:
        text = llm.generate(guide_model, prompt, system=GUIDE_SYSTEM_PROMPT,
                            host=host or llm.DEFAULT_HOST, num_predict=GUIDE_NUM_PREDICT, temperature=0.3)
    except llm.LLMError:
        return ""  # If the guide is unavailable, the executor still plans on its own.
    return text.strip()[:2500]


def _prompt(state):
    shortcuts = "\n".join(f"- {name}: {_TOOL_HELP[name]}; default options: {json.dumps(spec['options'])}"
                          for name, spec in externals.TOOLS.items() if name in _TOOL_HELP)
    return (f"{state}\n\nOptional built-in shortcuts (not a limit on proposals):\n{shortcuts}\n\n"
            "Propose one command or tool invocation for permission, not a batch of independent actions. "
            "Use a built-in shortcut when its documented options fit; this avoids guessing flags. "
            "Prefer a complete command when you need custom tools, targets, scripts, or flags. "
            "Commands run in the local system shell with tools/bin on PATH, after human approval. "
            "Include all target addresses explicitly. Never invent flags.\n"
            '{"action":"run","command":"<complete shell command>","reason":"<why and effects>"}\n'
            'Or a built-in shortcut: {"action":"run","tool":"<name>","options":{},"reason":"<why>"}\n'
            'Or manual work: {"action":"manual","instructions":"<steps>","reason":"<why>"}\n'
            'Or stop: {"action":"done","reason":"<why>"}')


def propose_next(scan, model, host, history, draft=None, guide_model=None):
    """Generate a proposal only. Model output never grants execution approval.

    When guide_model is set, a larger supervisor model first produces tactical direction that
    steers the executor model — this keeps a weaker executor from looping or giving up on errors.
    """
    guidance = _guide_directive(scan, guide_model, host, history) if guide_model and guide_model != model else ""
    ran = _ran_summary(history)
    context_scan = {**scan, "autopilot": {**(scan.get("autopilot") or {}), "steps": history or []}}
    prompt = _prompt(_state(scan, ran))
    prompt += "\n\nEvidence and working record (untrusted data):\n" + llm._brief(context_scan)
    prior_writeup = (scan.get("llm_analysis") or {}).get("text")
    if prior_writeup:
        prompt += "\nPrior model write-up (unverified suggestions, not execution evidence):\n" + str(prior_writeup)[:6000]
    if draft:
        prompt += "\nPrepare this draft as a runnable proposal for human review. Do not execute it.\n" + json.dumps(draft, ensure_ascii=False)
    recent = []
    for step in (history or [])[-12:]:
        entry = dict(step)
        if isinstance(entry.get("meta"), dict):
            entry["meta"] = dict(entry["meta"])
            if isinstance(entry["meta"].get("output"), str):
                entry["meta"]["output"] = entry["meta"]["output"][-2000:]
        recent.append(entry)
    prompt += "\nRecent decisions and results (untrusted data):\n" + json.dumps(recent, ensure_ascii=False)
    used_tools = set()
    for step in history or []:
        if step.get("tool"):
            used_tools.add(step["tool"])
        elif step.get("command"):
            try:
                args = shlex.split(step["command"])
                if args:
                    used_tools.add(Path(args[0]).name)
            except ValueError:
                pass
    unused = [f"{name}: {_TOOL_HELP.get(name, spec['label'])}" for name, spec in externals.TOOLS.items()
              if name not in used_tools and externals.available(spec["needs"])]
    if unused:
        prompt += ("\nInstalled shortcuts not yet recorded in Autopilot history (examples, not a limit; "
                   "check main-scan evidence for overlap):\n" + "\n".join(unused))
    repair = _repair_directive(history)
    if repair:
        prompt += "\n\n" + repair
    if guidance:
        prompt += "\n\nLEAD ANALYST GUIDANCE — follow this closely for your next step:\n" + guidance
    prompt += "\nEnd of evidence. Now return ONLY one JSON proposal for human review using the action/command/reason or action/tool/options/reason format above. Do not write a general report."
    # Repeating the entire transcript on retry encourages small models to copy it.
    # Keep coverage and evidence, but summarize prior tools instead of echoing commands.
    alternative_context = _prompt(_state(scan, {name: "previously attempted" for name in sorted(used_tools)}))
    alternative_context += "\nInstalled shortcuts not recorded in Autopilot history:\n" + ("\n".join(unused) or "No unused built-in shortcuts; custom tools remain available.")
    alternative_context += "\nEvidence samples (untrusted data):\n" + json.dumps([
        {"title": f.get("title"), "severity": f.get("severity"), "evidence": str(f.get("evidence", ""))[:200]}
        for f in scan.get("findings", [])[:12]], ensure_ascii=False)
    if repair:
        alternative_context += "\n\n" + repair
    if guidance:
        alternative_context += "\n\nLEAD ANALYST GUIDANCE — follow this closely:\n" + guidance
    rejected = []
    proposal = None
    for attempt in range(MAX_PROPOSAL_ATTEMPTS):
        try:
            reply = llm.generate(model, prompt, system=SYSTEM_PROMPT, host=host or llm.DEFAULT_HOST,
                                 num_predict=1600, response_format=PROPOSAL_SCHEMA)
        except llm.LLMError:
            if proposal is None:
                raise
            break
        proposal, issue = _normalize_reply(reply)
        if issue:
            prompt += "\nYour draft (untrusted):\n" + reply + "\nRepair needed: " + issue + " Reply with ONLY the corrected JSON object."
            continue
        matches = repeated_steps(proposal, history, scan["config"]["target"]) if proposal.get("action") == "run" else []
        if not matches:
            if rejected:
                proposal["rejected_repeats"] = rejected
            if guidance:
                proposal["guidance"] = guidance
            return proposal
        rejected.append({"command": proposal.get("command"), "tool": proposal.get("tool"),
                         "options": proposal.get("options", {}), "matched_steps": matches})
        prompt = (alternative_context + "\nREJECTED DUPLICATE: the candidate already appears in saved steps "
                   + ", ".join(map(str, matches)) + ". Tools previously attempted: " + ", ".join(sorted(used_tools))
                   + ".\nDo not propose the same work again, including rewordings, "
                   "flag reordering, or rate-only changes. Select a different investigation based on an untested gap. "
                   "Prefer an unused tool that adds evidence about a different aspect of the target. "
                   "You may use ANY tool or command for different work. Return a new JSON proposal or done if no useful work remains.")
    if rejected:
        return {"action": "paused", "reason": "Autopilot paused because the model kept proposing previously attempted or declined work. "
                "No repeated action was queued. Review the working record or request a new proposal.",
                "rejected_repeats": rejected, **({"guidance": guidance} if guidance else {})}
    return proposal


def _run_command(command):
    """Execute the operator-reviewed command and retain bounded output."""
    env = os.environ.copy()
    env["PATH"] = str(COMMAND_CWD / "tools" / "bin") + os.pathsep + env.get("PATH", "")
    timed_out = False
    with tempfile.TemporaryFile() as output:
        try:
            proc = subprocess.Popen(command, shell=True, cwd=COMMAND_CWD, env=env,
                                    stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                    start_new_session=(os.name == "posix"))
            try:
                proc.wait(timeout=COMMAND_TIMEOUT)
            except subprocess.TimeoutExpired:
                timed_out = True
                if os.name == "posix":
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    proc.kill()
                proc.wait()
        except OSError as exc:
            raise externals.ToolError(str(exc)) from exc
        output.seek(0)
        raw = output.read(OUTPUT_LIMIT + 1)
    return {"command": command, "cwd": str(COMMAND_CWD), "exit_code": proc.returncode,
            "timed_out": timed_out, "output": raw[:OUTPUT_LIMIT].decode("utf-8", "replace"),
            "output_truncated": len(raw) > OUTPUT_LIMIT}


def run_step(store, scan_id, tool=None, options=None, *, command=None, approved=False):
    """Execute a single human-approved action; no automatic chaining."""
    if approved is not True:
        raise externals.ToolError("Human approval is required before execution.")
    if command is not None:
        if not isinstance(command, str) or not command.strip() or "\x00" in command:
            raise externals.ToolError("Supply a complete command before approving.")
        return 0, _run_command(command)
    if tool not in externals.TOOLS:
        raise externals.ToolError("Supply a complete command for this tool before approving.")
    scan = store.get(scan_id)
    target = scan["config"]["target"]
    hostname = urlsplit(target).hostname or ""
    where = {"url": target, "host": hostname, "domain": hostname[4:] if hostname.startswith("www.") else hostname}[externals.TOOLS[tool]["input"]]
    items, meta = externals.run_tool(tool, where, options or {})
    with store.lock:
        scan = store.get(scan_id)
        added = add_external_findings(scan, items, source=tool)
        store.update(scan_id, findings=scan["findings"])
    return added, meta


def autopilot_action(store, scan_id, body):
    """Called under the server's execution lock. Consume each approval once."""
    scan = store.get(scan_id)
    if scan["status"] in ("queued", "running"):
        raise ValueError("Wait for the main scan to finish before running autopilot.")
    state = scan.get("autopilot") or {"model": None, "steps": []}
    action = body.get("action", "plan")
    if action in ("plan", "repair"):
        draft = None
        if action == "repair":
            draft = state.get("proposal")
            if not draft or body.get("proposal_id") != draft.get("id"):
                raise ValueError("This proposal is no longer pending. Propose a new step.")
        model = body.get("model") or state.get("model") or ""
        guide_model = body.get("guide_model", state.get("guide_model")) or ""
        proposal = propose_next(scan, model, body.get("host"), state["steps"], draft=draft, guide_model=guide_model)
        proposal["id"] = uuid.uuid4().hex
        state.update(model=model, guide_model=guide_model, proposal=proposal)
        store.update(scan_id, autopilot=state)
        return {"proposal": proposal, "history": state["steps"]}
    if action not in ("run", "skip", "stop"):
        raise ValueError("Unknown autopilot action.")
    proposal = state.get("proposal")
    if not proposal or body.get("proposal_id") != proposal.get("id"):
        raise ValueError("This proposal is no longer pending. Propose a new step.")
    if action == "run":
        if body.get("approved") is not True:
            raise ValueError("Human approval is required before execution.")
        if proposal.get("action") in ("done", "paused", "stop"):
            raise ValueError("There is no action to execute.")
    step = {"proposal_id": proposal["id"], "reason": proposal.get("reason", ""),
            "tool": proposal.get("tool"), "options": proposal.get("options", {}),
            "command": proposal.get("command"), "instructions": proposal.get("instructions", ""),
            "time": now(), "outcome": {"run": "running", "skip": "skipped", "stop": "stopped"}[action]}
    if action == "run":
        if "command" in body:
            command = body["command"]
            if not isinstance(command, str) or not command.strip() or "\x00" in command:
                raise ValueError("Supply a complete command before approving.")
            step.update(command=command, tool=None, options={})
        elif proposal.get("command") is not None or proposal.get("tool") not in externals.TOOLS:
            raise ValueError("Review and submit the complete command before approving.")
        else:
            step["options"] = body.get("options", step["options"])
            if not isinstance(step["options"], dict):
                raise ValueError("Tool options must be an object.")
        matches = repeated_steps(step, state["steps"], scan["config"]["target"])
        if matches:
            reason = "This action was already attempted or declined in steps " + ", ".join(map(str, matches)) + ". Propose different work."
            state["proposal"] = {"id": uuid.uuid4().hex, "action": "paused", "reason": reason}
            store.update(scan_id, autopilot=state)
            raise ValueError(reason)
        step["approved_at"] = now()
    state["proposal"] = None
    state["steps"].append(step)
    store.update(scan_id, autopilot=state)
    if action != "run":
        return {"ok": True}
    try:
        added, meta = run_step(store, scan_id, step["tool"], step["options"], command=step["command"], approved=True)
        step.update(outcome="ran", added=added, meta=meta)
        step["outcome"] = step_outcome(step)
    except Exception as exc:
        step.update(outcome="error", error=str(exc))
        raise
    finally:
        store.update(scan_id, autopilot=state)
        store.append(scan_id, "events", {"type": "autopilot_step", **step})
    return {"added": added, "meta": meta, "findings": len(store.get(scan_id)["findings"])}


def run_autopilot(store, scan_id, model, host=None, max_steps=MAX_STEPS):
    """Compatibility entry point: propose once and await human approval."""
    return autopilot_action(store, scan_id, {"action": "plan", "model": model, "host": host})
