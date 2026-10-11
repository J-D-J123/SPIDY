"""A reproducible working record from saved execution evidence, not model guesses."""
import json


def step_outcome(step):
    outcome = step.get("outcome", step.get("status", "unknown"))
    meta = step.get("meta") or {}
    if outcome == "ran" and meta.get("timed_out"):
        return "timed_out"
    if outcome == "ran" and meta.get("exit_code") not in (None, 0):
        return "failed"
    return outcome


def assessment_progress(scan):
    """Include all prior decisions, grouping identical attempts without forgetting them."""
    steps = (scan.get("autopilot") or {}).get("steps", [])
    lines = ["Assessment working record", scan.get("summary") or "No main-scan summary yet.",
             "Recorded findings/review items: " + str(len(scan.get("findings", []))) + "."]
    groups = {}
    for index, step in enumerate(steps, 1):
        command = step.get("command")
        label = command or step.get("tool") or "manual investigation"
        options = step.get("options") or {}
        signature = json.dumps([label, options, step_outcome(step)], sort_keys=True)
        group = groups.setdefault(signature, {"step": step, "indices": [], "added": 0})
        group["indices"].append(str(index))
        group["added"] += int(step.get("added", 0) or 0)
        group["step"] = step
    lines.append(f"Autopilot decisions recorded: {len(steps)}.")
    for group in groups.values():
        step = group["step"]
        outcome = step_outcome(step)
        label = step.get("command") or step.get("tool") or "manual investigation"
        options = json.dumps(step["options"], sort_keys=True) if step.get("options") else ""
        indices = ", ".join(group["indices"])
        lines.append(f"Steps {indices}: {outcome} — {label} {options}".rstrip())
        if step.get("reason"):
            lines.append("Purpose: " + str(step["reason"]))
        meta = step.get("meta") or {}
        if outcome == "ran":
            if step.get("command"):
                lines.append("Command completed; output requires review. Custom output is not automatically counted as findings.")
            else:
                lines.append(f"Added {group['added']} finding(s) across {len(group['indices'])} run(s). "
                             + ("No new findings recorded; this does not establish absence of vulnerabilities." if not group["added"] else "Matches still require validation."))
        elif outcome in ("failed", "error", "tool_error", "timed_out"):
            lines.append("Execution did not complete successfully; do not treat it as a completed check.")
        elif outcome in ("skipped", "stopped"):
            lines.append("Not executed: operator declined or stopped this action.")
        if meta.get("exit_code") is not None:
            lines.append(f"Exit code: {meta['exit_code']}.")
        if step.get("error") or step.get("detail"):
            lines.append("Error: " + str(step.get("error") or step["detail"]))
        if meta.get("output"):
            lines.append("Latest output excerpt (untrusted evidence): " + str(meta["output"])[-800:])
    for event in scan.get("events", []):
        if event.get("type") == "deep_scan":
            lines.append(f"Manual deep scan: {event.get('tool')} on {event.get('target')}; added {event.get('added', 0)} finding(s).")
    pending = (scan.get("autopilot") or {}).get("proposal")
    if pending and pending.get("action") == "paused":
        lines.append("Autopilot paused: " + pending.get("reason", "No new action proposed."))
    elif pending and pending.get("action") not in ("done", "stop"):
        lines.append("The current proposal is pending review, NOT executed.")
    lines.append("Next: use these results to choose an untested gap or a justified refinement; do not repeat unchanged, unproductive actions.")
    return "\n".join(lines)
