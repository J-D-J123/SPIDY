import hmac
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .scanner import Scanner, focus_checks, validate_config
from .store import LIMITATIONS, add_external_findings, markdown_report, now
from .analysis import advisory_verification, analyze, email_draft
from .host_inventory import validate_host_inventory
from . import llm, externals, agent
from .pdf_report import pdf_report
from .progress import assessment_progress


class ScanManager:
    def __init__(self, store, allow_private=False):
        self.store, self.allow_private = store, allow_private
        self.lock = threading.RLock()
        self.worker = None
        self.stop = None
        self.current_id = None

    def _start(self, config, approved=None, parent=None, seeds=None, denied=None, added=None):
        if self.worker and self.worker.is_alive():
            raise ValueError("A scan is already running. Stop it or wait for it to finish.")
        scan = self.store.create(config, approved, parent)
        if seeds or denied or added:
            self.store.update(scan["id"], seed_urls=seeds or [], denied_origins=denied or [], added_origins=added or [])
        self.stop = threading.Event()
        self.current_id = scan["id"]
        scanner = Scanner(self.store, scan["id"], self.allow_private, self.stop)
        self.worker = threading.Thread(target=scanner.run, daemon=True)
        self.worker.start()
        return self.store.get(scan["id"])

    def start(self, raw):
        config = validate_config(raw)
        with self.lock:
            return self._start(config)

    def cancel(self, scan_id):
        with self.lock:
            if self.current_id != scan_id or not self.worker or not self.worker.is_alive():
                raise ValueError("This scan is not running.")
            self.stop.set()
            self.store.append(scan_id, "events", {"time": now(), "type": "cancel_requested"})
        return {"ok": True}

    def decide(self, scan_id, body):
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError("Wait for the running scan to finish before applying scope decisions.")
            scan = self.store.get(scan_id)
            approve, deny = body.get("approve", []), body.get("deny", [])
            if not isinstance(approve, list) or not isinstance(deny, list) or not all(isinstance(o, str) for o in approve + deny):
                raise ValueError("Scope decisions must be lists of origins.")
            if not approve and not deny:
                raise ValueError("Select an origin to approve or deny.")
            if set(approve) & set(deny):
                raise ValueError("An origin cannot be both approved and denied.")
            pending = {p["origin"] for p in scan["pending_origins"] if p["decision"] == "pending"}
            if not set(approve + deny) <= pending:
                raise ValueError("Only pending origins can be approved or denied.")
            if approve and body.get("authorized") is not True:
                raise ValueError("Confirm permission to assess the additional origins.")
            for p in scan["pending_origins"]:
                if p["origin"] in approve:
                    p["decision"] = "approved"
                elif p["origin"] in deny:
                    p["decision"] = "denied"
            self.store.update(scan_id, pending_origins=scan["pending_origins"])
            self.store.append(scan_id, "events", {"time": now(), "type": "scope_decision", "approved": approve, "denied": deny})
            if approve:
                seeds = [p["url"] for p in scan["pending_origins"] if p["origin"] in approve]
                approved = sorted(set(scan["approved_origins"] + approve))
                denied = sorted(set(scan.get("denied_origins", []) + [p["origin"] for p in scan["pending_origins"] if p["decision"] == "denied"]))
                return self._start(scan["config"], approved, scan_id, seeds, denied, added=approve)
            return self.store.get(scan_id)


def create_server(store, port=8765, allow_private=False, demo_target=None):
    manager = ScanManager(store, allow_private)
    autopilot_lock = threading.Lock()
    autopilot_workers = {}
    autopilot_workers_lock = threading.Lock()
    token = secrets.token_urlsafe(32)
    static = Path(__file__).parent / "static"

    def settle_autopilot_task(scan_id, task_id, error):
        """Clear the in-flight marker once the background plan/run finishes."""
        with store.lock:
            scan = store.get(scan_id)
            state = scan.get("autopilot") or {}
            task = state.get("task") or {}
            if task.get("id") != task_id:
                return  # Superseded by a newer action; leave its marker alone.
            state["task"] = {**task, "status": "error", "error": error, "ended": now()} if error else None
            store.update(scan_id, autopilot=state)

    def run_autopilot_task(scan_id, body, task_id):
        """Do the slow work (LLM planning or tool/command execution) off the request thread."""
        try:
            agent.autopilot_action(store, scan_id, body)
            settle_autopilot_task(scan_id, task_id, None)
        except (llm.LLMError, externals.ToolError, ValueError) as exc:
            settle_autopilot_task(scan_id, task_id, str(exc))
        except Exception as exc:  # noqa: BLE001 - surface any failure to the operator, never hang
            settle_autopilot_task(scan_id, task_id, "Autopilot could not complete that action: " + str(exc))

    def dispatch_autopilot(scan_id, body):
        """Return immediately: planning and execution run in the background and are polled."""
        action = body.get("action", "plan")
        with autopilot_lock:
            scan = store.get(scan_id)
            if scan["status"] in ("queued", "running"):
                raise ValueError("Wait for the main scan to finish before running autopilot.")
            state = scan.get("autopilot") or {"model": None, "steps": []}
            task = state.get("task")
            with autopilot_workers_lock:
                worker = autopilot_workers.get(scan_id)
                alive = bool(worker and worker.is_alive())
            if task and task.get("status") == "running":
                if alive:
                    raise ValueError("An Autopilot action is in progress. Wait for it to finish.")
                state["task"] = None  # A task left "running" by a previous server process is stale.
                store.update(scan_id, autopilot=state)
            if action in ("skip", "stop"):
                return agent.autopilot_action(store, scan_id, body)  # Fast; keep it synchronous.
            if action not in ("plan", "repair", "run"):
                raise ValueError("Unknown autopilot action.")
            task_id = secrets.token_hex(8)
            kind = "run" if action == "run" else "plan"
            state.setdefault("steps", [])
            state["task"] = {"id": task_id, "kind": kind, "status": "running", "started": now()}
            store.update(scan_id, autopilot=state)
            worker = threading.Thread(target=run_autopilot_task, args=(scan_id, body, task_id), daemon=True)
            with autopilot_workers_lock:
                autopilot_workers[scan_id] = worker
            worker.start()
            return {"status": "working", "task": state["task"]}

    class Handler(BaseHTTPRequestHandler):
        server_version = "Spidy"

        def log_message(self, *_):
            pass

        def reply(self, status, data, content_type="application/json; charset=utf-8", download=None):
            payload = json.dumps(data).encode() if content_type.startswith("application/json") else (data.encode() if isinstance(data, str) else data)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if download:
                self.send_header("Content-Disposition", f'attachment; filename="{download}"')
            self.end_headers()
            self.wfile.write(payload)

        def trusted(self, mutation=False):
            actual_port = self.server.server_address[1]
            valid = {f"127.0.0.1:{actual_port}", f"localhost:{actual_port}"}
            host = self.headers.get("Host", "")
            if host not in valid:
                self.reply(403, {"error": "Untrusted Host header."})
                return False
            request_origin = self.headers.get("Origin")
            if request_origin and request_origin != f"http://{host}":
                self.reply(403, {"error": "Cross-origin requests are blocked."})
                return False
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                self.reply(403, {"error": "Cross-site requests are blocked."})
                return False
            if mutation and not hmac.compare_digest(self.headers.get("X-Spidy-Token", ""), token):
                self.reply(403, {"error": "Invalid session token. Reload the dashboard."})
                return False
            return True

        def do_GET(self):
            if not self.trusted():
                return
            path = urlsplit(self.path).path
            try:
                if path == "/api/config":
                    self.reply(200, {"token": token, "allow_private": allow_private, "demo_target": demo_target, "limitations": LIMITATIONS})
                elif path == "/api/scans":
                    self.reply(200, store.list())
                elif path == "/api/tools":
                    self.reply(200, {"tools": externals.tools_status()})
                elif path == "/api/llm/models":
                    try:
                        detailed = llm.models_detailed()
                        self.reply(200, {"available": True, "models": [m["name"] for m in detailed],
                                         "detailed": detailed, "host": llm.DEFAULT_HOST})
                    except llm.LLMError as exc:
                        self.reply(200, {"available": False, "models": [], "detailed": [], "host": llm.DEFAULT_HOST, "error": str(exc)})
                elif path.startswith("/api/scans/"):
                    pieces = path.strip("/").split("/")
                    if len(pieces) not in (3, 4):
                        raise KeyError()
                    scan = store.get(pieces[2])
                    scan["analysis"] = analyze(scan)
                    scan["advisory_verification"] = advisory_verification(scan)
                    scan["progress"] = assessment_progress(scan)
                    if len(pieces) == 3:
                        self.reply(200, scan)
                    elif pieces[3] == "report.md":
                        self.reply(200, markdown_report(scan), "text/markdown; charset=utf-8", f"spidy-{scan['id'][:8]}.md")
                    elif pieces[3] == "report.pdf":
                        self.reply(200, pdf_report(scan), "application/pdf", f"spidy-{scan['id'][:8]}.pdf")
                    elif pieces[3] == "report.json":
                        self.reply(200, scan, download=f"spidy-{scan['id'][:8]}.json")
                    elif pieces[3] == "email.txt":
                        self.reply(200, scan.get("email_draft", email_draft(scan, scan["analysis"])), "text/plain; charset=utf-8", f"spidy-{scan['id'][:8]}.email.txt")
                    else:
                        raise KeyError()
                elif path in ("/", "/app.js", "/style.css"):
                    filename, content_type = {"/": ("index.html", "text/html; charset=utf-8"),
                        "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}[path]
                    self.reply(200, (static / filename).read_bytes(), content_type)
                else:
                    raise KeyError()
            except KeyError:
                self.reply(404, {"error": "Not found"})

        def do_POST(self):
            if not self.trusted(mutation=True):
                return
            try:
                if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    raise ValueError("Expected application/json.")
                pieces = urlsplit(self.path).path.strip("/").split("/")
                inventory_import = len(pieces) == 4 and pieces[:2] == ["api", "scans"] and pieces[3] == "host-inventory"
                length = int(self.headers.get("Content-Length", "0"))
                # A host inventory lists up to 2000 packages; every other request is small.
                if not 0 < length <= (2_000_000 if inventory_import else 16384):
                    raise ValueError("Invalid request size.")
                self.connection.settimeout(5)
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError("Expected a JSON object.")
                if pieces == ["api", "scans"]:
                    self.reply(201, manager.start(body))
                elif pieces == ["api", "focus"]:
                    self.reply(200, {"checks": focus_checks(str(body.get("text", "")))})
                elif len(pieces) == 4 and pieces[:2] == ["api", "scans"] and pieces[3] == "cancel":
                    self.reply(200, manager.cancel(pieces[2]))
                elif len(pieces) == 4 and pieces[:2] == ["api", "scans"] and pieces[3] == "decisions":
                    self.reply(200, manager.decide(pieces[2], body))
                elif len(pieces) == 4 and pieces[:2] == ["api", "scans"] and pieces[3] == "draft":
                    scan = store.get(pieces[2])
                    draft = body.get("text")
                    if not isinstance(draft, str) or len(draft) > 12000:
                        raise ValueError("Draft must be text, up to 12000 characters.")
                    if scan["status"] in ("queued", "running"):
                        raise ValueError("Wait for this assessment to finish before saving its email draft.")
                    store.update(pieces[2], email_draft=draft)
                    self.reply(200, {"ok": True})
                elif len(pieces) == 4 and pieces[:2] == ["api", "scans"] and pieces[3] == "autopilot":
                    try:
                        result = dispatch_autopilot(pieces[2], body)
                    except (llm.LLMError, externals.ToolError) as exc:
                        raise ValueError(str(exc))
                    self.reply(200, result)
                elif len(pieces) == 4 and pieces[:2] == ["api", "scans"] and pieces[3] == "tool":
                    scan = store.get(pieces[2])
                    if scan["status"] in ("queued", "running"):
                        raise ValueError("Wait for the main scan to finish before running a deep scan.")
                    name = body.get("tool", "")
                    spec = externals.TOOLS.get(name)
                    if not spec:
                        raise ValueError("Unknown tool.")
                    from urllib.parse import urlsplit as _us
                    target_url = scan["config"]["target"]
                    host = _us(target_url).hostname or ""
                    where = {"url": target_url, "host": host, "domain": host[4:] if host.startswith("www.") else host}[spec["input"]]
                    options = body.get("options") if isinstance(body.get("options"), dict) else {}
                    try:
                        items, meta = externals.run_tool(name, where, options)
                    except externals.ToolError as exc:
                        raise ValueError(str(exc))
                    added = add_external_findings(scan, items, source=name)
                    store.update(pieces[2], findings=scan["findings"])
                    store.append(pieces[2], "events", {"time": now(), "type": "deep_scan", "tool": name, "target": where, "added": added, **meta})
                    self.reply(200, {"tool": name, "added": added, "findings": len(scan["findings"]), "meta": meta})
                elif len(pieces) == 4 and pieces[:2] == ["api", "scans"] and pieces[3] == "analyze":
                    scan = store.get(pieces[2])
                    if scan["status"] in ("queued", "running"):
                        raise ValueError("Wait for this assessment to finish before running a model analysis.")
                    host = body.get("host") or llm.DEFAULT_HOST
                    try:
                        result = llm.analyze_scan(scan, body.get("model", ""), host)
                    except llm.LLMError as exc:
                        raise ValueError(str(exc))
                    store.update(pieces[2], llm_analysis=result)
                    self.reply(200, result)
                elif inventory_import:
                    scan = store.get(pieces[2])
                    if scan["status"] in ("queued", "running"):
                        raise ValueError("Wait for this assessment to finish before importing a host inventory.")
                    store.update(pieces[2], inventory={**(scan.get("inventory") or {}),
                        "process_inventory": validate_host_inventory(body, scan["config"]["target"])})
                    self.reply(200, {"ok": True})
                else:
                    self.reply(404, {"error": "Not found"})
            except (ValueError, TypeError, UnicodeError) as exc:
                self.reply(400, {"error": str(exc)})
            except KeyError:
                self.reply(404, {"error": "Scan not found"})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.manager = manager
    return server
