"""Small loopback-only fixtures with deliberate, harmless security signals."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def start_demo():
    class DemoHandler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            p = urlsplit(self.path)
            q = parse_qs(p.query).get("q", [""])[0]
            if p.path == "/go":
                self.send_response(302)
                self.send_header("Location", parse_qs(p.query).get("next", ["/"])[0])
                self.end_headers()
                return
            fixtures = {"/.env": "APP_ENV=spidy_demo\nAPP_SECRET=FAKE_DEMO_VALUE\nDB_HOST=localhost\n",
                        "/.git/HEAD": "ref: refs/heads/demo\n",
                        "/config.php.bak": "<?php $demo_setting = 'placeholder'; ?>",
                        "/openapi.json": '{"openapi":"3.0.0","paths":{}}',
                        "/server-status": "Total Accesses: 1\nBusyWorkers: 1\n"}
            if p.path not in ("/", "/search") and p.path not in fixtures:
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Demo path not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8" if p.path in fixtures else "text/html; charset=utf-8")
            self.send_header("X-Powered-By", "Spidy-Demo/1.0")
            self.send_header("Set-Cookie", "demo_session=not-a-real-session; Path=/")
            if self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            if p.path in fixtures:
                body = fixtures[p.path]
            elif p.path == "/search":
                # Deliberately reflects inert Spidy markers and returns a mock SQL error.
                body = "<h1>Demo results</h1>" + ("SQLSTATE[42000]: demo query syntax error" if "'" in q else q)
            else:
                body = '''<!doctype html><title>Spidy local test target</title><h1>Spidy's local test target</h1>
                <p>This contains deliberate test signals, not a real application.</p>
                <a href="/search?q=spider">Search</a>
                <a href="/go?next=/">Demo redirect</a>
                <form method="get" action="/search"><input name="q" value="spider"></form>
                <form method="post" action="/account"><input name="display_name"></form>
                <form method="get" action="/login"><input type="password" name="password"></form>
                <a href="http://localhost:8767/">Separate demo origin: requires approval</a>'''
            self.wfile.write(body.encode())

    class ThirdPartyHandler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(b"<h1>Approved demo origin</h1><p>This origin should only be visited after explicit approval.</p>")

    servers = []
    try:
        for port, handler in ((8766, DemoHandler), (8767, ThirdPartyHandler)):
            server = ThreadingHTTPServer(("127.0.0.1", port), handler)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
    except OSError:
        for server in servers:
            server.shutdown()
            server.server_close()
        raise
    return servers
