import http.client
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .scope import normalize_url


@dataclass
class Response:
    url: str
    status: int
    headers: list
    body: str
    truncated: bool = False
    network: dict = field(default_factory=dict)

    def header(self, name):
        return ", ".join(v for k, v in self.headers if k.lower() == name.lower())


def readable_name(name):
    """Flatten ssl's nested certificate name tuples into 'commonName=example.com'."""
    return ", ".join(f"{key}={value}" for part in name for key, value in part)


def connect_pinned(addresses, timeout):
    last = None
    deadline = time.monotonic() + timeout
    for family, socktype, proto, _, address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Connection deadline exceeded")
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(remaining)
        try:
            sock.connect(address)
            return sock
        except OSError as exc:
            last = exc
            sock.close()
    raise last or OSError("No addresses available")


class Transport:
    def __init__(self, scope, record, cancelled, budget=100, delay=0.25, timeout=5):
        self.scope, self.record, self.cancelled = scope, record, cancelled
        self.budget, self.delay, self.timeout = budget, delay, timeout
        self.count = 0
        self.last_request = 0

    def get(self, url, purpose, check=None, headers=None, method="GET"):
        url = normalize_url(url)
        self.scope.require(url)
        if method not in ("GET", "HEAD", "OPTIONS"):
            raise ValueError("Only GET, HEAD, and OPTIONS are supported.")
        probe_headers = headers or {}
        if any(k != "Origin" for k in probe_headers) or any(re.search(r"[\r\n]", str(v)) for v in probe_headers.values()):
            raise ValueError("Only a plain Origin probe header is supported.")
        if self.cancelled():
            raise InterruptedError("Scan stopped by user")
        if self.count >= self.budget:
            raise InterruptedError("Request budget reached")
        time.sleep(max(0, self.delay - (time.monotonic() - self.last_request)))
        if self.cancelled():
            raise InterruptedError("Scan stopped by user")
        self.count += 1
        self.last_request = time.monotonic()
        started = time.monotonic()
        p = urlsplit(url)
        conn = http.client.HTTPConnection(p.hostname, p.port or (443 if p.scheme == "https" else 80), timeout=self.timeout)
        sock = None
        deadline_timer = None
        peer = None
        network = {}
        expired = threading.Event()
        def expire_connection():
            expired.set()
            # shutdown interrupts slow header/body reads even when a peer trickles bytes.
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        try:
            # Connect to the exact validated address; never resolve a second time.
            sock = connect_pinned(self.scope.resolve(url), self.timeout)
            peer = sock.getpeername()[0]
            network["ip"] = peer
            deadline_timer = threading.Timer(max(0.01, self.timeout - (time.monotonic() - started)), expire_connection)
            deadline_timer.daemon = True
            deadline_timer.start()
            if p.scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=p.hostname)
                certificate = sock.getpeercert()
                network.update(tls_version=sock.version(), cipher=sock.cipher()[0] if sock.cipher() else "",
                    certificate_not_after=certificate.get("notAfter", ""),
                    certificate_subject=readable_name(certificate.get("subject", ())), certificate_issuer=readable_name(certificate.get("issuer", ())),
                    certificate_dns_names=[name for kind, name in certificate.get("subjectAltName", ()) if kind == "DNS"][:32])
            conn.sock = sock
            conn.request(method, (p.path or "/") + (("?" + p.query) if p.query else ""), headers={
                "Host": p.netloc, "User-Agent": "Spidy/0.3 (authorized security assessment)",
                "Accept": "text/html,application/json;q=0.8,*/*;q=0.1", "Accept-Encoding": "identity", "Connection": "close",
                **probe_headers,
            })
            response = conn.getresponse()
            headers = response.getheaders()
            # Bound both response size and wall time, including slow streamed bodies.
            limit, chunks, size = 512 * 1024, [], 0
            while size <= limit:
                remaining = self.timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError("Response deadline exceeded")
                sock.settimeout(remaining)
                chunk = response.read1(min(16384, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                # http.client releases the socket as soon as a Content-Length body is complete.
                if response.isclosed():
                    break
            body = b"".join(chunks)[:limit].decode("utf-8", errors="replace")
            if expired.is_set():
                raise TimeoutError("Response deadline exceeded")
            result = Response(url, response.status, headers, body, size > limit, network)
            self.record("request", url=url, method=method, purpose=purpose, status=result.status,
                        check=check, request_headers=probe_headers,
                        ip=peer, tls_verified=p.scheme == "https", bytes=min(size, limit), truncated=result.truncated,
                        elapsed_ms=round((time.monotonic() - started) * 1000))
            return result
        except Exception as exc:
            self.record("request", url=url, method=method, purpose=purpose, check=check, request_headers=probe_headers, ip=peer, error=str(exc), elapsed_ms=round((time.monotonic() - started) * 1000))
            raise
        finally:
            if deadline_timer:
                deadline_timer.cancel()
            conn.close()
            if sock:
                sock.close()
