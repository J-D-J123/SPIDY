"""URL authorization and DNS validation, shared by every network operation."""
import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit


class ScopeError(ValueError):
    pass


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 4096 or re.search(r"[\x00-\x20\x7f\\]", value):
        raise ScopeError("Enter a valid HTTP(S) URL without spaces or control characters.")
    if "://" not in value:
        value = "https://" + value
    try:
        p = urlsplit(value)
        if p.scheme not in ("http", "https") or not p.hostname or p.username is not None or p.password is not None:
            raise ValueError()
        host = p.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if not host or "%" in host or not re.fullmatch(r"[a-z0-9.:-]+", host):
            raise ValueError()
        port = p.port if p.port is not None else (443 if p.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError()
    except (ValueError, UnicodeError) as exc:
        raise ScopeError("Invalid URL, hostname, or port.") from exc
    authority = f"[{host}]" if ":" in host else host
    if port != (443 if p.scheme == "https" else 80):
        authority += f":{port}"
    return urlunsplit((p.scheme, authority, p.path or "/", p.query, ""))


def origin(url: str) -> str:
    p = urlsplit(normalize_url(url))
    return f"{p.scheme}://{p.netloc}"


class Scope:
    def __init__(self, target: str, approved=(), allow_private=False):
        self.target = normalize_url(target)
        p = urlsplit(self.target)
        host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname
        self.origins = {origin(self.target), f"http://{host}", f"https://{host}"}
        self.origins.update(origin(u) for u in approved)
        self.allow_private = allow_private

    def permits(self, url: str) -> bool:
        return origin(url) in self.origins

    def require(self, url: str):
        if not self.permits(url):
            raise ScopeError(f"Origin requires approval: {origin(url)}")

    def resolve(self, url: str):
        # Authorize BEFORE DNS: even resolving an unapproved origin is disallowed.
        self.require(url)
        p = urlsplit(normalize_url(url))
        port = p.port or (443 if p.scheme == "https" else 80)
        addresses = socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)
        if not addresses:
            raise ScopeError("Hostname did not resolve.")
        for _, _, _, _, address in addresses:
            ip = ipaddress.ip_address(address[0])
            mapped = getattr(ip, "ipv4_mapped", None)
            if not self.allow_private and (not ip.is_global or ip.is_multicast or (mapped and (not mapped.is_global or mapped.is_multicast))):
                raise ScopeError("Private, loopback, reserved, or link-local address blocked. Use --allow-private only for an authorized local lab.")
        return addresses
