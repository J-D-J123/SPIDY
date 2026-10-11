"""Use nmap for service/version detection when it is installed.

nmap is the standard tool for this and does it far better than a hand-rolled
socket scan, so Spidy prefers it and keeps the built-in connect scan only as a
fallback. Safety is preserved by the caller: Scope validates and pins the target
IP, and only that numeric address is handed to nmap, with DNS resolution disabled
(-n), so nmap never looks up or scans anything but the authorized target address.
"""
import ipaddress
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET


class NmapError(Exception):
    """A sanitized nmap failure; the caller falls back to the built-in scan."""


MAX_PORTS = 128
_VERSION = None
# nmap product strings map onto the same services the advisory lookup recognizes.
_SERVICE_ALIASES = {"http-proxy": "http", "http-alt": "http", "ssl/http": "https"}


def available():
    return shutil.which("nmap") is not None


def version():
    global _VERSION
    if _VERSION is None:
        try:
            out = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5,
                                 env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}).stdout
            match = re.search(r"Nmap version (\S+)", out)
            _VERSION = match.group(1) if match else "unknown"
        except (OSError, subprocess.SubprocessError):
            _VERSION = "unknown"
    return _VERSION


def _clean(value, limit=300):
    return re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f]", " ", str(value))).strip()[:limit]


def parse(data):
    """Turn nmap XML into Spidy service records. Unparseable output is an error."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise NmapError(f"could not parse nmap output: {exc}")
    services = []
    for host in root.findall("host"):
        address = host.find("address")
        ip = address.get("addr", "") if address is not None else ""
        for port in host.findall("./ports/port"):
            try:
                portid = int(port.get("portid"))
            except (TypeError, ValueError):
                continue
            state_el = port.find("state")
            raw_state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            state = {"open": "open", "closed": "closed"}.get(raw_state, "filtered/unknown")
            svc = port.find("service")
            name = product = version_str = method = tunnel = extra = cpe = ""
            conf = 0
            if svc is not None:
                name = svc.get("name", "") or ""
                product = _clean(svc.get("product", ""), 120)
                version_str = _clean(svc.get("version", ""), 60)
                method = svc.get("method", "") or ""
                tunnel = svc.get("tunnel", "") or ""
                extra = _clean(svc.get("extrainfo", ""), 80)
                try:
                    conf = int(svc.get("conf", "0"))
                except (TypeError, ValueError):
                    conf = 0
                cpe_el = svc.find("cpe")
                cpe = cpe_el.text if cpe_el is not None and cpe_el.text else ""
            service = _SERVICE_ALIASES.get(name, name) or "unknown"
            if tunnel == "ssl" and service in ("http",):
                service = "https"
            verified = method == "probed" and bool(name)
            confidence = "high" if verified and product and conf >= 8 else "medium" if verified else "low"
            evidence = [f"nmap -sV: {service}"]
            if product:
                evidence.append(product + (f" {version_str}" if version_str else ""))
            if extra:
                evidence.append(f"({extra})")
            if tunnel:
                evidence.append(f"tunnel: {tunnel}")
            evidence.append(f"method {method or 'none'}, confidence {conf}/10")
            if cpe:
                evidence.append(_clean(cpe, 80))
            services.append({"ip": ip, "port": portid, "state": state, "service": service,
                             "service_hint": name or "unknown", "service_verified": verified,
                             "product": product, "version": version_str, "confidence": confidence,
                             "evidence": _clean("; ".join(evidence))})
    return services


def scan(ip, ports, timeout, ipv6=False):
    """Run `nmap -sV` against one validated numeric address and return service records."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise NmapError("refusing to scan a non-numeric address")
    numeric_ports = [str(int(p)) for p in ports][:MAX_PORTS]
    if not numeric_ports:
        return []
    budget = max(10, int(timeout))
    args = ["nmap", "-n", "-Pn", "-sV", "--version-intensity", "2", "-T4", "--max-retries", "2",
            "--host-timeout", f"{budget}s", "-oX", "-", "-p", ",".join(numeric_ports)]
    if ipv6:
        args.append("-6")
    args.append(ip)
    try:
        proc = subprocess.run(args, capture_output=True, timeout=budget + 20, check=False,
                              env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
    except subprocess.TimeoutExpired:
        raise NmapError("nmap exceeded its time budget")
    except OSError as exc:
        raise NmapError(f"nmap could not be started ({exc.errno})")
    if not proc.stdout:
        raise NmapError(_clean(proc.stderr.decode("utf-8", "replace"), 200) or "nmap produced no output")
    return parse(proc.stdout)
