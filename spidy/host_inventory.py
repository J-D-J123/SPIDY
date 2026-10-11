"""Owner-run Linux inventory collection and strictly bounded report imports.

Collection is an explicit CLI command, never a side effect of scanning a domain.
It reads process names/executables, not arguments, environment variables, or memory.
"""
import os
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .scope import normalize_url


FORMAT = "spidy-host-inventory-v1"
MAX_PROCESSES = 500
MAX_PACKAGES = 2000


def _command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False,
                                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
        if result.returncode == 0 and len(result.stdout) <= 2_000_000:
            return result.stdout
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""


def collect_host(target_host, proc_root="/proc", include_packages=True):
    host = urlsplit(normalize_url(target_host)).hostname
    process_root = Path(proc_root)
    packages, package_versions = [], {}
    if include_packages:
        output = _command(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"])
        for line in output.splitlines():
            fields = line.split("\t")
            if len(fields) == 2:
                # Multi-arch names carry a suffix such as ':amd64'; process lookups use the bare name.
                package_versions[fields[0].split(":")[0]] = fields[1]
                if len(packages) < MAX_PACKAGES:
                    packages.append({"name": fields[0][:160], "version": fields[1][:160], "source": "dpkg-query"})
    processes = []
    ownership_cache = {}
    paths = sorted((p for p in process_root.glob("[0-9]*") if p.name.isdigit()), key=lambda p: int(p.name))
    for path in paths[:MAX_PROCESSES]:
        try:
            name = (path / "comm").read_text()[:128].strip()
        except (OSError, UnicodeError):
            continue
        executable = ""
        try:
            executable = os.readlink(path / "exe")
        except OSError:
            pass
        package, version = "", ""
        if include_packages and executable.startswith("/") and " (deleted)" not in executable and len(ownership_cache) < 50:
            if executable not in ownership_cache:
                owner = _command(["dpkg-query", "-S", executable]).splitlines()
                package = owner[0].split(": ", 1)[0].split(":")[0] if owner else ""
                ownership_cache[executable] = package
            package = ownership_cache[executable]
            version = package_versions.get(package, "")
        processes.append({"pid": int(path.name), "name": name, "executable": Path(executable).name[:160],
                          "package": package[:160], "package_version": version[:160],
                          "version_note": "Installed package version; the running binary may predate a restart" if version else "Process version not established"})
    return {"format": FORMAT, "target_host": host, "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
            "processes": processes, "packages": packages,
            "limitations": ["Run this command on the actual authorized server. Declaring a hostname does not verify that this machine serves it.",
                            "Process visibility depends on local permissions and containers; missing entries do not prove a process is absent.",
                            "Arguments, environment variables, credentials, process memory, and remote hosts are not collected.",
                            "Installed package versions can include distribution backports; they are not proof of a vulnerability.",
                            f"Capped at {MAX_PROCESSES} processes, {MAX_PACKAGES} packages, and 50 package-owner queries."]}


def validate_host_inventory(raw, expected_host):
    if not isinstance(raw, dict) or raw.get("format") != FORMAT:
        raise ValueError("Expected a Spidy host inventory JSON document.")
    expected = urlsplit(normalize_url(expected_host)).hostname
    actual = urlsplit(normalize_url(str(raw.get("target_host", "")))).hostname
    if expected != actual:
        raise ValueError("Host inventory must be explicitly collected for this assessment's original hostname.")

    def text(value, maximum=160):
        if not isinstance(value, str) or len(value) > maximum or re.search(r"[\x00-\x08\x0b-\x1f\x7f]", value):
            raise ValueError("Host inventory contains invalid or oversized text fields.")
        return value

    collected_at = text(raw.get("collected_at", ""))
    try:
        datetime.fromisoformat(collected_at)
    except ValueError as exc:
        raise ValueError("Host inventory must include a valid collection timestamp.") from exc
    processes = raw.get("processes", [])
    packages = raw.get("packages", [])
    if not isinstance(processes, list) or len(processes) > MAX_PROCESSES or not isinstance(packages, list) or len(packages) > MAX_PACKAGES:
        raise ValueError("Host inventory exceeds the process/package limits.")
    clean_processes, clean_packages = [], []
    for item in processes:
        if not isinstance(item, dict) or type(item.get("pid")) is not int or not 1 <= item["pid"] <= 2**31 - 1:
            raise ValueError("Invalid process entry.")
        clean_processes.append({"pid": item["pid"], **{key: text(item.get(key, "")) for key in ("name", "executable", "package", "package_version", "version_note")}})
    for item in packages:
        if not isinstance(item, dict):
            raise ValueError("Invalid package entry.")
        clean_packages.append({key: text(item.get(key, "")) for key in ("name", "version", "source")})
    system = raw.get("platform", {})
    if not isinstance(system, dict):
        raise ValueError("Invalid platform metadata.")
    return {"status": "owner_supplied", "target_host": actual, "collected_at": collected_at,
            "platform": {key: text(system.get(key, "")) for key in ("system", "release", "machine")},
            "processes": clean_processes, "packages": clean_packages,
            "reason": "Operator-supplied host evidence; origin, completeness, and running binary versions are not independently verified. Package versions may include backports."}
