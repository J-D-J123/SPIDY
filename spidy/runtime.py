"""Identify the loaded backend separately from files served to the browser."""
import hashlib
from pathlib import Path

PLANNER_PROTOCOL = 2


def source_revision():
    digest = hashlib.sha256()
    for path in sorted(Path(__file__).parent.glob("*.py")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


LOADED_REVISION = source_revision()


def status():
    return {"planner_protocol": PLANNER_PROTOCOL, "backend_revision": LOADED_REVISION,
            "restart_required": source_revision() != LOADED_REVISION}
