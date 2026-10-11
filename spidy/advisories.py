"""Optional, minimal-data NVD lookup for remotely advertised product versions.

No target URL, address, banner, credentials, or page content is sent to NVD.
API reference: https://nvd.nist.gov/developers/vulnerabilities
Rate guidance: https://nvd.nist.gov/developers/start-here
"""
import http.client
import json
import re
import ssl
import threading
import time
from urllib.parse import urlencode


NVD_HOST = "services.nvd.nist.gov"
NVD_PATH = "/rest/json/cves/2.0"
MAX_PAIRS = 3
MAX_RESULTS = 20
MAX_RESPONSE_BYTES = 1024 * 1024
REQUEST_TIMEOUT = 8
READ_DEADLINE = 15
# No-key NVD public limit: five requests per rolling 30 seconds. Serialize
# requests across scan threads, with margin around the recommended six seconds.
REQUEST_INTERVAL = 6.1
_rate_lock = threading.Lock()
_last_request = float("-inf")

_PRODUCTS = {
    "apache": ("Apache HTTP Server", "apache", "http_server"),
    "apache http server": ("Apache HTTP Server", "apache", "http_server"),
    "apache httpd": ("Apache HTTP Server", "apache", "http_server"),
    "httpd": ("Apache HTTP Server", "apache", "http_server"),
    "nginx": ("nginx", "nginx", "nginx"),
    "openssh": ("OpenSSH", "openbsd", "openssh"),
    "php": ("PHP", "php", "php"),
    "iis": ("Microsoft IIS", "microsoft", "internet_information_services"),
    "microsoft-iis": ("Microsoft IIS", "microsoft", "internet_information_services"),
    "microsoft iis": ("Microsoft IIS", "microsoft", "internet_information_services"),
    "wordpress": ("WordPress", "wordpress", "wordpress"),
    "jquery": ("jQuery", "jquery", "jquery"),
    "python": ("Python", "python", "python"),
}
_NUMERIC_VERSION = re.compile(r"[0-9]{1,5}(?:\.[0-9]{1,5}){1,4}\Z")
_SSH_VERSION = re.compile(r"([0-9]{1,3}\.[0-9]{1,3})(p[0-9]{1,3})?\Z")
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,9}\Z")


class AdvisoryError(Exception):
    """A sanitized lookup failure safe to include in the assessment."""


class LookupCancelled(Exception):
    pass


def _check_cancelled(cancelled):
    if cancelled and cancelled():
        raise LookupCancelled()


def _reserve_request(cancelled):
    global _last_request
    # Cancellation remains responsive while another scan owns the rate gate.
    while not _rate_lock.acquire(timeout=0.1):
        _check_cancelled(cancelled)
    try:
        while True:
            _check_cancelled(cancelled)
            now = time.monotonic()
            wait = REQUEST_INTERVAL - (now - _last_request)
            if wait <= 0:
                _last_request = now
                return
            time.sleep(min(wait, 0.1))
    finally:
        _rate_lock.release()


def _request_json(cpe, cancelled=None):
    """Only call the fixed HTTPS endpoint; http.client has no proxy/redirect handling."""
    _check_cancelled(cancelled)
    connection = http.client.HTTPSConnection(
        NVD_HOST, timeout=REQUEST_TIMEOUT, context=ssl.create_default_context())
    try:
        _reserve_request(cancelled)
        _check_cancelled(cancelled)
        path = NVD_PATH + "?" + urlencode({"cpeName": cpe, "resultsPerPage": MAX_RESULTS}) + "&isVulnerable&noRejected"
        deadline = time.monotonic() + READ_DEADLINE
        connection.request("GET", path, headers={"Accept": "application/json", "User-Agent": "Spidy/0.3 advisory-lookup"})
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise AdvisoryError("NVD returned a redirect; it was not followed.")
        if response.status == 429:
            raise AdvisoryError("NVD rate limit reached; no automatic retry was made.")
        if response.status != 200:
            raise AdvisoryError(f"NVD returned HTTP {response.status}; lookup unavailable.")
        content_length = response.getheader("Content-Length")
        if content_length:
            try:
                too_large = int(content_length) > MAX_RESPONSE_BYTES
            except (ValueError, TypeError):
                raise AdvisoryError("NVD returned an invalid response length.") from None
            if too_large:
                raise AdvisoryError("NVD response exceeded the size limit; lookup incomplete.")
        if response.getheader("Content-Encoding", "identity").lower() not in ("identity", ""):
            raise AdvisoryError("NVD returned an unsupported content encoding.")
        chunks = []
        size = 0
        while True:
            _check_cancelled(cancelled)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AdvisoryError("NVD response exceeded the time limit; lookup incomplete.")
            if connection.sock:
                connection.sock.settimeout(min(REQUEST_TIMEOUT, remaining))
            chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise AdvisoryError("NVD response exceeded the size limit; lookup incomplete.")
        try:
            data = json.loads(b"".join(chunks))
        except (ValueError, UnicodeError, RecursionError):
            raise AdvisoryError("NVD returned invalid JSON; lookup unavailable.") from None
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise AdvisoryError("NVD returned an unexpected response; lookup unavailable.")
        return data
    except (OSError, http.client.HTTPException):
        # Do not publish exception strings: a proxy, resolver, or OS may include
        # local details. TLS failure is not retried with verification disabled.
        raise AdvisoryError("NVD connection or TLS verification failed; lookup unavailable.") from None
    finally:
        connection.close()


def _product_pairs(technologies):
    pairs, seen = [], set()
    skipped = {"unsupported_product": 0, "missing_version": 0, "invalid_version": 0, "pair_limit": 0}
    for tech in technologies or []:
        if not isinstance(tech, dict):
            skipped["unsupported_product"] += 1
            continue
        product = tech.get("product") or tech.get("name")
        mapping = _PRODUCTS.get(product.strip().casefold()) if isinstance(product, str) else None
        if not mapping:
            skipped["unsupported_product"] += 1
            continue
        version = tech.get("version")
        if version is None or version == "":
            skipped["missing_version"] += 1
            continue
        if not isinstance(version, str) or len(version) > 24:
            skipped["invalid_version"] += 1
            continue
        version = version.strip()
        name, vendor, cpe_product = mapping
        update, cpe_version = "*", version
        if name == "OpenSSH":
            match = _SSH_VERSION.fullmatch(version)
            if match:
                cpe_version, update = match.group(1), match.group(2) or "*"
        else:
            match = _NUMERIC_VERSION.fullmatch(version)
        if not match:
            skipped["invalid_version"] += 1
            continue
        cpe = f"cpe:2.3:a:{vendor}:{cpe_product}:{cpe_version}:{update}:*:*:*:*:*:*"
        if cpe in seen:
            continue
        seen.add(cpe)
        if len(pairs) >= MAX_PAIRS:
            skipped["pair_limit"] += 1
            continue
        pairs.append({"product": name, "version": version, "cpe": cpe})
    return pairs, skipped


def _version_compare(left, right):
    """Compare plain numeric ranges only; uncertain formats stay candidates."""
    if not _NUMERIC_VERSION.fullmatch(left) or not isinstance(right, str) or not _NUMERIC_VERSION.fullmatch(right):
        return None
    a, b = [int(x) for x in left.split(".")], [int(x) for x in right.split(".")]
    length = max(len(a), len(b))
    a += [0] * (length - len(a))
    b += [0] * (length - len(b))
    return (a > b) - (a < b)


def _configuration_match(cve, cpe):
    """Reject obvious unrelated/out-of-range CPEs; do not claim full applicability."""
    configs = cve.get("configurations")
    if not isinstance(configs, list) or not configs:
        return "NVD returned this CPE match; detailed applicability was unavailable."
    expected = cpe.split(":")
    pending = list(configs)
    inspected = 0
    while pending and inspected < 2000:
        node = pending.pop()
        inspected += 1
        if not isinstance(node, dict) or node.get("negate") is True:
            continue
        for children_key in ("nodes", "children"):
            children = node.get(children_key, [])
            if isinstance(children, list):
                pending.extend(children)
        matches = node.get("cpeMatch", [])
        for match in matches if isinstance(matches, list) else []:
            if not isinstance(match, dict) or match.get("vulnerable") is not True:
                continue
            criteria = match.get("criteria")
            if not isinstance(criteria, str):
                continue
            fields = criteria.split(":")
            if len(fields) != 13 or fields[:5] != expected[:5]:
                continue
            if fields[5] not in ("*", expected[5]):
                continue
            if expected[6] != "*" and fields[6] not in ("*", expected[6]):
                continue
            excluded = False
            for bound, reject in (("versionStartIncluding", lambda c: c < 0),
                                  ("versionStartExcluding", lambda c: c <= 0),
                                  ("versionEndIncluding", lambda c: c > 0),
                                  ("versionEndExcluding", lambda c: c >= 0)):
                if bound in match:
                    comparison = _version_compare(expected[5], match[bound])
                    if comparison is not None and reject(comparison):
                        excluded = True
                        break
            if not excluded:
                return "Advertised product/version matched NVD vulnerable CPE criteria; platform, component, configuration, and patch applicability still require owner verification."
    return None


def _references(cve):
    """Published reference URLs NVD lists for a CVE, exploit/PoC links surfaced first.

    These are pointers NVD already catalogs; nothing is fetched or executed.
    """
    refs, seen = [], set()
    raw = cve.get("references")
    for ref in raw if isinstance(raw, list) else []:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")) or len(url) > 500 or url in seen:
            continue
        seen.add(url)
        tags = [t for t in ref.get("tags", []) if isinstance(t, str)][:6] if isinstance(ref.get("tags"), list) else []
        refs.append({"url": _safe_text(url, 500), "tags": tags})
        if len(refs) >= 12:
            break
    refs.sort(key=lambda ref: "Exploit" not in ref["tags"])
    return refs


def _safe_text(value, limit=1500):
    if not isinstance(value, str):
        return ""
    return " ".join("".join(c for c in value if c.isprintable() or c.isspace()).split())[:limit]


def _candidate(item, pair):
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        return None
    cve = item["cve"]
    ident = cve.get("id")
    if not isinstance(ident, str) or not _CVE_ID.fullmatch(ident) or cve.get("vulnStatus") == "Rejected":
        return None
    reason = _configuration_match(cve, pair["cpe"])
    if not reason:
        return None
    result = {"id": ident, "title": f"{ident}: potential {pair['product']} {pair['version']} advisory",
              "url": f"https://nvd.nist.gov/vuln/detail/{ident}", "product": pair["product"],
              "version": pair["version"], "match_reason": reason, "status": "candidate",
              "references": _references(cve)}
    descriptions = cve.get("descriptions", [])
    if isinstance(descriptions, list):
        result["description"] = next((_safe_text(d.get("value")) for d in descriptions
                                      if isinstance(d, dict) and d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    if isinstance(metrics, dict):
        for kind in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            rows = metrics.get(kind, [])
            if not isinstance(rows, list):
                continue
            for metric in rows:
                if not isinstance(metric, dict):
                    continue
                cvss = metric.get("cvssData")
                severity = cvss.get("baseSeverity") if isinstance(cvss, dict) else None
                severity = severity or metric.get("baseSeverity")
                if isinstance(severity, str) and severity.upper() in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
                    result["severity"] = severity.lower()
                    result["severity_context"] = "Published advisory severity; not a confirmed severity for this target."
                    return result
    return result


def lookup_advisories(technologies, enabled=False, record=None, cancelled=None):
    """Look up at most three known products. Opt-in is explicit and defaults off.

    ``record``, when supplied, receives an event dict; ``cancelled`` is a
    zero-argument predicate. Neither callback is sent to the provider.
    """
    result = {"status": "disabled", "provider": "NIST NVD", "candidates": [], "queries": [],
              "limitations": [
                  "These are potential advisories, not confirmed vulnerabilities. Advertised versions can be spoofed or patched through backports.",
                  "Platform, client/server component, configuration, and shared hosting or edge-service applicability need owner verification.",
                  f"Lookup covers at most {MAX_PAIRS} recognized product/version pairs and {MAX_RESULTS} returned records per pair; it is not exhaustive.",
                  "Only canonical product/version CPEs are sent to NVD. Target domains, IP addresses, raw banners, page contents, and credentials are not sent.",
                  "Reference links, including any tagged Exploit, are pointers NVD publishes; Spidy does not fetch, host, or run them. Review before use and only against systems you are authorized to test.",
                  "Empty results, missing versions, and provider failures do not establish that the system has no vulnerabilities.",
              ], "skipped": {}}
    if enabled is not True:
        result["limitations"].append("External advisory lookup was disabled; no provider connection was made.")
        return result
    try:
        _check_cancelled(cancelled)
    except LookupCancelled:
        result["status"] = "cancelled"
        return result
    pairs, result["skipped"] = _product_pairs(technologies)
    if not pairs:
        result["status"] = "no_versions"
        result["limitations"].append("No supported product with an explicit recognized version was available for lookup.")
        return result
    failures, completed, limited = 0, 0, bool(result["skipped"]["pair_limit"])
    for pair in pairs:
        query = {**pair, "status": "pending", "count": 0}
        try:
            _check_cancelled(cancelled)
            result["queries"].append(query)
            data = _request_json(pair["cpe"], cancelled)
            _check_cancelled(cancelled)
            candidates, seen = [], set()
            for item in data["vulnerabilities"][:MAX_RESULTS]:
                candidate = _candidate(item, pair)
                if candidate and candidate["id"] not in seen:
                    candidates.append(candidate)
                    seen.add(candidate["id"])
            total = data.get("totalResults")
            if not isinstance(total, int) or isinstance(total, bool) or total < 0:
                raise AdvisoryError("NVD returned an invalid result count; lookup unavailable.")
            query.update(status="completed", count=len(candidates), returned=len(data["vulnerabilities"][:MAX_RESULTS]),
                         total_results=total, truncated=total > MAX_RESULTS)
            limited = limited or query["truncated"]
            result["candidates"].extend(candidates)
            completed += 1
        except LookupCancelled:
            query["status"] = "cancelled"
            result["status"] = "cancelled"
            if record:
                record({"type": "advisory_lookup", "check": "advisories", **query})
            return result
        except AdvisoryError as exc:
            failures += 1
            query.update(status="unavailable", reason=str(exc))
        if record:
            record({"type": "advisory_lookup", "check": "advisories", **query})
    result["status"] = "unavailable" if failures and not completed else "partial" if failures or limited else "completed"
    return result
