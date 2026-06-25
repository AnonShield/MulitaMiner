"""Per-finding signal extraction for prioritization.

Pure functions that turn one extracted record into the three SSVC decision-tree
inputs plus the CVE keys. Deterministic, no I/O — the KEV set and EPSS map are
passed in (loaded once from ``feeds``). See ``archive/notes/PLANO_PRIORIZACAO.md``.
"""
from __future__ import annotations

import ipaddress
import json
import re

# EPSS score at/above which exploitation counts as "likely". Default follows the
# operating point referenced by FIRST for the EPSS model (~0.1, near the F1-optimal
# remediation cutoff). Configurable per user risk tolerance via the ``threshold``
# argument — see https://www.first.org/epss/ and PLANO_PRIORIZACAO.md.
EPSS_LIKELY_THRESHOLD = 0.10

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# Hostnames that resolve to private networks by RFC/convention. Used only to move
# a finding to "internal"; everything else stays at the cautious "exposed" default,
# so this can only correct false-"exposed", never invent a false-"internal".
_INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".home", ".corp", ".intranet")

# Where the asset host lives varies by scanner. To support a new scanner, add its
# field name here — no code change. Direct (scalar) fields are tried first, in
# order; these cover the common names across scanners (OpenVAS/Nessus/Tenable/...).
HOST_FIELDS = (
    "host", "hostname", "ip", "ip_address", "address",
    "target", "asset", "url", "uri", "endpoint",
)
# Some scanners (e.g. Tenable WAS) instead nest the host inside a list of
# instances, as a URL. These are the list field(s) and the per-instance keys.
INSTANCE_FIELDS = ("instances",)
INSTANCE_HOST_KEYS = ("instance", "url", "uri", "host", "endpoint")


def extract_cve_ids(record: dict) -> list[str]:
    """CVE IDs mentioned in a record, upper-cased, deduped, order preserved.

    OpenVAS carries them inside ``references`` (a list of ``"cve: CVE-..."`` /
    ``"url: ..."`` strings); ``plugin`` / ``plugin_details`` are scanned too.
    """
    parts: list[str] = []
    refs = record.get("references")
    if isinstance(refs, list):
        parts.extend(str(x) for x in refs)
    elif refs:
        parts.append(str(refs))
    for key in ("plugin", "plugin_details"):
        val = record.get(key)
        if val:
            parts.append(val if isinstance(val, str) else json.dumps(val))

    seen: dict[str, None] = {}
    for match in _CVE_RE.findall(" ".join(parts)):
        seen[match.upper()] = None
    return list(seen)


def host_of(record: dict) -> str | None:
    """The asset host/URL for a record, across scanner field conventions.

    Tries the direct ``HOST_FIELDS`` first (OpenVAS ``host``, others' ``ip`` etc.),
    then falls back to the host nested in a list of ``instances`` (Tenable WAS puts
    it in ``instance`` as a URL). Returns the first match, or ``None``.
    """
    for key in HOST_FIELDS:
        value = record.get(key)
        if value and isinstance(value, (str, int)):
            return str(value)
    for key in INSTANCE_FIELDS:
        items = record.get(key)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    for sub in INSTANCE_HOST_KEYS:
                        if item.get(sub):
                            return str(item[sub])
    return None


def exposure(record: dict) -> str:
    """``"internal"`` if the host is a private/loopback IP or an internal-looking
    name, else ``"exposed"``.

    Cautious by default: anything we can't confidently call internal — a public
    FQDN, a WAS URL, a missing host — is ``"exposed"``, erring toward urgency. The
    name heuristic only ever moves a finding *to* internal, so it cannot wrongly
    downgrade a public asset.
    """
    host = host_of(record)
    if not host:
        return "exposed"
    hostname = _hostname(str(host))
    if not hostname:
        return "exposed"
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return "internal" if _name_looks_internal(hostname) else "exposed"
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return "internal"
    return "exposed"


def severity_band(record: dict) -> str:
    """``"high"`` / ``"medium"`` / ``"low"`` from CVSS, falling back to the label.

    A present, positive ``cvss`` wins; otherwise the scanner's ``severity`` word
    (Critical/High/Medium/Low/Log/None) is mapped — covers records with no CVSS.
    """
    cvss = _coerce_float(record.get("cvss"))
    if cvss is not None and cvss > 0:
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"
    return _band_from_label(record.get("severity"))


def exploitation(
    cve_ids: list[str],
    kev: set[str],
    epss: dict[str, float],
    threshold: float = EPSS_LIKELY_THRESHOLD,
) -> str:
    """Exploitation evidence: ``"active"`` / ``"likely"`` / ``"none"`` / ``"unknown"``.

    - ``"active"`` — a CVE is in KEV (confirmed exploitation).
    - ``"likely"`` — EPSS ≥ threshold.
    - ``"none"`` — has a CVE but KEV/EPSS show little evidence (we *checked*).
    - ``"unknown"`` — no CVE at all, so KEV/EPSS cannot be consulted. Absence of a
      CVE key is absence of evidence, not evidence of safety — so it is not treated
      as "none" (typical of Tenable WAS findings: SQLi/XSS with no CVE).
    """
    if not cve_ids:
        return "unknown"
    if any(cve in kev for cve in cve_ids):
        return "active"
    if max_epss(cve_ids, epss) >= threshold:
        return "likely"
    return "none"


def max_epss(cve_ids: list[str], epss: dict[str, float]) -> float:
    """Highest EPSS score among the record's CVEs (0.0 if none). For ordering."""
    return max((epss.get(cve, 0.0) for cve in cve_ids), default=0.0)


# --------------------------------------------------------------------------- #
# internals
# --------------------------------------------------------------------------- #
def _coerce_float(value) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _band_from_label(label) -> str:
    word = str(label or "").strip().lower()
    if word in ("critical", "high"):
        return "high"
    if word == "medium":
        return "medium"
    return "low"  # low / log / none / info / unknown


def _hostname(host: str) -> str:
    """Strip a URL scheme / path / port down to the bare host (WAS gives URLs)."""
    host = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", host.strip(), flags=re.IGNORECASE)
    host = host.split("/")[0].split("?")[0]
    # drop :port, but not the colons inside an IPv6 literal ("[::1]" / "fe80::1")
    if ":" in host and not _looks_ipv6(host):
        host = host.rsplit(":", 1)[0]
    return host.strip("[]").lower()


def _looks_ipv6(host: str) -> bool:
    return host.count(":") >= 2


def _name_looks_internal(hostname: str) -> bool:
    """A single-label name (no dot) or a private/special-use suffix → internal."""
    if "." not in hostname:
        return True  # bare host like "srv01" is never a public FQDN
    return hostname.endswith(_INTERNAL_SUFFIXES)
