"""
IOC (Indicator of Compromise) extraction service.

Extracts IPs, domains, URLs, file hashes, and email addresses from
free-text alert descriptions and raw log fields using regex patterns.
"""

import re
from typing import List, Dict

# ─── Regex patterns ────────────────────────────────────────────────────────────

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|ru|cn|de|uk|biz|info|onion|xyz|top|club|tk|ml|ga|cf|gq)\b",
    re.IGNORECASE,
)

_URL_RE = re.compile(
    r"https?://[^\s\"'<>\]]+",
    re.IGNORECASE,
)

_MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Private / reserved IP ranges to exclude from results
_PRIVATE_NETS = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.255\.255\.255)"
)


def extract_iocs(text: str) -> List[Dict[str, str]]:
    """
    Return a de-duplicated list of IOC dicts extracted from *text*.
    Each dict has keys: ``type`` and ``value``.
    """
    if not text:
        return []

    found: List[Dict[str, str]] = []
    seen: set = set()

    def add(ioc_type: str, value: str):
        key = (ioc_type, value.lower())
        if key not in seen:
            seen.add(key)
            found.append({"type": ioc_type, "value": value})

    # URLs first (they contain IPs/domains — avoid double-counting)
    for m in _URL_RE.finditer(text):
        add("url", m.group())

    # Remove URL spans from text before further matching
    clean = _URL_RE.sub(" ", text)

    for m in _IP_RE.finditer(clean):
        ip = m.group()
        if not _PRIVATE_NETS.match(ip):
            add("ip", ip)

    for m in _DOMAIN_RE.finditer(clean):
        add("domain", m.group().lower())

    for m in _SHA256_RE.finditer(clean):
        add("sha256", m.group().lower())

    for m in _SHA1_RE.finditer(clean):
        add("sha1", m.group().lower())

    for m in _MD5_RE.finditer(clean):
        add("md5", m.group().lower())

    for m in _EMAIL_RE.finditer(clean):
        add("email", m.group().lower())

    return found
