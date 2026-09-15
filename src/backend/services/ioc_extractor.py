"""
ioc_extractor.py – Pure regex-based IOC extraction from unstructured text.
No DB access; safe to unit-test in isolation.
"""
import re
from typing import List

# ── Compiled patterns ─────────────────────────────────────────────────────────

# URLs first — extracted and removed before IP/domain matching to avoid
# double-counting a domain that appears inside a URL.
_URL = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)

# IPv4 — four octets; private/reserved ranges filtered out after match.
_IPV4 = re.compile(
    r'\b((?:\d{1,3}\.){3}\d{1,3})\b'
)

_PRIVATE_PREFIXES = (
    "10.", "127.", "0.", "255.",
)
_PRIVATE_172 = re.compile(r'^172\.(1[6-9]|2\d|3[01])\.')
_PRIVATE_192 = re.compile(r'^192\.168\.')

def _is_private_ip(ip: str) -> bool:
    if any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
        return True
    if _PRIVATE_172.match(ip):
        return True
    if _PRIVATE_192.match(ip):
        return True
    return False

# Domains — word.tld or word.word.tld etc.
_DOMAIN_TLDS = (
    r"com|net|org|io|ru|cn|de|uk|biz|info|onion|xyz|top|club|tk|ml|ga|cf|gq"
)
_DOMAIN = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:' + _DOMAIN_TLDS + r')\b',
    re.IGNORECASE,
)

# File hashes — check longest first so SHA256 isn't partially caught as MD5.
# Anchored with word boundaries; hex chars only.
_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
_SHA1   = re.compile(r'\b[0-9a-fA-F]{40}\b')
_MD5    = re.compile(r'\b[0-9a-fA-F]{32}\b')

# Email addresses
_EMAIL = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')


# ── Public API ────────────────────────────────────────────────────────────────

def extract_iocs(text: str) -> List[dict]:
    """
    Extract IOCs from *text* and return a de-duplicated list of dicts with
    keys ``type`` and ``value``.  Type is one of: IP, DOMAIN, URL, HASH, EMAIL.
    Pure function — no side-effects, no DB access.
    """
    if not text:
        return []

    seen: set = set()
    results: list = []

    def _add(ioc_type: str, value: str) -> None:
        key = (ioc_type, value.lower())
        if key not in seen:
            seen.add(key)
            results.append({"type": ioc_type, "value": value})

    # 1. URLs — extracted first; their spans are blanked so downstream
    #    patterns don't re-match the domains/IPs inside them.
    url_spans: list[tuple[int, int]] = []
    for m in _URL.finditer(text):
        _add("URL", m.group())
        url_spans.append((m.start(), m.end()))

    # Build a scrubbed copy (replace URL spans with spaces) for IP/domain.
    scrubbed = list(text)
    for start, end in url_spans:
        for i in range(start, end):
            scrubbed[i] = ' '
    scrubbed_text = ''.join(scrubbed)

    # 2. Hashes — longest first to avoid partial matches.
    hash_spans: list[tuple[int, int]] = []
    for pattern, label in ((_SHA256, "HASH"), (_SHA1, "HASH"), (_MD5, "HASH")):
        for m in pattern.finditer(scrubbed_text):
            # Skip if already covered by a longer hash match.
            if any(s <= m.start() and m.end() <= e for s, e in hash_spans):
                continue
            _add(label, m.group())
            hash_spans.append((m.start(), m.end()))

    # 3. Email addresses (before domain, to avoid matching the domain part).
    email_spans: list[tuple[int, int]] = []
    for m in _EMAIL.finditer(scrubbed_text):
        _add("EMAIL", m.group())
        email_spans.append((m.start(), m.end()))

    # 4. IPv4 — skip private/reserved.
    for m in _IPV4.finditer(scrubbed_text):
        if not _is_private_ip(m.group(1)):
            _add("IP", m.group(1))

    # 5. Domains — skip anything that is inside an email span already matched.
    for m in _DOMAIN.finditer(scrubbed_text):
        if any(s <= m.start() and m.end() <= e for s, e in email_spans):
            continue
        _add("DOMAIN", m.group().lower())

    return results
