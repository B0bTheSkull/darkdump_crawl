"""
Extraction patterns for emails, IPs, credentials, crypto addresses,
API keys, and sensitive keyword contexts from raw text dumps.
"""
import re
import math
from collections import defaultdict

# ── Regex patterns ──────────────────────────────────────────────────────────

EMAIL_RE = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

URL_RE = re.compile(
    r'https?://[^\s<>"\')]{4,}'
)

PHONE_RE = re.compile(
    r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
)

# Credential-style patterns: "user:password" or "email:pass"
CREDENTIAL_RE = re.compile(
    r'(?m)^([a-zA-Z0-9._%+\-]{3,50}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|[a-zA-Z0-9_.\-]{3,30})'
    r'\s*[:|\t]\s*'
    r'([^\s:|\t\r\n]{6,100})'
    r'\s*$'
)

# Crypto wallet addresses
BITCOIN_RE = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
ETHEREUM_RE = re.compile(r'\b0x[a-fA-F0-9]{40}\b')

# API key / secret patterns
API_KEY_CONTEXT_RE = re.compile(
    r'(?i)(?:api[_\-\s]?key|secret[_\-\s]?key|access[_\-\s]?token|auth[_\-\s]?token'
    r'|bearer|private[_\-\s]?key|client[_\-\s]?secret)\s*[=:"\'\s]+\s*'
    r'([a-zA-Z0-9_\-/+.]{16,})'
)

AWS_KEY_RE = re.compile(r'\b(AKIA[0-9A-Z]{16})\b')

# SSH/PEM private keys
PRIVATE_KEY_RE = re.compile(
    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
)

DEFAULT_KEYWORDS = [
    "password", "passwd", "pass", "secret", "credential",
    "token", "api_key", "private_key", "aws_access", "aws_secret",
    "database", "db_pass", "connection_string", "auth", "bearer",
    "ssn", "social security", "credit card", "cvv", "bank account",
    "admin", "root", "sudo", "login"
]


def _extract_keyword_contexts(text, keywords):
    """Find lines containing sensitive keywords."""
    results = []
    seen = set()
    lines = text.splitlines()
    all_kw = [kw.lower() for kw in keywords]

    for i, line in enumerate(lines):
        line_lower = line.lower()
        for kw in all_kw:
            if kw in line_lower:
                snippet = line.strip()[:200]
                if snippet and snippet not in seen:
                    seen.add(snippet)
                    results.append({
                        "keyword": kw,
                        "line_number": i + 1,
                        "context": snippet
                    })
    return results


def _entropy(s):
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_credentials(text):
    """Extract user:pass style credential pairs."""
    results = []
    seen = set()
    for match in CREDENTIAL_RE.finditer(text):
        user, pwd = match.group(1), match.group(2)
        if len(pwd) < 6 or pwd.lower() in ("http", "https", "null", "none", "true", "false"):
            continue
        pair = f"{user}:{pwd}"
        if pair not in seen:
            seen.add(pair)
            results.append(pair)
    return results


def extract_api_keys(text):
    """Extract API keys and AWS access keys."""
    results = []
    seen = set()

    for m in API_KEY_CONTEXT_RE.finditer(text):
        key = m.group(1).strip("\"'")
        if _entropy(key) > 3.5 and key not in seen:
            seen.add(key)
            results.append({"type": "api_key_context", "value": key})

    for m in AWS_KEY_RE.finditer(text):
        key = m.group(1)
        if key not in seen:
            seen.add(key)
            results.append({"type": "aws_access_key", "value": key})

    return results


def extract_all(text, extra_keywords=None):
    """Run all extractors. Returns structured dict of findings."""
    keywords = DEFAULT_KEYWORDS + (extra_keywords or [])

    return {
        "emails": list(set(EMAIL_RE.findall(text))),
        "ips": list(set(IP_RE.findall(text))),
        "urls": list(set(URL_RE.findall(text))),
        "phone_numbers": list(set(PHONE_RE.findall(text))),
        "credentials": extract_credentials(text),
        "api_keys": extract_api_keys(text),
        "bitcoin_wallets": list(set(BITCOIN_RE.findall(text))),
        "ethereum_wallets": list(set(ETHEREUM_RE.findall(text))),
        "private_keys_found": bool(PRIVATE_KEY_RE.search(text)),
        "keyword_hits": _extract_keyword_contexts(text, keywords),
    }
