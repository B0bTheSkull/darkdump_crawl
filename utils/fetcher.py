"""HTTP fetcher with retry logic and user-agent rotation."""
import time
import random
import socket
import ipaddress
import requests
from pathlib import Path
from urllib.parse import urlsplit

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

SESSION = requests.Session()

ALLOWED_SCHEMES = ("http", "https")


class UnsafeURLError(ValueError):
    """Raised when a URL targets a disallowed scheme or a private/loopback host."""


def _ip_is_blocked(ip):
    """True if an ip address object is in a range we must never fetch."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local       # 169.254.0.0/16 — cloud metadata endpoint lives here
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_url(url):
    """Validate a user-supplied URL against SSRF.

    Allows only http/https and rejects URLs whose host resolves to a
    private, loopback, link-local, reserved, multicast or unspecified
    address (e.g. 127.0.0.1, localhost, 10.x, 192.168.x, 169.254.169.254).

    Returns the URL unchanged if safe; raises UnsafeURLError otherwise.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError(f"scheme not allowed: {scheme or '(none)'}")

    host = parts.hostname
    if not host:
        raise UnsafeURLError("URL has no host")

    # If the host is a literal IP, check it directly; otherwise resolve every
    # address it maps to and reject if ANY of them is blocked.
    try:
        literal = ipaddress.ip_address(host)
        candidates = [literal]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, parts.port or (443 if scheme == "https" else 80))
        except socket.gaierror as e:
            raise UnsafeURLError(f"could not resolve host: {host} ({e})")
        candidates = []
        for info in infos:
            addr = info[4][0]
            # strip IPv6 scope id if present
            addr = addr.split("%", 1)[0]
            candidates.append(ipaddress.ip_address(addr))

    for ip in candidates:
        if _ip_is_blocked(ip):
            raise UnsafeURLError(f"host resolves to disallowed address: {ip}")

    return url


def fetch_url(url, timeout=15, retries=3, backoff=2.0):
    """Fetch a URL with retry logic. Returns text content or None."""
    try:
        validate_url(url)
    except UnsafeURLError as e:
        print(f"  \033[91m[!]\033[0m Refusing to fetch unsafe URL {url}: {e}")
        return None

    headers = {"User-Agent": random.choice(USER_AGENTS)}

    for attempt in range(1, retries + 1):
        try:
            r = SESSION.get(url, headers=headers, timeout=timeout)
            if r.status_code == 200:
                return r.text
            elif r.status_code == 429:
                wait = backoff * attempt
                print(f"  \033[33m[!]\033[0m Rate limited (429). Waiting {wait:.0f}s...")
                time.sleep(wait)
            elif r.status_code == 404:
                return None
            else:
                print(f"  \033[33m[!]\033[0m HTTP {r.status_code} for {url}")
        except requests.Timeout:
            print(f"  \033[33m[!]\033[0m Timeout (attempt {attempt}/{retries})")
        except requests.RequestException as e:
            print(f"  \033[33m[!]\033[0m Request error: {e}")

        if attempt < retries:
            time.sleep(backoff)

    return None


def fetch_urls_from_file(filepath):
    """Read URLs from a file (one per line, # for comments)."""
    p = Path(filepath)
    if not p.exists():
        print(f"\033[91m[!]\033[0m URL file not found: {filepath}")
        return []
    return [
        line.strip() for line in p.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
