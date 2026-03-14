"""HTTP fetcher with retry logic and user-agent rotation."""
import time
import random
import requests
from pathlib import Path

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

SESSION = requests.Session()


def fetch_url(url, timeout=15, retries=3, backoff=2.0):
    """Fetch a URL with retry logic. Returns text content or None."""
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
