"""Tests for the SSRF guard in utils.fetcher.validate_url."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.fetcher import validate_url, UnsafeURLError  # noqa: E402


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/admin",
    "http://localhost:8080/",
    "https://localhost/",
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://10.0.0.5/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
])
def test_rejects_private_and_loopback(url):
    with pytest.raises(UnsafeURLError):
        validate_url(url)


@pytest.mark.parametrize("url", [
    "ftp://example.com/file",
    "file:///etc/passwd",
    "gopher://127.0.0.1:11211/",
    "//example.com/no-scheme",
])
def test_rejects_disallowed_schemes(url):
    with pytest.raises(UnsafeURLError):
        validate_url(url)


def test_rejects_missing_host():
    with pytest.raises(UnsafeURLError):
        validate_url("http:///path-only")


def test_allows_public_http_url():
    # 8.8.8.8 is a public address (literal, no DNS needed) — should pass.
    assert validate_url("http://8.8.8.8/") == "http://8.8.8.8/"
    assert validate_url("https://93.184.216.34/") == "https://93.184.216.34/"
