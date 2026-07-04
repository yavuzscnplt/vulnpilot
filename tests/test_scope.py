import pytest

from vulnpilot.scope import ScopeError, normalize_target


def test_bare_host_defaults_to_https():
    t = normalize_target("example.com")
    assert t.scheme == "https"
    assert t.url == "https://example.com"
    assert t.hostname == "example.com"


def test_full_url_preserved_without_trailing_slash():
    t = normalize_target("http://example.com/app/")
    assert t.scheme == "http"
    assert t.url == "http://example.com/app"
    assert t.hostname == "example.com"


def test_empty_target_rejected():
    with pytest.raises(ScopeError):
        normalize_target("   ")


def test_unsupported_scheme_rejected():
    with pytest.raises(ScopeError):
        normalize_target("ftp://example.com")
