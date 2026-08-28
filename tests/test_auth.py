"""Auth remediation locks: URL trust check and credential source isolation."""

import pytest

from icloud_mcp import auth
from icloud_mcp.auth import require_trusted_url, get_credentials, AuthenticationError
from icloud_mcp.config import config

BASE = "https://caldav.icloud.com"


# --- require_trusted_url --------------------------------------------------

# The two backslash bypasses: urlparse reports a trailing/foreign host while
# the HTTP stack connects to the leading host, so a naive host check would pass
# these and leak Basic-Auth to evil.com. They MUST raise.
BACKSLASH_BYPASSES = [
    r"https://evil.com\@contacts.icloud.com/x",
    r"https://evil.com\.icloud.com/x",
]


@pytest.mark.parametrize("url", BACKSLASH_BYPASSES)
def test_backslash_authority_raises(url):
    with pytest.raises(ValueError):
        require_trusted_url(url, BASE, "event_id")


# A userinfo "@" authority is the same credential-leak class and must also raise.
def test_userinfo_authority_raises():
    with pytest.raises(ValueError):
        require_trusted_url("https://evil.com/@caldav.icloud.com/x", BASE, "event_id")


TRUSTED_URLS = [
    "/123/calendars/work/",                       # relative -> resolves against base
    "https://p72-caldav.icloud.com/123/",         # provider partition host under icloud.com
    "https://caldav.icloud.com/123/calendars/",   # the configured host itself
]


@pytest.mark.parametrize("url", TRUSTED_URLS)
def test_trusted_urls_pass(url):
    # Must NOT raise.
    require_trusted_url(url, BASE, "event_id")


def test_public_suffix_not_widened():
    # A 2-label base must never treat the public suffix (.com) as the parent,
    # or every *.com host would be "trusted".
    with pytest.raises(ValueError):
        require_trusted_url("https://evil.com/x", "https://icloud.com", "event_id")


# Both production call paths pass a 3-label base: calendar.py -> CALDAV_SERVER,
# contacts.py -> CARDDAV_SERVER. Exercise the check against both real bases so a
# base-specific regression (partition host refused, bypass admitted) is caught.
PROD_BASES = [config.CALDAV_SERVER, config.CARDDAV_SERVER]


@pytest.mark.parametrize("base", PROD_BASES)
def test_partition_host_trusted_for_both_bases(base):
    require_trusted_url("https://p72-caldav.icloud.com/1/", base, "id")  # no raise


@pytest.mark.parametrize("base", PROD_BASES)
def test_backslash_bypass_raises_for_both_bases(base):
    with pytest.raises(ValueError):
        require_trusted_url(r"https://evil.com\@contacts.icloud.com/x", base, "id")


# --- get_credentials ------------------------------------------------------

def _set_headers(monkeypatch, headers):
    # get_http_headers lowercases keys; monkeypatch the name used inside auth.
    monkeypatch.setattr(auth, "get_http_headers", lambda: headers)


def test_header_email_does_not_pull_env_password(monkeypatch):
    # An attacker-supplied email header must never borrow the operator's env
    # password. With only the email header present, the password stays unset and
    # auth is refused -- no mixing of a header credential with an env secret.
    _set_headers(monkeypatch, {"x-apple-email": "attacker@example.com"})
    monkeypatch.setattr(config, "FALLBACK_EMAIL", "owner@icloud.com")
    monkeypatch.setattr(config, "FALLBACK_PASSWORD", "env-secret")
    with pytest.raises(AuthenticationError):
        get_credentials(None)


def test_header_password_does_not_pull_env_email(monkeypatch):
    # Symmetric: a password header alone must not pair with the env email.
    _set_headers(monkeypatch, {"x-apple-app-specific-password": "hunter2"})
    monkeypatch.setattr(config, "FALLBACK_EMAIL", "owner@icloud.com")
    monkeypatch.setattr(config, "FALLBACK_PASSWORD", "env-secret")
    with pytest.raises(AuthenticationError):
        get_credentials(None)


def test_both_from_headers(monkeypatch):
    _set_headers(monkeypatch, {
        "x-apple-email": "user@icloud.com",
        "x-apple-app-specific-password": "app-pw",
    })
    # env set but must be ignored because headers are present
    monkeypatch.setattr(config, "FALLBACK_EMAIL", "owner@icloud.com")
    monkeypatch.setattr(config, "FALLBACK_PASSWORD", "env-secret")
    email, password = get_credentials(None)
    assert email == "user@icloud.com"
    assert password == "app-pw"


def test_both_from_env_when_no_headers(monkeypatch):
    _set_headers(monkeypatch, {})
    monkeypatch.setattr(config, "FALLBACK_EMAIL", "owner@icloud.com")
    monkeypatch.setattr(config, "FALLBACK_PASSWORD", "env-secret")
    email, password = get_credentials(None)
    assert email == "owner@icloud.com"
    assert password == "env-secret"


def test_incomplete_env_raises(monkeypatch):
    _set_headers(monkeypatch, {})
    monkeypatch.setattr(config, "FALLBACK_EMAIL", "owner@icloud.com")
    monkeypatch.setattr(config, "FALLBACK_PASSWORD", None)
    with pytest.raises(AuthenticationError):
        get_credentials(None)
