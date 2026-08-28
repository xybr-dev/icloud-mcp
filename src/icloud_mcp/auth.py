"""Authentication management for iCloud MCP server."""

from typing import Tuple, Optional
from urllib.parse import urlparse
from fastmcp import Context
from fastmcp.server.dependencies import get_http_headers
from .config import config


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


def require_trusted_url(url: str, base: str, kind: str) -> None:
    """Reject absolute URLs that point away from *base*'s host family.

    Object ids (calendar_id / event_id / contact_id) are caller-controlled
    URLs that get requested with the user's Basic-Auth credentials attached,
    so an absolute URL naming a foreign host leaks those credentials to that
    host. Relative paths resolve against the configured server and are fine.
    Provider partition hosts (e.g. p72-caldav.icloud.com) stay allowed via
    the shared parent domain.
    """
    parsed = urlparse(url)
    if not parsed.scheme and not parsed.netloc:
        return
    base_parsed = urlparse(base)
    # urlparse and requests/urllib3 disagree on authorities containing a
    # backslash or userinfo: urlparse reports the trailing host while the HTTP
    # stack connects to the leading host, so a payload like
    # "https://evil.com\@contacts.icloud.com/x" would pass the host check below
    # yet send the Basic-Auth credential to evil.com. Reject those outright.
    if "\\" in parsed.netloc or "@" in parsed.netloc:
        raise ValueError(
            f"{kind} has an untrusted authority; refusing to send credentials to "
            f"{parsed.netloc}"
        )
    # Strip a trailing root dot so the FQDN form (contacts.icloud.com.) of the
    # configured host is not rejected as foreign.
    host = (parsed.hostname or "").rstrip(".")
    base_host = (base_parsed.hostname or "").rstrip(".")
    # Registrable parent: for a 3+ label host (e.g. contacts.icloud.com) this is
    # the last two labels (icloud.com), which admits provider partition hosts
    # like p72-caldav.icloud.com. For a 2-label base it stays the base itself so
    # the check never widens to a public suffix (.com).
    labels = base_host.split(".")
    parent = ".".join(labels[-2:]) if len(labels) >= 3 else base_host
    same_domain = host == base_host or host.endswith("." + parent)
    if parsed.scheme != base_parsed.scheme or not same_domain:
        raise ValueError(
            f"{kind} must be a relative path or a {base_parsed.scheme} URL under "
            f"{base_host}; refusing to send credentials to {parsed.netloc}"
        )


def get_credentials(context: Context) -> Tuple[str, str]:
    """Extract iCloud credentials from HTTP headers."""

    # Get HTTP headers using FastMCP's dependency function (keys are lowercased)
    headers = get_http_headers()

    email: Optional[str]
    password: Optional[str]
    # If either credential header is present, both credentials come from headers
    # only. Never pair a caller-supplied header with the operator's env secret:
    # that would let an attacker's email header borrow the env password.
    if "x-apple-email" in headers or "x-apple-app-specific-password" in headers:
        email = headers.get("x-apple-email")
        password = headers.get("x-apple-app-specific-password")
    else:
        email = config.FALLBACK_EMAIL
        password = config.FALLBACK_PASSWORD

    # Validate credentials
    if not email or not password:
        raise AuthenticationError(
            "Authentication required. Provide credentials via headers "
            "(X-Apple-Email, X-Apple-App-Specific-Password) or environment variables "
            "(ICLOUD_EMAIL, ICLOUD_APP_SPECIFIC_PASSWORD)"
        )

    return email, password


def require_auth(context: Context) -> Tuple[str, str]:
    """Decorator-friendly authentication check."""
    return get_credentials(context)
