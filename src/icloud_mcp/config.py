"""Configuration management for iCloud MCP server."""

import os
from typing import Optional
from dotenv import load_dotenv, find_dotenv

# Load environment variables from a .env in the CWD tree only. Bare load_dotenv()
# searches upward from this module's install path, which reaches the operator's
# home ~/.env and leaks machine-wide secrets; usecwd anchors the search to CWD.
load_dotenv(find_dotenv(usecwd=True))


class Config:
    """Configuration for iCloud MCP server (stateless, loaded from environment)."""

    # Default iCloud servers
    CALDAV_SERVER: str = os.getenv("CALDAV_SERVER", "https://caldav.icloud.com")
    CARDDAV_SERVER: str = os.getenv("CARDDAV_SERVER", "https://contacts.icloud.com")
    IMAP_SERVER: str = os.getenv("IMAP_SERVER", "imap.mail.me.com")
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.mail.me.com")

    # Ports
    MCP_SERVER_PORT: int = int(os.getenv("MCP_SERVER_PORT", "8000"))
    IMAP_PORT: int = int(os.getenv("IMAP_PORT", "993"))
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))

    # Email folders
    SENT_FOLDER: str = os.getenv("SENT_FOLDER", "Sent Messages")

    # Network timeout (seconds) for outbound IMAP/SMTP/CalDAV/CardDAV/HTTP calls
    HTTP_TIMEOUT: int = int(os.getenv("HTTP_TIMEOUT", "30"))

    # MCP transport / auth
    MCP_AUTH_TOKEN: Optional[str] = os.getenv("MCP_AUTH_TOKEN") or None
    MCP_BIND_HOST: str = os.getenv("HOST") or "127.0.0.1"

    # Recipient allowlist for outbound email; empty list means allow all
    EMAIL_SEND_ALLOWLIST: list[str] = [
        x.strip() for x in os.getenv("EMAIL_SEND_ALLOWLIST", "").split(",") if x.strip()
    ]

    # Fallback credentials (if not provided in headers)
    FALLBACK_EMAIL: Optional[str] = os.getenv("ICLOUD_EMAIL")
    FALLBACK_PASSWORD: Optional[str] = os.getenv("ICLOUD_APP_SPECIFIC_PASSWORD")


config = Config()
