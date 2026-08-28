"""Email remediation locks: limit clamping, MIME decode safety, send allowlist,
and that a connection failure surfaces the real error (not a NameError from the
offload refactor's finally block referencing an unbound `client`).
"""

import asyncio

import pytest

from icloud_mcp import email as email_mod
from icloud_mcp.email import (
    _decode_mime_header,
    list_folders,
    list_messages,
    get_message,
    get_messages,
    search_messages,
    send_message,
)
from icloud_mcp.config import config


def run(coro):
    return asyncio.run(coro)


# --- fakes ----------------------------------------------------------------

class FakeIMAP:
    """Minimal IMAPClient stand-in that records the ids passed to fetch().

    Has no `_imap` attribute, so email._close_imap_client is a no-op on it.
    """

    def __init__(self, n_ids):
        self.n_ids = n_ids
        self.fetched_ids = None

    def list_folders(self):
        return []

    def select_folder(self, folder):
        return {b"EXISTS": self.n_ids}

    def search(self, criteria, charset=None):
        return list(range(1, self.n_ids + 1))

    def fetch(self, ids, data):
        self.fetched_ids = list(ids)
        return {}  # empty -> the parse loop yields no rows; we assert on fetched_ids


class FakeSMTP:
    def __init__(self):
        self.sent = []

    def send_message(self, msg, from_addr=None, to_addrs=None):
        self.sent.append(to_addrs)

    def quit(self):
        pass

    def close(self):
        pass


class FakeSentIMAP:
    """IMAP stand-in for the send path's Sent-folder append."""

    def __init__(self):
        self.appended = []

    def append(self, folder, msg_bytes, flags=None):
        self.appended.append(folder)


# --- test 3: limit handling ----------------------------------------------

@pytest.fixture
def patch_auth(monkeypatch):
    monkeypatch.setattr(email_mod, "require_auth", lambda ctx: ("me@icloud.com", "pw"))


@pytest.mark.parametrize("bad_limit", [0, -5, None])
def test_list_messages_limit_bounded(monkeypatch, patch_auth, bad_limit):
    # A folder of 1000 messages; a non-positive/None limit must NOT fetch the
    # whole folder. The remediation clamps to 20 (then caps at 200).
    fake = FakeIMAP(n_ids=1000)
    monkeypatch.setattr(email_mod, "_get_imap_client", lambda u, p: fake)
    run(list_messages(None, folder="INBOX", limit=bad_limit))
    assert fake.fetched_ids is not None
    assert len(fake.fetched_ids) == 20
    assert len(fake.fetched_ids) < fake.n_ids  # never the whole folder


def test_list_messages_limit_capped(monkeypatch, patch_auth):
    # An absurdly large limit is hard-capped at 200.
    fake = FakeIMAP(n_ids=1000)
    monkeypatch.setattr(email_mod, "_get_imap_client", lambda u, p: fake)
    run(list_messages(None, folder="INBOX", limit=100000))
    assert len(fake.fetched_ids) == 200


@pytest.mark.parametrize("bad_limit", [0, -1, None])
def test_search_messages_limit_bounded(monkeypatch, patch_auth, bad_limit):
    fake = FakeIMAP(n_ids=1000)
    monkeypatch.setattr(email_mod, "_get_imap_client", lambda u, p: fake)
    run(search_messages(None, query="hello", folder="INBOX", limit=bad_limit))
    assert fake.fetched_ids is not None
    assert len(fake.fetched_ids) == 20
    assert len(fake.fetched_ids) < fake.n_ids


# --- test 4: MIME header decode safety -----------------------------------

def test_decode_malformed_header_returns_raw():
    raw = "=?utf-8?b?A!!!?="
    # Must not raise; a malformed encoded-word falls back to the raw string.
    assert _decode_mime_header(raw) == raw


def test_decode_empty_header():
    assert _decode_mime_header("") == ""


def test_decode_valid_header():
    # sanity: a real encoded-word still decodes ("=?utf-8?q?Hi?=" -> "Hi")
    assert _decode_mime_header("=?utf-8?q?Hi?=") == "Hi"


# --- connection-failure semantics (offload/finally regression) -----------

# The four helpers that bind `client` INSIDE the try block; if _get_imap_client
# raises, `client` is unbound where the finally references it. The finally's
# inner try/except must swallow that NameError so the ORIGINAL ConnectionError
# propagates -- not a NameError masking the real failure. Verify every one.
@pytest.mark.parametrize("fn,kwargs", [
    (list_folders, {}),
    (list_messages, {"folder": "INBOX"}),
    (get_message, {"message_id": "1"}),
    (get_messages, {"message_ids": ["1"]}),
])
def test_connection_failure_surfaces_real_error(monkeypatch, patch_auth, fn, kwargs):
    def boom(u, p):
        raise ConnectionError("connect failed")

    monkeypatch.setattr(email_mod, "_get_imap_client", boom)
    with pytest.raises(ConnectionError):
        run(fn(None, **kwargs))


# --- test 7: send allowlist ----------------------------------------------

def test_send_refuses_recipient_outside_allowlist(monkeypatch, patch_auth):
    monkeypatch.setattr(config, "EMAIL_SEND_ALLOWLIST", ["allowed@example.com"])

    # If the allowlist check works, SMTP is never reached. Wire the client
    # factories to blow up so a bypass would fail loudly instead of silently.
    def must_not_connect(u, p):
        raise AssertionError("SMTP/IMAP must not be contacted for a refused send")

    monkeypatch.setattr(email_mod, "_get_smtp_client", must_not_connect)
    monkeypatch.setattr(email_mod, "_get_imap_client", must_not_connect)

    with pytest.raises(ValueError):
        run(send_message(None, to="outsider@evil.com", subject="s", body="b"))


def test_send_allows_recipient_inside_allowlist(monkeypatch, patch_auth):
    monkeypatch.setattr(config, "EMAIL_SEND_ALLOWLIST", ["allowed@example.com"])
    smtp = FakeSMTP()
    sent_imap = FakeSentIMAP()
    monkeypatch.setattr(email_mod, "_get_smtp_client", lambda u, p: smtp)
    monkeypatch.setattr(email_mod, "_get_imap_client", lambda u, p: sent_imap)

    result = run(send_message(None, to="allowed@example.com", subject="s", body="b"))
    assert result["status"] == "success"
    assert smtp.sent  # SMTP was actually invoked for an allowed recipient
