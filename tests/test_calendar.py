"""Calendar remediation locks: userinfo stripped from per-event base URL, and
create/update produce the same UTC DTSTART for the same naive input.
"""

import pytest

from icloud_mcp import calendar as cal


# --- test 5: _event_base_url strips userinfo -----------------------------

def test_event_base_url_drops_userinfo():
    ev = "https://user:pass@p72-caldav.icloud.com:443/1/calendars/work/evt.ics"
    base = cal._event_base_url(ev)
    assert base == "https://p72-caldav.icloud.com:443"
    assert "@" not in base
    assert "user" not in base
    assert "pass" not in base


def test_event_base_url_no_port():
    ev = "https://attacker:secret@caldav.icloud.com/x"
    base = cal._event_base_url(ev)
    assert base == "https://caldav.icloud.com"
    assert "secret" not in base and "attacker" not in base


# --- test 6: create vs update DTSTART parity for naive input --------------

@pytest.mark.parametrize("tzname", ["America/New_York", "Europe/Moscow", "UTC"])
@pytest.mark.parametrize("naive", ["2026-08-02T10:30:00", "2026-12-31T23:15:00"])
def test_create_update_same_dtstart(monkeypatch, tzname, naive):
    # Both paths interpret a naive datetime in DEFAULT_TZ and convert to UTC.
    monkeypatch.setenv("DEFAULT_TZ", tzname)

    # create_event's timed-start rendering
    create_line = cal._ics_dt_line("DTSTART", naive)

    # update_event's rendering: _to_utc_datetime -> aware UTC datetime
    update_dt = cal._to_utc_datetime(naive)
    update_line = "DTSTART:" + update_dt.strftime("%Y%m%dT%H%M%SZ")

    assert create_line == update_line
    assert create_line.endswith("Z")


def test_default_tz_actually_shifts(monkeypatch):
    # Guard against a trivial pass: a non-UTC zone must move the wall-clock time.
    monkeypatch.setenv("DEFAULT_TZ", "America/New_York")
    # 2026-08-02 is EDT (UTC-4): 10:30 local -> 14:30 UTC.
    assert cal._ics_dt_line("DTSTART", "2026-08-02T10:30:00") == "DTSTART:20260802T143000Z"
