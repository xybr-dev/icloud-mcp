"""Checks for recurrence rule validation."""

from icloud_mcp.calendar import _normalize_rrule


def test_accepts_common_rules():
    assert _normalize_rrule("FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=12") == "FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=12"
    assert _normalize_rrule("FREQ=DAILY") == "FREQ=DAILY"
    assert _normalize_rrule("FREQ=MONTHLY;BYMONTHDAY=15") == "FREQ=MONTHLY;BYMONTHDAY=15"
    # A UTC UNTIL alongside a naive DTSTART is the common case, and must not be rejected
    assert _normalize_rrule("FREQ=WEEKLY;UNTIL=20261231T000000Z") == "FREQ=WEEKLY;UNTIL=20261231T000000Z"


def test_normalizes_prefix_and_case():
    assert _normalize_rrule("RRULE:FREQ=WEEKLY;COUNT=3") == "FREQ=WEEKLY;COUNT=3"
    assert _normalize_rrule("  rrule:freq=weekly;count=3  ") == "FREQ=WEEKLY;COUNT=3"


def test_rejects_garbage():
    for bad in ("", "   ", "garbage", "FREQ=BOGUS", "every week"):
        try:
            _normalize_rrule(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


if __name__ == "__main__":
    test_accepts_common_rules()
    test_normalizes_prefix_and_case()
    test_rejects_garbage()
    print("ok")
