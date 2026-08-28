"""Checks for event alarm (VALARM) offsets."""

import vobject

from icloud_mcp.calendar import _alarm_blocks, _event_reminders, _normalize_reminders


def test_normalizes_offsets():
    assert _normalize_reminders([60, "10", -540]) == [60, 10, -540]
    assert _normalize_reminders([]) == []


def test_rejects_non_integer_offsets():
    for bad in (["soon"], [None], [[60]]):
        try:
            _normalize_reminders(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_alarm_blocks():
    assert _alarm_blocks([]) == ""
    block = _alarm_blocks([60])
    assert "TRIGGER;RELATED=START:-PT60M" in block
    assert block.count("BEGIN:VALARM") == 1
    # Negative means after the start: an all-day event alerting at 9:00 AM
    assert "TRIGGER;RELATED=START:PT540M" in _alarm_blocks([-540])
    assert _alarm_blocks([60, 10]).count("BEGIN:VALARM") == 2


def _vevent(*alarm_triggers):
    alarms = "".join(
        f"BEGIN:VALARM\nACTION:DISPLAY\nDESCRIPTION:Reminder\nTRIGGER:{t}\nEND:VALARM\n"
        for t in alarm_triggers
    )
    return vobject.readOne(
        "BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nUID:x\n"
        "DTSTART:20260101T090000\nSUMMARY:t\n" + alarms + "END:VEVENT\nEND:VCALENDAR"
    ).vevent


def test_reads_offsets_back():
    assert _event_reminders(_vevent()) == []
    assert _event_reminders(_vevent("-PT1H", "-PT10M")) == [60, 10]
    assert _event_reminders(_vevent("PT9H")) == [-540]
    # An absolute DATE-TIME trigger has no minutes-before value: skipped, not crashed
    assert _event_reminders(_vevent("20260101T080000Z", "-PT10M")) == [10]


def test_blocks_round_trip():
    ical = (
        "BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nUID:x\n"
        "DTSTART:20260101T090000\nSUMMARY:t\n" + _alarm_blocks([60, 10])
        + "END:VEVENT\nEND:VCALENDAR"
    )
    assert _event_reminders(vobject.readOne(ical).vevent) == [60, 10]


if __name__ == "__main__":
    test_normalizes_offsets()
    test_rejects_non_integer_offsets()
    test_alarm_blocks()
    test_reads_offsets_back()
    test_blocks_round_trip()
    print("ok")
