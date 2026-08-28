"""CalDAV tools for calendar management."""

import anyio
import caldav
import functools
import os
import re
import smtplib
import ssl
from dateutil.rrule import rrulestr
from datetime import date, datetime, time, timedelta, timezone
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from zoneinfo import ZoneInfo
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from fastmcp import Context
from .auth import require_auth, require_trusted_url
from .config import config

import logging

logger = logging.getLogger(__name__)


def _get_caldav_client(email: str, password: str) -> caldav.DAVClient:
    """Create CalDAV client (stateless)."""
    return caldav.DAVClient(
        url=config.CALDAV_SERVER,
        username=email,
        password=password,
        timeout=config.HTTP_TIMEOUT,
    )


async def _to_thread(fn, *args, **kwargs):
    """Run a blocking library call off the event loop.

    The caldav/SMTP/IMAP calls below do synchronous socket I/O; awaiting them
    on a worker thread keeps a slow or hung server from stalling the whole
    single-threaded MCP event loop.
    """
    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))


def _normalize_rrule(recurrence: str) -> str:
    """
    Validate and normalize an iCalendar recurrence rule.

    Accepts a bare rule ("FREQ=WEEKLY;COUNT=3") or one with the property name
    included ("RRULE:FREQ=WEEKLY;COUNT=3"), in any case.

    Raises:
        ValueError: If the rule is empty or not a parseable recurrence rule.
    """
    rule = recurrence.strip()
    if rule.upper().startswith('RRULE:'):
        rule = rule[len('RRULE:'):].strip()
    rule = rule.upper()

    # No dtstart on purpose: passing one makes dateutil reject a naive DTSTART
    # combined with a UTC UNTIL, which is the most common form of both.
    try:
        rrulestr(rule)
    except Exception as e:
        raise ValueError(f"Invalid recurrence rule {recurrence!r}: {e}")

    return rule


def _event_base_url(event_id: str) -> str:
    """Base URL for a per-event DAVClient, built from host (and port) only.

    Never from netloc: netloc carries any ``user:pass@`` userinfo, which caldav
    would then use to override the authenticated account's credentials.
    """
    parsed = urlparse(event_id)
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return f"{parsed.scheme}://{host}"


def _strip_mailto(addr: str) -> str:
    """Strip a leading (case-insensitive) ``mailto:`` scheme from an address."""
    addr = addr.strip()
    if addr[:7].lower() == "mailto:":
        addr = addr[7:]
    return addr.strip()


def _event_organizer_email(vevent) -> Optional[str]:
    """ORGANIZER address of a stored VEVENT, or None when absent."""
    organizer = getattr(vevent, "organizer", None)
    if organizer is None or not getattr(organizer, "value", None):
        return None
    return _strip_mailto(str(organizer.value))


def _stored_attendee_recipients(vevent) -> List[str]:
    """Attendee addresses read back from a stored event, validated before use.

    A planted event can carry attacker-chosen ATTENDEE values; validating them
    here (same rule as create/update input) stops the authenticated account
    from being turned into a mailer for arbitrary or injected recipients.
    """
    recipients: List[str] = []
    if hasattr(vevent, "attendee_list"):
        for att in vevent.attendee_list:
            if not hasattr(att, "value"):
                continue
            addr = _strip_mailto(str(att.value))
            try:
                recipients.append(_validate_attendee_email(addr))
            except ValueError:
                logger.warning("Skipping invalid stored attendee address: %r", addr)
    return recipients


def _to_utc_datetime(value) -> datetime:
    """Coerce a date / datetime / ISO string to an aware UTC datetime.

    Naive datetimes and bare dates are interpreted in DEFAULT_TZ (system tz),
    matching create_event's DTSTART/DTEND rendering. ZoneInfo("UTC") is used
    (not timezone.utc) because vobject cannot serialize the latter.
    """
    if isinstance(value, str):
        value = date.fromisoformat(value) if len(value) == 10 else datetime.fromisoformat(value)
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=_default_tz())
    else:  # bare date -> midnight
        dt = datetime.combine(value, time()).replace(tzinfo=_default_tz())
    return dt.astimezone(ZoneInfo("UTC"))


def _value_is_all_day(v) -> bool:
    return isinstance(v, date) and not isinstance(v, datetime)


def _display_dtend(vevent, fallback=None):
    """Caller-facing DTEND string.

    All-day DTEND is stored exclusive (RFC 5545), but create_event echoes the
    caller's inclusive input; undo the +1 here so update/delete report and
    email the same inclusive end and a round-trip does not drift by a day.
    """
    if not hasattr(vevent, "dtend") or vevent.dtend.value is None:
        return fallback
    v = vevent.dtend.value
    if _value_is_all_day(v):
        return (v - timedelta(days=1)).isoformat()
    return v.isoformat() if hasattr(v, "isoformat") else str(v)


def _set_vevent_dt(prop, value, is_date: bool) -> None:
    """Assign a date/datetime to a DTSTART/DTEND property, fixing its params.

    Clears TZID / vobject's X-VOBJ-ORIGINAL-TZID leftovers and toggles
    VALUE=DATE so an all-day <-> timed transition never emits a stale param.
    """
    prop.value = value
    prop.params.pop("TZID", None)
    prop.params.pop("X-VOBJ-ORIGINAL-TZID", None)
    if is_date:
        prop.params["VALUE"] = ["DATE"]
    else:
        prop.params.pop("VALUE", None)


def _default_tz():
    """Timezone for naive datetime inputs: DEFAULT_TZ env var, else system local."""
    name = os.getenv("DEFAULT_TZ", "").strip()
    if name:
        try:
            return ZoneInfo(name)
        except Exception:
            pass
    return datetime.now().astimezone().tzinfo


def _ics_escape(text: str) -> str:
    """Escape TEXT property values per RFC 5545 (incl. newlines)."""
    return (
        text.replace("\\", "\\\\")
        .replace(";", "\\;")
        .replace(",", "\\,")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace("\r", "\\n")
    )


def _validate_attendee_email(attendee_email: str) -> str:
    """Reject attendee addresses that could inject ICS properties or headers."""
    cleaned = attendee_email.strip()
    if not re.fullmatch(r"[^\s;,:\\\"'<>]+@[^\s;,:\\\"'<>]+", cleaned):
        raise ValueError(f"Invalid attendee email address: {attendee_email!r}")
    return cleaned


def _ics_dt_line(prop: str, value: str) -> str:
    """Render DTSTART/DTEND from an ISO string.

    Date-only input becomes an all-day VALUE=DATE property. Datetimes are
    converted to UTC (naive input is interpreted in DEFAULT_TZ / system tz) —
    previously the offset was silently dropped, shifting events for any
    caller that passed UTC or an explicit offset.
    """
    if len(value) == 10:
        return f"{prop};VALUE=DATE:{date.fromisoformat(value).strftime('%Y%m%d')}"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_default_tz())
    return f"{prop}:{dt.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"


def _require_trusted_dav_url(url: str, kind: str) -> None:
    """Reject absolute URLs pointing away from the configured CalDAV server."""
    require_trusted_url(url, config.CALDAV_SERVER, kind)


def _send_calendar_invitation(
    organizer_email: str,
    organizer_password: str,
    attendee_email: str,
    ical_data: str,
    summary: str,
    start: str,
    end: str,
    location: Optional[str] = None,
    method: str = "REQUEST"
) -> None:
    """
    Send calendar invitation via email (iTIP protocol).

    Args:
        organizer_email: Organizer's email address
        organizer_password: Organizer's password
        attendee_email: Attendee's email address
        ical_data: iCalendar data (VCALENDAR format)
        summary: Event summary
        start: Start datetime string
        end: End datetime string
        location: Event location (optional)
        method: iTIP method (REQUEST, CANCEL, etc.)
    """
    # Recipient allowlist (same gate as email.py's send path): empty means
    # allow all (back-compat). When set, this bounds the confused-deputy path
    # where a stored event names attacker-chosen recipients.
    allowlist = config.EMAIL_SEND_ALLOWLIST
    if allowlist and attendee_email.strip().lower() not in {a.lower() for a in allowlist}:
        raise ValueError(f"Recipient not in EMAIL_SEND_ALLOWLIST: {attendee_email}")

    # Create multipart message
    msg = MIMEMultipart('alternative')
    msg['From'] = organizer_email
    msg['To'] = attendee_email
    msg['Subject'] = f"Invitation: {summary}"

    # Add Date header
    from email.utils import formatdate
    msg['Date'] = formatdate(localtime=True)

    # Create plain text part
    text_body = f"""You have been invited to the following event:

Summary: {summary}
Start: {start}
End: {end}"""

    if location:
        text_body += f"\nLocation: {location}"

    text_body += f"\n\nOrganizer: {organizer_email}"

    msg.attach(MIMEText(text_body, 'plain'))

    # Modify iCalendar data to include METHOD.
    # Normalize CRLF first: serialized vobject data (update/cancel paths) uses
    # \r\n, and the un-normalized comparison silently skipped METHOD insertion,
    # so cancellations went out without METHOD:CANCEL and were ignored.
    ical_lines = ical_data.strip().replace('\r\n', '\n').split('\n')
    if ical_lines[0] == 'BEGIN:VCALENDAR':
        # Insert METHOD after BEGIN:VCALENDAR
        ical_lines.insert(1, f'METHOD:{method}')
        ical_with_method = '\n'.join(ical_lines)
    else:
        ical_with_method = ical_data

    # Add organizer to the VEVENT if not present
    if 'ORGANIZER' not in ical_with_method:
        # Insert ORGANIZER after UID
        ical_lines = ical_with_method.split('\n')
        for i, line in enumerate(ical_lines):
            if line.startswith('UID:'):
                ical_lines.insert(i + 1, f'ORGANIZER;CN={organizer_email}:mailto:{organizer_email}')
                break
        ical_with_method = '\n'.join(ical_lines)

    # Create calendar part with proper content type
    cal_part = MIMEText(ical_with_method, 'calendar', 'utf-8')
    cal_part.add_header('Content-Class', 'urn:content-classes:calendarmessage')
    cal_part.add_header('Content-Type', f'text/calendar; method={method}; charset=UTF-8')
    msg.attach(cal_part)

    # Send via SMTP
    smtp_client = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT, timeout=30)
    try:
        # Explicit context: bare starttls() on Python <3.13 skips certificate
        # verification, allowing credential theft by a MITM.
        smtp_client.starttls(context=ssl.create_default_context())
        smtp_client.login(organizer_email, organizer_password)
        smtp_client.send_message(msg, from_addr=organizer_email, to_addrs=[attendee_email])
    finally:
        smtp_client.quit()

    # Save copy to Sent folder via IMAP (same as regular emails)
    try:
        from .email import _get_imap_client, _close_imap_client

        imap_client = _get_imap_client(organizer_email, organizer_password)
        try:
            # Convert message to bytes (CRLF per RFC 3501 for IMAP APPEND)
            import email.policy as _email_policy
            msg_bytes = msg.as_bytes(policy=_email_policy.SMTP)

            # Try to append to Sent folder
            try:
                imap_client.append(config.SENT_FOLDER, msg_bytes, flags=['\\Seen'])
            except Exception:
                # Try common alternatives
                for folder_name in ['Sent', 'Sent Items', config.SENT_FOLDER]:
                    try:
                        imap_client.append(folder_name, msg_bytes, flags=['\\Seen'])
                        break
                    except Exception:
                        continue
        finally:
            _close_imap_client(imap_client)
    except Exception:
        # Silently ignore errors saving to Sent folder
        pass


async def list_calendars(context: Context) -> List[Dict[str, Any]]:
    """
    List all available calendars.

    Returns:
        List of calendars with id, name, and description
    """
    email, password = require_auth(context)
    client = _get_caldav_client(email, password)
    principal = await _to_thread(client.principal)
    calendars = await _to_thread(principal.calendars)

    result = []
    for cal in calendars:
        result.append({
            "id": str(cal.url),
            "name": cal.name or "Unnamed Calendar",
            "url": str(cal.url)
        })

    return result


async def list_events(
    context: Context,
    calendar_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    List calendar events with optional filtering.

    Args:
        calendar_id: Specific calendar URL/ID (optional, defaults to all non-reminder calendars)
        start_date: Start date filter in ISO format (YYYY-MM-DD)
        end_date: End date filter in ISO format (YYYY-MM-DD)

    Returns:
        List of events with details. Recurring events are expanded into one entry per
        occurrence, each carrying "recurrence_id" (the occurrence's own start). Expansion
        strips the rule, so "recurrence" is only populated for non-recurring events; a
        non-empty "recurrence_id" is what marks a row as one occurrence of a series.
        Note that every occurrence shares the series' "id"/"url".
    """
    email, password = require_auth(context)
    client = _get_caldav_client(email, password)
    principal = await _to_thread(client.principal)

    # Parse dates. Naive inputs are interpreted in DEFAULT_TZ (or system tz):
    # the caldav library treats naive datetimes as container-local time, which
    # shifted the search window by the user's UTC offset when TZ=UTC.
    tz = _default_tz()
    if start_date:
        start = datetime.fromisoformat(start_date)
        # If only date provided (no time), set to start of day
        if len(start_date) == 10:  # Format: YYYY-MM-DD
            start = start.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        start = datetime.now() - timedelta(days=90)
    if start.tzinfo is None:
        start = start.replace(tzinfo=tz)

    if end_date:
        end = datetime.fromisoformat(end_date)
        # If only date provided (no time), set to end of day
        if len(end_date) == 10:  # Format: YYYY-MM-DD
            end = end.replace(hour=23, minute=59, second=59, microsecond=999999)
    else:
        end = datetime.now() + timedelta(days=365)
    if end.tzinfo is None:
        end = end.replace(tzinfo=tz)

    result = []

    # Get calendars
    if calendar_id:
        _require_trusted_dav_url(calendar_id, "calendar_id")
        calendars_to_search = [caldav.Calendar(client=client, url=calendar_id)]
    else:
        all_calendars = await _to_thread(principal.calendars)
        if not all_calendars:
            return []

        # Filter out reminder calendars (they don't have events in the same format)
        calendars_to_search = [
            cal for cal in all_calendars
            if cal.name and '⚠' not in cal.name and 'reminder' not in cal.name.lower()
        ]

        # If all calendars are filtered out, search all
        if not calendars_to_search:
            calendars_to_search = all_calendars

    # Search events in all relevant calendars
    for calendar in calendars_to_search:
        try:
            # calendar.search is the supported API (date_search is deprecated
            # since caldav 3.0 and scheduled for removal in 4.0)
            events = await _to_thread(
                calendar.search, start=start, end=end, event=True, expand=True
            )

            for event in events:
                try:
                    # Load only when search() returned a bare href without data.
                    # A plain load() re-GETs the master VEVENT and overwrites the
                    # expanded occurrence, so recurring events lose the queried
                    # date and report their series-creation date instead.
                    await _to_thread(event.load, only_if_unloaded=True)
                    vevent = event.vobject_instance.vevent

                    # Parse start/end dates safely
                    start_value = None
                    end_value = None

                    if hasattr(vevent, 'dtstart') and vevent.dtstart:
                        try:
                            start_value = vevent.dtstart.value
                            if hasattr(start_value, 'isoformat'):
                                start_value = start_value.isoformat()
                            else:
                                start_value = str(start_value)
                        except Exception as _e:
                            pass

                    if hasattr(vevent, 'dtend') and vevent.dtend:
                        try:
                            end_value = vevent.dtend.value
                            if hasattr(end_value, 'isoformat'):
                                end_value = end_value.isoformat()
                            else:
                                end_value = str(end_value)
                        except Exception as _e:
                            pass

                    recurrence_id_value = ""
                    if hasattr(vevent, 'recurrence_id') and vevent.recurrence_id:
                        try:
                            rid = vevent.recurrence_id.value
                            recurrence_id_value = rid.isoformat() if hasattr(rid, 'isoformat') else str(rid)
                        except Exception as _e:
                            pass

                    result.append({
                        "id": str(event.url),
                        "summary": str(vevent.summary.value) if hasattr(vevent, 'summary') and vevent.summary else "",
                        "description": str(vevent.description.value) if hasattr(vevent, 'description') and vevent.description else "",
                        "start": start_value,
                        "end": end_value,
                        "location": str(vevent.location.value) if hasattr(vevent, 'location') and vevent.location else "",
                        # Read RRULE off the VEVENT, never the raw ical - VTIMEZONE blocks
                        # carry their own RRULE lines and would give false positives.
                        "recurrence": str(vevent.rrule.value) if hasattr(vevent, 'rrule') and vevent.rrule else "",
                        "recurrence_id": recurrence_id_value,
                        "calendar": calendar.name or "Unknown",
                        "url": str(event.url)
                    })
                except Exception as _e:
                    # Skip malformed events, but leave a trace for operators
                    logger.warning("Skipping malformed event in %r: %s", calendar.name, _e)
                    continue
        except Exception as _e:
            # Skip calendars that fail to search, but leave a trace: a swallowed
            # auth/network failure otherwise looks identical to "no events"
            logger.warning("Calendar search failed for %r: %s", calendar.name, _e)
            continue

    return result


async def create_event(
    context: Context,
    summary: str,
    start: str,
    end: str,
    description: Optional[str] = None,
    location: Optional[str] = None,
    attendees: Optional[List[str]] = None,
    recurrence: Optional[str] = None,
    calendar_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a new calendar event.

    Args:
        summary: Event title
        start: Start datetime in ISO format
        end: End datetime in ISO format
        description: Event description (optional)
        location: Event location (optional)
        attendees: List of attendee email addresses to invite (optional)
        recurrence: iCalendar RRULE making this a recurring series, e.g.
            "FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=12" (optional)
        calendar_id: Target calendar URL/ID (optional, defaults to first non-reminder calendar)

    Returns:
        Created event details
    """
    # Validate before touching the network, so a bad rule cannot half-create an event
    rrule = _normalize_rrule(recurrence) if recurrence else None

    email, password = require_auth(context)
    client = _get_caldav_client(email, password)
    principal = await _to_thread(client.principal)

    # Get calendar
    if calendar_id:
        _require_trusted_dav_url(calendar_id, "calendar_id")
        calendar = caldav.Calendar(client=client, url=calendar_id)
    else:
        all_calendars = await _to_thread(principal.calendars)
        if not all_calendars:
            raise ValueError("No calendars found")

        # Filter out reminder/task calendars - they don't support VEVENT
        event_calendars = [
            cal for cal in all_calendars
            if cal.name and '⚠' not in cal.name and 'reminder' not in cal.name.lower()
        ]

        if not event_calendars:
            raise ValueError("No event calendars found (only reminder/task calendars available)")

        calendar = event_calendars[0]

    # Build iCalendar data with proper formatting for iCloud
    now = datetime.now(timezone.utc)

    # Value type is decided by the START: a date-only start is an all-day
    # event and BOTH endpoints render as VALUE=DATE (mixing DATE with
    # DATE-TIME is invalid per RFC 5545 and iCloud rejects it). All-day DTEND
    # is exclusive, so the inclusive last day is bumped by one day — always,
    # not only for a same-day range (a multi-day range otherwise ends early).
    if len(start) == 10:
        s_date = date.fromisoformat(start)
        e_date = date.fromisoformat(end) if len(end) == 10 else datetime.fromisoformat(end).date()
        last_day = max(s_date, e_date)
        start_line = f"DTSTART;VALUE=DATE:{s_date.strftime('%Y%m%d')}"
        end_line = f"DTEND;VALUE=DATE:{(last_day + timedelta(days=1)).strftime('%Y%m%d')}"
    else:
        start_line = _ics_dt_line("DTSTART", start)
        # Coerce a bare-date end to a datetime so a timed start never pairs
        # with a DATE end.
        end_input = (
            datetime.combine(date.fromisoformat(end), time()).isoformat()
            if len(end) == 10
            else end
        )
        end_line = _ics_dt_line("DTEND", end_input)

    # Generate UID without dots (iCloud compatible)
    uid = f"{int(now.timestamp())}{now.microsecond}@icloud-mcp"

    # Build proper iCalendar format (iCloud is very strict about formatting)
    ical_data = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//iCloud MCP//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
UID:{uid}
DTSTAMP:{now.strftime('%Y%m%dT%H%M%SZ')}
ORGANIZER;CN={email}:mailto:{email}
{start_line}
{end_line}
SUMMARY:{_ics_escape(summary)}
STATUS:CONFIRMED
SEQUENCE:0
"""

    if description:
        ical_data += f"DESCRIPTION:{_ics_escape(description)}\n"
    if location:
        ical_data += f"LOCATION:{_ics_escape(location)}\n"
    if rrule:
        # Not escaped: RRULE's semicolons and commas are structural, not literal text
        ical_data += f"RRULE:{rrule}\n"

    # Add attendees (meeting invitations)
    if attendees:
        attendees = [_validate_attendee_email(a) for a in attendees]
        for attendee_email in attendees:
            # Format: ATTENDEE;CN=email;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:email
            ical_data += f"ATTENDEE;CN={attendee_email};CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:{attendee_email}\n"

    ical_data += "END:VEVENT\nEND:VCALENDAR"

    # Create event using add_event (more reliable than save_event for iCloud)
    try:
        event = await _to_thread(calendar.add_event, ical_data)
    except Exception as e:
        # If add_event fails, try save_event as fallback
        raise ValueError(f"Failed to create event in calendar '{calendar.name}': {str(e)}")

    # Send email invitations to attendees (iTIP protocol)
    if attendees:
        for attendee_email in attendees:
            try:
                await _to_thread(
                    _send_calendar_invitation,
                    organizer_email=email,
                    organizer_password=password,
                    attendee_email=attendee_email,
                    ical_data=ical_data,
                    summary=summary,
                    start=start,
                    end=end,
                    location=location,
                    method="REQUEST",
                )
            except Exception as e:
                # Log error but don't fail the event creation
                # The event is already created, we just failed to send the invitation
                logger.error(f"Failed to send invitation to {attendee_email}: {e}")

    return {
        "id": str(event.url),
        "summary": summary,
        "start": start,
        "end": end,
        "description": description or "",
        "location": location or "",
        "attendees": attendees or [],
        "recurrence": rrule or "",
        "calendar": calendar.name,
        "url": str(event.url)
    }


async def update_event(
    context: Context,
    event_id: str,
    summary: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    description: Optional[str] = None,
    location: Optional[str] = None,
    attendees: Optional[List[str]] = None,
    recurrence: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update an existing calendar event.

    Updating an event that has a recurrence rule affects the WHOLE SERIES;
    single-occurrence edits (RECURRENCE-ID / EXDATE) are not supported yet.

    Args:
        event_id: Event URL/ID
        summary: New event title (optional)
        start: New start datetime in ISO format (optional)
        end: New end datetime in ISO format (optional)
        description: New description (optional)
        location: New location (optional)
        attendees: New list of attendee email addresses (optional, replaces existing)
        recurrence: New iCalendar RRULE (optional). Pass "" to drop recurrence and make
            this a single event; omit to leave any existing rule alone.

    Returns:
        Updated event details
    """
    # Validate before touching the network, so a bad rule cannot partially apply
    rrule = _normalize_rrule(recurrence) if recurrence else None

    email, password = require_auth(context)

    # Create a client with the correct base URL for this specific event
    # This prevents URL joining errors when event is on a different server (e.g., p72-caldav.icloud.com)
    _require_trusted_dav_url(event_id, "event_id")
    event_base_url = _event_base_url(event_id)
    event_client = caldav.DAVClient(
        url=event_base_url, username=email, password=password, timeout=config.HTTP_TIMEOUT
    )

    try:
        # Load existing event using CalendarObjectResource
        event = caldav.CalendarObjectResource(client=event_client, url=event_id)
        await _to_thread(event.load)
    except Exception as e:
        raise Exception(f"Error loading event: {str(e)}")

    vevent = event.vobject_instance.vevent

    # Update fields
    if summary:
        vevent.summary.value = summary
    # DTSTART/DTEND: same tz + all-day semantics as create_event. The value
    # type (all-day vs timed) is governed by the new-or-stored start; both
    # endpoints render as that type so we never emit an invalid mixed
    # DATE / DATE-TIME event. A stored endpoint the caller did not change is
    # coerced only when its type would otherwise clash with the target.
    if start or end:
        stored_start = vevent.dtstart.value if hasattr(vevent, "dtstart") else None
        stored_end = vevent.dtend.value if hasattr(vevent, "dtend") else None
        ref = start if start else stored_start
        if isinstance(ref, str):
            all_day = len(ref) == 10
        elif ref is not None:
            all_day = _value_is_all_day(ref)
        else:
            all_day = None

        if all_day is not None:
            # DTSTART
            if start:
                new_start = date.fromisoformat(start) if all_day else _to_utc_datetime(start)
                _set_vevent_dt(vevent.dtstart, new_start, all_day)
            elif stored_start is not None and _value_is_all_day(stored_start) != all_day:
                coerced = stored_start.date() if all_day else _to_utc_datetime(stored_start)
                _set_vevent_dt(vevent.dtstart, coerced, all_day)

            # DTEND
            if end:
                if all_day:
                    last_day = date.fromisoformat(end) if len(end) == 10 else datetime.fromisoformat(end).date()
                    if start and len(start) == 10:
                        last_day = max(last_day, date.fromisoformat(start))
                    new_end = last_day + timedelta(days=1)  # RFC 5545 exclusive DTEND
                else:
                    new_end = _to_utc_datetime(end)
                dtend_prop = vevent.dtend if hasattr(vevent, "dtend") else vevent.add("dtend")
                _set_vevent_dt(dtend_prop, new_end, all_day)
            elif stored_end is not None and _value_is_all_day(stored_end) != all_day:
                coerced = stored_end.date() if all_day else _to_utc_datetime(stored_end)
                _set_vevent_dt(vevent.dtend, coerced, all_day)
    if description is not None:
        if hasattr(vevent, 'description'):
            vevent.description.value = description
        else:
            vevent.add('description').value = description
    if location is not None:
        if hasattr(vevent, 'location'):
            vevent.location.value = location
        else:
            vevent.add('location').value = location

    if recurrence is not None:
        if rrule:
            if hasattr(vevent, 'rrule'):
                vevent.rrule.value = rrule
            else:
                vevent.add('rrule').value = rrule
        elif hasattr(vevent, 'rrule'):
            # Empty string means "make this a single event"
            vevent.remove(vevent.rrule)

    # Update attendees
    if attendees is not None:
        attendees = [_validate_attendee_email(a) for a in attendees]
        # Remove existing attendees
        if hasattr(vevent, 'attendee_list'):
            for att in list(vevent.attendee_list):
                vevent.remove(att)

        # Add new attendees
        for attendee_email in attendees:
            att = vevent.add('attendee')
            att.value = f'mailto:{attendee_email}'
            att.params['CN'] = [attendee_email]
            att.params['CUTYPE'] = ['INDIVIDUAL']
            att.params['ROLE'] = ['REQ-PARTICIPANT']
            att.params['PARTSTAT'] = ['NEEDS-ACTION']
            att.params['RSVP'] = ['TRUE']

    # Save changes - use PUT request directly to avoid parent dependency
    try:
        # Serialize the updated vCalendar data and send PUT request
        updated_ical = event.vobject_instance.serialize()
        await _to_thread(
            event_client.put,
            event_id,
            updated_ical,
            {"Content-Type": "text/calendar; charset=utf-8"},
        )
    except Exception as e:
        raise Exception(f"Error saving event: {str(e)}")

    # Extract attendees for response, validating each address read back from
    # the stored event before it can become a recipient (confused-deputy).
    attendee_list = _stored_attendee_recipients(vevent)

    # Send update notifications only when attendees were modified AND this
    # account is the event's ORGANIZER — a planted event organized by someone
    # else must not use the victim's account to email its attendees.
    if attendees is not None and attendee_list:
        organizer = _event_organizer_email(vevent)
        if organizer is None or organizer.lower() != email.lower():
            logger.warning(
                "Skipping iTIP REQUEST: event organizer %r is not the "
                "authenticated account; not emailing attendees", organizer
            )
        else:
            event_summary = str(vevent.summary.value) if hasattr(vevent, 'summary') else ""
            event_start = vevent.dtstart.value.isoformat() if hasattr(vevent, 'dtstart') else start
            event_end = _display_dtend(vevent, end)
            event_location = str(vevent.location.value) if hasattr(vevent, 'location') else None

            for attendee_email in attendee_list:
                try:
                    await _to_thread(
                        _send_calendar_invitation,
                        organizer_email=email,
                        organizer_password=password,
                        attendee_email=attendee_email,
                        ical_data=updated_ical,
                        summary=event_summary,
                        start=event_start,
                        end=event_end,
                        location=event_location,
                        method="REQUEST",  # Use REQUEST for updates too
                    )
                except Exception as e:
                    # Log error but don't fail the update
                    logger.error(f"Failed to send update notification to {attendee_email}: {e}")

    return {
        "id": str(event.url),
        "summary": str(vevent.summary.value) if hasattr(vevent, 'summary') else "",
        "start": vevent.dtstart.value.isoformat() if hasattr(vevent, 'dtstart') else None,
        "end": _display_dtend(vevent, None),
        "description": str(vevent.description.value) if hasattr(vevent, 'description') else "",
        "location": str(vevent.location.value) if hasattr(vevent, 'location') else "",
        "attendees": attendee_list,
        "recurrence": str(vevent.rrule.value) if hasattr(vevent, 'rrule') else "",
        "url": str(event.url)
    }


async def delete_event(context: Context, event_id: str) -> Dict[str, str]:
    """
    Delete a calendar event.

    Deleting an event that has a recurrence rule deletes the WHOLE SERIES;
    deleting a single occurrence (EXDATE) is not supported yet.

    Args:
        event_id: Event URL/ID to delete

    Returns:
        Confirmation message
    """
    email, password = require_auth(context)

    # Create a client with the correct base URL for this specific event
    # This prevents URL joining errors when event is on a different server (e.g., p72-caldav.icloud.com)
    _require_trusted_dav_url(event_id, "event_id")
    event_base_url = _event_base_url(event_id)
    event_client = caldav.DAVClient(
        url=event_base_url, username=email, password=password, timeout=config.HTTP_TIMEOUT
    )

    # Use CalendarObjectResource to handle full URLs correctly
    event = caldav.CalendarObjectResource(client=event_client, url=event_id)

    # Load event to get attendees before deleting
    attendee_list = []
    event_summary = ""
    event_start = ""
    event_end = ""
    event_location = None
    ical_data = None
    event_organizer = None

    try:
        await _to_thread(event.load)
        vevent = event.vobject_instance.vevent

        # Extract event details
        event_summary = str(vevent.summary.value) if hasattr(vevent, 'summary') else "Event"
        if hasattr(vevent, 'dtstart'):
            event_start = vevent.dtstart.value.isoformat() if hasattr(vevent.dtstart.value, 'isoformat') else str(vevent.dtstart.value)
        event_end = _display_dtend(vevent, event_end)
        if hasattr(vevent, 'location'):
            event_location = str(vevent.location.value)

        # Extract attendees, validating each address read back from the stored
        # event before it can become a CANCEL recipient (confused-deputy).
        attendee_list = _stored_attendee_recipients(vevent)
        event_organizer = _event_organizer_email(vevent)

        # Get the iCalendar data for CANCEL notifications
        ical_data = event.vobject_instance.serialize()

    except Exception as e:
        # If we can't load the event, just delete it
        logger.warning(f"Could not load event details before deletion: {e}")

    # Delete the event
    await _to_thread(event.delete)

    # Send cancellation notifications only when this account is the event's
    # ORGANIZER — a planted event organized by someone else must not use the
    # victim's account to email its attendees.
    if attendee_list and ical_data:
        if event_organizer is None or event_organizer.lower() != email.lower():
            logger.warning(
                "Skipping iTIP CANCEL: event organizer %r is not the "
                "authenticated account; not emailing attendees", event_organizer
            )
        else:
            for attendee_email in attendee_list:
                try:
                    await _to_thread(
                        _send_calendar_invitation,
                        organizer_email=email,
                        organizer_password=password,
                        attendee_email=attendee_email,
                        ical_data=ical_data,
                        summary=event_summary,
                        start=event_start,
                        end=event_end,
                        location=event_location,
                        method="CANCEL",
                    )
                except Exception as e:
                    # Log error but don't fail the deletion
                    logger.error(f"Failed to send cancellation to {attendee_email}: {e}")

    return {"status": "success", "message": f"Event {event_id} deleted"}


async def search_events(
    context: Context,
    query: str,
    calendar_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search for events by text query.

    Args:
        query: Search text (matches summary and description)
        calendar_id: Specific calendar URL/ID (optional)
        start_date: Start date filter in ISO format (optional)
        end_date: End date filter in ISO format (optional)

    Returns:
        List of matching events
    """
    # Get all events
    events = await list_events(context, calendar_id, start_date, end_date)

    # Filter by query
    query_lower = query.lower()
    filtered_events = [
        event for event in events
        if query_lower in event.get("summary", "").lower()
        or query_lower in event.get("description", "").lower()
        or query_lower in event.get("location", "").lower()
    ]

    return filtered_events
