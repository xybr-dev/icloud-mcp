"""IMAP/SMTP tools for email management."""

import imaplib
import smtplib
import ssl
import email
import email.policy
import logging
import sys
import os
import functools
import anyio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
from email.utils import getaddresses
from typing import List, Dict, Any, Optional
from datetime import datetime
from fastmcp import Context
from imapclient import IMAPClient
from .auth import require_auth
from .config import config

# Configure minimal logging (only errors)
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Log errors to stderr
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.ERROR)
stderr_handler.setFormatter(formatter)
logger.addHandler(stderr_handler)


async def _run(func, *args, **kwargs):
    """Run a blocking (socket I/O) call off the event loop in a worker thread."""
    return await anyio.to_thread.run_sync(functools.partial(func, *args, **kwargs))


def _get_imap_client(username: str, password: str) -> IMAPClient:
    """Create IMAP client (stateless)."""
    # timeout: tools run synchronously on the server's event loop, so a hung
    # TCP connection without a timeout would freeze every tool incl. /health
    client = IMAPClient(config.IMAP_SERVER, port=config.IMAP_PORT, ssl=True, use_uid=True, timeout=30)
    client.login(username, password)
    return client


def _close_imap_client(client: IMAPClient) -> None:
    """Safely close IMAP client connection."""
    try:
        # Don't call logout() - it causes "file property has no setter" error in Python 3.14+
        # Just close the underlying socket
        if hasattr(client, '_imap') and hasattr(client._imap, 'sock'):
            client._imap.sock.close()
    except Exception as _e:
        pass  # Silently ignore errors on close


def _find_trash_folder(client: IMAPClient) -> Optional[str]:
    """Locate the trash folder via SPECIAL-USE \\Trash, then common names."""
    try:
        # RFC 6154 SPECIAL-USE \Trash. Pass the literal flag: the constant lives
        # at imapclient.imapclient.TRASH, not on the package, so the old
        # imapclient.TRASH raised AttributeError and this path never ran.
        special = client.find_special_folder(b"\\Trash")
        if special:
            return special
    except Exception:
        pass
    try:
        existing = {f[2] for f in client.list_folders()}
    except Exception:
        return None
    for name in ('Deleted Messages', 'Trash', 'Deleted Items', 'Корзина'):
        if name in existing:
            return name
    return None


def _expunge_message(client: IMAPClient, msg_id: int) -> None:
    """Expunge only the targeted message (UID EXPUNGE), not the whole folder.

    A bare EXPUNGE also purges messages other clients (e.g. iPhone Mail)
    flagged \\Deleted but not yet expunged. Falls back to full expunge only
    when the server genuinely lacks UIDPLUS; any UID EXPUNGE failure on a
    UIDPLUS server surfaces instead of silently widening to a full expunge.
    """
    if client.has_capability('UIDPLUS'):
        client.uid_expunge([msg_id])
    else:
        client.expunge()


def _last_copyuid(client: IMAPClient) -> Optional[int]:
    """Destination UID from the server's COPYUID (UIDPLUS) response, or None.

    The COPYUID response code (``COPYUID <uidvalidity> <src-set> <dest-set>``)
    lands in imaplib's untagged_responses after a UID COPY; imapclient.copy()
    does not surface it. Read it right after the copy, before the next command.
    """
    try:
        resp = client._imap.untagged_responses.pop('COPYUID', None)
        if not resp:
            return None
        raw = resp[-1]
        if isinstance(raw, bytes):
            raw = raw.decode('ascii', errors='ignore')
        # last token is the dest UID set; for a single message it is one UID
        dest = raw.split()[-1].split(',')[-1].split(':')[-1]
        return int(dest)
    except Exception:
        return None


def _get_smtp_client(username: str, password: str) -> smtplib.SMTP:
    """Create SMTP client (stateless)."""
    client = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT, timeout=30)
    # Explicit context: bare starttls() on Python <3.13 skips certificate
    # verification, allowing credential theft by a MITM.
    client.starttls(context=ssl.create_default_context())
    client.login(username, password)
    return client


def _decode_mime_header(header_value: str) -> str:
    """Decode MIME encoded email header."""
    if not header_value:
        return ""

    # A malformed encoded-word (e.g. "=?utf-8?b?A!!!?=") makes decode_header
    # raise HeaderParseError; fall back to the raw header rather than propagate.
    try:
        decoded_parts = decode_header(header_value)
    except Exception:
        return header_value
    result = []

    for content, charset in decoded_parts:
        if isinstance(content, bytes):
            try:
                result.append(content.decode(charset or 'utf-8', errors='ignore'))
            except Exception as _e:
                result.append(content.decode('utf-8', errors='ignore'))
        else:
            result.append(str(content))

    return ' '.join(result)


async def list_folders(context: Context) -> List[Dict[str, Any]]:
    """
    List all email folders/mailboxes.

    Returns:
        List of folders with name and flags
    """
    try:
        username, password = require_auth(context)

        client = await _run(_get_imap_client, username, password)

        folders = await _run(client.list_folders)

        result = []
        for flags, delimiter, name in folders:
            result.append({
                "name": name,
                "flags": [flag.decode() if isinstance(flag, bytes) else flag for flag in flags],
                "delimiter": delimiter
            })

        return result
    except Exception as _e:
        raise
    finally:
        try:
            _close_imap_client(client)
        except Exception as _e:
            pass


async def list_messages(
    context: Context,
    folder: str = "INBOX",
    limit: int = 20,
    unread_only: bool = False
) -> List[Dict[str, Any]]:
    """
    List messages in a folder.

    Args:
        folder: Folder name (default: INBOX)
        limit: Maximum number of messages to return
        unread_only: Only return unread messages

    Returns:
    """
    try:
        # Clamp limit: limit<=0 -> [-0:] returns the WHOLE folder; a hard cap
        # bounds the fetch regardless of caller input.
        if limit is None or limit <= 0:
            limit = 20
        limit = min(limit, 200)

        username, password = require_auth(context)

        client = await _run(_get_imap_client, username, password)

        await _run(client.select_folder, folder)

        # Search for messages
        if unread_only:
            messages = await _run(client.search, ['UNSEEN'])
        else:
            messages = await _run(client.search, ['ALL'])


        # Get most recent messages
        message_ids = list(messages)[-limit:] if len(messages) > limit else list(messages)
        message_ids.reverse()  # Most recent first

        if not message_ids:
            return []

        # Fetch full message body to extract body_text
        response = await _run(client.fetch, message_ids, [b'FLAGS', b'BODY.PEEK[]'])

        result = []
        for msg_id, data in response.items():
            try:
                # Try multiple possible keys for the message body
                raw_email = None
                for key in [b'BODY[]', 'BODY[]', b'RFC822', 'RFC822', b'BODY.PEEK[]']:
                    if key in data:
                        raw_email = data[key]
                        break

                if raw_email is None:
                    continue

                msg = email.message_from_bytes(raw_email)

                # Extract body_text
                body_text = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if content_type == "text/plain":
                            try:
                                body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                break
                            except Exception as _e:
                                pass
                else:
                    try:
                        body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except Exception as _e:
                        pass

                # Truncate list-view bodies: full bodies of dozens of messages
                # blow up the caller's context (use get_message for full text)
                if len(body_text) > 500:
                    body_text = body_text[:500] + "… [truncated, use email_get_message for full text]"

                result.append({
                    "id": str(msg_id),
                    "subject": _decode_mime_header(msg.get('Subject', '')),
                    "from": _decode_mime_header(msg.get('From', '')),
                    "to": _decode_mime_header(msg.get('To', '')),
                    "date": msg.get('Date', ''),
                    "flags": [flag.decode() if isinstance(flag, bytes) else flag for flag in data.get(b'FLAGS', data.get('FLAGS', []))],
                    "folder": folder,
                    "body_text": body_text
                })
            except Exception as _e:
                continue

        return result

    except Exception as _e:
        raise
    finally:
        try:
            _close_imap_client(client)
        except Exception as _e:
            pass

async def get_message(
    context: Context,
    message_id: str,
    folder: str = "INBOX",
    include_body: bool = True,
    full_html: bool = False
) -> Dict[str, Any]:
    """
    Get a specific message with full details.

    Args:
        message_id: Message ID
        folder: Folder name (default: INBOX)
        include_body: Include message body content
        full_html: Include full HTML body (default: False, only text body returned)

    Returns:
        Complete message details
    """
    try:
        username, password = require_auth(context)
        client = await _run(_get_imap_client, username, password)

        await _run(client.select_folder, folder)

        msg_id = int(message_id)

        # Use BODY.PEEK[] instead of RFC822 - more reliable with IMAPClient
        response = await _run(client.fetch, [msg_id], [b'FLAGS', b'BODY.PEEK[]'])

        if msg_id not in response:
            raise ValueError(f"Message {message_id} not found")

        data = response[msg_id]

        # Try multiple possible keys for the message body
        raw_email = None
        for key in [b'BODY[]', 'BODY[]', b'RFC822', 'RFC822', b'BODY.PEEK[]']:
            if key in data:
                raw_email = data[key]
                break

        if raw_email is None:
            # Log available keys for debugging
            available_keys = list(data.keys())
            raise KeyError(f"Message body not found. Available keys: {available_keys}")

        msg = email.message_from_bytes(raw_email)

        result = {
            "id": message_id,
            "subject": _decode_mime_header(msg.get('Subject', '')),
            "from": _decode_mime_header(msg.get('From', '')),
            "to": _decode_mime_header(msg.get('To', '')),
            "cc": _decode_mime_header(msg.get('Cc', '')),
            "date": msg.get('Date', ''),
            "flags": [flag.decode() if isinstance(flag, bytes) else flag for flag in data.get(b'FLAGS', data.get('FLAGS', []))],
            "folder": folder
        }

        if include_body:
            # Extract body
            body_text = ""
            body_html = ""

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    # keep only the FIRST part of each type: without the guard
                    # a later text/plain attachment overwrote the actual body
                    if content_type == "text/plain" and not body_text:
                        try:
                            body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except Exception as _e:
                            pass
                    elif content_type == "text/html" and full_html and not body_html:
                        try:
                            body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except Exception as _e:
                            pass
            else:
                try:
                    body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                except Exception as _e:
                    pass

            result["body_text"] = body_text
            if full_html:
                result["body_html"] = body_html

        return result

    except Exception as _e:
        raise
    finally:
        try:
            _close_imap_client(client)
        except Exception as _e:
            pass


async def get_messages(
    context: Context,
    message_ids: List[str],
    folder: str = "INBOX",
    include_body: bool = True,
    full_html: bool = False
) -> List[Dict[str, Any]]:
    """
    Get multiple messages at once.

    Args:
        message_ids: List of message IDs to fetch
        folder: Folder name (default: INBOX)
        include_body: Include message body content
        full_html: Include full HTML body (default: False, only text body returned)

    Returns:
        List of message details
    """
    try:
        username, password = require_auth(context)
        client = await _run(_get_imap_client, username, password)

        await _run(client.select_folder, folder)

        # Convert string IDs to integers, capped: this is the one fetch path
        # without a limit, so an arbitrarily long message_ids list would pull
        # unbounded full bodies into memory (the shape the limit clamp prevents
        # elsewhere).
        msg_ids = [int(mid) for mid in message_ids][:200]

        # Fetch all messages at once
        response = await _run(client.fetch, msg_ids, [b'FLAGS', b'BODY.PEEK[]'])

        results = []

        for msg_id in msg_ids:
            # Guard each message: one poisoned message (or a RecursionError
            # from message_from_bytes on deep MIME nesting) must not kill the
            # whole batch.
            try:
                if msg_id not in response:
                    # Skip missing messages
                    continue

                data = response[msg_id]

                # Try multiple possible keys for the message body
                raw_email = None
                for key in [b'BODY[]', 'BODY[]', b'RFC822', 'RFC822', b'BODY.PEEK[]']:
                    if key in data:
                        raw_email = data[key]
                        break

                if raw_email is None:
                    # Skip messages without body
                    continue

                msg = email.message_from_bytes(raw_email)

                result = {
                    "id": str(msg_id),
                    "subject": _decode_mime_header(msg.get('Subject', '')),
                    "from": _decode_mime_header(msg.get('From', '')),
                    "to": _decode_mime_header(msg.get('To', '')),
                    "cc": _decode_mime_header(msg.get('Cc', '')),
                    "date": msg.get('Date', ''),
                    "flags": [flag.decode() if isinstance(flag, bytes) else flag for flag in data.get(b'FLAGS', data.get('FLAGS', []))],
                    "folder": folder
                }

                if include_body:
                    # Extract body
                    body_text = ""
                    body_html = ""

                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            if content_type == "text/plain":
                                try:
                                    body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                except Exception as _e:
                                    pass
                            elif content_type == "text/html" and full_html:
                                try:
                                    body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                except Exception as _e:
                                    pass
                    else:
                        try:
                            body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except Exception as _e:
                            pass

                    result["body_text"] = body_text
                    if full_html:
                        result["body_html"] = body_html

                results.append(result)
            except Exception as _e:
                continue

        return results

    except Exception as _e:
        raise
    finally:
        try:
            _close_imap_client(client)
        except Exception as _e:
            pass

async def search_messages(
    context: Context,
    query: str,
    folder: str = "INBOX",
    limit: int = 50
) -> List[Dict[str, Any]]:
    """
    Search for messages by text query.

    Args:
        query: Search text (searches subject and from fields)
        folder: Folder name (default: INBOX)
        limit: Maximum number of results

    Returns:
        List of matching messages
    """
    # Clamp limit: limit<=0 -> [-0:] returns the WHOLE folder; a hard cap
    # bounds the fetch regardless of caller input.
    if limit is None or limit <= 0:
        limit = 20
    limit = min(limit, 200)

    username, password = require_auth(context)
    client = await _run(_get_imap_client, username, password)

    try:
        await _run(client.select_folder, folder)

        # Try server-side search with UTF-8 charset (RFC 2978)
        # This works with modern IMAP servers including iCloud
        try:
            # FLAT criteria: nested ['OR',['SUBJECT',q],['FROM',q]] makes
            # imapclient drop the CHARSET, so every non-ASCII query failed
            # into the local-filtering fallback.
            messages = await _run(
                client.search,
                ['OR', 'SUBJECT', query, 'FROM', query],
                charset='UTF-8'
            )

            message_ids = list(messages)[-limit:] if len(messages) > limit else list(messages)
            message_ids.reverse()

            if not message_ids:
                return []

            # Fetch full message body to extract body_text
            response = await _run(client.fetch, message_ids, [b'FLAGS', b'BODY.PEEK[]'])

            result = []
            for msg_id, data in response.items():
                try:
                    # Try multiple possible keys for the message body
                    raw_email = None
                    for key in [b'BODY[]', 'BODY[]', b'RFC822', 'RFC822', b'BODY.PEEK[]']:
                        if key in data:
                            raw_email = data[key]
                            break

                    if raw_email is None:
                        continue

                    msg = email.message_from_bytes(raw_email)

                    # Extract body_text
                    body_text = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            if content_type == "text/plain":
                                try:
                                    body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                    break
                                except Exception as _e:
                                    pass
                    else:
                        try:
                            body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except Exception as _e:
                            pass

                    result.append({
                        "id": str(msg_id),
                        "subject": _decode_mime_header(msg.get('Subject', '')),
                        "from": _decode_mime_header(msg.get('From', '')),
                        "to": _decode_mime_header(msg.get('To', '')),
                        "date": msg.get('Date', ''),
                        "flags": [flag.decode() if isinstance(flag, bytes) else flag for flag in data.get(b'FLAGS', data.get('FLAGS', []))],
                        "folder": folder,
                        "body_text": body_text
                    })
                except Exception as _e:
                    continue

            return result

        except imaplib.IMAP4.error as charset_error:
            # Only an IMAP search/charset failure (imapclient errors subclass
            # imaplib.IMAP4.error) triggers the local-filtering fallback; a
            # message-parse bug or a network error must NOT be masked as an
            # unsupported charset and silently rescan the whole folder.
            logger.error(f"Server-side UTF-8 search failed: {charset_error}. Falling back to local filtering.")

            # Fetch more messages to search through locally, hard-capped.
            fetch_limit = min(max(limit * 10, 200), 500)

            # Get all message IDs
            all_msg_ids = await _run(client.search, ['ALL'])
            message_ids = list(all_msg_ids)[-fetch_limit:] if len(all_msg_ids) > fetch_limit else list(all_msg_ids)
            message_ids.reverse()

            if not message_ids:
                return []

            # Fetch full messages with body
            response = await _run(client.fetch, message_ids, [b'FLAGS', b'BODY.PEEK[]'])

            all_messages = []
            for msg_id, data in response.items():
                try:
                    # Try multiple possible keys for the message body
                    raw_email = None
                    for key in [b'BODY[]', 'BODY[]', b'RFC822', 'RFC822', b'BODY.PEEK[]']:
                        if key in data:
                            raw_email = data[key]
                            break

                    if raw_email is None:
                        continue

                    msg = email.message_from_bytes(raw_email)

                    # Extract body_text
                    body_text = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            if content_type == "text/plain":
                                try:
                                    body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                    break
                                except Exception as _e:
                                    pass
                    else:
                        try:
                            body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except Exception as _e:
                            pass

                    all_messages.append({
                        "id": str(msg_id),
                        "subject": _decode_mime_header(msg.get('Subject', '')),
                        "from": _decode_mime_header(msg.get('From', '')),
                        "to": _decode_mime_header(msg.get('To', '')),
                        "date": msg.get('Date', ''),
                        "flags": [flag.decode() if isinstance(flag, bytes) else flag for flag in data.get(b'FLAGS', data.get('FLAGS', []))],
                        "folder": folder,
                        "body_text": body_text
                    })
                except Exception as _e:
                    continue

            # Filter messages locally (supports any Unicode)
            query_lower = query.lower()
            filtered_messages = [
                msg for msg in all_messages
                if query_lower in msg.get("subject", "").lower()
                or query_lower in msg.get("from", "").lower()
                or query_lower in msg.get("to", "").lower()
            ]

            return filtered_messages[:limit]

    finally:
        try:
            _close_imap_client(client)
        except Exception as _e:
            pass

async def send_message(
    context: Context,
    to: str,
    subject: str,
    body: str,
    cc: Optional[str] = None,
    bcc: Optional[str] = None,
    html: bool = False
) -> Dict[str, str]:
    """
    Send an email message via SMTP.

    Args:
        to: Recipient email address
        subject: Email subject
        body: Email body content
        cc: CC recipients (optional, comma-separated)
        bcc: BCC recipients (optional, comma-separated)
        html: Whether body is HTML (default: False)

    Returns:
        Confirmation message
    """
    username, password = require_auth(context)

    # Create message
    msg = MIMEMultipart('alternative') if html else MIMEText(body)

    msg['From'] = username
    msg['To'] = to
    msg['Subject'] = subject

    if cc:
        msg['Cc'] = cc
    if bcc:
        msg['Bcc'] = bcc

    if html:
        msg.attach(MIMEText(body, 'html'))

    recipients = [to]
    if cc:
        recipients.extend([addr.strip() for addr in cc.split(',')])
    if bcc:
        recipients.extend([addr.strip() for addr in bcc.split(',')])

    # Reject any recipient that does not parse to exactly one address. A form
    # like "attacker@evil.com," parses to zero addresses yet smtplib would
    # still deliver it, sneaking past the allowlist; a multi-address string
    # would split unpredictably. Fail loudly instead.
    for r in recipients:
        if len([a for _name, a in getaddresses([r]) if a]) != 1:
            raise ValueError(f"Invalid recipient address: {r!r}")

    # Normalize to bare addresses so the allowlist check and the SMTP envelope
    # operate on the SAME set: raw recipient strings and getaddresses-parsed
    # addresses diverge, so handing SMTP the raw strings would deliver to
    # addresses the allowlist never approved.
    addrs = [addr for _name, addr in getaddresses(recipients) if addr]

    # Recipient allowlist: an empty list means allow all (back-compat). When
    # set, every to/cc/bcc address must be present or the send is refused.
    allowlist = config.EMAIL_SEND_ALLOWLIST
    if allowlist:
        allowed = {a.lower() for a in allowlist}
        disallowed = [a for a in addrs if a.lower() not in allowed]
        if disallowed:
            raise ValueError(
                "Recipient(s) not in EMAIL_SEND_ALLOWLIST: " + ", ".join(disallowed)
            )

    # Send via SMTP (off the event loop; connect+login+send are blocking)
    client = await _run(_get_smtp_client, username, password)
    try:
        await _run(client.send_message, msg, from_addr=username, to_addrs=addrs)
    finally:
        # Synchronous cleanup, NOT await _run(...): if the request is cancelled
        # mid-send, an awaited call in finally hits a checkpoint under an
        # already-cancelled scope and raises CancelledError (a BaseException,
        # not caught by except Exception) before quit/close run, leaking the
        # socket. quit() only reaches close() if QUIT succeeds; the second
        # guard releases the socket even when QUIT throws.
        try:
            client.quit()
        except Exception as _e:
            pass
        try:
            client.close()
        except Exception as _e:
            pass

    # Save copy to Sent folder via IMAP
    imap_client = None
    try:
        imap_client = await _run(_get_imap_client, username, password)

        # Add Date header if not present
        if 'Date' not in msg:
            from email.utils import formatdate
            msg['Date'] = formatdate(localtime=True)

        # Append message to Sent folder
        # SMTP policy: IMAP APPEND requires CRLF line endings (RFC 3501);
        # bare as_bytes() emits LF and some servers mangle the stored copy
        msg_bytes = msg.as_bytes(policy=email.policy.SMTP)

        # Try to append to Sent folder
        try:
            await _run(imap_client.append, config.SENT_FOLDER, msg_bytes, flags=['\\Seen'])
        except Exception as e:
            # If Sent Messages folder doesn't exist, try common alternatives
            for folder_name in ['Sent', 'Sent Items', config.SENT_FOLDER]:
                try:
                    await _run(imap_client.append, folder_name, msg_bytes, flags=['\\Seen'])
                    break
                except Exception:
                    continue
            else:
                # Log error but don't fail the send operation
                logger.error(f"Could not save to Sent folder: {e}")

    except Exception as e:
        # Log error but don't fail the send operation
        logger.error(f"Error saving to Sent folder: {e}")

    finally:
        if imap_client:
            _close_imap_client(imap_client)

    return {
        "status": "success",
        "message": f"Email sent to {to}"
    }


async def move_message(
    context: Context,
    message_id: str,
    from_folder: str,
    to_folder: str
) -> Dict[str, str]:
    """
    Move a message to another folder.

    Args:
        message_id: Message ID
        from_folder: Source folder
        to_folder: Destination folder

    Returns:
        Confirmation message
    """
    username, password = require_auth(context)

    client = await _run(_get_imap_client, username, password)

    try:
        await _run(client.select_folder, from_folder)
        msg_id = int(message_id)

        # UIDs are folder-scoped: a stale/cross-folder id would otherwise copy
        # then delete the WRONG message (or nothing) and still report success.
        check = await _run(client.fetch, [msg_id], [b'FLAGS'])
        if msg_id not in check:
            raise ValueError(f"Message {message_id} not found in folder {from_folder}")

        # Copy to destination
        await _run(client.copy, [msg_id], to_folder)
        new_uid = _last_copyuid(client)

        # Delete from source
        await _run(client.delete_messages, [msg_id])
        await _run(_expunge_message, client, msg_id)

        result = {
            "status": "success",
            "message": f"Message {message_id} moved from {from_folder} to {to_folder}"
        }
        if new_uid is not None:
            result["new_id"] = str(new_uid)
            result["message"] += f" (new id {new_uid})"
        return result
    finally:
        try:
            _close_imap_client(client)
        except Exception as _e:
            pass

async def delete_message(
    context: Context,
    message_id: str,
    folder: str = "INBOX",
    permanent: bool = False
) -> Dict[str, str]:
    """
    Delete a message.

    Args:
        message_id: Message ID
        folder: Folder name (default: INBOX)
        permanent: Permanently delete (True) or move to trash (False)

    Returns:
        Confirmation message
    """
    username, password = require_auth(context)

    client = await _run(_get_imap_client, username, password)

    try:
        await _run(client.select_folder, folder)
        msg_id = int(message_id)

        # UIDs are folder-scoped: without this check a stale/cross-folder id
        # would delete the wrong message (or nothing) and still report success.
        check = await _run(client.fetch, [msg_id], [b'FLAGS'])
        if msg_id not in check:
            raise ValueError(f"Message {message_id} not found in folder {folder}")

        if permanent:
            # Permanent deletion
            await _run(client.delete_messages, [msg_id])
            await _run(_expunge_message, client, msg_id)
            message = f"Message {message_id} permanently deleted"
        else:
            # Move to trash. NEVER fall back to permanent deletion: the old
            # fallback turned ANY copy failure (folder named "Deleted
            # Messages" on iCloud, network hiccup, quota) into a silent
            # permanent delete reported as "moved to Trash".
            trash = await _run(_find_trash_folder, client)
            if trash is None:
                raise ValueError(
                    "No trash folder found on the server; "
                    "pass permanent=True to delete permanently"
                )
            await _run(client.copy, [msg_id], trash)
            await _run(client.delete_messages, [msg_id])
            await _run(_expunge_message, client, msg_id)
            message = f"Message {message_id} moved to {trash}"

        return {
            "status": "success",
            "message": message
        }
    finally:
        try:
            _close_imap_client(client)
        except Exception as _e:
            pass

async def mark_as_read(
    context: Context,
    message_id: str,
    folder: str = "INBOX"
) -> Dict[str, str]:
    """
    Mark a message as read.

    Args:
        message_id: Message ID
        folder: Folder name (default: INBOX)

    Returns:
        Confirmation message
    """
    username, password = require_auth(context)

    client = await _run(_get_imap_client, username, password)

    try:
        await _run(client.select_folder, folder)
        msg_id = int(message_id)
        await _run(client.add_flags, [msg_id], ['\\Seen'])

        return {
            "status": "success",
            "message": f"Message {message_id} marked as read"
        }
    finally:
        try:
            _close_imap_client(client)
        except Exception as _e:
            pass

async def mark_as_unread(
    context: Context,
    message_id: str,
    folder: str = "INBOX"
) -> Dict[str, str]:
    """
    Mark a message as unread.

    Args:
        message_id: Message ID
        folder: Folder name (default: INBOX)

    Returns:
        Confirmation message
    """
    username, password = require_auth(context)

    client = await _run(_get_imap_client, username, password)

    try:
        await _run(client.select_folder, folder)
        msg_id = int(message_id)
        await _run(client.remove_flags, [msg_id], ['\\Seen'])

        return {
            "status": "success",
            "message": f"Message {message_id} marked as unread"
        }
    finally:
        try:
            _close_imap_client(client)
        except Exception as _e:
            pass
