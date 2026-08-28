"""CardDAV tools for contacts management using direct HTTP/WebDAV requests."""

import logging
import functools
import anyio
import requests
from requests.auth import HTTPBasicAuth
import vobject
from typing import List, Dict, Any, Optional
from fastmcp import Context
from .auth import require_auth, require_trusted_url
from .config import config
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
import uuid

logger = logging.getLogger(__name__)


def _require_trusted_contact_url(contact_id: str) -> None:
    """Reject contact_id URLs pointing away from the configured CardDAV server.

    The requests session sends Basic-Auth credentials PREEMPTIVELY on every
    request, so without this check a foreign contact_id URL hands the user's
    credentials to that host on the very first GET/PUT/DELETE.
    """
    require_trusted_url(contact_id, config.CARDDAV_SERVER, "contact_id")


def _primary_org(vcard) -> str:
    """Primary ORG unit as a single string.

    vCard ORG is structured (a list of units). This tool models 'organization'
    as the first/primary unit. A scalar value from an external producer is
    returned whole rather than indexed (str(val)[0] would return its first
    character, a silent wrong answer).
    """
    if not hasattr(vcard, 'org') or not vcard.org.value:
        return ""
    val = vcard.org.value
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val)


def _remove_props_and_group_siblings(vcard, props) -> None:
    """Remove each property plus any X-* label line sharing its Apple group.

    Apple groups a property with its label metadata via an itemN. prefix
    (e.g. item2.TEL + item2.X-ABLABEL). Removing only the TEL orphans the
    X-ABLABEL. Sweep the X-* siblings so no dangling label survives; only
    X-* lines are swept, never a co-grouped primary property.

    Removal is by object identity, never vcard.remove(): ContentLine.__eq__
    compares (name, params, value), so vcard.remove() deletes the first
    value-equal line, not the object passed. Two Apple X-ABLABELs both valued
    "_$!<Home>!$_" (a Home address and a Home phone) would otherwise delete the
    wrong label. Rebuild each contents list keeping entries by id().
    """
    remove_ids = {id(p) for p in props}
    groups = {getattr(p, 'group', None) for p in props}
    groups.discard(None)
    if groups:
        for child in vcard.getChildren():
            if getattr(child, 'group', None) in groups and child.name.upper().startswith('X-'):
                remove_ids.add(id(child))
    for key in list(vcard.contents.keys()):
        kept = [c for c in vcard.contents[key] if id(c) not in remove_ids]
        if kept:
            vcard.contents[key] = kept
        else:
            del vcard.contents[key]


def _parse_vcard_contact(vcard, contact_id: str) -> Dict[str, Any]:
    """Render a vobject vCard into the tool-facing contact dict."""
    contact = {
        "id": contact_id,
        "name": str(vcard.fn.value) if hasattr(vcard, 'fn') else "",
        "phones": [],
        "emails": [],
        "addresses": [],
        "organization": _primary_org(vcard),
        "title": str(vcard.title.value) if hasattr(vcard, 'title') else "",
        "url": contact_id
    }
    if hasattr(vcard, 'tel_list'):
        for tel in vcard.tel_list:
            contact["phones"].append(str(tel.value))
    if hasattr(vcard, 'email_list'):
        for em in vcard.email_list:
            contact["emails"].append(str(em.value))
    if hasattr(vcard, 'adr_list'):
        for adr in vcard.adr_list:
            # vobject renders a street-only ADR as "street\n,  "; strip the
            # trailing separator noise. Genuine multi-component addresses are
            # unaffected (verified byte-identical).
            contact["addresses"].append(str(adr.value).rstrip(' ,\n'))
    return contact


def _get_carddav_session(email: str, password: str) -> tuple:
    """Create authenticated session for CardDAV (stateless)."""
    session = requests.Session()
    session.auth = HTTPBasicAuth(email, password)
    session.headers.update({
        'Content-Type': 'text/xml; charset=utf-8',
        'User-Agent': 'iCloud-MCP/1.0'
    })
    return session, email


def _discover_principal(session: requests.Session, base_url: str) -> str:
    """Discover principal URL for the user."""
    propfind_body = '''<?xml version="1.0" encoding="UTF-8"?>
    <d:propfind xmlns:d="DAV:">
        <d:prop>
            <d:current-user-principal/>
        </d:prop>
    </d:propfind>'''
    
    response = session.request('PROPFIND', base_url, data=propfind_body, headers={'Depth': '0'}, timeout=config.HTTP_TIMEOUT)
    response.raise_for_status()

    # Parse XML response
    root = ET.fromstring(response.content)
    ns = {'d': 'DAV:'}
    principal_elem = root.find('.//d:current-user-principal/d:href', ns)
    
    if principal_elem is not None and principal_elem.text:
        return urljoin(base_url, principal_elem.text)
    
    raise ValueError("Could not discover principal URL")


def _discover_addressbook_home(session: requests.Session, principal_url: str) -> str:
    """Discover addressbook home URL."""
    # principal_url comes from server XML; refuse to send Basic-Auth off-host.
    require_trusted_url(principal_url, config.CARDDAV_SERVER, "principal URL")
    propfind_body = '''<?xml version="1.0" encoding="UTF-8"?>
    <d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
        <d:prop>
            <card:addressbook-home-set/>
        </d:prop>
    </d:propfind>'''

    response = session.request('PROPFIND', principal_url, data=propfind_body, headers={'Depth': '0'}, timeout=config.HTTP_TIMEOUT)
    response.raise_for_status()
    
    # Parse XML response
    root = ET.fromstring(response.content)
    ns = {'d': 'DAV:', 'card': 'urn:ietf:params:xml:ns:carddav'}
    addressbook_elem = root.find('.//card:addressbook-home-set/d:href', ns)
    
    if addressbook_elem is not None and addressbook_elem.text:
        return urljoin(principal_url, addressbook_elem.text)
    
    raise ValueError("Could not discover addressbook home URL")


def _list_addressbooks(session: requests.Session, addressbook_home_url: str) -> List[Dict[str, str]]:
    """List all addressbooks."""
    # addressbook_home_url comes from server XML; refuse to send Basic-Auth off-host.
    require_trusted_url(addressbook_home_url, config.CARDDAV_SERVER, "addressbook home URL")
    propfind_body = '''<?xml version="1.0" encoding="UTF-8"?>
    <d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
        <d:prop>
            <d:displayname/>
            <d:resourcetype/>
            <card:addressbook-description/>
        </d:prop>
    </d:propfind>'''

    response = session.request('PROPFIND', addressbook_home_url, data=propfind_body, headers={'Depth': '1'}, timeout=config.HTTP_TIMEOUT)
    response.raise_for_status()
    
    # Parse XML response
    root = ET.fromstring(response.content)
    ns = {'d': 'DAV:', 'card': 'urn:ietf:params:xml:ns:carddav'}
    
    addressbooks = []
    for response_elem in root.findall('.//d:response', ns):
        href_elem = response_elem.find('d:href', ns)
        resourcetype_elem = response_elem.find('.//d:resourcetype', ns)
        
        # Check if this is an addressbook
        if resourcetype_elem is not None and resourcetype_elem.find('card:addressbook', ns) is not None:
            book_url = urljoin(addressbook_home_url, href_elem.text) if href_elem is not None else ''
            # href comes from server XML; skip a book that redirects off-host
            # rather than letting a later request hand it credentials.
            try:
                require_trusted_url(book_url, config.CARDDAV_SERVER, "addressbook URL")
            except ValueError as e:
                logger.warning("Skipping untrusted addressbook URL: %s", e)
                continue
            displayname_elem = response_elem.find('.//d:displayname', ns)

            addressbook = {
                'url': book_url,
                'name': displayname_elem.text if displayname_elem is not None and displayname_elem.text else 'Unnamed'
            }
            addressbooks.append(addressbook)

    return addressbooks


def _fetch_all_vcards(session: requests.Session, addressbook_url: str) -> List[Dict[str, Any]]:
    """Fetch all vCards from an addressbook."""
    # Make sure URL ends with /
    if not addressbook_url.endswith('/'):
        addressbook_url += '/'

    # addressbook_url is server-derived; refuse to send Basic-Auth off-host.
    require_trusted_url(addressbook_url, config.CARDDAV_SERVER, "addressbook URL")

    query_body = '''<?xml version="1.0" encoding="UTF-8"?>
    <card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
        <d:prop>
            <d:getetag/>
            <card:address-data/>
        </d:prop>
    </card:addressbook-query>'''

    try:
        response = session.request('REPORT', addressbook_url, data=query_body, headers={'Depth': '1'}, timeout=config.HTTP_TIMEOUT)
        response.raise_for_status()
    except Exception as e:
        logger.warning("Error fetching vCards from %s: %s", addressbook_url, e)
        return []
    
    # Parse XML response
    vcards = []
    try:
        root = ET.fromstring(response.content)
        ns = {'d': 'DAV:', 'card': 'urn:ietf:params:xml:ns:carddav'}
        
        for response_elem in root.findall('.//d:response', ns):
            href_elem = response_elem.find('d:href', ns)
            vcard_data_elem = response_elem.find('.//card:address-data', ns)
            etag_elem = response_elem.find('.//d:getetag', ns)
            
            if vcard_data_elem is not None and vcard_data_elem.text:
                item_url = urljoin(addressbook_url, href_elem.text) if href_elem is not None else ''
                # href comes from server XML; drop off-host ids so callers are
                # not handed contact_ids that later tool calls will refuse.
                try:
                    require_trusted_url(item_url, config.CARDDAV_SERVER, "contact URL")
                except ValueError as e:
                    logger.warning("Skipping untrusted contact URL: %s", e)
                    continue
                vcards.append({
                    'url': item_url,
                    'data': vcard_data_elem.text,
                    'etag': etag_elem.text if etag_elem is not None else ''
                })
    except Exception as e:
        logger.warning("Error parsing vCards response: %s", e)

    return vcards


async def list_contacts(
    context: Context,
    limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    List all contacts.

    Args:
        limit: Maximum number of contacts to return (optional)

    Returns:
        List of contacts with name, phone, email, address
    """
    email, password = require_auth(context)
    session, _ = _get_carddav_session(email, password)
    
    try:
        # Discover URLs (blocking socket I/O off the event loop)
        base_url = config.CARDDAV_SERVER
        principal_url = await anyio.to_thread.run_sync(functools.partial(_discover_principal, session, base_url))
        addressbook_home_url = await anyio.to_thread.run_sync(functools.partial(_discover_addressbook_home, session, principal_url))
        addressbooks = await anyio.to_thread.run_sync(functools.partial(_list_addressbooks, session, addressbook_home_url))

        if not addressbooks:
            return []

        # Fetch vCards from ALL addressbooks (contacts in books beyond the
        # first were silently invisible before). Sequential awaits: one
        # requests.Session is not safe to share across threads concurrently.
        vcards = []
        for book in addressbooks:
            book_vcards = await anyio.to_thread.run_sync(functools.partial(_fetch_all_vcards, session, book['url']))
            vcards.extend(book_vcards)

        # Parse vCards
        result = []
        count = 0

        for vcard_data in vcards:
            if limit and count >= limit:
                break
            
            try:
                vcard = vobject.readOne(vcard_data['data'])
                
                contact = {
                    "id": vcard_data['url'],
                    "name": "",
                    "phones": [],
                    "emails": [],
                    "addresses": [],
                    "url": vcard_data['url']
                }
                
                # Extract name
                if hasattr(vcard, 'fn') and vcard.fn and hasattr(vcard.fn, 'value'):
                    contact["name"] = str(vcard.fn.value)
                
                # Extract phone numbers
                if hasattr(vcard, 'tel_list'):
                    for tel in vcard.tel_list:
                        if hasattr(tel, 'value') and tel.value:
                            contact["phones"].append(str(tel.value))
                
                # Extract emails
                if hasattr(vcard, 'email_list'):
                    for em in vcard.email_list:
                        if hasattr(em, 'value') and em.value:
                            contact["emails"].append(str(em.value))
                
                # Extract addresses
                if hasattr(vcard, 'adr_list'):
                    for adr in vcard.adr_list:
                        if hasattr(adr, 'value'):
                            try:
                                addr_str = str(adr.value) if adr.value else ""
                                if addr_str:
                                    contact["addresses"].append(addr_str)
                            except Exception as _e:
                                continue
                
                # Only add contact if it has a name or at least one other field
                if contact["name"] or contact["phones"] or contact["emails"]:
                    result.append(contact)
                    count += 1
            
            except Exception as e:
                logger.warning("Error parsing vCard: %s", e)
                continue
        
        return result
    
    except Exception as e:
        raise ValueError(f"Failed to list contacts: {str(e)}")


async def get_contact(context: Context, contact_id: str) -> Dict[str, Any]:
    """
    Get a specific contact by ID.

    Args:
        contact_id: Contact URL/ID

    Returns:
        Contact details
    """
    email, password = require_auth(context)
    _require_trusted_contact_url(contact_id)
    session, _ = _get_carddav_session(email, password)

    try:
        response = await anyio.to_thread.run_sync(functools.partial(session.get, contact_id, timeout=config.HTTP_TIMEOUT))
        response.raise_for_status()

        vcard = vobject.readOne(response.text)
        return _parse_vcard_contact(vcard, contact_id)

    except Exception as e:
        raise ValueError(f"Failed to get contact: {str(e)}")


async def create_contact(
    context: Context,
    name: str,
    phones: Optional[List[str]] = None,
    emails: Optional[List[str]] = None,
    addresses: Optional[List[str]] = None,
    organization: Optional[str] = None,
    title: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a new contact.

    Args:
        name: Full name
        phones: List of phone numbers (optional)
        emails: List of email addresses (optional)
        addresses: List of postal addresses (optional)
        organization: Company/organization name (optional)
        title: Job title (optional)

    Returns:
        Created contact details
    """
    email, password = require_auth(context)
    session, _ = _get_carddav_session(email, password)
    
    try:
        # Discover URLs (blocking socket I/O off the event loop)
        base_url = config.CARDDAV_SERVER
        principal_url = await anyio.to_thread.run_sync(functools.partial(_discover_principal, session, base_url))
        addressbook_home_url = await anyio.to_thread.run_sync(functools.partial(_discover_addressbook_home, session, principal_url))
        addressbooks = await anyio.to_thread.run_sync(functools.partial(_list_addressbooks, session, addressbook_home_url))

        if not addressbooks:
            raise ValueError("No addressbooks found")

        addressbook_url = addressbooks[0]['url']
        if not addressbook_url.endswith('/'):
            addressbook_url += '/'
        # addressbook_url is server-derived; refuse to PUT credentials off-host.
        require_trusted_url(addressbook_url, config.CARDDAV_SERVER, "addressbook URL")
        
        # Create vCard
        vcard = vobject.vCard()
        vcard.add('fn').value = name
        vcard.add('n').value = vobject.vcard.Name(family='', given=name)
        
        # Generate unique UID
        unique_id = str(uuid.uuid4())
        vcard.add('uid').value = unique_id
        
        # Add phones
        if phones:
            for phone in phones:
                tel = vcard.add('tel')
                tel.value = phone
                tel.type_param = 'CELL'
        
        # Add emails
        if emails:
            for em in emails:
                email_obj = vcard.add('email')
                email_obj.value = em
                email_obj.type_param = 'INTERNET'
        
        # Add addresses
        if addresses:
            for addr in addresses:
                adr = vcard.add('adr')
                adr.value = vobject.vcard.Address(street=addr)
        
        # Add organization
        if organization:
            vcard.add('org').value = [organization]
        
        # Add title
        if title:
            vcard.add('title').value = title
        
        # Serialize vCard
        vcard_data = vcard.serialize()
        
        # PUT vCard to server
        contact_url = f"{addressbook_url}{unique_id}.vcf"

        response = await anyio.to_thread.run_sync(functools.partial(
            session.put,
            contact_url,
            data=vcard_data,
            headers={'Content-Type': 'text/vcard; charset=utf-8'},
            timeout=config.HTTP_TIMEOUT,
        ))
        response.raise_for_status()
        
        return {
            "id": contact_url,
            "name": name,
            "phones": phones or [],
            "emails": emails or [],
            "addresses": addresses or [],
            "organization": organization or "",
            "title": title or "",
            "url": contact_url
        }
    
    except Exception as e:
        raise ValueError(f"Failed to create contact: {str(e)}")


async def update_contact(
    context: Context,
    contact_id: str,
    name: Optional[str] = None,
    phones: Optional[List[str]] = None,
    emails: Optional[List[str]] = None,
    addresses: Optional[List[str]] = None,
    organization: Optional[str] = None,
    title: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update an existing contact.

    Args:
        contact_id: Contact URL/ID
        name: New full name (optional)
        phones: New list of phone numbers (optional)
        emails: New list of email addresses (optional)
        addresses: New list of postal addresses (optional)
        organization: New company/organization (optional)
        title: New job title (optional)

    Returns:
        Updated contact details
    """
    email, password = require_auth(context)
    _require_trusted_contact_url(contact_id)
    session, _ = _get_carddav_session(email, password)

    try:
        # Get existing vCard (blocking socket I/O off the event loop)
        response = await anyio.to_thread.run_sync(functools.partial(session.get, contact_id, timeout=config.HTTP_TIMEOUT))
        response.raise_for_status()
        etag = response.headers.get('ETag', '')

        vcard = vobject.readOne(response.text)

        # Update fields
        if name:
            if hasattr(vcard, 'fn'):
                vcard.fn.value = name
            else:
                vcard.add('fn').value = name
            # Keep structured N in sync so Apple's N-based sorting matches the
            # new FN. A single free-text name has no clean family/given split,
            # so mirror create_contact: full string in 'given', family empty.
            n_value = vobject.vcard.Name(family='', given=name)
            if hasattr(vcard, 'n'):
                vcard.n.value = n_value
            else:
                vcard.add('n').value = n_value

        if phones is not None:
            # Remove existing phones plus their grouped X-ABLABEL siblings.
            if hasattr(vcard, 'tel_list'):
                _remove_props_and_group_siblings(vcard, list(vcard.tel_list))
            # Add new phones
            for phone in phones:
                tel = vcard.add('tel')
                tel.value = phone
                tel.type_param = 'CELL'

        if emails is not None:
            # Remove existing emails plus their grouped X-ABLABEL siblings.
            if hasattr(vcard, 'email_list'):
                _remove_props_and_group_siblings(vcard, list(vcard.email_list))
            # Add new emails
            for em in emails:
                email_obj = vcard.add('email')
                email_obj.value = em
                email_obj.type_param = 'INTERNET'

        if addresses is not None:
            # In-place street replacement for the 1:1 overlap: overwriting the
            # existing ADR's street preserves its city/region/postcode/country,
            # itemN group, X-ABADR, X-ABLABEL and TYPE, which a remove-and-add
            # would zero (Address(street=...) leaves every other slot empty).
            # The tool exposes one free-text string per address; store it in the
            # ADR street component. Only net-new addresses get a fresh Address.
            existing_adrs = list(vcard.adr_list) if hasattr(vcard, 'adr_list') else []
            for i, addr in enumerate(addresses):
                if i < len(existing_adrs):
                    existing_adrs[i].value.street = addr
                else:
                    adr = vcard.add('adr')
                    adr.value = vobject.vcard.Address(street=addr)
            # Drop existing addresses beyond the new count (id-based, with groups).
            if len(existing_adrs) > len(addresses):
                _remove_props_and_group_siblings(vcard, existing_adrs[len(addresses):])

        if organization is not None:
            if hasattr(vcard, 'org') and isinstance(vcard.org.value, list) and vcard.org.value:
                # Replace the primary ORG unit; preserve existing sub-units
                # (e.g. department) instead of destroying them.
                vcard.org.value = [organization] + list(vcard.org.value[1:])
            elif hasattr(vcard, 'org'):
                vcard.org.value = [organization]
            else:
                vcard.add('org').value = [organization]

        if title is not None:
            if hasattr(vcard, 'title'):
                vcard.title.value = title
            else:
                vcard.add('title').value = title
        
        # Serialize and PUT back
        vcard_data = vcard.serialize()
        
        headers = {'Content-Type': 'text/vcard; charset=utf-8'}
        if etag:
            headers['If-Match'] = etag

        response = await anyio.to_thread.run_sync(functools.partial(session.put, contact_id, data=vcard_data, headers=headers, timeout=config.HTTP_TIMEOUT))
        response.raise_for_status()

        # Return the ACTUAL updated vCard state: echoing the sparse input
        # made untouched fields look wiped (phones/emails/addresses = [])
        return _parse_vcard_contact(vcard, contact_id)

    except Exception as e:
        raise ValueError(f"Failed to update contact: {str(e)}")


async def delete_contact(context: Context, contact_id: str) -> Dict[str, str]:
    """
    Delete a contact.

    Args:
        contact_id: Contact URL/ID to delete

    Returns:
        Confirmation message
    """
    email, password = require_auth(context)
    _require_trusted_contact_url(contact_id)
    session, _ = _get_carddav_session(email, password)

    try:
        response = await anyio.to_thread.run_sync(functools.partial(session.delete, contact_id, timeout=config.HTTP_TIMEOUT))
        response.raise_for_status()

        return {"status": "success", "message": f"Contact {contact_id} deleted"}
    
    except Exception as e:
        raise ValueError(f"Failed to delete contact: {str(e)}")


async def search_contacts(
    context: Context,
    query: str
) -> List[Dict[str, Any]]:
    """
    Search for contacts by text query.

    Args:
        query: Search text (matches name, email, phone)

    Returns:
        List of matching contacts
    """
    # Get all contacts
    contacts = await list_contacts(context)
    
    # Filter by query
    query_lower = query.lower()
    filtered_contacts = [
        contact for contact in contacts
        if query_lower in contact.get("name", "").lower()
        or any(query_lower in email.lower() for email in contact.get("emails", []))
        or any(query_lower in phone.lower() for phone in contact.get("phones", []))
    ]
    
    return filtered_contacts
