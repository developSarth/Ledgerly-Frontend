"""Clio Manage OAuth, encrypted tokens, bill sync, and safe workflow logging."""
from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from cryptography.fernet import Fernet, InvalidToken

from settings import settings


class ClioIntegrationError(RuntimeError):
    """Safe, non-sensitive error raised by the Clio integration layer."""


_REGIONS = {
    "us": ("https://app.clio.com", "https://app.clio.com/api/v4"),
    "eu": ("https://eu.app.clio.com", "https://eu.app.clio.com/api/v4"),
    "ca": ("https://ca.app.clio.com", "https://ca.app.clio.com/api/v4"),
    "au": ("https://au.app.clio.com", "https://au.app.clio.com/api/v4"),
}
_TIMEOUT = httpx.Timeout(20.0, connect=5.0)
_BILL_FIELDS = "id,number,state,due_at,issued_at,balance,total,updated_at,client{id,name,primary_email_address},matter{id}"


def _region() -> tuple[str, str]:
    try:
        return _REGIONS[settings.clio_region]
    except KeyError as exc:
        raise ClioIntegrationError("CLIO_REGION must be one of us, eu, ca, or au.") from exc


def _fernet() -> Fernet:
    if not settings.clio_token_encryption_key:
        raise ClioIntegrationError("CLIO_TOKEN_ENCRYPTION_KEY is not configured.")
    try:
        return Fernet(settings.clio_token_encryption_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ClioIntegrationError("CLIO_TOKEN_ENCRYPTION_KEY is invalid; generate a Fernet key.") from exc


def encrypt_token(value: str) -> str:
    if not value:
        raise ClioIntegrationError("Clio returned an empty token.")
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_token(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeEncodeError, ValueError) as exc:
        raise ClioIntegrationError("Stored Clio credentials could not be decrypted.") from exc


def authorization_url(state: str) -> str:
    authorize_base, _ = _region()
    query = urlencode({
        "response_type": "code",
        "client_id": settings.clio_client_id,
        "redirect_uri": settings.clio_redirect_uri,
        "state": state,
        "redirect_on_decline": "true",
    })
    return f"{authorize_base}/oauth/authorize?{query}"


def _post_token(form: dict[str, str]) -> dict[str, Any]:
    authorize_base, _ = _region()
    payload = {
        "client_id": settings.clio_client_id,
        "client_secret": settings.clio_client_secret,
        **form,
    }
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
            response = client.post(f"{authorize_base}/oauth/token", data=payload)
        response.raise_for_status()
        body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ClioIntegrationError("Clio token exchange failed. Check the app credentials, region, and redirect URI.") from exc
    if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
        raise ClioIntegrationError("Clio returned an incomplete token response.")
    return body


def exchange_code(code: str) -> dict[str, Any]:
    return _post_token({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.clio_redirect_uri,
    })


def refresh_tokens(refresh_token: str) -> dict[str, Any]:
    return _post_token({"grant_type": "refresh_token", "refresh_token": refresh_token})


def _api_json(access_token: str, url: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    _, api_base = _region()
    allowed_host = urlparse(api_base).netloc
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != allowed_host or not parsed.path.startswith("/api/v4/"):
        raise ClioIntegrationError("Clio returned an unsafe pagination URL.")
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
            response = client.get(url, params=params, headers={"Authorization": f"Bearer {access_token}"})
        response.raise_for_status()
        body = response.json()
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            raise ClioIntegrationError("Clio authorization expired or was revoked. Reconnect the Clio account.") from exc
        if status == 403:
            raise ClioIntegrationError("Clio denied this request. Check the required read permissions and the connected user's Clio role.") from exc
        if status == 429:
            raise ClioIntegrationError("Clio rate limit reached. Wait briefly, then sync again.") from exc
        raise ClioIntegrationError(f"Clio API request failed with status {status}.") from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise ClioIntegrationError("Could not reach Clio or read its response.") from exc
    if not isinstance(body, dict):
        raise ClioIntegrationError("Clio returned an unexpected response.")
    return body


def current_user(access_token: str) -> dict[str, Any]:
    _, api_base = _region()
    body = _api_json(access_token, f"{api_base}/users/who_am_i", {"fields": "id,name"})
    data = body.get("data")
    if not isinstance(data, dict) or data.get("id") is None:
        raise ClioIntegrationError("Clio did not identify the authorized user.")
    return data


def _api_write(access_token: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Call a fixed Clio v4 write path; arbitrary hosts and paths are rejected."""
    _, api_base = _region()
    if not path.startswith("/") or ".." in path or not path.endswith(".json"):
        raise ClioIntegrationError("Unsafe Clio API path.")
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
            response = client.post(f"{api_base}{path}", json=payload,
                                   headers={"Authorization": f"Bearer {access_token}"})
        response.raise_for_status()
        body = response.json()
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            raise ClioIntegrationError("Clio authorization expired or was revoked; reconnect the account.") from exc
        if status == 403:
            raise ClioIntegrationError("Clio denied this write. Check the required write permission and the connected user's role.") from exc
        if status == 429:
            raise ClioIntegrationError("Clio rate limit reached; retry later.") from exc
        raise ClioIntegrationError(f"Clio API returned status {status} while logging the communication.") from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise ClioIntegrationError("Could not reach Clio or read its response.") from exc
    if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
        raise ClioIntegrationError("Clio did not confirm creation of the communication record.")
    return body["data"]


def find_contact_id(access_token: str, email: str) -> str | None:
    """Find one exact email match; ambiguous/no matches are never guessed."""
    _, api_base = _region()
    body = _api_json(access_token, f"{api_base}/contacts.json", {
        "query": email, "limit": "100", "fields": "id,email_addresses"
    })
    rows = body.get("data")
    if not isinstance(rows, list):
        raise ClioIntegrationError("Clio returned an unexpected Contacts response.")
    matches: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("id") is None:
            continue
        addresses = row.get("email_addresses")
        if isinstance(addresses, list) and any(
                isinstance(item, dict) and str(item.get("address", "")).casefold() == email.casefold()
                for item in addresses):
            matches.add(str(row["id"]))
    return next(iter(matches)) if len(matches) == 1 else None


def record_sent_email(access_token: str, *, sender_user_id: str, recipient_contact_id: str,
                      subject: str, body: str, sent_at: str, matter_id: str | None = None) -> str:
    """Record a successfully sent email as a Clio Communication; does not send it."""
    data: dict[str, Any] = {
        "type": "EmailCommunication", "subject": subject, "body": body,
        "received_at": sent_at,
        "senders": [{"id": int(sender_user_id), "type": "User"}],
        "receivers": [{"id": int(recipient_contact_id), "type": "Contact"}],
    }
    if matter_id and str(matter_id).isdigit():
        data["matter"] = {"id": int(matter_id)}
    result = _api_write(access_token, "/communications.json", {"data": data})
    if result.get("id") is None:
        raise ClioIntegrationError("Clio did not return a Communication ID.")
    return str(result["id"])


def _activity_matches(access_token: str, marker: str, matter_id: str) -> list[dict[str, Any]]:
    """Search by deterministic note marker and require exact values before reuse."""
    _, api_base = _region()
    body = _api_json(access_token, f"{api_base}/activities.json", {
        "query": marker, "limit": "100",
        "fields": "id,type,date,note,matter{id},non_billable,no_charge",
    })
    rows = body.get("data")
    if not isinstance(rows, list):
        raise ClioIntegrationError("Clio returned an unexpected Activities response.")
    return [row for row in rows if isinstance(row, dict)
            and row.get("note") == marker
            and row.get("type") == "TimeEntry"
            and row.get("non_billable") is True
            and row.get("no_charge") is True
            and isinstance(row.get("matter"), dict)
            and str(row["matter"].get("id")) == str(matter_id)]


def ensure_nonbillable_activity(access_token: str, *, matter_id: str, performed_on: str,
                                workflow_run_id: str) -> tuple[str, bool]:
    """Create or reuse one non-billable, no-charge TimeEntry as a workflow audit marker.

    Returns (Clio activity ID, created). The note carries no client or invoice content.
    Before creating, an exact-match search makes retries after a lost response safe.
    """
    if not str(matter_id).isdigit() or len(str(matter_id)) > 20:
        raise ClioIntegrationError("A valid Clio matter is required to log the workflow Activity.")
    if not workflow_run_id or len(workflow_run_id) > 80:
        raise ClioIntegrationError("Invalid Ledgerly workflow marker.")
    marker = f"Ledgerly non-billable reminder activity [workflow:{workflow_run_id}]"
    matches = _activity_matches(access_token, marker, str(matter_id))
    if len(matches) > 1:
        raise ClioIntegrationError("More than one matching Clio Activity exists; manual reconciliation is required.")
    if matches:
        return str(matches[0]["id"]), False
    result = _api_write(access_token, "/activities.json", {"data": {
        "type": "TimeEntry", "date": performed_on, "note": marker,
        "matter": {"id": int(matter_id)}, "non_billable": True, "no_charge": True,
    }})
    if result.get("id") is None:
        raise ClioIntegrationError("Clio did not return an Activity ID.")
    return str(result["id"]), True


def find_nonbillable_activity(access_token: str, *, matter_id: str, workflow_run_id: str) -> str | None:
    """Verify an existing audit Activity without creating or modifying any Clio record."""
    marker = f"Ledgerly non-billable reminder activity [workflow:{workflow_run_id}]"
    matches = _activity_matches(access_token, marker, str(matter_id))
    if len(matches) > 1:
        raise ClioIntegrationError("More than one matching Clio Activity exists; manual reconciliation is required.")
    return str(matches[0]["id"]) if matches else None


def verify_email_communication(access_token: str, communication_id: str, *,
                               subject: str, recipient_contact_id: str) -> bool:
    """Verify a staff-provided Clio Communication ID before reconciling its audit state."""
    if not communication_id.isdigit() or len(communication_id) > 20:
        return False
    _, api_base = _region()
    response = _api_json(access_token, f"{api_base}/communications/{communication_id}.json", {
        "fields": "id,type,subject,receivers{id,type}"
    })
    row = response.get("data")
    if not isinstance(row, dict) or str(row.get("id")) != communication_id:
        return False
    if row.get("type") != "EmailCommunication" or row.get("subject") != subject:
        return False
    receivers = row.get("receivers")
    return bool(isinstance(receivers, list) and any(
        isinstance(item, dict) and str(item.get("id")) == str(recipient_contact_id)
        and item.get("type") == "Contact" for item in receivers
    ))


def fetch_all_bills(access_token: str, maximum_pages: int = 500) -> list[dict[str, Any]]:
    """Fetch every bill serially using Clio's cursor pagination; never follow an arbitrary host."""
    _, api_base = _region()
    url = f"{api_base}/bills.json"
    params: dict[str, str] | None = {
        "fields": _BILL_FIELDS,
        "order": "id(asc)",
        "limit": "200",
    }
    bills: list[dict[str, Any]] = []
    for _ in range(maximum_pages):
        body = _api_json(access_token, url, params)
        params = None
        rows = body.get("data")
        if not isinstance(rows, list):
            raise ClioIntegrationError("Clio returned an unexpected Bills response.")
        bills.extend(row for row in rows if isinstance(row, dict))
        next_url = (body.get("meta") or {}).get("paging", {}).get("next")
        if not next_url:
            return bills
        parsed = urlparse(str(next_url))
        _, api_base = _region()
        expected = urlparse(api_base)
        if parsed.scheme != "https" or parsed.netloc != expected.netloc or parsed.path.rstrip("/") != f"{expected.path}/bills.json":
            raise ClioIntegrationError("Clio returned an unexpected Bills pagination link.")
        token_values = parse_qs(parsed.query).get("page_token")
        if not token_values or not token_values[0]:
            raise ClioIntegrationError("Clio returned a pagination link without a cursor.")
        url = f"{api_base}/bills.json"
        params = {"fields": _BILL_FIELDS, "order": "id(asc)", "limit": "200", "page_token": token_values[0]}
    raise ClioIntegrationError("Clio Bills exceeded the safe 100,000-record sync limit; contact support before retrying.")


def deauthorize(access_token: str) -> None:
    authorize_base, _ = _region()
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
            response = client.post(
                f"{authorize_base}/oauth/deauthorize",
                data={"token": access_token},
                headers={"Authorization": f"Bearer {access_token}"},
            )
        if response.status_code not in {200, 401}:
            raise ClioIntegrationError(f"Clio deauthorization returned status {response.status_code}.")
    except httpx.HTTPError as exc:
        raise ClioIntegrationError("Could not revoke the Clio token. Try disconnecting again.") from exc
