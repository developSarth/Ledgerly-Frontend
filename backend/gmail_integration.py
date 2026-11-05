"""Restricted Gmail OAuth, token refresh, sending, and reply-thread helpers."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken

from settings import settings

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
TIMEOUT = httpx.Timeout(25.0, connect=5.0)


class GmailIntegrationError(RuntimeError):
    """Safe, non-sensitive Gmail integration error."""


def _fernet() -> Fernet:
    key = settings.integration_token_encryption_key
    if not key:
        raise GmailIntegrationError("Integration token encryption is not configured.")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise GmailIntegrationError("Integration token encryption key is invalid.") from exc


def encrypt_token(token: str) -> str:
    if not token:
        raise GmailIntegrationError("Google returned an empty token.")
    return _fernet().encrypt(token.encode()).decode("ascii")


def decrypt_token(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode("ascii")).decode()
    except (InvalidToken, UnicodeEncodeError, ValueError) as exc:
        raise GmailIntegrationError("Stored Google credentials could not be decrypted.") from exc


def authorization_url(state: str) -> str:
    query = {
        "client_id": settings.gmail_client_id,
        "redirect_uri": settings.gmail_redirect_uri,
        "response_type": "code",
        "scope": " ".join(settings.gmail_scopes),
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
    }
    return f"{AUTH_URL}?{urlencode(query)}"


def _token_request(data: dict[str, str]) -> dict[str, Any]:
    payload = {**data, "client_id": settings.gmail_client_id,
               "client_secret": settings.gmail_client_secret}
    try:
        response = httpx.post(TOKEN_URL, data=payload, timeout=TIMEOUT, follow_redirects=False)
        response.raise_for_status()
        body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise GmailIntegrationError("Google OAuth token exchange failed. Check the client and exact redirect URI.") from exc
    if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
        raise GmailIntegrationError("Google returned an incomplete OAuth token response.")
    return body


def exchange_code(code: str) -> dict[str, Any]:
    return _token_request({"grant_type": "authorization_code", "code": code,
                           "redirect_uri": settings.gmail_redirect_uri})


def refresh_access_token(refresh_token: str) -> dict[str, Any]:
    return _token_request({"grant_type": "refresh_token", "refresh_token": refresh_token})


def _api(access_token: str, method: str, path: str, *, params: dict[str, str] | None = None,
         json_body: dict[str, Any] | None = None) -> dict[str, Any]:
    if not path.startswith("/") or ".." in path:
        raise GmailIntegrationError("Unsafe Gmail API path.")
    try:
        response = httpx.request(method, API_BASE + path, params=params, json=json_body,
                                 headers={"Authorization": f"Bearer {access_token}"},
                                 timeout=TIMEOUT, follow_redirects=False)
        response.raise_for_status()
        body = response.json() if response.content else {}
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            raise GmailIntegrationError("Gmail authorization expired or was revoked; reconnect the mailbox.") from exc
        if status == 403:
            raise GmailIntegrationError("Gmail denied this action; verify the OAuth scopes and consent-screen status.") from exc
        if status == 429:
            raise GmailIntegrationError("Gmail rate limit reached; retry later.") from exc
        raise GmailIntegrationError(f"Gmail API returned status {status}.") from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise GmailIntegrationError("Could not reach Gmail or read its response.") from exc
    if not isinstance(body, dict):
        raise GmailIntegrationError("Gmail returned an unexpected response.")
    return body


def profile(access_token: str) -> dict[str, Any]:
    body = _api(access_token, "GET", "/profile")
    address = str(body.get("emailAddress") or "").strip().lower()
    if "@" not in address:
        raise GmailIntegrationError("Google did not return the connected mailbox address.")
    return {"email": address, "history_id": str(body.get("historyId") or "")}


def send_email(access_token: str, recipient: str, subject: str, body: str) -> dict[str, str]:
    message = EmailMessage()
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")
    result = _api(access_token, "POST", "/messages/send", json_body={"raw": raw})
    message_id, thread_id = result.get("id"), result.get("threadId")
    if not isinstance(message_id, str) or not isinstance(thread_id, str):
        raise GmailIntegrationError("Gmail did not confirm a message and thread ID.")
    return {"message_id": message_id, "thread_id": thread_id}


def list_thread_messages(access_token: str, thread_id: str) -> list[dict[str, Any]]:
    if not thread_id or len(thread_id) > 200 or not thread_id.isalnum():
        raise GmailIntegrationError("Stored Gmail thread ID is invalid.")
    body = _api(access_token, "GET", f"/threads/{thread_id}", params={"format": "full"})
    messages = body.get("messages")
    return [row for row in messages if isinstance(row, dict)] if isinstance(messages, list) else []


def _headers(message: dict[str, Any]) -> dict[str, str]:
    payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
    headers = payload.get("headers") if isinstance(payload.get("headers"), list) else []
    return {str(item.get("name", "")).casefold(): str(item.get("value", ""))
            for item in headers if isinstance(item, dict)}


def _plain_body(part: dict[str, Any]) -> str:
    chunks: list[str] = []
    if part.get("mimeType") == "text/plain":
        data = (part.get("body") or {}).get("data")
        if data:
            try:
                chunks.append(base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace"))
            except (ValueError, TypeError):
                pass
    for child in part.get("parts", []) if isinstance(part.get("parts"), list) else []:
        if isinstance(child, dict):
            chunks.append(_plain_body(child))
    return "\n".join(value for value in chunks if value).strip()[:30000]


def parse_reply(message: dict[str, Any], mailbox: str) -> dict[str, str] | None:
    headers = _headers(message)
    sender = headers.get("from", "")
    recipient = headers.get("to", "")
    # Exclude our sent copy and messages not addressed to the connected mailbox.
    message_id = str(message.get("id") or "")
    if (not message_id or len(message_id) > 140 or not message_id.isalnum()
            or mailbox.casefold() in sender.casefold() or mailbox.casefold() not in recipient.casefold()):
        return None
    payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
    text = _plain_body(payload)
    if not text:
        return None
    return {"message_id": message_id,
            "sender": sender[:320], "subject": headers.get("subject", "")[:500],
            "internal_date": str(message.get("internalDate") or ""), "body": text}
