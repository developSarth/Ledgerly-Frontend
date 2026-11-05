"""Ledgerly's Python API. The browser is a presentation client; persistence,
authentication checks, and Supabase RPC calls are handled here.

Invoice data uses the user's own JWT and Supabase RLS. Durable workflow-run
mutations and encrypted Clio OAuth storage use a backend-only elevated client
after the API derives firm scope from the authenticated identity. This stage
never sends email or SMS and never writes to Clio.
"""
from __future__ import annotations

import os
import logging
import json
import hashlib
import re
import secrets
import time
import httpx
from datetime import date, datetime, time as day_time, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from supabase import Client, create_client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL") or os.getenv("VITE_SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY") or os.getenv("VITE_SUPABASE_ANON_KEY", "")
logger = logging.getLogger("ledgerly.api")

app = FastAPI(title="Ledgerly API", version="1.0.0")
_local_frontend_origins = {
    "http://localhost:5173", "http://127.0.0.1:5173",
}
_configured_frontend_origins = {
    x.strip() for x in os.getenv("FRONTEND_ORIGINS", "").split(",") if x.strip()
}
origins = sorted(_local_frontend_origins | _configured_frontend_origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Workflow-Run-ID"],
    expose_headers=["X-Request-ID", "X-Workflow-Run-ID"],
)


@app.middleware("http")
async def request_diagnostics(request: Request, call_next):
    request_id = str(uuid4())
    try:
        workflow_run_id = str(UUID(request.headers.get("X-Workflow-Run-ID", "")))
    except ValueError:
        workflow_run_id = str(uuid4())
    request.state.request_id = request_id
    request.state.workflow_run_id = workflow_run_id
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        logger.error("request_failed request_id=%s workflow_run_id=%s method=%s path=%s error_type=%s",
                     request_id, workflow_run_id, request.method, request.url.path, type(exc).__name__)
        response = JSONResponse(
            status_code=500,
            content={"detail": "The request could not be completed.", "request_id": request_id,
                     "workflow_run_id": workflow_run_id},
        )
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Workflow-Run-ID"] = workflow_run_id
    logger.info("request_complete request_id=%s workflow_run_id=%s method=%s path=%s status=%s duration_ms=%d",
                request_id, workflow_run_id, request.method, request.url.path, response.status_code,
                int((time.perf_counter() - started) * 1000))
    return response


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=256)
    firm_name: str = Field(default="", max_length=160)


class PasswordResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=320)

    @field_validator("email")
    @classmethod
    def normalize_reset_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Enter a valid email address")
        return value


class PasswordUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=10, max_length=256)


class InvoiceImportRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invoice_number: str = Field(min_length=1, max_length=160)
    client_name: str = Field(min_length=1, max_length=240)
    client_email: str = Field(min_length=3, max_length=320)
    amount: Decimal = Field(ge=0, max_digits=14, decimal_places=2)
    amount_due: Decimal = Field(ge=0, max_digits=14, decimal_places=2)
    currency: str = Field(pattern=r"^[A-Za-z]{3}$")
    issue_date: date | None = None
    due_date: date
    status: Literal["unpaid", "paid", "void"] = "unpaid"
    source_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("invoice_number", "client_name", "client_email")
    @classmethod
    def trim_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value

    @field_validator("client_email")
    @classmethod
    def validate_email_shape(cls, value: str) -> str:
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("must be a valid email address")
        return value.lower()

    @field_validator("source_data")
    @classmethod
    def limit_source_data(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 100 or len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")) > 32768:
            raise ValueError("source_data may contain at most 100 columns and 32 KB")
        return value

    @model_validator(mode="after")
    def balance_not_above_invoice_total(self) -> "InvoiceImportRow":
        if self.amount_due > self.amount:
            raise ValueError("amount_due cannot exceed amount")
        return self


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_name: str = Field(min_length=1, max_length=255)
    rows: list[InvoiceImportRow] = Field(min_length=1, max_length=5000)

    @field_validator("file_name")
    @classmethod
    def trim_file_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("file_name must not be blank")
        return value

    @field_validator("rows")
    @classmethod
    def limit_payload_size(cls, value: list[InvoiceImportRow]) -> list[InvoiceImportRow]:
        if len(json.dumps([row.model_dump(mode="json") for row in value], ensure_ascii=False).encode("utf-8")) > 10 * 1024 * 1024:
            raise ValueError("invoice import payload exceeds 10 MB; split the file into smaller batches")
        return value


class InvoiceActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invoice_id: UUID
    action_key: str = Field(min_length=1, max_length=160)


class InvoiceReviewDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approved", "rejected", "pending"]


class InvoiceDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    invoice_ids: list[UUID] = Field(min_length=1, max_length=500)

    @field_validator("invoice_ids")
    @classmethod
    def deduplicate_invoice_ids(cls, value: list[UUID]) -> list[UUID]:
        unique = list(dict.fromkeys(value))
        if len(unique) != len(value):
            raise ValueError("invoice_ids must not contain duplicates")
        return unique


class FirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)

    @field_validator("name")
    @classmethod
    def trim_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("name must not be blank")
        return value


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refresh_token: str = Field(min_length=1, max_length=4096)


class CsvHeaderMapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    headers: list[str] = Field(min_length=1, max_length=100)

    @field_validator("headers")
    @classmethod
    def normalize_headers(cls, value: list[str]) -> list[str]:
        cleaned = [header.replace("\ufeff", "").strip() for header in value]
        if any(not header for header in cleaned):
            raise ValueError("CSV headers cannot be blank.")
        normalized = [" ".join(header.split()).casefold() for header in cleaned]
        if len(set(normalized)) != len(normalized):
            raise ValueError("CSV headers must be unique after trimming and case normalization.")
        return cleaned


class ReplyClassificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    invoice_id: UUID
    email_text: str = Field(min_length=1, max_length=30000)

    @field_validator("email_text")
    @classmethod
    def require_reply_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("email_text cannot be blank.")
        return value


class ReminderDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    invoice_id: UUID
    message_type: Literal["initial", "gentle", "firm"]


class ReminderWorkflowStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    invoice_id: UUID
    message_type: Literal["initial", "gentle", "firm"]


class ReminderWorkflowReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "reject"]
    draft_version: str = Field(pattern=r"^[0-9a-f]{64}$")
    subject: str | None = Field(default=None, max_length=180)
    body: str | None = Field(default=None, max_length=5000)

    @field_validator("subject", "body")
    @classmethod
    def trim_review_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @model_validator(mode="after")
    def approved_draft_must_be_complete(self) -> "ReminderWorkflowReviewRequest":
        if self.decision == "approve" and (not self.subject or not self.body):
            raise ValueError("Approval requires a non-empty subject and message body.")
        return self


class TeamInvitationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=320)
    role: Literal["admin", "reviewer", "sender", "viewer"]

    @field_validator("email")
    @classmethod
    def validate_team_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Enter a valid team member email.")
        return value


class TeamInvitationAcceptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=32, max_length=128)


class ReplyResolutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reply_type: Literal["promise", "question", "help", "dispute", "ooo", "payment_claim", "opt_out", "other"]
    promise_date: date | None = None
    pause_until: date | None = None
    resolution_note: str = Field(default="", max_length=500)

    @field_validator("resolution_note")
    @classmethod
    def trim_resolution_note(cls, value: str) -> str:
        return value.strip()


class ConfirmNotSentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation: Literal["I checked Gmail Sent and confirmed no message was sent"]


class ClioLogReconcileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    communication_id: str = Field(pattern=r"^[0-9]{1,20}$")


class WorkflowPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshot_max_age_hours: int = Field(default=24, ge=1, le=72)
    initial_min_days_overdue: int = Field(default=0, ge=0, le=90)
    gentle_interval_days: int = Field(default=7, ge=1, le=90)
    firm_min_days_overdue: int = Field(default=21, ge=7, le=180)
    send_window_start: day_time = day_time(9, 0)
    send_window_end: day_time = day_time(17, 0)
    weekdays_only: bool = True
    require_distinct_approver_sender: bool = False

    @model_validator(mode="after")
    def validate_policy(self) -> "WorkflowPolicyUpdate":
        if self.firm_min_days_overdue < self.initial_min_days_overdue:
            raise ValueError("firm_min_days_overdue must be at least initial_min_days_overdue")
        if self.send_window_start >= self.send_window_end:
            raise ValueError("send window start must be before send window end")
        return self

    @field_validator("send_window_start", "send_window_end")
    @classmethod
    def require_local_wall_clock_time(cls, value: day_time) -> day_time:
        if value.tzinfo is not None:
            raise ValueError("Send window values must be local wall-clock times without a UTC offset")
        return value


class SuppressionReinstateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=320)
    reason: str = Field(min_length=10, max_length=500)

    @field_validator("email")
    @classmethod
    def normalize_suppression_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Enter a valid email address")
        return value

    @field_validator("reason")
    @classmethod
    def trim_reinstatement_reason(cls, value: str) -> str:
        return value.strip()


class FirmSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timezone: str = Field(min_length=1, max_length=64)

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        value = value.strip()
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("Use a valid IANA timezone, such as America/New_York") from exc
        return value


def configured() -> bool:
    return bool(SUPABASE_URL and SUPABASE_KEY and "YOUR_PROJECT" not in SUPABASE_URL)


def new_client(jwt: str | None = None) -> Client:
    if not configured():
        raise HTTPException(status_code=503, detail="Supabase persistence is not configured.")
    client = create_client(SUPABASE_URL, SUPABASE_KEY)
    if jwt:
        client.postgrest.auth(jwt)
    return client


def admin_client() -> Client:
    """Create a backend-only Supabase client for OAuth state and encrypted tokens."""
    try:
        from settings import settings
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Backend integration settings are unavailable.") from exc
    if not settings.supabase_configured or not settings.supabase_service_role_key:
        raise HTTPException(status_code=503, detail="The backend Supabase service-role key is not configured.")
    try:
        return create_client(settings.supabase_url, settings.supabase_service_role_key)
    except Exception as exc:
        logger.warning("admin_supabase_client_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not initialize the secure integration store.") from exc


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ledgerly-api"}


@app.get("/api/config")
def public_config() -> dict[str, bool]:
    return {"cloud_configured": configured()}


def _auth_upstream_error(exc: Exception, *, action: str, request_id: str) -> HTTPException:
    """Translate Supabase Auth failures without logging or returning credentials."""
    status = getattr(exc, "status", None)
    if not isinstance(status, int):
        status = getattr(getattr(exc, "response", None), "status_code", None)
    status = status if isinstance(status, int) and not isinstance(status, bool) else None

    raw_code = getattr(exc, "code", None)
    raw_code = getattr(raw_code, "value", raw_code)
    code = str(raw_code or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9_]{1,64}", code):
        code = "unknown"

    logger.warning("supabase_auth_failed request_id=%s action=%s status=%s code=%s error_type=%s",
                   request_id, action, status if status is not None else "unknown", code,
                   type(exc).__name__)

    if code == "email_not_confirmed":
        return HTTPException(
            status_code=403,
            detail="Confirm this email address using Supabase’s confirmation link before signing in. Check your inbox and spam folder.",
        )
    if code in {"invalid_credentials", "invalid_login_credentials", "invalid_grant"}:
        return HTTPException(
            status_code=401,
            detail="Email or password is incorrect. If this account requires email confirmation, confirm the address before signing in.",
        )
    if code in {"weak_password", "password_too_short"}:
        return HTTPException(status_code=422, detail="The password does not meet this Supabase project's password policy.")
    if action == "sign-up" and code in {"user_already_exists", "email_exists"}:
        return HTTPException(status_code=409, detail="An account may already exist for this address. Try signing in or use password recovery.")
    if status == 429:
        return HTTPException(status_code=429, detail="Supabase Auth is rate limiting requests. Wait briefly, then try again.")
    if status in {402, 540}:
        return HTTPException(status_code=503, detail="Supabase reports this project is restricted or paused. Check the project's status and billing in Supabase.")
    if status is None or status >= 500 or status in {401, 403}:
        return HTTPException(status_code=503, detail="Supabase Auth is unavailable or the project key was rejected. Check the project status and backend Supabase URL/key configuration.")
    if action == "sign-up":
        return HTTPException(status_code=400, detail="Supabase rejected account creation. Check the email format, password policy, and Auth settings.")
    return HTTPException(status_code=401, detail="Supabase rejected sign-in. Check the credentials and email-confirmation status.")


@app.post("/api/auth/sign-in")
def sign_in(body: Credentials, request: Request) -> dict[str, Any]:
    try:
        result = new_client().auth.sign_in_with_password({"email": body.email, "password": body.password})
        return {"session": result.session.model_dump() if result.session else None,
                "user": result.user.model_dump() if result.user else None}
    except HTTPException:
        raise
    except Exception as exc:
        raise _auth_upstream_error(exc, action="sign-in",
                                   request_id=getattr(request.state, "request_id", "unavailable")) from exc


@app.post("/api/auth/sign-up")
def sign_up(body: Credentials, request: Request) -> dict[str, Any]:
    from settings import settings
    try:
        result = new_client().auth.sign_up({"email": body.email, "password": body.password,
            "options": {"data": {"firm_name": body.firm_name},
                        "email_redirect_to": f"{settings.frontend_public_url}/?auth-confirmed=1"}})
        return {"session": result.session.model_dump() if result.session else None,
                "user": result.user.model_dump() if result.user else None}
    except HTTPException:
        raise
    except Exception as exc:
        raise _auth_upstream_error(exc, action="sign-up",
                                   request_id=getattr(request.state, "request_id", "unavailable")) from exc


@app.post("/api/auth/refresh")
def refresh_session(body: RefreshRequest) -> dict[str, Any]:
    try:
        result = new_client().auth.refresh_session(body.refresh_token)
        if not result.session:
            raise ValueError("No refreshed session")
        return result.session.model_dump()
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Session expired. Sign in again.") from exc


@app.post("/api/auth/password-reset", status_code=202)
def request_password_reset(body: PasswordResetRequest) -> dict[str, str]:
    """Request Supabase's email recovery flow without revealing account existence."""
    from settings import settings
    response = {"message": "If an account exists for this address, password recovery instructions will be sent."}
    if not configured():
        return response
    try:
        new_client().auth.reset_password_email(
            body.email,
            options={"redirect_to": f"{settings.frontend_public_url}/?password-recovery=1"},
        )
    except Exception as exc:
        # Keep account enumeration and provider details out of the response.
        logger.warning("password_recovery_request_failed error_type=%s", type(exc).__name__)
    return response


@app.post("/api/auth/confirmation/resend", status_code=202)
def resend_signup_confirmation(body: PasswordResetRequest, request: Request) -> dict[str, str]:
    """Resend signup confirmation without disclosing whether the address exists."""
    from settings import settings
    response = {"message": "If an unconfirmed account exists for this address, a confirmation email will be sent."}
    if not configured():
        return response
    try:
        new_client().auth.resend({
            "type": "signup",
            "email": body.email,
            "options": {"email_redirect_to": f"{settings.frontend_public_url}/?auth-confirmed=1"},
        })
    except Exception as exc:
        request_id = getattr(request.state, "request_id", "unavailable")
        logger.warning("signup_confirmation_resend_failed request_id=%s error_type=%s",
                       request_id, type(exc).__name__)
    return response


def authenticated_client(authorization: str | None = Header(default=None)) -> tuple[Client, Any, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Sign in is required.")
    jwt = authorization[7:].strip()
    if not jwt:
        raise HTTPException(status_code=401, detail="Sign in is required.")
    client = new_client(jwt)
    try:
        user = client.auth.get_user(jwt).user
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Session expired. Sign in again.") from exc
    if not user:
        raise HTTPException(status_code=401, detail="Session expired. Sign in again.")
    return client, user, jwt


def current_session(session: tuple[Client, Any, str] = Depends(authenticated_client)) -> dict[str, Any]:
    client, user, access_token = session
    return {"client": client, "user": user, "access_token": access_token}


@app.post("/api/auth/password-update")
def update_password(body: PasswordUpdateRequest,
                    ctx: dict[str, Any] = Depends(current_session)) -> dict[str, bool]:
    try:
        response = httpx.put(
            f"{SUPABASE_URL.rstrip('/')}/auth/v1/user",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {ctx['access_token']}",
                     "Content-Type": "application/json"},
            json={"password": body.password}, timeout=15.0, follow_redirects=False,
        )
        response.raise_for_status()
        return {"updated": True}
    except Exception as exc:
        logger.warning("password_update_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=401, detail="Password recovery session is invalid or expired. Request a new recovery email.") from exc


@app.get("/api/ops/readiness")
def operational_readiness(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    firm_id = _require_role(ctx, "owner", "admin")
    from settings import settings
    required_tables = ["firm_workflow_policies", "ledgerly_audit_events", "invoice_paid_transitions",
                       "workflow_runs", "workflow_deliveries", "gmail_connections", "clio_connections"]
    table_status: dict[str, bool] = {}
    try:
        admin = admin_client()
        for table in required_tables:
            try:
                admin.table(table).select("*").limit(0).execute()
                table_status[table] = True
            except Exception:
                table_status[table] = False
        try:
            admin.table("workflow_deliveries").select(
                "clio_activity_status,clio_activity_id,clio_activity_marker,clio_activity_updated_at"
            ).limit(0).execute()
            table_status["clio_activity_audit_columns"] = True
        except Exception:
            table_status["clio_activity_audit_columns"] = False
        connected_clio = bool(admin.table("clio_connections").select("id").eq("firm_id", firm_id).limit(1).execute().data)
        connected_gmail = bool(admin.table("gmail_connections").select("id").eq("firm_id", firm_id).limit(1).execute().data)
        checks = {
            "supabase": settings.supabase_configured and bool(settings.supabase_service_role_key),
            "langchain_model": settings.ai_features_enabled and settings.openai_configured,
            "gmail_oauth": settings.gmail_oauth_configured and settings.gmail_features_enabled,
            "email_send_gate": settings.email_send_enabled,
            "gmail_connected": connected_gmail,
            "clio_oauth": settings.clio_configured,
            "clio_connected": connected_clio,
        }
        result = {
            "service": "ledgerly-api",
            "firm_id": firm_id,
            "database_migrations_ready": all(table_status.values()),
            "schema_checks": table_status,
            "configuration": checks,
            "automatic_sending": False,
            "bill_write_enabled_in_workflow": False,
            "activity_write_enabled_in_workflow": True,
            "activity_write_boundary": "Only after a confirmed human-approved email send; non-billable and no-charge; no Bill writes; no Activity without a linked Clio matter.",
            "ready_for_reviewed_demo": all(table_status.values()) and checks["supabase"] and checks["langchain_model"],
            "ready_for_end_to_end_demo": all(table_status.values()) and all(checks.values()),
            "team_invite_delivery": "secure link is copied/shared manually",
            "production_deployment_reviewed": False,
        }
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("operational_readiness_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not inspect backend readiness. Check server configuration and Supabase connectivity.") from exc


@app.get("/api/auth/session")
def get_session(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    u = ctx["user"]
    return {"user": {"id": str(u.id), "email": u.email,
                      "user_metadata": getattr(u, "user_metadata", {}) or {}}}


def _clio_service():
    try:
        from settings import settings
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Clio integration settings are unavailable.") from exc
    if not settings.clio_features_enabled:
        raise HTTPException(status_code=503, detail="Clio integration is disabled. Set CLIO_FEATURES_ENABLED=true after setup.")
    if not settings.clio_configured:
        raise HTTPException(status_code=503, detail="Complete the Clio credentials, token-encryption key, region, and Supabase service-role settings first.")
    try:
        import clio_integration
        return clio_integration
    except Exception as exc:
        logger.warning("clio_dependencies_missing error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Install backend/requirements.txt to enable Clio integration.") from exc


@app.post("/api/integrations/clio/authorize")
def clio_authorize(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    service = _clio_service()
    firm_id = _require_role(ctx, "owner", "admin")
    admin = admin_client()
    state = secrets.token_urlsafe(32)
    state_hash = hashlib.sha256(state.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    try:
        admin.table("clio_oauth_states").delete().lt("expires_at", now.isoformat()).execute()
        admin.table("clio_oauth_states").insert({
            "state_hash": state_hash,
            "firm_id": firm_id,
            "initiated_by": str(ctx["user"].id),
            "expires_at": (now + timedelta(minutes=10)).isoformat(),
        }).execute()
    except Exception as exc:
        logger.warning("clio_oauth_state_create_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not start Clio authorization.") from exc
    return {"authorization_url": service.authorization_url(state), "expires_in_seconds": 600}


def _consume_clio_state(admin: Client, state: str) -> dict[str, Any] | None:
    if not state or len(state) > 512:
        return None
    digest = hashlib.sha256(state.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    try:
        rows = (admin.table("clio_oauth_states").update({"consumed_at": now})
                .eq("state_hash", digest).is_("consumed_at", "null")
                .gt("expires_at", now).select("firm_id,initiated_by").limit(1).execute().data)
    except Exception as exc:
        logger.warning("clio_oauth_state_consume_failed error_type=%s", type(exc).__name__)
        return None
    return rows[0] if rows else None


def _clio_callback_page(success: bool, message: str) -> HTMLResponse:
    title = "Clio connected" if success else "Clio connection not completed"
    color = "#18835d" if success else "#a43f45"
    body = ("Clio Manage is connected. Return to Ledgerly and refresh the connection status."
            if success else message)
    # Both possible messages are fixed server strings, not request parameters.
    html = ("<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
            f"<title>{title}</title><body style='font:16px system-ui;max-width:560px;margin:12vh auto;padding:24px;color:#24263a'>"
            f"<h1 style='color:{color}'>{title}</h1><p>{body}</p><p>You can close this tab.</p></body></html>")
    return HTMLResponse(html, status_code=200 if success else 400, headers={"Cache-Control": "no-store"})


@app.get("/api/integrations/clio/callback", response_class=HTMLResponse)
def clio_callback(code: str | None = None, state: str | None = None,
                  error: str | None = None) -> HTMLResponse:
    service = _clio_service()
    admin = admin_client()
    oauth_state = _consume_clio_state(admin, state or "")
    if not oauth_state:
        return _clio_callback_page(False, "The authorization request expired or could not be verified. Start again from Ledgerly.")
    if error or not code:
        return _clio_callback_page(False, "Clio access was declined or the authorization response was incomplete.")
    try:
        tokens = service.exchange_code(code)
        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")
        if not access_token or not refresh_token:
            raise service.ClioIntegrationError("Clio did not return both required tokens.")
        current_user = service.current_user(access_token)
        expires_in = max(60, min(int(tokens.get("expires_in", 2592000)), 31536000))
        now = datetime.now(timezone.utc)
        from settings import settings
        connection = {
            "firm_id": oauth_state["firm_id"],
            "clio_user_id": str(current_user["id"]),
            "clio_user_name": str(current_user.get("name") or "")[:240],
            "region": settings.clio_region,
            "encrypted_access_token": service.encrypt_token(access_token),
            "encrypted_refresh_token": service.encrypt_token(refresh_token),
            "access_token_expires_at": (now + timedelta(seconds=expires_in)).isoformat(),
            "connected_by": oauth_state["initiated_by"],
            "connected_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }
        admin.table("clio_connections").upsert(connection, on_conflict="firm_id").execute()
    except Exception as exc:
        logger.warning("clio_oauth_callback_failed error_type=%s", type(exc).__name__)
        return _clio_callback_page(False, "Clio could not be connected. Check the developer app credentials, region, scopes, and registered callback URL, then start again.")
    return _clio_callback_page(True, "")


@app.get("/api/integrations/clio/status")
def clio_connection_status(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    _clio_service()
    firm_id = _firm_id(ctx)
    try:
        rows = (admin_client().table("clio_connections").select(
            "clio_user_id,clio_user_name,region,connected_at,last_synced_at"
        ).eq("firm_id", firm_id).limit(1).execute().data)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("clio_status_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not load the Clio connection status.") from exc
    if not rows:
        return {"connected": False}
    row = rows[0]
    return {"connected": True, **row}


def _normalize_clio_bill(raw: dict[str, Any], default_currency: str) -> tuple[dict[str, Any] | None, str | None]:
    state = str(raw.get("state") or "").lower()
    if state in {"draft", "awaiting_approval"}:
        return None, "ignored"
    if state not in {"awaiting_payment", "paid", "void", "deleted"}:
        return None, "invalid"
    bill_id = raw.get("id")
    number = str(raw.get("number") or (f"CLIO-{bill_id}" if bill_id is not None else "")).strip()
    client = raw.get("client") if isinstance(raw.get("client"), dict) else {}
    client_name = str(client.get("name") or "").strip()
    matter = raw.get("matter") if isinstance(raw.get("matter"), dict) else {}
    due_value = raw.get("due_at")
    try:
        due_date = date.fromisoformat(str(due_value)[:10])
    except (TypeError, ValueError):
        return None, "invalid"
    try:
        balance = Decimal(str(raw.get("balance", "0")))
        total = Decimal(str(raw.get("total", raw.get("balance", "0"))))
    except Exception:
        return None, "invalid"
    if not bill_id or not number or not client_name or not balance.is_finite() or not total.is_finite():
        return None, "invalid"
    if balance < 0 or total < 0:
        return None, "invalid"
    if total < balance:
        total = balance
    if balance == 0 and state == "awaiting_payment":
        state = "paid"
    status = "paid" if state == "paid" else "void" if state in {"void", "deleted"} else "unpaid"
    email = str(client.get("primary_email_address") or "").strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        email = None
    issue_date = raw.get("issued_at")
    try:
        issue_date = date.fromisoformat(str(issue_date)[:10]).isoformat() if issue_date else None
    except (TypeError, ValueError):
        issue_date = None
    updated_at = raw.get("updated_at")
    return {
        "clio_bill_id": str(bill_id),
        "invoice_number": number[:160],
        "client_name": client_name[:240],
        "client_email": email,
        "amount": str(total.quantize(Decimal("0.01"))),
        "amount_due": str((Decimal("0") if status in {"paid", "void"} else balance).quantize(Decimal("0.01"))),
        "currency": default_currency,
        "issue_date": issue_date,
        "due_date": due_date.isoformat(),
        "status": status,
        "source_data": {"provider": "clio", "clio_bill_id": str(bill_id), "clio_state": state,
                        "clio_contact_id": str(client.get("id")) if client.get("id") is not None else None,
                        "clio_matter_id": str(matter.get("id")) if matter.get("id") is not None else None},
        "source_updated_at": updated_at or datetime.now(timezone.utc).isoformat(),
    }, None


def _upsert_clio_invoice(admin: Client, firm_id: str, import_id: str,
                         row: dict[str, Any]) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    rows = (admin.table("invoices").select("id,status,outreach_state,clio_bill_id")
            .eq("firm_id", firm_id).eq("clio_bill_id", row["clio_bill_id"]).limit(1).execute().data)
    if not rows:
        rows = (admin.table("invoices").select("id,status,outreach_state,clio_bill_id")
                .eq("firm_id", firm_id).eq("invoice_number", row["invoice_number"]).limit(1).execute().data)
    existing = rows[0] if rows else None
    payload = {
        **row,
        "firm_id": firm_id,
        "last_import_id": import_id,
        "updated_at": now,
    }
    if existing:
        if existing.get("clio_bill_id") and str(existing["clio_bill_id"]) != row["clio_bill_id"]:
            return False
        old_status = existing.get("status")
        new_status = row["status"]
        if new_status in {"paid", "void"}:
            payload.update({
                "outreach_state": "closed",
                "next_action_on": None,
                "pause_until": None,
                "last_action": "Payment confirmed by Clio" if new_status == "paid" else "Bill marked void in Clio",
            })
        elif old_status in {"paid", "void"} and new_status == "unpaid":
            payload.update({
                "outreach_state": "needs_review",
                "next_action_on": None,
                "last_action": "Clio bill reopened; review required before outreach",
            })
        elif not row.get("client_email"):
            payload.update({
                "outreach_state": "needs_review",
                "next_action_on": None,
                "last_action": "Client billing email missing in Clio; review required",
            })
        result = admin.table("invoices").update(payload).eq("id", existing["id"]).eq("firm_id", firm_id).execute()
        return bool(result.data)
    if not row.get("client_email"):
        payload.update({
            "outreach_state": "needs_review",
            "last_action": "Client billing email missing in Clio; review required",
        })
    result = admin.table("invoices").insert(payload).execute()
    return bool(result.data)


@app.post("/api/integrations/clio/sync")
def sync_clio_bills(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    service = _clio_service()
    firm_id = _require_role(ctx, "owner", "admin")
    admin = admin_client()
    try:
        connections = (admin.table("clio_connections").select("*").eq("firm_id", firm_id).limit(1).execute().data)
    except Exception as exc:
        logger.warning("clio_connection_read_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not load the Clio connection.") from exc
    if not connections:
        raise HTTPException(status_code=409, detail="Connect a Clio Manage account before syncing bills.")
    connection = connections[0]
    now = datetime.now(timezone.utc)
    try:
        access_token = service.decrypt_token(connection["encrypted_access_token"])
        refresh_token = service.decrypt_token(connection["encrypted_refresh_token"])
        expiry = datetime.fromisoformat(str(connection["access_token_expires_at"]).replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= now + timedelta(minutes=5):
            refreshed = service.refresh_tokens(refresh_token)
            access_token = refreshed["access_token"]
            refresh_token = refreshed.get("refresh_token") or refresh_token
            expires_in = max(60, min(int(refreshed.get("expires_in", 2592000)), 31536000))
            connection["access_token_expires_at"] = (now + timedelta(seconds=expires_in)).isoformat()
            connection["encrypted_access_token"] = service.encrypt_token(access_token)
            connection["encrypted_refresh_token"] = service.encrypt_token(refresh_token)
            admin.table("clio_connections").update({
                "encrypted_access_token": connection["encrypted_access_token"],
                "encrypted_refresh_token": connection["encrypted_refresh_token"],
                "access_token_expires_at": connection["access_token_expires_at"],
                "updated_at": now.isoformat(),
            }).eq("firm_id", firm_id).execute()
        bills = service.fetch_all_bills(access_token)
        imports = admin.table("invoice_imports").insert({
            "firm_id": firm_id,
            "uploaded_by": connection["connected_by"],
            "file_name": "Clio Manage sync",
            "source_system": "clio",
            "received_rows": len(bills),
            "covers_all_invoices": False,
        }).select("id").single().execute().data
        import_id = imports["id"]
        accepted = ignored = invalid = 0
        from settings import settings
        for bill in bills:
            normalized, reason = _normalize_clio_bill(bill, settings.clio_default_currency)
            if reason == "ignored":
                ignored += 1
                continue
            if normalized is None:
                invalid += 1
                continue
            if _upsert_clio_invoice(admin, firm_id, import_id, normalized):
                accepted += 1
            else:
                invalid += 1
        complete = invalid == 0
        admin.table("invoice_imports").update({
            "accepted_rows": accepted,
            "ignored_rows": ignored,
            "invalid_rows": invalid,
            "covers_all_invoices": complete,
        }).eq("id", import_id).eq("firm_id", firm_id).execute()
        admin.table("clio_connections").update({
            "last_synced_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("firm_id", firm_id).execute()
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("clio_bill_sync_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Clio bill sync failed. The latest snapshot remains ineligible for drafting; resolve the issue and sync again.") from exc
    _record_audit(firm_id, str(ctx["user"].id), "clio_bill_sync_completed", "invoice_import", str(import_id),
                  "Clio bills synchronized into a complete or review-required snapshot.",
                  {"received_rows": len(bills), "accepted_rows": accepted, "invalid_rows": invalid,
                   "covers_all_invoices": complete})
    return {
        "import_id": import_id,
        "source_system": "clio",
        "received_rows": len(bills),
        "accepted_rows": accepted,
        "ignored_rows": ignored,
        "invalid_rows": invalid,
        "covers_all_invoices": complete,
        "synced_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/integrations/clio/disconnect")
def disconnect_clio(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, bool]:
    service = _clio_service()
    firm_id = _require_role(ctx, "owner", "admin")
    admin = admin_client()
    try:
        rows = (admin.table("clio_connections").select("encrypted_access_token")
                .eq("firm_id", firm_id).limit(1).execute().data)
        if not rows:
            return {"disconnected": True}
        access_token = service.decrypt_token(rows[0]["encrypted_access_token"])
        service.deauthorize(access_token)
        admin.table("clio_connections").delete().eq("firm_id", firm_id).execute()
    except Exception as exc:
        logger.warning("clio_disconnect_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not safely disconnect Clio. Try again or revoke Ledgerly from Clio Manage settings.") from exc
    return {"disconnected": True}


@app.post("/api/auth/sign-out")
def sign_out(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, bool]:
    try:
        ctx["client"].auth.sign_out()
    except Exception:
        # The browser also clears its token immediately. A provider-side signout
        # failure must not retain the local session.
        pass
    return {"signed_out": True}


@app.get("/api/cloud/firm")
def get_firm(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any] | None:
    client, user = ctx["client"], ctx["user"]
    try:
        owned = (client.table("firms").select("id,name,automation_enabled,timezone")
                 .eq("owner_user_id", str(user.id)).limit(1).execute().data)
        if owned:
            return {**owned[0], "member_role": "owner"}
        members = (admin_client().table("firm_members").select("firm_id,role")
                   .eq("user_id", str(user.id)).eq("status", "active").limit(2).execute().data)
        if not members:
            return None
        if len(members) != 1:
            raise HTTPException(status_code=409, detail="This account belongs to more than one firm; contact the firm administrator.")
        firm = (client.table("firms").select("id,name,automation_enabled,timezone")
                .eq("id", members[0]["firm_id"]).limit(1).execute().data)
        if not firm:
            return None
        return {**firm[0], "member_role": members[0]["role"]}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Could not load firm settings.") from exc


@app.post("/api/cloud/firm")
def create_firm(body: FirmRequest, ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    client, user = ctx["client"], ctx["user"]
    try:
        return (client.table("firms").insert({"owner_user_id": str(user.id), "name": body.name.strip()})
                .select("id,name,automation_enabled,timezone").single().execute().data)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Could not create the firm record.") from exc


@app.put("/api/cloud/firm/settings")
def update_firm_settings(body: FirmSettingsUpdate,
                         ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    firm_id = _require_role(ctx, "owner", "admin")
    try:
        result = (ctx["client"].table("firms").update({"timezone": body.timezone})
                  .eq("id", firm_id).select("id,name,timezone").single().execute().data)
        try:
            admin_client().table("ledgerly_audit_events").insert({
                "firm_id": firm_id, "actor_user_id": str(ctx["user"].id),
                "event_type": "firm_timezone_updated", "target_type": "firm", "target_id": firm_id,
                "summary": "Firm timezone updated.", "metadata": {"timezone": body.timezone},
            }).execute()
        except Exception as audit_exc:
            logger.warning("firm_timezone_audit_failed error_type=%s", type(audit_exc).__name__)
        return result
    except Exception as exc:
        logger.warning("firm_settings_update_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not update firm settings.") from exc


@app.get("/api/team")
def list_firm_team(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    firm_id = _require_role(ctx, "owner", "admin")
    try:
        admin = admin_client()
        members = (admin.table("firm_members").select("id,user_id,email,role,status,joined_at")
                   .eq("firm_id", firm_id).order("created_at").execute().data)
        invitations = (admin.table("firm_invitations").select("id,email,role,status,expires_at,created_at")
                       .eq("firm_id", firm_id).eq("status", "pending").order("created_at", desc=True).execute().data)
        return {"members": members, "invitations": invitations, "your_role": _firm_access(ctx)["role"]}
    except Exception as exc:
        logger.warning("team_list_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not load the firm team.") from exc


@app.post("/api/team/invitations")
def create_team_invitation(body: TeamInvitationRequest,
                           ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    firm_id = _require_role(ctx, "owner", "admin")
    inviter_role = _firm_access(ctx)["role"]
    if body.role == "admin" and inviter_role != "owner":
        raise HTTPException(status_code=403, detail="Only the firm owner can invite another administrator.")
    admin = admin_client()
    try:
        members = (admin.table("firm_members").select("id,status").eq("firm_id", firm_id)
                   .eq("email", body.email).eq("status", "active").limit(1).execute().data)
        if members:
            raise HTTPException(status_code=409, detail="This email is already an active team member.")
        # Replace an older pending link. Only a hash is retained by the server.
        admin.table("firm_invitations").update({"status": "revoked"}).eq("firm_id", firm_id).eq(
            "email", body.email).eq("status", "pending").execute()
        token = secrets.token_urlsafe(40)
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        inserted = (admin.table("firm_invitations").insert({
            "firm_id": firm_id, "email": body.email, "role": body.role,
            "token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "invited_by": str(ctx["user"].id), "expires_at": expires_at.isoformat(),
        }).select("id,email,role,status,expires_at,created_at").single().execute().data)
        from settings import settings
        base = settings.frontend_public_url
        if not re.fullmatch(r"https?://[^\s/]+(?::\d+)?(?:/[^\s]*)?", base):
            raise HTTPException(status_code=503, detail="Set FRONTEND_PUBLIC_URL to the frontend origin before creating team invites.")
        return {"invitation": inserted, "invite_url": f"{base}/?invite={token}"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("team_invitation_create_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not create the team invitation.") from exc


@app.post("/api/team/invitations/accept")
def accept_team_invitation(body: TeamInvitationAcceptRequest,
                           ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    email = str(getattr(ctx["user"], "email", "") or "").strip().lower()
    if not email or not (getattr(ctx["user"], "email_confirmed_at", None)
                         or getattr(ctx["user"], "confirmed_at", None)):
        raise HTTPException(status_code=403, detail="Your authenticated account has no verified email address.")
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    try:
        result = admin_client().rpc("accept_firm_invitation", {
            "p_token_hash": token_hash, "p_user_id": str(ctx["user"].id), "p_email": email,
        }).execute().data
        if isinstance(result, list) and result:
            result = result[0]
        if not isinstance(result, dict) or not result.get("ok"):
            reason = result.get("reason") if isinstance(result, dict) else "invalid_or_expired"
            if reason == "email_mismatch":
                raise HTTPException(status_code=403, detail="Sign in with the email address this invitation was sent to.")
            if reason == "already_in_another_firm":
                raise HTTPException(status_code=409, detail="This account already belongs to another firm. Sign in with a separate account for the invitation.")
            raise HTTPException(status_code=404, detail="This team invitation is invalid, expired, or already used.")
        return {"accepted": True, "firm_id": result["firm_id"], "role": result["role"]}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("team_invitation_accept_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not accept the team invitation.") from exc


@app.delete("/api/team/members/{member_id}")
def revoke_team_member(member_id: UUID, ctx: dict[str, Any] = Depends(current_session)) -> dict[str, bool]:
    firm_id = _require_role(ctx, "owner", "admin")
    actor_role = _firm_access(ctx)["role"]
    admin = admin_client()
    try:
        rows = (admin.table("firm_members").select("id,user_id,role")
                .eq("id", str(member_id)).eq("firm_id", firm_id).eq("status", "active").limit(1).execute().data)
        if not rows:
            raise HTTPException(status_code=404, detail="Active team member not found.")
        target = rows[0]
        if target["role"] == "admin" and actor_role != "owner":
            raise HTTPException(status_code=403, detail="Only the firm owner can remove an administrator.")
        admin.table("firm_members").update({"status": "revoked", "updated_at": datetime.now(timezone.utc).isoformat()})\
            .eq("id", str(member_id)).eq("firm_id", firm_id).eq("status", "active").execute()
        return {"revoked": True}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("team_member_revoke_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not remove this team member.") from exc


@app.delete("/api/team/invitations/{invitation_id}")
def revoke_team_invitation(invitation_id: UUID,
                           ctx: dict[str, Any] = Depends(current_session)) -> dict[str, bool]:
    firm_id = _require_role(ctx, "owner", "admin")
    try:
        rows = (admin_client().table("firm_invitations").update({"status": "revoked"})
                .eq("id", str(invitation_id)).eq("firm_id", firm_id).eq("status", "pending").execute().data)
        if not rows:
            raise HTTPException(status_code=404, detail="Pending invitation not found.")
        return {"revoked": True}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("team_invitation_revoke_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not revoke this invitation.") from exc


@app.get("/api/cloud/invoices")
def invoices(ctx: dict[str, Any] = Depends(current_session)) -> list[dict[str, Any]]:
    firm = _firm_id(ctx)
    try:
        return (ctx["client"].table("invoices").select(
            "id, invoice_number, client_name, client_email, amount, amount_due, currency, issue_date, due_date, status, staff_review_status, staff_reviewed_by, staff_reviewed_at, source_updated_at, last_import_id, source_system, clio_bill_id, outreach_state, first_contacted_on, last_contacted_on, next_action_on, pause_until, promise_date, reply_memory, last_action"
        ).eq("firm_id", firm).order("due_date").execute().data)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Could not load invoices.") from exc


@app.post("/api/cloud/invoices/{invoice_id}/review")
def review_invoice_record(invoice_id: UUID, body: InvoiceReviewDecisionRequest,
                          ctx: dict[str, Any] = Depends(current_session)) -> Any:
    _require_role(ctx, "owner", "admin", "reviewer")
    return _rpc(ctx, "record_invoice_review", {
        "p_invoice_id": str(invoice_id), "p_decision": body.decision,
    })


@app.delete("/api/cloud/invoices")
def delete_invoice_records(body: InvoiceDeleteRequest,
                           ctx: dict[str, Any] = Depends(current_session)) -> Any:
    _require_role(ctx, "owner", "admin")
    return _rpc(ctx, "delete_invoice_records", {
        "p_invoice_ids": [str(invoice_id) for invoice_id in body.invoice_ids],
    })


@app.get("/api/cloud/latest-import")
def latest_import(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any] | None:
    firm = _firm_id(ctx)
    try:
        rows = (ctx["client"].table("invoice_imports").select(
            "id,file_name,source_system,imported_at,covers_all_invoices,received_rows,accepted_rows,duplicate_rows,invalid_rows,ignored_rows"
        ).eq("firm_id", firm).order("imported_at", desc=True).limit(1).execute().data)
        return rows[0] if rows else None
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Could not load the latest invoice import.") from exc


@app.get("/api/cloud/events")
def events(ctx: dict[str, Any] = Depends(current_session)) -> list[dict[str, Any]]:
    firm = _firm_id(ctx)
    try:
        return (ctx["client"].table("invoice_events").select("event_type,summary,created_at,invoices(invoice_number)")
                .eq("firm_id", firm).order("created_at", desc=True).limit(50).execute().data)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Could not load activity.") from exc


def _firm_policy(firm_id: str) -> dict[str, Any]:
    """Load firm-owned workflow rules; missing schema fails closed."""
    try:
        rows = (admin_client().table("firm_workflow_policies").select(
            "firm_id,snapshot_max_age_hours,initial_min_days_overdue,gentle_interval_days,"
            "firm_min_days_overdue,send_window_start,send_window_end,weekdays_only,"
            "require_distinct_approver_sender,manual_send_required,updated_by,updated_at"
        ).eq("firm_id", firm_id).limit(1).execute().data)
        if not rows:
            raise HTTPException(status_code=503, detail="Firm workflow policy is missing. Apply the latest Ledgerly migration.")
        return rows[0]
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("workflow_policy_read_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not load firm workflow policy. Check the latest Supabase migration.") from exc


@app.get("/api/cloud/policy")
def get_workflow_policy(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    firm_id = _firm_id(ctx)
    policy = _firm_policy(firm_id)
    return {
        **policy,
        "approval_roles": {"invoice_review": ["owner", "admin", "reviewer"],
                           "message_review": ["owner", "admin", "reviewer"],
                           "send": ["owner", "admin", "sender"],
                           "policy_management": ["owner", "admin"]},
        "automatic_sending_enabled": False,
    }


@app.put("/api/cloud/policy")
def update_workflow_policy(body: WorkflowPolicyUpdate,
                           ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    firm_id = _require_role(ctx, "owner", "admin")
    try:
        data = body.model_dump()
        result = ctx["client"].rpc("set_firm_workflow_policy", {
            "p_firm_id": firm_id,
            "p_snapshot_max_age_hours": data["snapshot_max_age_hours"],
            "p_initial_min_days_overdue": data["initial_min_days_overdue"],
            "p_gentle_interval_days": data["gentle_interval_days"],
            "p_firm_min_days_overdue": data["firm_min_days_overdue"],
            "p_send_window_start": data["send_window_start"].isoformat(),
            "p_send_window_end": data["send_window_end"].isoformat(),
            "p_weekdays_only": data["weekdays_only"],
            "p_require_distinct_approver_sender": data["require_distinct_approver_sender"],
        }).execute().data
        return result if isinstance(result, dict) else (result[0] if isinstance(result, list) and result else {})
    except Exception as exc:
        logger.warning("workflow_policy_update_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not update the firm workflow policy. No automatic sending was enabled.") from exc


@app.get("/api/dashboard")
def dashboard_summary(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    """Return firm-scoped metrics from persisted source records, with freshness context."""
    firm_id = _firm_id(ctx)
    policy = _firm_policy(firm_id)
    client = admin_client()
    try:
        firm_rows = client.table("firms").select("id,name,timezone").eq("id", firm_id).limit(1).execute().data
        if not firm_rows:
            raise HTTPException(status_code=404, detail="Firm not found.")
        firm = firm_rows[0]
        invoices = (client.table("invoices").select(
            "id,invoice_number,amount_due,currency,status,due_date,staff_review_status,outreach_state"
        ).eq("firm_id", firm_id).execute().data)
        imports = (client.table("invoice_imports").select(
            "id,source_system,file_name,imported_at,covers_all_invoices,received_rows,accepted_rows,invalid_rows"
        ).eq("firm_id", firm_id).order("imported_at", desc=True).limit(1).execute().data)
        runs = (client.table("workflow_runs").select("id,status,updated_at")
                .eq("firm_id", firm_id).in_("status", ["awaiting_review", "approved_pending_delivery", "sending", "delivery_unknown"])
                .execute().data)
        replies = (client.table("gmail_reply_intake").select("id,status")
                   .eq("firm_id", firm_id).in_("status", ["needs_review", "resolving"]).execute().data)
        unresolved_delivery = (client.table("workflow_deliveries").select("id,status,clio_log_status,clio_activity_status,invoice_state_recorded")
                               .eq("firm_id", firm_id).or_("status.eq.delivery_unknown,clio_log_status.eq.failed,clio_activity_status.eq.failed,clio_activity_status.eq.unknown,invoice_state_recorded.eq.false")
                               .execute().data)
        audit = (client.table("ledgerly_audit_events").select("event_type,target_type,target_id,summary,created_at")
                 .eq("firm_id", firm_id).order("created_at", desc=True).limit(20).execute().data)
        latest = imports[0] if imports else None
        # Query one extra UTC day so firms east of UTC do not lose events from
        # the first hours of their local calendar month; exact local filtering follows.
        month_floor_utc = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
        paid_events = (client.table("invoice_paid_transitions").select("invoice_id,recorded_at")
                       .eq("firm_id", firm_id).gte("recorded_at", month_floor_utc.isoformat()).execute().data)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("dashboard_summary_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not build the dashboard from current firm records. Check the latest Supabase migration and connectivity.") from exc

    try:
        local_zone = ZoneInfo(str(firm.get("timezone") or "UTC"))
    except ZoneInfoNotFoundError:
        local_zone = ZoneInfo("UTC")
    now_local = datetime.now(local_zone)
    today = now_local.date()
    open_invoices = [item for item in invoices if item.get("status") == "unpaid" and Decimal(str(item.get("amount_due") or 0)) > 0]
    overdue = [item for item in open_invoices if date.fromisoformat(str(item["due_date"])) < today]
    try:
        imported_at = datetime.fromisoformat(str(latest["imported_at"]).replace("Z", "+00:00")) if latest else None
        if imported_at and imported_at.tzinfo is None:
            imported_at = imported_at.replace(tzinfo=timezone.utc)
        age_seconds = max(0, int((datetime.now(timezone.utc) - imported_at.astimezone(timezone.utc)).total_seconds())) if imported_at else None
    except (TypeError, ValueError, KeyError):
        imported_at, age_seconds = None, None
    fresh = bool(latest and latest.get("covers_all_invoices") and age_seconds is not None
                 and age_seconds <= int(policy["snapshot_max_age_hours"]) * 3600
                 and imported_at is not None
                 and imported_at <= datetime.now(timezone.utc) + timedelta(minutes=5))
    start_of_month = datetime.combine(today.replace(day=1), day_time.min, tzinfo=local_zone).astimezone(timezone.utc)
    month_events = []
    for event in paid_events:
        try:
            recorded_at = datetime.fromisoformat(str(event["recorded_at"]).replace("Z", "+00:00"))
            if recorded_at.tzinfo is None:
                recorded_at = recorded_at.replace(tzinfo=timezone.utc)
            if recorded_at.astimezone(timezone.utc) >= start_of_month:
                month_events.append(event)
        except (TypeError, ValueError, KeyError):
            continue
    paid_invoice_ids = {str(event["invoice_id"]) for event in month_events if event.get("invoice_id")}

    from settings import settings
    readiness = {
        "complete_invoice_snapshot": fresh,
        "clio_connected": False,
        "gmail_connected": False,
        "ai_enabled": bool(settings.ai_features_enabled and settings.openai_configured),
        "email_sending_enabled": bool(settings.email_send_enabled and settings.gmail_features_enabled),
        "attention_required": len(replies) + len(unresolved_delivery),
    }
    for table, key in (("clio_connections", "clio_connected"), ("gmail_connections", "gmail_connected")):
        try:
            readiness[key] = bool(client.table(table).select("id").eq("firm_id", firm_id).limit(1).execute().data)
        except Exception:
            readiness[key] = False
    return {
        "computed_at": datetime.now(timezone.utc).isoformat(), "timezone": str(local_zone), "local_date": today.isoformat(),
        "firm": {"id": firm_id, "name": firm["name"]},
        "metrics": {
            "outstanding_balance_by_currency": _sum_by_currency(open_invoices),
            "overdue_balance_by_currency": _sum_by_currency(overdue),
            "open_invoice_count": len(open_invoices), "overdue_invoice_count": len(overdue),
            "invoice_review_count": sum(1 for item in open_invoices if item.get("staff_review_status", "pending") == "pending"),
            "draft_review_count": sum(1 for item in runs if item["status"] == "awaiting_review"),
            "approved_not_sent_count": sum(1 for item in runs if item["status"] == "approved_pending_delivery"),
            "reply_review_count": len(replies), "delivery_attention_count": len(unresolved_delivery),
            "invoices_marked_paid_this_month": len(paid_invoice_ids),
        },
        "source": {"latest_snapshot": latest, "snapshot_age_seconds": age_seconds,
                   "snapshot_fresh": fresh, "snapshot_max_age_hours": int(policy["snapshot_max_age_hours"]),
                   "payment_history_note": "Count is invoices newly marked paid in Ledgerly this month from an authoritative unpaid-to-paid source update. It is not a cash-received date or amount. Earlier paid invoices are not backfilled."},
        "readiness": readiness,
        "recent_audit": audit if _firm_access(ctx)["role"] in {"owner", "admin", "reviewer"} else [],
    }


def _sum_by_currency(rows: list[dict[str, Any]]) -> dict[str, str]:
    totals: dict[str, Decimal] = {}
    for row in rows:
        currency = str(row.get("currency") or "USD").strip()
        totals[currency] = totals.get(currency, Decimal("0")) + Decimal(str(row.get("amount_due") or 0))
    return {key: str(value) for key, value in totals.items()}


@app.get("/api/audit-events")
def list_audit_events(limit: int = 50, ctx: dict[str, Any] = Depends(current_session)) -> list[dict[str, Any]]:
    firm_id = _require_role(ctx, "owner", "admin", "reviewer")
    limit = max(1, min(limit, 200))
    try:
        return (admin_client().table("ledgerly_audit_events").select(
            "id,actor_user_id,event_type,target_type,target_id,summary,metadata,created_at"
        ).eq("firm_id", firm_id).order("created_at", desc=True).limit(limit).execute().data)
    except Exception as exc:
        logger.warning("audit_event_list_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not load the audit history. Apply the latest Ledgerly migration.") from exc


@app.get("/api/contacts/suppressions")
def list_contact_suppressions(ctx: dict[str, Any] = Depends(current_session)) -> list[dict[str, Any]]:
    firm_id = _require_role(ctx, "owner", "admin", "reviewer")
    try:
        return (admin_client().table("contact_suppressions").select(
            "id,email,reason,source_reply_id,created_by,created_at"
        ).eq("firm_id", firm_id).order("created_at", desc=True).limit(500).execute().data)
    except Exception as exc:
        logger.warning("suppression_list_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not load the firm's suppression list.") from exc


@app.post("/api/contacts/suppressions/reinstate")
def reinstate_contact_suppression(body: SuppressionReinstateRequest,
                                  ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    firm_id = _require_role(ctx, "owner", "admin")
    try:
        result = ctx["client"].rpc("reinstate_contact_suppression", {
            "p_firm_id": firm_id, "p_email": body.email, "p_reason": body.reason,
        }).execute().data
        return result if isinstance(result, dict) else (result[0] if isinstance(result, list) and result else {})
    except Exception as exc:
        logger.warning("suppression_reinstatement_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not reinstate this address. It remains suppressed until the correction is recorded.") from exc


@app.post("/api/ai/csv-header-map")
def ai_csv_header_map(body: CsvHeaderMapRequest, ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    service = _ai_service()
    proposed = _invoke_ai("csv_header_map", service.suggest_csv_header_map, body.headers)
    mapping = proposed.model_dump()

    # The model may only choose from the exact headers supplied by the caller.
    # Validate this deterministically before returning a suggestion to the UI.
    exact_headers = {" ".join(header.split()).casefold(): header for header in body.headers}
    used: set[str] = set()
    uncertain = {
        " ".join(header.split()).casefold()
        for header in mapping.get("uncertain_headers", [])
        if isinstance(header, str)
    }
    for field in ("invoice_number", "client_name", "client_email", "amount", "amount_due",
                  "currency", "issue_date", "due_date", "status"):
        candidate = mapping.get(field)
        if candidate is None:
            continue
        normalized = " ".join(str(candidate).split()).casefold()
        if normalized not in exact_headers or normalized in used:
            mapping[field] = None
            if normalized in exact_headers:
                uncertain.add(normalized)
            continue
        mapping[field] = exact_headers[normalized]
        used.add(normalized)
    mapping["uncertain_headers"] = [exact_headers[key] for key in body.headers
                                    if " ".join(key.split()).casefold() in uncertain]
    return {"suggestion": mapping, "requires_user_confirmation": True, "imported": False}


@app.post("/api/ai/reply-classification")
def ai_reply_classification(body: ReplyClassificationRequest,
                            ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    _require_role(ctx, "owner", "admin", "reviewer", "sender")
    invoice = _load_invoice_for_ai(ctx, body.invoice_id)
    facts = _invoice_facts(invoice)
    service = _ai_service()
    result = _invoke_ai("reply_classification", service.classify_reply, body.email_text, facts)
    classification = result.model_dump()

    # High-risk reply categories always pause and require a person, regardless
    # of the model's suggested flags. The API does not persist or act on it.
    category = classification["category"]
    classification["pause_followup"] = True
    if category in {"question", "help", "dispute", "payment_claim", "opt_out", "other"}:
        classification["human_review_required"] = True

    # Do not accept a model-provided quotation as evidence unless it is an
    # exact substring of the source email.
    excerpt = classification.get("evidence_excerpt", "")
    if not excerpt or excerpt not in body.email_text:
        classification["evidence_excerpt"] = ""
        classification["human_review_required"] = True

    for field in ("promise_date", "pause_until"):
        value = classification.get(field)
        if value is not None:
            try:
                date.fromisoformat(value)
            except (TypeError, ValueError):
                classification[field] = None
                classification["human_review_required"] = True
    if category == "promise" and not classification.get("promise_date"):
        classification["human_review_required"] = True
    if category == "ooo" and not classification.get("pause_until"):
        classification["human_review_required"] = True

    return {
        "invoice_id": str(body.invoice_id),
        "invoice_number": invoice["invoice_number"],
        "classification": classification,
        "persisted": False,
        "followup_changed": False,
    }


@app.post("/api/ai/reminder-draft")
def ai_reminder_draft(body: ReminderDraftRequest,
                      ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    _require_role(ctx, "owner", "admin", "reviewer", "sender")
    invoice = _load_invoice_for_ai(ctx, body.invoice_id)
    _require_fresh_invoice_snapshot(ctx, invoice)
    if invoice["status"] != "unpaid" or Decimal(str(invoice["amount_due"])) <= 0:
        raise HTTPException(status_code=409, detail="Only an open invoice with a positive balance can be drafted.")
    if invoice.get("staff_review_status", "pending") != "approved":
        raise HTTPException(status_code=409, detail="Approve this invoice record before preparing a client reminder.")
    if not invoice.get("client_email"):
        raise HTTPException(status_code=409, detail="This invoice has no valid client billing email. Review the Clio contact before drafting.")

    firm_id = _firm_id(ctx)
    policy = _firm_policy(firm_id)
    stage_error = _reminder_stage_error(invoice, body.message_type, policy, _firm_local_now(firm_id).date())
    if stage_error:
        raise HTTPException(status_code=409, detail=stage_error)
    if invoice.get("outreach_state") in {"paused", "needs_review", "needs_status_check", "closed"}:
        raise HTTPException(status_code=409, detail="Follow-up is paused or needs human review. Resolve that status before preparing another draft.")

    firm_id = _require_role(ctx, "owner", "admin", "reviewer")
    try:
        firm = (ctx["client"].table("firms").select("name").eq("id", firm_id).single().execute().data)
    except Exception as exc:
        logger.warning("ai_draft_firm_lookup_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not load the firm's display name.") from exc
    facts = _invoice_facts(invoice)
    facts["firm_name"] = firm["name"]
    service = _ai_service()
    draft = _invoke_ai("reminder_draft", service.draft_reminder, facts, body.message_type)
    return {
        "invoice_id": str(invoice["id"]),
        "invoice_number": invoice["invoice_number"],
        "to": invoice["client_email"],
        "message_type": body.message_type,
        "source_updated_at": invoice["source_updated_at"],
        "last_import_id": invoice["last_import_id"],
        "draft": draft.model_dump(mode="json"),
        "requires_human_review": True,
        "sent": False,
    }


def _firm_id(ctx: dict[str, Any]) -> str:
    return _firm_access(ctx)["firm_id"]


def _firm_access(ctx: dict[str, Any]) -> dict[str, str]:
    """Resolve exactly one firm and role from server-trusted owner/member records."""
    cached = ctx.get("_firm_access")
    if cached:
        return cached
    user_id = str(ctx["user"].id)
    try:
        admin = admin_client()
        owned = (admin.table("firms").select("id").eq("owner_user_id", user_id).limit(1).execute().data)
        if owned:
            result = {"firm_id": str(owned[0]["id"]), "role": "owner"}
        else:
            rows = (admin.table("firm_members").select("firm_id,role")
                    .eq("user_id", user_id).eq("status", "active").limit(2).execute().data)
            if not rows:
                raise HTTPException(status_code=404, detail="You are not an active member of a Ledgerly firm.")
            if len(rows) != 1:
                raise HTTPException(status_code=409, detail="This account belongs to more than one firm; contact the firm administrator.")
            result = {"firm_id": str(rows[0]["firm_id"]), "role": str(rows[0]["role"])}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("firm_membership_lookup_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not verify firm membership.") from exc
    ctx["_firm_access"] = result
    return result


def _require_role(ctx: dict[str, Any], *roles: str) -> str:
    access = _firm_access(ctx)
    if access["role"] not in roles:
        raise HTTPException(status_code=403, detail="Your Ledgerly role does not allow this action. Ask a firm admin if you need access.")
    return access["firm_id"]


def _record_audit(firm_id: str, actor_id: str, event_type: str, target_type: str,
                  target_id: str | None, summary: str, metadata: dict[str, Any] | None = None) -> None:
    """Write a compact audit event without logging message or invoice content."""
    try:
        admin_client().table("ledgerly_audit_events").insert({
            "firm_id": firm_id, "actor_user_id": actor_id, "event_type": event_type,
            "target_type": target_type, "target_id": target_id, "summary": summary[:500],
            "metadata": metadata or {},
        }).execute()
    except Exception as exc:
        # External effects and already-committed workflow decisions cannot be
        # rolled back here; their durable workflow/delivery rows remain the
        # reconciliation source if this secondary audit write is unavailable.
        logger.error("audit_event_write_failed event_type=%s error_type=%s", event_type, type(exc).__name__)


def _ai_service():
    """Load optional AI dependencies lazily so the demo API still starts without them."""
    try:
        from settings import settings
    except Exception as exc:
        logger.warning("ai_settings_load_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="AI integration settings are unavailable.") from exc
    if not settings.ai_features_enabled:
        raise HTTPException(status_code=503, detail="AI features are disabled on this backend.")
    if not settings.openai_configured:
        raise HTTPException(status_code=503, detail="OPENAI_API_KEY is not configured on the backend.")
    try:
        import integrations
        return integrations
    except Exception as exc:
        logger.warning("ai_dependencies_missing error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Install backend/requirements.txt to enable AI features.") from exc


def _invoke_ai(operation: str, function, *args):
    try:
        return function(*args)
    except HTTPException:
        raise
    except Exception as exc:
        # Never log prompts, source emails, invoice facts, or model output.
        logger.warning("ai_operation_failed operation=%s error_type=%s", operation, type(exc).__name__)
        raise HTTPException(status_code=502, detail="AI could not return a valid structured result; review the item manually.") from exc


def _load_invoice_for_ai(ctx: dict[str, Any], invoice_id: UUID) -> dict[str, Any]:
    firm_id = _firm_id(ctx)
    try:
        rows = (ctx["client"].table("invoices").select(
            "id,firm_id,invoice_number,client_name,client_email,amount,amount_due,currency,issue_date,due_date,status,staff_review_status,source_updated_at,last_import_id,source_system,clio_bill_id,source_data,first_contacted_on,last_contacted_on,outreach_state"
        ).eq("id", str(invoice_id)).eq("firm_id", firm_id).limit(1).execute().data)
    except Exception as exc:
        logger.warning("ai_invoice_lookup_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not load this invoice.") from exc
    if not rows:
        raise HTTPException(status_code=404, detail="Invoice not found in this firm's workspace.")
    return rows[0]


def _invoice_facts(invoice: dict[str, Any]) -> dict[str, Any]:
    # Only send facts needed for classification/drafting; do not send internal
    # IDs, client email addresses, full source_data, or other invoice columns.
    return {
        "invoice_number": invoice["invoice_number"],
        "client_name": invoice["client_name"],
        "amount_due": str(invoice["amount_due"]),
        "currency": invoice["currency"],
        "due_date": invoice["due_date"],
        "status": invoice["status"],
    }


def _require_fresh_invoice_snapshot(ctx: dict[str, Any], invoice: dict[str, Any]) -> dict[str, Any]:
    firm_id = invoice["firm_id"]
    try:
        imports = (ctx["client"].table("invoice_imports").select("id,imported_at,covers_all_invoices")
                   .eq("firm_id", firm_id).order("imported_at", desc=True).limit(1).execute().data)
    except Exception as exc:
        logger.warning("ai_snapshot_lookup_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not verify the invoice snapshot.") from exc
    if not imports:
        raise HTTPException(status_code=409, detail="Sync Clio or import a complete current invoice CSV before drafting outreach.")
    latest = imports[0]
    imported_at = latest.get("imported_at")
    try:
        timestamp = datetime.fromisoformat(str(imported_at).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise HTTPException(status_code=409, detail="The latest invoice snapshot has an invalid timestamp; sync Clio or re-import the CSV.")
    policy = _firm_policy(firm_id)
    now = datetime.now(timezone.utc)
    if (not latest.get("covers_all_invoices")
            or str(invoice.get("last_import_id")) != str(latest.get("id"))
            or timestamp < now - timedelta(hours=int(policy["snapshot_max_age_hours"]))
            or timestamp > now + timedelta(minutes=5)):
        raise HTTPException(status_code=409, detail=f"Sync Clio or import a complete invoice CSV within the last {int(policy['snapshot_max_age_hours'])} hours before drafting outreach.")
    return latest


def _firm_local_now(firm_id: str) -> datetime:
    try:
        rows = admin_client().table("firms").select("timezone").eq("id", firm_id).limit(1).execute().data
        timezone_name = str(rows[0].get("timezone") or "UTC") if rows else "UTC"
        try:
            zone = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError:
            logger.warning("invalid_firm_timezone firm_id=%s; using UTC", firm_id)
            zone = ZoneInfo("UTC")
        return datetime.now(zone)
    except Exception as exc:
        logger.warning("firm_timezone_read_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not verify the firm's timezone. No reminder action was taken.") from exc


def _reminder_stage_error(invoice: dict[str, Any], message_type: str,
                          policy: dict[str, Any], local_today: date) -> str | None:
    due_date = date.fromisoformat(str(invoice["due_date"]))
    days_overdue = (local_today - due_date).days
    first_contacted = invoice.get("first_contacted_on")
    if message_type == "initial":
        if first_contacted:
            return "An initial reminder is unavailable because outreach is already recorded."
        if days_overdue < int(policy["initial_min_days_overdue"]):
            return f"The invoice is not yet eligible for an initial reminder. Policy requires {int(policy['initial_min_days_overdue'])} day(s) overdue."
    elif not first_contacted:
        return "Record the initial reminder before preparing a follow-up."
    elif message_type == "gentle":
        last_contacted = invoice.get("last_contacted_on") or first_contacted
        try:
            elapsed = (local_today - date.fromisoformat(str(last_contacted))).days
        except ValueError:
            return "The previous reminder date is invalid. Refresh the invoice source before continuing."
        if elapsed < int(policy["gentle_interval_days"]):
            return f"Wait at least {int(policy['gentle_interval_days'])} days after the last reminder before preparing a gentle follow-up."
    elif message_type == "firm" and days_overdue < int(policy["firm_min_days_overdue"]):
        return f"A firm reminder is available only after {int(policy['firm_min_days_overdue'])} days overdue."
    return None


def _workflow_admin() -> Client:
    """Workflow state mutations are server-only; browser JWTs are read-only for this table."""
    return admin_client()


def _get_workflow_run(ctx: dict[str, Any], workflow_run_id: UUID) -> dict[str, Any]:
    firm_id = _firm_id(ctx)
    try:
        rows = (ctx["client"].table("workflow_runs").select("*")
                .eq("id", str(workflow_run_id)).eq("firm_id", firm_id).limit(1).execute().data)
    except Exception as exc:
        logger.warning("workflow_read_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not load the workflow run.") from exc
    if not rows:
        raise HTTPException(status_code=404, detail="Workflow run not found.")
    return rows[0]


def _workflow_public(run: dict[str, Any], invoice: dict[str, Any] | None = None) -> dict[str, Any]:
    draft = run.get("draft") if isinstance(run.get("draft"), dict) else None
    return {
        "workflow_run_id": run["id"],
        "invoice_id": run["invoice_id"],
        "invoice_number": (invoice or {}).get("invoice_number"),
        "to": (invoice or {}).get("client_email"),
        "message_type": run["message_type"],
        "status": run["status"],
        "current_step": run["current_step"],
        "source_snapshot_id": run.get("source_snapshot_id"),
        "source_updated_at": run.get("source_updated_at"),
        "draft": draft,
        "draft_version": run.get("draft_version"),
        "review_decision": run.get("review_decision"),
        "initiated_by": run.get("initiated_by"),
        "reviewed_by": run.get("reviewed_by"),
        "reviewed_at": run.get("reviewed_at"),
        "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"),
        "error_code": run.get("error_code"),
        "error_message": run.get("error_message"),
        "sent": False,
    }


def _read_run_by_idempotency(ctx: dict[str, Any], firm_id: str, idempotency_key: str) -> dict[str, Any] | None:
    try:
        rows = (ctx["client"].table("workflow_runs").select("*")
                .eq("firm_id", firm_id).eq("idempotency_key", idempotency_key).limit(1).execute().data)
        return rows[0] if rows else None
    except Exception as exc:
        logger.warning("workflow_idempotency_lookup_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not check whether this workflow was already started.") from exc


def _workflow_source_timestamp(invoice: dict[str, Any]) -> str | None:
    value = invoice.get("source_updated_at")
    if not value:
        return None
    return str(value)


def _workflow_source_is_current(ctx: dict[str, Any], run: dict[str, Any]) -> bool:
    """Recheck the authoritative invoice and complete snapshot before reuse/delivery eligibility."""
    try:
        invoice = _load_invoice_for_ai(ctx, UUID(run["invoice_id"]))
        latest = _require_fresh_invoice_snapshot(ctx, invoice)
    except HTTPException as exc:
        if exc.status_code in {404, 409}:
            return False
        raise
    return bool(
        str(latest.get("id")) == str(run.get("source_snapshot_id"))
        and _workflow_source_timestamp(invoice) == run.get("source_updated_at")
        and invoice.get("status") == "unpaid"
        and invoice.get("staff_review_status", "pending") == "approved"
        and Decimal(str(invoice.get("amount_due", 0))) > 0
        and invoice.get("outreach_state") not in {"paused", "needs_review", "needs_status_check", "closed"}
    )


@app.post("/api/workflows/reminder-drafts")
def start_reminder_workflow(
    body: ReminderWorkflowStartRequest,
    idempotency_key: str = Header(min_length=8, max_length=128, alias="Idempotency-Key"),
    ctx: dict[str, Any] = Depends(current_session),
) -> dict[str, Any]:
    """Run the fixed LangGraph validation/draft flow and persist its review pause."""
    firm_id = _require_role(ctx, "owner", "admin", "reviewer")
    policy = _firm_policy(firm_id)
    prior = _read_run_by_idempotency(ctx, firm_id, idempotency_key)
    if prior:
        if str(prior.get("invoice_id")) != str(body.invoice_id) or prior.get("message_type") != body.message_type:
            raise HTTPException(status_code=409, detail="This idempotency key was already used for a different invoice or reminder stage.")
        invoice = None
        try:
            invoice = _load_invoice_for_ai(ctx, body.invoice_id)
        except HTTPException:
            pass
        return _workflow_public(prior, invoice)

    # A second tab/request should reuse an existing pending draft instead of
    # producing competing approvals for the same invoice.
    try:
        active = (ctx["client"].table("workflow_runs").select("*")
                  .eq("firm_id", firm_id).eq("invoice_id", str(body.invoice_id))
                  .in_("status", ["running", "awaiting_review"])
                  .order("updated_at", desc=True).limit(1).execute().data)
    except Exception as exc:
        logger.warning("workflow_active_lookup_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not check for an existing draft review.") from exc
    if active:
        existing = active[0]
        if existing.get("message_type") != body.message_type:
            raise HTTPException(status_code=409, detail="A draft for this invoice is already active at a different reminder stage. Open or discard it before starting another.")
        try:
            updated_at = datetime.fromisoformat(str(existing["updated_at"]).replace("Z", "+00:00"))
            if updated_at.tzinfo is None:
                updated_at = updated_at.replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError):
            updated_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        if existing["status"] == "awaiting_review" or updated_at > datetime.now(timezone.utc) - timedelta(minutes=5):
            invoice = None
            try:
                invoice = _load_invoice_for_ai(ctx, body.invoice_id)
            except HTTPException:
                pass
            return _workflow_public(existing, invoice)
        try:
            (_workflow_admin().table("workflow_runs").update({
                "status": "failed", "current_step": "complete", "error_code": "workflow_interrupted",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", existing["id"]).eq("firm_id", firm_id).eq("status", "running").execute())
        except Exception as exc:
            logger.warning("workflow_interrupted_run_close_failed error_type=%s", type(exc).__name__)
            raise HTTPException(status_code=503, detail="A previous workflow is still being recovered. Try again shortly.") from exc

    try:
        approved = (ctx["client"].table("workflow_runs").select("*")
                    .eq("firm_id", firm_id).eq("invoice_id", str(body.invoice_id))
                    .eq("status", "approved_pending_delivery")
                    .order("updated_at", desc=True).limit(1).execute().data)
    except Exception as exc:
        logger.warning("workflow_approved_lookup_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not check for an existing approved draft.") from exc
    if approved:
        existing = approved[0]
        if _workflow_source_is_current(ctx, existing):
            invoice = _load_invoice_for_ai(ctx, body.invoice_id)
            return _workflow_public(existing, invoice)
        try:
            (_workflow_admin().table("workflow_runs").update({
                "status": "stale", "current_step": "complete", "error_code": "source_changed",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", existing["id"]).eq("firm_id", firm_id)
              .eq("status", "approved_pending_delivery").execute())
        except Exception as exc:
            logger.warning("workflow_old_approval_stale_failed error_type=%s", type(exc).__name__)
            raise HTTPException(status_code=503, detail="The invoice changed, but the previous approval could not be invalidated.") from exc

    user_id = str(ctx["user"].id)
    try:
        created = (_workflow_admin().table("workflow_runs").insert({
            "firm_id": firm_id,
            "invoice_id": str(body.invoice_id),
            "initiated_by": user_id,
            "idempotency_key": idempotency_key,
            "message_type": body.message_type,
            "status": "running",
            "current_step": "eligibility_check",
        }).execute().data)
    except Exception as exc:
        # Handle a concurrent request that won the partial unique/idempotency race.
        prior = _read_run_by_idempotency(ctx, firm_id, idempotency_key)
        if prior:
            return _workflow_public(prior)
        try:
            raced = (ctx["client"].table("workflow_runs").select("*")
                     .eq("firm_id", firm_id).eq("invoice_id", str(body.invoice_id))
                     .in_("status", ["running", "awaiting_review"])
                     .order("updated_at", desc=True).limit(1).execute().data)
        except Exception:
            raced = []
        if raced:
            return _workflow_public(raced[0])
        logger.warning("workflow_run_create_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not create a durable workflow run. Check the workflow migration and backend Supabase key.") from exc
    if not created:
        raise HTTPException(status_code=503, detail="Could not create a durable workflow run.")
    run = created[0]

    try:
        from workflow_graph import WorkflowGuardrailError, run_reminder_workflow

        def validate(state: dict[str, Any]) -> dict[str, Any]:
            try:
                invoice = _load_invoice_for_ai(ctx, UUID(state["invoice_id"]))
            except HTTPException as exc:
                if exc.status_code == 404:
                    raise WorkflowGuardrailError("invoice_not_found", "This invoice is no longer available in the firm's workspace.") from exc
                raise
            try:
                latest = _require_fresh_invoice_snapshot(ctx, invoice)
            except HTTPException as exc:
                if exc.status_code == 409:
                    raise WorkflowGuardrailError("snapshot_stale", str(exc.detail)) from exc
                raise
            if invoice["status"] != "unpaid" or Decimal(str(invoice["amount_due"])) <= 0:
                raise WorkflowGuardrailError("invoice_closed", "Only an open invoice with a positive balance can be drafted.")
            if invoice.get("staff_review_status", "pending") != "approved":
                raise WorkflowGuardrailError("invoice_not_approved", "Approve this invoice record before preparing a client reminder.")
            if not invoice.get("client_email"):
                raise WorkflowGuardrailError("missing_recipient", "This invoice has no valid client billing email. Review the Clio contact before drafting.")
            if invoice.get("outreach_state") in {"paused", "needs_review", "needs_status_check", "closed"}:
                raise WorkflowGuardrailError("outreach_paused", "Follow-up is paused or needs human review. Resolve that status before preparing another draft.")
            try:
                deliveries = (_workflow_admin().table("workflow_deliveries").select("workflow_run_id,status")
                              .eq("firm_id", firm_id).eq("invoice_id", str(invoice["id"]))
                              .in_("status", ["sending", "delivery_unknown"]).limit(10).execute().data)
            except Exception as exc:
                logger.warning("workflow_delivery_guard_failed error_type=%s", type(exc).__name__)
                raise WorkflowGuardrailError("delivery_state_unavailable", "Could not verify an earlier email delivery. Refresh status before drafting again.") from exc
            if deliveries:
                raise WorkflowGuardrailError("delivery_needs_reconciliation", "A prior email may be sending or needs delivery reconciliation. Check Gmail before preparing another reminder.")
            if body.message_type == "initial":
                try:
                    sent_initial = (_workflow_admin().table("workflow_runs").select("id")
                                    .eq("firm_id", firm_id).eq("invoice_id", str(invoice["id"]))
                                    .eq("message_type", "initial").eq("status", "sent").limit(1).execute().data)
                except Exception as exc:
                    logger.warning("workflow_initial_delivery_guard_failed error_type=%s", type(exc).__name__)
                    raise WorkflowGuardrailError("delivery_state_unavailable", "Could not verify an earlier sent reminder. Refresh status before drafting again.") from exc
                if sent_initial:
                    raise WorkflowGuardrailError("initial_already_recorded", "An initial reminder was already sent from Ledgerly.")
            today = _firm_local_now(firm_id).date()
            first_contacted = invoice.get("first_contacted_on")
            stage_error = _reminder_stage_error(invoice, body.message_type, policy, today)
            if stage_error:
                code = "initial_already_recorded" if first_contacted and body.message_type == "initial" else (
                    "initial_required" if not first_contacted and body.message_type in {"gentle", "firm"} else
                    "firm_too_early" if body.message_type == "firm" else "reminder_stage_not_eligible")
                raise WorkflowGuardrailError(code, stage_error)
            try:
                firm = (ctx["client"].table("firms").select("name").eq("id", firm_id).single().execute().data)
            except Exception as exc:
                logger.warning("workflow_firm_lookup_failed error_type=%s", type(exc).__name__)
                raise WorkflowGuardrailError("firm_lookup_failed", "Could not load the firm's display name.") from exc
            return {
                "invoice": invoice,
                "firm_name": firm["name"],
                "source_snapshot_id": str(latest["id"]),
                "source_updated_at": _workflow_source_timestamp(invoice),
                "invoice_number": invoice["invoice_number"],
                "recipient": invoice["client_email"],
            }

        def prepare(state: dict[str, Any]) -> dict[str, Any]:
            try:
                service = _ai_service()
                facts = _invoice_facts(state["invoice"])
                facts["firm_name"] = state["firm_name"]
                draft = _invoke_ai("reminder_draft", service.draft_reminder, facts, body.message_type)
                return {"draft": draft.model_dump(mode="json")}
            except HTTPException as exc:
                raise WorkflowGuardrailError("ai_unavailable", str(exc.detail)) from exc

        result = run_reminder_workflow(
            {
                "invoice_id": str(body.invoice_id),
                "message_type": body.message_type,
                "status": "running",
                "current_step": "eligibility_check",
            },
            validate,
            prepare,
        )
        draft = result.get("draft") if result.get("status") == "awaiting_review" else None
        draft_version = hashlib.sha256(json.dumps(draft, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest() if draft else None
        update = {
            "status": result.get("status", "failed"),
            "current_step": result.get("current_step", "complete"),
            "source_snapshot_id": result.get("source_snapshot_id"),
            "source_updated_at": result.get("source_updated_at"),
            "draft": draft,
            "draft_version": draft_version,
            "error_code": result.get("error_code"),
            "error_message": result.get("error_message"),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        saved = (_workflow_admin().table("workflow_runs").update(update)
                 .eq("id", run["id"]).eq("firm_id", firm_id).eq("status", "running").execute().data)
        persisted = saved[0] if saved else _get_workflow_run(ctx, UUID(run["id"]))
        invoice = result.get("invoice")
        if persisted.get("status") == "awaiting_review":
            _record_audit(firm_id, user_id, "reminder_draft_prepared", "workflow_run", str(run["id"]),
                          "Reminder draft prepared and paused for human review.",
                          {"invoice_id": str(body.invoice_id), "message_type": body.message_type})
        return _workflow_public(persisted, invoice)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("workflow_execution_failed run_id=%s error_type=%s", run["id"], type(exc).__name__)
        try:
            saved = (_workflow_admin().table("workflow_runs").update({
                "status": "failed", "current_step": "complete", "error_code": "workflow_execution_failed",
                "error_message": "The workflow could not complete. No message was sent; review the invoice and try again.",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", run["id"]).eq("firm_id", firm_id).eq("status", "running").execute().data)
            failed = saved[0] if saved else _get_workflow_run(ctx, UUID(run["id"]))
            return _workflow_public(failed)
        except Exception as save_exc:
            logger.error("workflow_failure_state_persist_failed run_id=%s error_type=%s", run["id"], type(save_exc).__name__)
            raise HTTPException(status_code=503, detail="The workflow stopped unexpectedly and its status could not be saved. Contact support with the request ID.") from exc


@app.get("/api/workflows/reminder-drafts")
def list_reminder_workflows(ctx: dict[str, Any] = Depends(current_session)) -> list[dict[str, Any]]:
    firm_id = _firm_id(ctx)
    try:
        rows = (ctx["client"].table("workflow_runs").select("*").eq("firm_id", firm_id)
                .in_("status", ["running", "awaiting_review", "approved_pending_delivery"])
                .order("updated_at", desc=True).limit(100).execute().data)
        result = []
        for row in rows:
            if row["status"] == "approved_pending_delivery" and not _workflow_source_is_current(ctx, row):
                try:
                    saved = (_workflow_admin().table("workflow_runs").update({
                        "status": "stale", "current_step": "complete", "error_code": "source_changed",
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    }).eq("id", row["id"]).eq("firm_id", firm_id)
                      .eq("status", "approved_pending_delivery").execute().data)
                    if saved:
                        row = saved[0]
                    continue
                except Exception as exc:
                    logger.warning("workflow_list_stale_transition_failed error_type=%s", type(exc).__name__)
                    continue
            result.append(_workflow_public(row))
        return result
    except Exception as exc:
        logger.warning("workflow_list_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not load draft workflow status.") from exc


@app.get("/api/workflows/reminder-drafts/{workflow_run_id}")
def get_reminder_workflow(workflow_run_id: UUID, ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    run = _get_workflow_run(ctx, workflow_run_id)
    invoice = None
    try:
        invoice = _load_invoice_for_ai(ctx, UUID(run["invoice_id"]))
    except HTTPException:
        pass
    return _workflow_public(run, invoice)


@app.post("/api/workflows/reminder-drafts/{workflow_run_id}/review")
def review_reminder_workflow(
    workflow_run_id: UUID,
    body: ReminderWorkflowReviewRequest,
    ctx: dict[str, Any] = Depends(current_session),
) -> dict[str, Any]:
    firm_id = _require_role(ctx, "owner", "admin", "reviewer")
    run = _get_workflow_run(ctx, workflow_run_id)
    if run["status"] != "awaiting_review":
        # An identical retry after a successful review is safe and returns the
        # persisted result; conflicting decisions never overwrite that result.
        if run.get("review_decision") == body.decision and run.get("reviewed_by") == str(ctx["user"].id):
            invoice = None
            try:
                invoice = _load_invoice_for_ai(ctx, UUID(run["invoice_id"]))
            except HTTPException:
                pass
            return _workflow_public(run, invoice)
        raise HTTPException(status_code=409, detail="This draft is no longer waiting for review. Refresh the workflow status.")
    if not run.get("draft_version") or not secrets.compare_digest(str(run["draft_version"]), body.draft_version):
        raise HTTPException(status_code=409, detail="This draft changed after it was opened. Refresh it before reviewing.")

    try:
        from workflow_graph import run_review_transition
        transitioned = run_review_transition(str(workflow_run_id), body.decision)
    except Exception as exc:
        logger.warning("workflow_review_graph_failed run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not advance this workflow review. The draft remains unsent.") from exc

    update: dict[str, Any] = {
        "status": transitioned["status"],
        "current_step": transitioned["current_step"],
        "review_decision": body.decision,
        "reviewed_by": str(ctx["user"].id),
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "error_code": None,
        "error_message": None,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    invoice = None
    if body.decision == "approve":
        try:
            invoice = _load_invoice_for_ai(ctx, UUID(run["invoice_id"]))
            latest = _require_fresh_invoice_snapshot(ctx, invoice)
            if (str(latest.get("id")) != str(run.get("source_snapshot_id"))
                    or _workflow_source_timestamp(invoice) != run.get("source_updated_at")):
                raise WorkflowSnapshotChanged()
            if (invoice["status"] != "unpaid" or Decimal(str(invoice["amount_due"])) <= 0
                    or invoice.get("staff_review_status", "pending") != "approved"):
                raise WorkflowSnapshotChanged()
            if invoice.get("outreach_state") in {"paused", "needs_review", "needs_status_check", "closed"}:
                raise WorkflowSnapshotChanged()
        except WorkflowSnapshotChanged:
            update.update({
                "status": "stale", "current_step": "complete", "error_code": "source_changed",
                "review_decision": None, "reviewed_by": None, "reviewed_at": None,
            })
            try:
                saved = (_workflow_admin().table("workflow_runs").update(update)
                         .eq("id", str(workflow_run_id)).eq("firm_id", firm_id)
                         .eq("status", "awaiting_review").execute().data)
            except Exception as exc:
                logger.warning("workflow_stale_persist_failed error_type=%s", type(exc).__name__)
                raise HTTPException(status_code=503, detail="The invoice changed, but the workflow could not record its stale status.") from exc
            return _workflow_public(saved[0] if saved else _get_workflow_run(ctx, workflow_run_id), invoice)
        except HTTPException as exc:
            if exc.status_code in {404, 409}:
                update.update({
                    "status": "stale", "current_step": "complete", "error_code": "source_changed",
                    "review_decision": None, "reviewed_by": None, "reviewed_at": None,
                })
                try:
                    saved = (_workflow_admin().table("workflow_runs").update(update)
                             .eq("id", str(workflow_run_id)).eq("firm_id", firm_id)
                             .eq("status", "awaiting_review").execute().data)
                except Exception as save_exc:
                    logger.warning("workflow_stale_persist_failed error_type=%s", type(save_exc).__name__)
                    raise HTTPException(status_code=503, detail="The invoice source is stale. Refresh it before reviewing this draft.") from save_exc
                return _workflow_public(saved[0] if saved else _get_workflow_run(ctx, workflow_run_id), invoice)
            raise
        update.update({
            "draft": {"subject": body.subject, "body": body.body},
            "draft_version": hashlib.sha256(json.dumps(
                {"subject": body.subject, "body": body.body}, sort_keys=True, ensure_ascii=False
            ).encode("utf-8")).hexdigest(),
        })
    else:
        pass

    try:
        saved = (_workflow_admin().table("workflow_runs").update(update)
                 .eq("id", str(workflow_run_id)).eq("firm_id", firm_id)
                 .eq("status", "awaiting_review").eq("draft_version", body.draft_version).execute().data)
    except Exception as exc:
        logger.warning("workflow_review_persist_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not save the review decision. The draft remains unsent.") from exc
    if not saved:
        latest = _get_workflow_run(ctx, workflow_run_id)
        if latest.get("review_decision") == body.decision and latest.get("reviewed_by") == str(ctx["user"].id):
            return _workflow_public(latest, invoice)
        raise HTTPException(status_code=409, detail="The draft was reviewed in another session. Refresh its status.")
    _record_audit(firm_id, str(ctx["user"].id), f"reminder_draft_{body.decision}", "workflow_run",
                  str(workflow_run_id), "Reminder draft review decision recorded.",
                  {"invoice_id": str(run["invoice_id"]), "draft_version": body.draft_version})
    return _workflow_public(saved[0], invoice)


class WorkflowSnapshotChanged(Exception):
    """Invoice data or its complete source snapshot changed after drafting."""


def _rpc(ctx: dict[str, Any], name: str, args: dict[str, Any]) -> Any:
    # Firm scope is always resolved from the authenticated identity.
    args["p_firm_id"] = _firm_id(ctx)
    try:
        result = ctx["client"].rpc(name, args).execute()
        return result.data
    except Exception as exc:
        logger.warning("supabase_rpc_failed operation=%s error_type=%s", name, type(exc).__name__)
        raise HTTPException(status_code=502, detail="The invoice operation could not be completed.") from exc


@app.post("/api/cloud/imports")
def import_invoices(body: ImportRequest, idempotency_key: str = Header(min_length=8, max_length=128, alias="Idempotency-Key"),
                    ctx: dict[str, Any] = Depends(current_session)) -> Any:
    _require_role(ctx, "owner", "admin")
    rows = [row.model_dump(mode="json") for row in body.rows]
    return _rpc(ctx, "import_invoice_csv_idempotent", {
        "p_file_name": body.file_name.strip(), "p_rows": rows,
        "p_idempotency_key": idempotency_key,
    })


@app.post("/api/cloud/outreach")
def record_outreach(ctx: dict[str, Any] = Depends(current_session)) -> Any:
    raise HTTPException(status_code=410, detail="Simulated outreach has been retired. Create, approve, and explicitly send a reminder through the LangGraph workflow.")


@app.post("/api/cloud/replies")
def save_reply(ctx: dict[str, Any] = Depends(current_session)) -> Any:
    raise HTTPException(status_code=410, detail="Simulated replies have been retired. Sync real replies from the connected Gmail threads and resolve them in the review queue.")


@app.post("/api/cloud/resume")
def resume_outreach(body: InvoiceActionRequest, ctx: dict[str, Any] = Depends(current_session)) -> Any:
    _require_role(ctx, "owner", "admin", "reviewer")
    return _rpc(ctx, "resume_invoice_outreach", {
        "p_invoice_id": str(body.invoice_id), "p_action_key": body.action_key,
    })


@app.post("/api/cloud/automation/enable")
def enable_automation(ctx: dict[str, Any] = Depends(current_session)) -> Any:
    raise HTTPException(status_code=409, detail="Automatic scheduling is disabled by firm policy. Only manually approved reminders may be sent.")


# Actual delivery is a separate, explicit user action after the persisted
# approval. It never creates or edits a Bill or billable Activity.
def _gmail_service():
    from settings import settings
    if not settings.gmail_features_enabled:
        raise HTTPException(status_code=503, detail="Gmail integration is disabled. Set GMAIL_FEATURES_ENABLED=true after setup.")
    if not settings.gmail_oauth_configured:
        raise HTTPException(status_code=503, detail="Complete Google OAuth, token-encryption, and Supabase server-key settings first.")
    try:
        import gmail_integration
        return gmail_integration
    except Exception as exc:
        logger.warning("gmail_dependencies_missing error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Install backend/requirements.txt to enable Gmail integration.") from exc


@app.post("/api/integrations/gmail/authorize")
def gmail_authorize(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, str]:
    service = _gmail_service()
    admin = admin_client()
    firm_id = _require_role(ctx, "owner", "admin")
    state = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    try:
        admin.table("gmail_oauth_states").delete().lt("expires_at", now.isoformat()).execute()
        admin.table("gmail_oauth_states").insert({
            "state_hash": hashlib.sha256(state.encode()).hexdigest(),
            "firm_id": firm_id, "initiated_by": str(ctx["user"].id),
            "expires_at": (now + timedelta(minutes=10)).isoformat(),
        }).execute()
    except Exception as exc:
        logger.warning("gmail_oauth_state_create_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not securely start Google authorization.") from exc
    return {"authorization_url": service.authorization_url(state)}


def _consume_gmail_state(admin: Client, raw_state: str) -> dict[str, Any] | None:
    if not raw_state or len(raw_state) > 256:
        return None
    digest = hashlib.sha256(raw_state.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    try:
        rows = (admin.table("gmail_oauth_states").update({"consumed_at": now.isoformat()})
                .eq("state_hash", digest).is_("consumed_at", "null")
                .gt("expires_at", now.isoformat()).execute().data)
        return rows[0] if rows else None
    except Exception as exc:
        logger.warning("gmail_oauth_state_consume_failed error_type=%s", type(exc).__name__)
        return None


def _gmail_callback_page(success: bool, message: str = "") -> HTMLResponse:
    title = "Gmail connected" if success else "Gmail connection failed"
    safe_message = (message or "You can close this window and return to Ledgerly.")
    return HTMLResponse(
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
        f"<title>{title}</title></head><body style='font:16px system-ui;max-width:560px;margin:12vh auto;padding:24px'>"
        f"<h1>{title}</h1><p>{safe_message}</p><p>You can close this window and return to Ledgerly.</p></body></html>",
        status_code=200 if success else 400,
    )


@app.get("/api/integrations/gmail/callback", response_class=HTMLResponse)
def gmail_callback(code: str | None = None, state: str | None = None,
                   error: str | None = None) -> HTMLResponse:
    service = _gmail_service()
    admin = admin_client()
    oauth_state = _consume_gmail_state(admin, state or "")
    if not oauth_state:
        return _gmail_callback_page(False, "The authorization request expired or could not be verified. Start again from Ledgerly.")
    if error or not code:
        return _gmail_callback_page(False, "Google authorization was declined or incomplete.")
    try:
        token = service.exchange_code(code)
        refresh = token.get("refresh_token")
        if not refresh:
            # OAuth may omit a refresh token if user consent was previously granted.
            old = (admin.table("gmail_connections").select("encrypted_refresh_token")
                   .eq("firm_id", oauth_state["firm_id"]).limit(1).execute().data)
            refresh = service.decrypt_token(old[0]["encrypted_refresh_token"]) if old else None
        if not refresh:
            return _gmail_callback_page(False, "Google did not issue a refresh token. Revoke the existing Ledgerly grant in Google Account permissions, then reconnect.")
        access = token["access_token"]
        profile = service.profile(access)
        expires = max(60, min(int(token.get("expires_in", 3600)), 86400))
        now = datetime.now(timezone.utc)
        admin.table("gmail_connections").upsert({
            "firm_id": oauth_state["firm_id"], "email_address": profile["email"],
            "encrypted_access_token": service.encrypt_token(access),
            "encrypted_refresh_token": service.encrypt_token(refresh),
            "access_token_expires_at": (now + timedelta(seconds=expires)).isoformat(),
            "connected_by": oauth_state["initiated_by"], "connected_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }, on_conflict="firm_id").execute()
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("gmail_oauth_callback_failed error_type=%s", type(exc).__name__)
        return _gmail_callback_page(False, "Gmail could not be connected. Check the OAuth client, exact callback URL, Gmail API enablement, and requested scopes.")
    return _gmail_callback_page(True)


@app.get("/api/integrations/gmail/status")
def gmail_connection_status(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    _gmail_service()
    try:
        rows = (admin_client().table("gmail_connections").select("email_address,connected_at,updated_at")
                .eq("firm_id", _firm_id(ctx)).limit(1).execute().data)
    except Exception as exc:
        logger.warning("gmail_status_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not load Gmail connection status.") from exc
    return {"connected": bool(rows), **(rows[0] if rows else {})}


def _fresh_access_token(admin: Client, table: str, firm_id: str, service) -> tuple[dict[str, Any], str]:
    rows = admin.table(table).select("*").eq("firm_id", firm_id).limit(1).execute().data
    if not rows:
        raise HTTPException(status_code=409, detail="Connect the required integration before sending.")
    connection = rows[0]
    now = datetime.now(timezone.utc)
    access = service.decrypt_token(connection["encrypted_access_token"])
    refresh = service.decrypt_token(connection["encrypted_refresh_token"])
    expiry = datetime.fromisoformat(str(connection["access_token_expires_at"]).replace("Z", "+00:00"))
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= now + timedelta(minutes=5):
        refreshed = service.refresh_tokens(refresh) if table == "clio_connections" else service.refresh_access_token(refresh)
        access = refreshed["access_token"]
        refresh = refreshed.get("refresh_token") or refresh
        duration = max(60, min(int(refreshed.get("expires_in", 3600)), 31536000))
        connection["access_token_expires_at"] = (now + timedelta(seconds=duration)).isoformat()
        connection["encrypted_access_token"] = service.encrypt_token(access)
        connection["encrypted_refresh_token"] = service.encrypt_token(refresh)
        admin.table(table).update({
            "encrypted_access_token": connection["encrypted_access_token"],
            "encrypted_refresh_token": connection["encrypted_refresh_token"],
            "access_token_expires_at": connection["access_token_expires_at"],
            "updated_at": now.isoformat(),
        }).eq("firm_id", firm_id).execute()
    return connection, access


@app.post("/api/workflows/reminder-drafts/{workflow_run_id}/send")
def send_approved_reminder(workflow_run_id: UUID,
                           ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    """Explicitly send one approved draft once; then log it in Clio Communications."""
    from settings import settings
    service = _gmail_service()
    if not settings.email_send_enabled:
        raise HTTPException(status_code=503, detail="Email delivery is disabled. Set EMAIL_SEND_ENABLED=true only when you are ready to send reviewed messages.")
    firm_id = _require_role(ctx, "owner", "admin", "sender")
    policy = _firm_policy(firm_id)
    run = _get_workflow_run(ctx, workflow_run_id)
    if run["status"] == "sent":
        rows = (admin_client().table("workflow_deliveries").select("status,clio_log_status,clio_activity_status,clio_activity_id,sent_at")
                .eq("workflow_run_id", str(workflow_run_id)).limit(1).execute().data)
        return {"workflow_run_id": str(workflow_run_id), "status": "sent", "duplicate_request": True,
                **(rows[0] if rows else {})}
    if run["status"] != "approved_pending_delivery" or run.get("review_decision") != "approve":
        raise HTTPException(status_code=409, detail="Only a currently approved reminder can be sent.")
    try:
        from workflow_graph import run_delivery_authorization_transition
        delivery_transition = run_delivery_authorization_transition(
            str(workflow_run_id), run["status"], run.get("review_decision"), human_send_click=True
        )
    except Exception as exc:
        logger.warning("workflow_delivery_gate_failed run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
        raise HTTPException(status_code=409, detail="The workflow could not authorize delivery. The message remains unsent.") from exc
    if policy.get("manual_send_required") is not True:
        raise HTTPException(status_code=503, detail="Firm policy is invalid: manual human sending must remain enabled.")
    if policy.get("require_distinct_approver_sender") and run.get("reviewed_by") == str(ctx["user"].id):
        raise HTTPException(status_code=403, detail="Firm policy requires a different authorized person to send than the person who approved this message.")
    local_now = _firm_local_now(firm_id)
    start_time = day_time.fromisoformat(str(policy["send_window_start"]))
    end_time = day_time.fromisoformat(str(policy["send_window_end"]))
    if (policy.get("weekdays_only") and local_now.weekday() >= 5) or not (start_time <= local_now.time().replace(tzinfo=None) < end_time):
        raise HTTPException(status_code=409, detail=f"Sending is allowed only between {start_time.strftime('%H:%M')} and {end_time.strftime('%H:%M')} firm local time{', Monday–Friday' if policy.get('weekdays_only') else ''}.")
    if not run.get("draft") or not run.get("draft_version"):
        raise HTTPException(status_code=409, detail="The approved message is incomplete; review it again.")
    if not _workflow_source_is_current(ctx, run):
        try:
            _workflow_admin().table("workflow_runs").update({
                "status": "stale", "current_step": "complete", "error_code": "source_changed",
                "error_message": "Invoice status or source snapshot changed after approval.",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", str(workflow_run_id)).eq("firm_id", firm_id).eq("status", "approved_pending_delivery").execute()
        except Exception:
            pass
        raise HTTPException(status_code=409, detail="Invoice data changed after approval. Sync Clio and review a fresh draft.")

    invoice = _load_invoice_for_ai(ctx, UUID(run["invoice_id"]))
    stage_error = _reminder_stage_error(invoice, run["message_type"], policy, local_now.date())
    if stage_error:
        raise HTTPException(status_code=409, detail=f"Firm policy changed or this reminder is no longer eligible: {stage_error}")
    if not invoice.get("client_email") or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", invoice["client_email"]):
        raise HTTPException(status_code=409, detail="The invoice has no valid billing email address.")
    admin = admin_client()
    try:
        opt_out = (admin.table("gmail_reply_intake").select("id")
                   .eq("firm_id", firm_id).eq("sender_email", invoice["client_email"].strip().lower())
                   .eq("category", "opt_out").in_("status", ["needs_review", "resolving"]).limit(1).execute().data)
        suppression = (admin.table("contact_suppressions").select("id")
                       .eq("firm_id", firm_id).eq("email", invoice["client_email"].strip().lower())
                       .limit(1).execute().data)
    except Exception as exc:
        logger.warning("delivery_opt_out_check_failed run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
        raise HTTPException(status_code=503, detail="Could not verify prior opt-out replies. No email was sent.") from exc
    if opt_out or suppression:
        raise HTTPException(status_code=409, detail="This contact may have opted out or has a confirmed suppression. Staff must resolve the reply before sending any message to this address.")
    existing = (admin.table("workflow_deliveries").select("status,clio_log_status,sent_at")
                .eq("workflow_run_id", str(workflow_run_id)).limit(1).execute().data)
    if existing:
        # Sending, sent, or ambiguous delivery is never automatically retried.
        raise HTTPException(status_code=409, detail=f"Delivery already has status '{existing[0]['status']}'. Refresh status; uncertain sends require manual Gmail reconciliation.")

    gmail = _gmail_service()
    clio = _clio_service()
    now = datetime.now(timezone.utc)
    try:
        gmail_connection, gmail_token = _fresh_access_token(admin, "gmail_connections", firm_id, gmail)
        clio_connection, clio_token = _fresh_access_token(admin, "clio_connections", firm_id, clio)
        contact_id = clio.find_contact_id(clio_token, invoice["client_email"])
        if not contact_id:
            raise HTTPException(status_code=409, detail="Clio did not return exactly one contact matching the billing email. Resolve the contact before sending.")
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("delivery_preflight_failed run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not verify Gmail and Clio are ready. No email was sent.") from exc

    claim = {
        "firm_id": firm_id, "workflow_run_id": str(workflow_run_id), "invoice_id": str(run["invoice_id"]),
        "status": "sending", "recipient": invoice["client_email"], "updated_at": now.isoformat(),
        "approved_by": run.get("reviewed_by"), "sent_by": str(ctx["user"].id),
    }
    try:
        admin.table("workflow_deliveries").insert(claim).execute()
        claimed = (_workflow_admin().table("workflow_runs").update({
            "status": delivery_transition["status"], "current_step": delivery_transition["current_step"], "updated_at": now.isoformat(),
        }).eq("id", str(workflow_run_id)).eq("firm_id", firm_id)
          .eq("status", "approved_pending_delivery").execute().data)
        if not claimed:
            admin.table("workflow_deliveries").update({"status": "failed", "error_code": "approval_changed",
                    "error_phase": "pre_send", "updated_at": now.isoformat()}).eq("workflow_run_id", str(workflow_run_id)).execute()
            raise HTTPException(status_code=409, detail="Approval changed before sending. No email was sent.")
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("delivery_claim_failed run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
        raise HTTPException(status_code=409, detail="Could not safely claim this delivery. Refresh before trying again.") from exc

    try:
        sent = gmail.send_email(gmail_token, invoice["client_email"], run["draft"]["subject"], run["draft"]["body"])
    except Exception as exc:
        # A timeout may occur after Gmail accepted the message. Treat it as
        # ambiguous and never auto-retry, preventing duplicate client email.
        logger.warning("gmail_send_result_unknown run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
        at = datetime.now(timezone.utc).isoformat()
        admin.table("workflow_deliveries").update({"status": "delivery_unknown", "error_code": "gmail_result_unknown",
                "error_phase": "send_unknown", "updated_at": at}).eq("workflow_run_id", str(workflow_run_id)).execute()
        _workflow_admin().table("workflow_runs").update({"status": "delivery_unknown", "current_step": "complete",
                "error_code": "delivery_unknown", "error_message": "Gmail did not confirm the result. Check the mailbox before any retry.",
                "updated_at": at}).eq("id", str(workflow_run_id)).eq("firm_id", firm_id).execute()
        raise HTTPException(status_code=502, detail="Gmail did not confirm delivery. Check Sent mail before taking action; Ledgerly will not retry automatically.") from exc

    sent_at = datetime.now(timezone.utc).isoformat()
    admin.table("workflow_deliveries").update({"status": "sent", "gmail_message_id": sent["message_id"],
            "gmail_thread_id": sent["thread_id"], "sent_at": sent_at, "updated_at": sent_at
            }).eq("workflow_run_id", str(workflow_run_id)).execute()
    _workflow_admin().table("workflow_runs").update({"status": "sent", "current_step": "complete",
            "error_code": None, "error_message": None, "updated_at": sent_at
            }).eq("id", str(workflow_run_id)).eq("firm_id", firm_id).execute()

    invoice_state_recorded = False
    try:
        recorded = _rpc(ctx, "record_email_delivery", {
            "p_invoice_id": str(run["invoice_id"]), "p_workflow_run_id": str(workflow_run_id),
            "p_message_type": run["message_type"], "p_sent_at": sent_at,
        })
        invoice_state_recorded = isinstance(recorded, dict) and recorded.get("ok") is True
    except Exception as exc:
        logger.warning("sent_email_invoice_state_record_failed run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
    admin.table("workflow_deliveries").update({"invoice_state_recorded": invoice_state_recorded,
            "updated_at": datetime.now(timezone.utc).isoformat()
            }).eq("workflow_run_id", str(workflow_run_id)).execute()

    clio_log_status = "failed"
    communication_id = None
    try:
        communication_id = clio.record_sent_email(
            clio_token, sender_user_id=str(clio_connection["clio_user_id"]),
            recipient_contact_id=contact_id, subject=run["draft"]["subject"],
            body=run["draft"]["body"], sent_at=sent_at,
            matter_id=((invoice.get("source_data") or {}).get("clio_matter_id")
                       if isinstance(invoice.get("source_data"), dict) else None),
        )
        clio_log_status = "logged"
    except Exception as exc:
        # Mail is already sent; never resend to recover a Clio logging failure.
        logger.warning("clio_communication_log_failed run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
    admin.table("workflow_deliveries").update({"clio_log_status": clio_log_status,
            "clio_communication_id": communication_id, "error_code": None if clio_log_status == "logged" else "clio_log_failed",
            "error_phase": None if clio_log_status == "logged" else "post_send_log",
            "updated_at": datetime.now(timezone.utc).isoformat()
            }).eq("workflow_run_id", str(workflow_run_id)).execute()

    # This is a separate audit Activity, not a bill or a billable time entry.
    # It is attached only when the source Clio bill includes an unambiguous matter.
    activity_status, activity_id = "skipped_no_matter", None
    activity_marker = f"Ledgerly non-billable reminder activity [workflow:{workflow_run_id}]"
    matter_id = ((invoice.get("source_data") or {}).get("clio_matter_id")
                 if isinstance(invoice.get("source_data"), dict) else None)
    if matter_id:
        activity_status = "unknown"  # persist marker/state before the remote write for crash recovery
        admin.table("workflow_deliveries").update({
            "clio_activity_status": activity_status,
            "clio_activity_marker": activity_marker,
            "clio_activity_updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("workflow_run_id", str(workflow_run_id)).eq("firm_id", firm_id).execute()
        try:
            activity_id, _created = clio.ensure_nonbillable_activity(
                clio_token, matter_id=str(matter_id),
                performed_on=local_now.date().isoformat(), workflow_run_id=str(workflow_run_id),
            )
            activity_status = "logged"
        except Exception as exc:
            # A network/server timeout can happen after Clio accepted the write.
            # Do not retry the create; the explicit reconcile action only searches.
            logger.warning("clio_activity_log_ambiguous run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
    activity_marker_value = activity_marker if matter_id else None
    admin.table("workflow_deliveries").update({
        "clio_activity_status": activity_status,
        "clio_activity_id": activity_id,
        "clio_activity_marker": activity_marker_value,
        "clio_activity_updated_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }).eq("workflow_run_id", str(workflow_run_id)).eq("firm_id", firm_id).execute()
    _record_audit(firm_id, str(ctx["user"].id), "reminder_sent", "workflow_run", str(workflow_run_id),
                  "Approved reminder sent through the connected firm mailbox.",
                  {"invoice_id": str(run["invoice_id"]), "clio_log_status": clio_log_status,
                   "clio_activity_status": activity_status, "invoice_state_recorded": invoice_state_recorded})
    return {"workflow_run_id": str(workflow_run_id), "status": "sent", "sent_at": sent_at,
            "clio_log_status": clio_log_status, "invoice_state_recorded": invoice_state_recorded,
            "clio_activity_status": activity_status, "clio_activity_id": activity_id,
            "message": "Email sent." if clio_log_status == "logged" and invoice_state_recorded
            else "Email sent. Reconcile the Clio communication and invoice follow-up log before proceeding; do not resend."}


@app.get("/api/workflows/reminder-drafts/{workflow_run_id}/delivery")
def get_reminder_delivery(workflow_run_id: UUID,
                          ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    """Read a sanitized delivery state for manual reconciliation; never retries."""
    _get_workflow_run(ctx, workflow_run_id)  # firm-scoped authorization check
    try:
        rows = (admin_client().table("workflow_deliveries").select(
            "status,clio_log_status,clio_activity_status,clio_activity_id,clio_activity_marker,clio_activity_updated_at,invoice_state_recorded,error_code,error_phase,sent_at,created_at,updated_at"
        ).eq("workflow_run_id", str(workflow_run_id)).eq("firm_id", _firm_id(ctx)).limit(1).execute().data)
    except Exception as exc:
        logger.warning("delivery_status_read_failed run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not load delivery status.") from exc
    return rows[0] if rows else {"status": "not_started", "clio_activity_status": "not_attempted"}


@app.post("/api/workflows/reminder-drafts/{workflow_run_id}/delivery/confirm-not-sent")
def confirm_delivery_not_sent(workflow_run_id: UUID, body: ConfirmNotSentRequest,
                              ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    firm_id = _require_role(ctx, "owner", "admin", "sender")
    run = _get_workflow_run(ctx, workflow_run_id)
    admin = admin_client()
    try:
        rows = (admin.table("workflow_deliveries").select("status,error_code,updated_at")
                .eq("workflow_run_id", str(workflow_run_id)).eq("firm_id", firm_id).limit(1).execute().data)
        if not rows:
            raise HTTPException(status_code=404, detail="No delivery attempt exists for this draft.")
        delivery = rows[0]
        if delivery["status"] == "failed" and delivery.get("error_code") == "delivery_confirmed_not_sent":
            return {"confirmed": True, "duplicate_request": True, "new_review_required": True}
        if delivery["status"] not in {"sending", "delivery_unknown"}:
            raise HTTPException(status_code=409, detail=f"Delivery status is '{delivery['status']}'; this action is only for uncertain sends.")
        updated = datetime.fromisoformat(str(delivery["updated_at"]).replace("Z", "+00:00"))
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - updated < timedelta(minutes=5):
            raise HTTPException(status_code=409, detail="Wait five minutes after the last delivery update, then check Gmail Sent before confirming.")
        if run.get("status") not in {"sending", "delivery_unknown"}:
            raise HTTPException(status_code=409, detail="The workflow status changed. Refresh before reconciling.")
        now = datetime.now(timezone.utc).isoformat()
        admin.table("workflow_deliveries").update({
            "status": "failed", "error_code": "delivery_confirmed_not_sent", "error_phase": "pre_send",
            "updated_at": now,
        }).eq("workflow_run_id", str(workflow_run_id)).eq("firm_id", firm_id).execute()
        _workflow_admin().table("workflow_runs").update({
            "status": "failed", "current_step": "complete", "error_code": "delivery_confirmed_not_sent",
            "error_message": "Staff checked Gmail Sent and confirmed no message was sent. Start a new draft and review it again.",
            "updated_at": now,
        }).eq("id", str(workflow_run_id)).eq("firm_id", firm_id).execute()
        return {"confirmed": True, "new_review_required": True,
                "message": "This attempt is closed. Create and approve a new draft before trying again."}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("delivery_not_sent_reconciliation_failed run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not record the delivery reconciliation.") from exc


@app.post("/api/workflows/reminder-drafts/{workflow_run_id}/delivery/reconcile-clio-activity")
def reconcile_clio_activity(workflow_run_id: UUID,
                             ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    """Search Clio for the deterministic Activity marker; this endpoint never creates one."""
    firm_id = _require_role(ctx, "owner", "admin", "sender")
    run = _get_workflow_run(ctx, workflow_run_id)
    if run["status"] != "sent":
        raise HTTPException(status_code=409, detail="Only a confirmed sent email can have an Activity audit record.")
    admin = admin_client()
    try:
        deliveries = (admin.table("workflow_deliveries").select(
            "status,clio_activity_status,clio_activity_id,clio_activity_marker"
        ).eq("workflow_run_id", str(workflow_run_id)).eq("firm_id", firm_id).limit(1).execute().data)
        if not deliveries or deliveries[0]["status"] != "sent":
            raise HTTPException(status_code=409, detail="The delivery is not confirmed as sent.")
        delivery = deliveries[0]
        if delivery.get("clio_activity_status") == "skipped_no_matter":
            return {"status": "skipped_no_matter", "activity_id": None}
        if delivery.get("clio_activity_status") == "logged" and delivery.get("clio_activity_id"):
            return {"status": "logged", "activity_id": delivery["clio_activity_id"], "duplicate_request": True}
        if delivery.get("clio_activity_status") not in {"unknown", "failed"}:
            raise HTTPException(status_code=409, detail="There is no unresolved Clio Activity record to reconcile.")
        invoice = _load_invoice_for_ai(ctx, UUID(run["invoice_id"]))
        matter_id = ((invoice.get("source_data") or {}).get("clio_matter_id")
                     if isinstance(invoice.get("source_data"), dict) else None)
        if not matter_id or not delivery.get("clio_activity_marker"):
            raise HTTPException(status_code=409, detail="This invoice has no linked Clio matter for Activity reconciliation.")
        clio = _clio_service()
        _connection, access_token = _fresh_access_token(admin, "clio_connections", firm_id, clio)
        activity_id = clio.find_nonbillable_activity(
            access_token, matter_id=str(matter_id), workflow_run_id=str(workflow_run_id)
        )
        if not activity_id:
            return {"status": "unknown", "activity_id": None,
                    "message": "Clio has not returned a matching Activity. Ledgerly did not create another one; check Clio or contact support before taking further action."}
        admin.table("workflow_deliveries").update({
            "clio_activity_status": "logged", "clio_activity_id": activity_id,
            "clio_activity_updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("workflow_run_id", str(workflow_run_id)).eq("firm_id", firm_id).execute()
        _record_audit(firm_id, str(ctx["user"].id), "clio_activity_reconciled", "workflow_run",
                      str(workflow_run_id), "Existing Clio non-billable Activity verified.",
                      {"invoice_id": str(run["invoice_id"])})
        return {"status": "logged", "activity_id": activity_id}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("clio_activity_reconciliation_failed run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not verify the Clio Activity. No new Activity was created.") from exc


@app.post("/api/workflows/reminder-drafts/{workflow_run_id}/delivery/reconcile-clio")
def reconcile_clio_communication(workflow_run_id: UUID, body: ClioLogReconcileRequest,
                                 ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    firm_id = _require_role(ctx, "owner", "admin", "sender")
    run = _get_workflow_run(ctx, workflow_run_id)
    if run["status"] != "sent":
        raise HTTPException(status_code=409, detail="Only a confirmed sent email can be reconciled with Clio.")
    admin = admin_client()
    try:
        rows = (admin.table("workflow_deliveries").select("status,clio_log_status")
                .eq("workflow_run_id", str(workflow_run_id)).eq("firm_id", firm_id).limit(1).execute().data)
        if not rows or rows[0]["status"] != "sent":
            raise HTTPException(status_code=409, detail="The delivery is not confirmed as sent.")
        if rows[0]["clio_log_status"] == "logged":
            return {"logged": True, "duplicate_request": True}
        invoice = _load_invoice_for_ai(ctx, UUID(run["invoice_id"]))
        clio = _clio_service()
        connection, access_token = _fresh_access_token(admin, "clio_connections", firm_id, clio)
        contact_id = clio.find_contact_id(access_token, invoice["client_email"])
        if not contact_id or not clio.verify_email_communication(
                access_token, body.communication_id, subject=run["draft"]["subject"],
                recipient_contact_id=contact_id):
            raise HTTPException(status_code=422, detail="That Clio ID does not match this sent email's subject, type, and client contact.")
        admin.table("workflow_deliveries").update({
            "clio_log_status": "logged", "clio_communication_id": body.communication_id,
            "error_code": None, "error_phase": None, "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("workflow_run_id", str(workflow_run_id)).eq("firm_id", firm_id).execute()
        return {"logged": True, "communication_id": body.communication_id}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("clio_log_reconciliation_failed run_id=%s error_type=%s", workflow_run_id, type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not verify the Clio Communication. No new Clio record was created.") from exc


@app.post("/api/integrations/gmail/replies/sync")
def sync_gmail_replies(ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    """Poll only Gmail threads Ledgerly sent; each new client reply pauses outreach."""
    service = _gmail_service()
    firm_id = _require_role(ctx, "owner", "admin", "reviewer")
    admin = admin_client()
    try:
        connection, access_token = _fresh_access_token(admin, "gmail_connections", firm_id, service)
        deliveries = (admin.table("workflow_deliveries").select(
            "workflow_run_id,invoice_id,gmail_thread_id,recipient,sent_at"
        ).eq("firm_id", firm_id).eq("status", "sent").not_.is_("gmail_thread_id", "null")
          .order("sent_at", desc=True).limit(200).execute().data)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("gmail_reply_sync_preflight_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not prepare Gmail reply sync.") from exc

    received = saved = skipped = failed = 0
    summaries: list[dict[str, Any]] = []
    for delivery in deliveries:
        try:
            messages = service.list_thread_messages(access_token, str(delivery["gmail_thread_id"]))
            invoice = _load_invoice_for_ai(ctx, UUID(delivery["invoice_id"]))
            for message in messages:
                parsed = service.parse_reply(message, connection["email_address"])
                if not parsed:
                    continue
                # Only treat a message as a client reply when the sender matches
                # this invoice's verified billing address. Never infer identity.
                from email.utils import parseaddr
                sender_address = parseaddr(parsed["sender"])[1].strip().lower()
                if not sender_address or sender_address != str(invoice.get("client_email") or "").strip().lower():
                    continue
                received += 1
                prior = (admin.table("gmail_reply_intake").select("id")
                         .eq("firm_id", firm_id).eq("gmail_message_id", parsed["message_id"]).limit(1).execute().data)
                if prior:
                    skipped += 1
                    continue
                category, summary, evidence = "other", "A client replied. Open the original message in Gmail and review it.", ""
                try:
                    ai = _ai_service()
                    classified = _invoke_ai("reply_classification", ai.classify_reply,
                                            parsed["body"], _invoice_facts(invoice))
                    category = classified.category
                    summary = classified.summary.strip()[:1000]
                    evidence = classified.evidence_excerpt.strip()[:500]
                except HTTPException:
                    # Intake must still pause reminders if AI is unavailable.
                    pass
                # Conservative default pauses every incoming reply for staff
                # review. The model's category is advisory, not an action.
                self_pause = _rpc(ctx, "pause_invoice_for_inbound_reply", {
                    "p_invoice_id": str(delivery["invoice_id"]),
                    "p_gmail_message_id": parsed["message_id"], "p_summary": summary,
                })
                try:
                    from workflow_graph import run_inbound_reply_pause_transition
                    run_inbound_reply_pause_transition(parsed["message_id"], category)
                except Exception as graph_exc:
                    # SQL has already applied the fail-closed pause; graph
                    # diagnostics cannot undo it or trigger an email action.
                    logger.warning("reply_pause_graph_unavailable error_type=%s", type(graph_exc).__name__)
                timestamp = None
                try:
                    timestamp = datetime.fromtimestamp(int(parsed["internal_date"]) / 1000, timezone.utc).isoformat()
                except (TypeError, ValueError, OverflowError):
                    timestamp = datetime.now(timezone.utc).isoformat()
                admin.table("gmail_reply_intake").insert({
                    "firm_id": firm_id, "invoice_id": str(delivery["invoice_id"]),
                    "workflow_run_id": str(delivery["workflow_run_id"]),
                    "gmail_message_id": parsed["message_id"], "sender": parsed["sender"],
                    "sender_email": sender_address,
                    "subject": parsed["subject"], "received_at": timestamp,
                    "category": category, "summary": summary, "evidence_excerpt": evidence,
                    "human_review_required": True,
                }).execute()
                saved += 1
                summaries.append({"invoice_id": str(delivery["invoice_id"]), "category": category,
                                  "summary": summary, "pause_result": self_pause.get("reason") if isinstance(self_pause, dict) else "saved"})
        except Exception as exc:
            failed += 1
            logger.warning("gmail_reply_thread_sync_failed run_id=%s error_type=%s",
                           delivery.get("workflow_run_id"), type(exc).__name__)
    return {"checked_threads": len(deliveries), "replies_seen": received, "new_replies": saved,
            "duplicates_skipped": skipped, "thread_errors": failed, "items": summaries}


@app.get("/api/integrations/gmail/replies")
def list_gmail_replies(ctx: dict[str, Any] = Depends(current_session)) -> list[dict[str, Any]]:
    _gmail_service()
    firm_id = _require_role(ctx, "owner", "admin", "reviewer")
    try:
        rows = (admin_client().table("gmail_reply_intake").select(
            "id,invoice_id,workflow_run_id,sender,sender_email,subject,received_at,category,summary,evidence_excerpt,status,created_at"
        ).eq("firm_id", firm_id).order("created_at", desc=True).limit(100).execute().data)
        return rows
    except Exception as exc:
        logger.warning("gmail_reply_list_failed error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not load client replies.") from exc


@app.post("/api/integrations/gmail/replies/{reply_id}/resolve")
def resolve_gmail_reply(reply_id: UUID, body: ReplyResolutionRequest,
                        ctx: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    firm_id = _require_role(ctx, "owner", "admin", "reviewer")
    if body.reply_type == "promise" and not body.promise_date:
        raise HTTPException(status_code=422, detail="Enter the payment date the client promised.")
    if body.reply_type == "ooo" and not body.pause_until:
        raise HTTPException(status_code=422, detail="Enter the return date before pausing an out-of-office reply.")
    admin = admin_client()
    actor_id = str(ctx["user"].id)
    try:
        rows = (admin.table("gmail_reply_intake").select("*").eq("id", str(reply_id))
                .eq("firm_id", firm_id).limit(1).execute().data)
        if not rows:
            raise HTTPException(status_code=404, detail="Client reply not found.")
        reply = rows[0]
        if reply["status"] == "resolved":
            return {"resolved": True, "duplicate_request": True, "reply_id": str(reply_id)}
        if reply["status"] == "resolving" and reply.get("resolved_by") != actor_id:
            raise HTTPException(status_code=409, detail="Another reviewer is resolving this reply. Refresh the queue.")
        if reply["status"] == "needs_review":
            claimed = (admin.table("gmail_reply_intake").update({"status": "resolving", "resolved_by": actor_id})
                       .eq("id", str(reply_id)).eq("firm_id", firm_id).eq("status", "needs_review").execute().data)
            if not claimed:
                raise HTTPException(status_code=409, detail="This reply changed in another session. Refresh the queue.")
        try:
            from workflow_graph import run_reply_resolution_transition
            run_reply_resolution_transition(body.reply_type)
        except Exception as graph_exc:
            raise HTTPException(status_code=422, detail="The selected reply type cannot be resolved by the workflow.") from graph_exc
        result = _rpc(ctx, "record_reply_resolution", {
            "p_invoice_id": str(reply["invoice_id"]), "p_reply_id": str(reply_id),
            "p_reply_type": body.reply_type, "p_summary": reply["summary"],
            "p_promise_date": body.promise_date.isoformat() if body.promise_date else None,
            "p_pause_until": body.pause_until.isoformat() if body.pause_until else None,
        })
        if isinstance(result, dict) and result.get("ok") is False:
            raise HTTPException(status_code=409, detail="The reply could not be applied to this invoice. Refresh source data and try again.")
        if body.reply_type == "opt_out":
            admin.table("contact_suppressions").upsert({
                "firm_id": firm_id, "email": reply["sender_email"].strip().lower(),
                "source_reply_id": str(reply_id),
                "reason": body.resolution_note or "Client opt-out confirmed by staff.",
                "created_by": actor_id,
            }, on_conflict="firm_id,email").execute()
        now = datetime.now(timezone.utc).isoformat()
        admin.table("gmail_reply_intake").update({
            "category": body.reply_type, "status": "resolved", "resolved_by": actor_id,
            "resolved_at": now, "resolution_note": body.resolution_note or None,
        }).eq("id", str(reply_id)).eq("firm_id", firm_id).eq("status", "resolving").eq("resolved_by", actor_id).execute()
        _record_audit(firm_id, actor_id, "gmail_reply_resolved", "gmail_reply", str(reply_id),
                      "Client reply resolved by an authorized reviewer; outreach remains paused.",
                      {"invoice_id": str(reply["invoice_id"]), "reply_type": body.reply_type})
        return {"resolved": True, "reply_id": str(reply_id), "reply_type": body.reply_type,
                "invoice_state": result.get("outreach_state") if isinstance(result, dict) else None}
    except HTTPException:
        raise
    except Exception as exc:
        try:
            admin.table("gmail_reply_intake").update({"status": "needs_review", "resolved_by": None})\
                .eq("id", str(reply_id)).eq("firm_id", firm_id).eq("status", "resolving").eq("resolved_by", actor_id).execute()
        except Exception:
            pass
        logger.warning("gmail_reply_resolution_failed reply_id=%s error_type=%s", reply_id, type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not resolve this reply; it remains paused for review.") from exc
