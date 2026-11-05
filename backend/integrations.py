"""Integration building blocks. These helpers do not send messages by themselves."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from settings import settings

TEMPLATE_ROOT = Path(__file__).resolve().parent / "templates"
PROMPT_ROOT = TEMPLATE_ROOT / "prompts"
EMAIL_ROOT = TEMPLATE_ROOT / "email"


class IntegrationNotConfigured(RuntimeError):
    """Raised when a feature is used before its server-side credentials exist."""


class CsvHeaderMap(BaseModel):
    """Suggested source-column mapping. Application validation remains authoritative."""

    invoice_number: str | None = Field(description="Source header for the invoice identifier, or null if unclear.")
    client_name: str | None = Field(description="Source header for the billed client's name, or null if unclear.")
    client_email: str | None = Field(description="Source header for the client's billing email, or null if unclear.")
    amount: str | None = Field(description="Source header for the original invoice total, or null if unclear.")
    amount_due: str | None = Field(description="Source header for remaining balance due, or null if unclear.")
    currency: str | None = Field(description="Source header for ISO currency, or null if absent or unclear.")
    issue_date: str | None = Field(description="Source header for the invoice issue date, or null if absent or unclear.")
    due_date: str | None = Field(description="Source header for the due date, or null if unclear.")
    status: str | None = Field(description="Source header for invoice payment status, or null if unclear.")
    uncertain_headers: list[str] = Field(description="Headers that could not be mapped safely.")


class ReplyClassification(BaseModel):
    category: Literal["promise", "question", "help", "dispute", "ooo", "payment_claim", "opt_out", "other"]
    summary: str = Field(description="Brief factual summary grounded only in the supplied email.")
    promise_date: str | None = Field(description="Promised date in YYYY-MM-DD format, otherwise null.")
    pause_until: str | None = Field(description="Explicit return date for an out-of-office reply in YYYY-MM-DD format, otherwise null.")
    pause_followup: bool = Field(description="Whether automated follow-up must pause pending review or a condition.")
    human_review_required: bool = Field(description="True for disputes, questions, payment claims, opt-outs, or uncertainty.")
    evidence_excerpt: str = Field(description="Short exact phrase from the email supporting the classification.")


class EmailDraft(BaseModel):
    subject: str = Field(min_length=1, max_length=180)
    body: str = Field(min_length=1, max_length=5000)
    needs_human_review: Literal[True] = True


class RenderedEmail(BaseModel):
    subject: str = Field(min_length=1, max_length=180)
    body: str = Field(min_length=1, max_length=5000)


def get_chat_model() -> ChatOpenAI:
    if not settings.ai_features_enabled:
        raise IntegrationNotConfigured("AI features are disabled. Set AI_FEATURES_ENABLED=true after adding OPENAI_API_KEY.")
    if not settings.openai_api_key:
        raise IntegrationNotConfigured("OPENAI_API_KEY is not configured on the backend.")
    options: dict[str, Any] = {
        "model": settings.openai_model,
        "api_key": settings.openai_api_key,
        "timeout": settings.openai_timeout_seconds,
        "max_retries": settings.openai_max_retries,
    }
    if settings.openai_base_url:
        options["base_url"] = settings.openai_base_url
    return ChatOpenAI(**options)


def _prompt(filename: str) -> ChatPromptTemplate:
    content = (PROMPT_ROOT / filename).read_text(encoding="utf-8")
    return ChatPromptTemplate.from_messages([("system", content), ("human", "{input_data}")])


def suggest_csv_header_map(headers: list[str]) -> CsvHeaderMap:
    """Suggest mappings from header names only; do not send invoice rows or client PII."""
    if not headers or len(headers) > 100:
        raise ValueError("Provide between 1 and 100 CSV headers.")
    chain = _prompt("csv_header_mapping.md") | get_chat_model().with_structured_output(CsvHeaderMap)
    return chain.invoke({"input_data": json.dumps({"headers": headers}, ensure_ascii=False)})


def classify_reply(email_text: str, invoice_facts: dict[str, Any]) -> ReplyClassification:
    if not email_text.strip() or len(email_text) > 30_000:
        raise ValueError("Email text must contain 1 to 30,000 characters.")
    chain = _prompt("reply_classification.md") | get_chat_model().with_structured_output(ReplyClassification)
    payload = {"email_text": email_text, "invoice_facts": invoice_facts}
    return chain.invoke({"input_data": json.dumps(payload, ensure_ascii=False, default=str)})


def draft_reminder(invoice_facts: dict[str, Any], message_type: Literal["initial", "gentle", "firm"]) -> EmailDraft:
    chain = _prompt("email_draft.md") | get_chat_model().with_structured_output(EmailDraft)
    payload = {"message_type": message_type, "invoice_facts": invoice_facts}
    return chain.invoke({"input_data": json.dumps(payload, ensure_ascii=False, default=str)})


def render_email_template(message_type: Literal["initial", "gentle", "firm"], context: dict[str, Any]) -> RenderedEmail:
    """Render a deterministic plain-text subject/body from validated invoice data."""
    env = Environment(
        loader=FileSystemLoader(str(EMAIL_ROOT)),
        undefined=StrictUndefined,
        autoescape=select_autoescape(default=False, default_for_string=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    subject = env.get_template(f"{message_type}.subject.j2").render(**context).strip()
    body = env.get_template(f"{message_type}.body.txt.j2").render(**context).strip()
    return RenderedEmail(subject=subject, body=body)
