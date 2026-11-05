"""Bounded LangGraph orchestration for Ledgerly's human-approved workflow.

The graph has fixed, deterministic edges; the model cannot select tools or
change workflow state. Supabase persists the run between API requests. Review,
delivery authorization, and reply routing are deterministic graph transitions;
the graph never sends email or writes to Clio by itself.
"""
from __future__ import annotations

from typing import Any, Callable, Literal, TypedDict

from langgraph.graph import END, START, StateGraph


class ReminderWorkflowState(TypedDict, total=False):
    workflow_run_id: str
    invoice_id: str
    message_type: Literal["initial", "gentle", "firm"]
    status: str
    current_step: str
    error_code: str | None
    error_message: str | None
    review_decision: str | None
    invoice: dict[str, Any]
    firm_name: str
    source_snapshot_id: str
    draft: dict[str, Any]
    source_updated_at: str
    invoice_number: str
    recipient: str
    human_send_click: bool
    reply_type: str
    followup_action: str


ValidateInvoice = Callable[[ReminderWorkflowState], dict[str, Any]]
PrepareDraft = Callable[[ReminderWorkflowState], dict[str, Any]]


class WorkflowGuardrailError(Exception):
    """Expected fail-closed eligibility or policy outcome safe to show a user."""

    def __init__(self, code: str, public_message: str):
        super().__init__(code)
        self.code = code
        self.public_message = public_message


def run_reminder_workflow(
    initial_state: ReminderWorkflowState,
    validate_invoice: ValidateInvoice,
    prepare_draft: PrepareDraft,
) -> ReminderWorkflowState:
    """Run validate → draft → review-pause or a review-resume transition."""

    def validate_node(state: ReminderWorkflowState) -> dict[str, Any]:
        try:
            validated = validate_invoice(state)
            return {
                **validated,
                "status": "running",
                "current_step": "draft_preparation",
                "error_code": None,
                "error_message": None,
            }
        except WorkflowGuardrailError as exc:
            return {
                "status": "failed",
                "current_step": "eligibility_check",
                "error_code": exc.code,
                "error_message": exc.public_message,
            }
        except Exception:
            return {
                "status": "failed",
                "current_step": "eligibility_check",
                "error_code": "validation_unavailable",
                "error_message": "Could not verify this invoice. Refresh the invoice data and try again.",
            }

    def draft_node(state: ReminderWorkflowState) -> dict[str, Any]:
        try:
            prepared = prepare_draft(state)
            return {
                **prepared,
                "status": "running",
                "current_step": "human_review",
                "error_code": None,
                "error_message": None,
            }
        except WorkflowGuardrailError as exc:
            return {
                "status": "failed",
                "current_step": "draft_preparation",
                "error_code": exc.code,
                "error_message": exc.public_message,
            }
        except Exception:
            return {
                "status": "failed",
                "current_step": "draft_preparation",
                "error_code": "draft_generation_failed",
                "error_message": "Could not prepare a draft. No message was sent; try again or review the invoice manually.",
            }

    def human_review_node(state: ReminderWorkflowState) -> dict[str, Any]:
        # First invocation lands here and pauses. A later authenticated review
        # request replays this deterministic transition from persisted state.
        decision = state.get("review_decision")
        if decision == "approve":
            return {"status": "approved_pending_delivery", "current_step": "delivery"}
        if decision == "reject":
            return {"status": "discarded", "current_step": "complete"}
        return {"status": "awaiting_review", "current_step": "human_review"}

    graph = StateGraph(ReminderWorkflowState)
    graph.add_node("eligibility_check", validate_node)
    graph.add_node("draft_preparation", draft_node)
    graph.add_node("human_review", human_review_node)
    graph.add_conditional_edges(
        START,
        lambda state: "review" if state.get("review_decision") else "eligibility",
        {"eligibility": "eligibility_check", "review": "human_review"},
    )
    graph.add_conditional_edges(
        "eligibility_check",
        lambda state: "stop" if state.get("status") == "failed" else "draft",
        {"stop": END, "draft": "draft_preparation"},
    )
    graph.add_edge("draft_preparation", "human_review")
    graph.add_edge("human_review", END)
    return graph.compile().invoke(initial_state)


def run_review_transition(workflow_run_id: str, decision: Literal["approve", "reject"]) -> ReminderWorkflowState:
    """Resume from persisted review state without re-running the LLM."""
    return run_reminder_workflow(
        {
            "workflow_run_id": workflow_run_id,
            "invoice_id": "",
            "message_type": "initial",
            "status": "awaiting_review",
            "review_decision": decision,
        },
        lambda _state: {},
        lambda _state: {},
    )


def run_delivery_authorization_transition(
    workflow_run_id: str, status: str, review_decision: str, human_send_click: bool
) -> ReminderWorkflowState:
    """A graph gate for the explicit Send click; it authorizes state only."""
    def authorize(state: ReminderWorkflowState) -> dict[str, Any]:
        if (state.get("status") != "approved_pending_delivery"
                or state.get("review_decision") != "approve"
                or state.get("human_send_click") is not True):
            return {"status": "blocked", "current_step": "human_review",
                    "error_code": "human_send_approval_required"}
        return {"status": "sending", "current_step": "delivery", "error_code": None}

    graph = StateGraph(ReminderWorkflowState)
    graph.add_node("human_delivery_gate", authorize)
    graph.add_edge(START, "human_delivery_gate")
    graph.add_edge("human_delivery_gate", END)
    result = graph.compile().invoke({
        "workflow_run_id": workflow_run_id, "status": status,
        "review_decision": review_decision, "human_send_click": human_send_click,
    })
    if result.get("status") != "sending":
        raise WorkflowGuardrailError("human_send_approval_required", "Only an approved draft with a separate human Send action can enter delivery.")
    return result


def run_inbound_reply_pause_transition(reply_id: str, category: str) -> ReminderWorkflowState:
    """Every inbound reply pauses outreach; model labels never choose actions."""
    def pause(_state: ReminderWorkflowState) -> dict[str, Any]:
        return {"status": "needs_review", "current_step": "human_reply_review",
                "error_code": None, "followup_action": "pause_for_human_review",
                "review_decision": None}

    graph = StateGraph(ReminderWorkflowState)
    graph.add_node("pause_for_human_review", pause)
    graph.add_edge(START, "pause_for_human_review")
    graph.add_edge("pause_for_human_review", END)
    return graph.compile().invoke({"workflow_run_id": reply_id, "reply_type": category})


def run_reply_resolution_transition(reply_type: str) -> ReminderWorkflowState:
    """Map human-confirmed reply categories to conservative, non-sending actions."""
    actions = {
        "promise": "pause_until_confirmed_date",
        "ooo": "pause_until_return_date",
        "payment_claim": "pause_and_check_authoritative_payment_source",
        "opt_out": "keep_suppressed_until_admin_reinstates_with_reason",
        "question": "pause_for_human_response",
        "help": "pause_for_human_response",
        "dispute": "pause_for_responsible_attorney",
        "other": "pause_for_human_review",
    }

    def resolve(state: ReminderWorkflowState) -> dict[str, Any]:
        category = state.get("reply_type", "")
        if category not in actions:
            return {"status": "blocked", "current_step": "human_reply_review",
                    "error_code": "unsupported_reply_type"}
        return {"status": "resolved", "current_step": "complete",
                "followup_action": actions[category], "error_code": None}

    graph = StateGraph(ReminderWorkflowState)
    graph.add_node("human_reply_resolution", resolve)
    graph.add_edge(START, "human_reply_resolution")
    graph.add_edge("human_reply_resolution", END)
    result = graph.compile().invoke({"reply_type": reply_type})
    if result.get("status") != "resolved":
        raise WorkflowGuardrailError("unsupported_reply_type", "Choose a supported reply type before resolving this item.")
    return result
