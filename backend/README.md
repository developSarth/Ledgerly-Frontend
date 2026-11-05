# Ledgerly Python API

The FastAPI service owns authenticated Supabase access. The browser never receives a service-role key. Invoice and firm data use the signed-in user's token and RLS; workflow-run state mutations and Clio OAuth token storage use the backend-only elevated key after the API has derived and checked the authenticated firm's scope.

## Run

From `Ledgerly/backend`, create a virtual environment, install `requirements.txt`, and start the API:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Set `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and a backend-only `SUPABASE_SECRET_KEY` or legacy `SUPABASE_SERVICE_ROLE_KEY` in `Ledgerly/.env`. The elevated key is required for protected workflow-run mutations and Clio OAuth state/encrypted token storage. Never expose it to the browser. The server also accepts the previous `VITE_SUPABASE_*` names during migration.

The API allows the local Vite origins on port 5173 (localhost and 127.0.0.1). Set `FRONTEND_ORIGINS` to the exact trusted origins for deployment and `FRONTEND_PUBLIC_URL` to the dashboard origin that should receive signup confirmation, password recovery, and invitation links. Add those redirect URLs to Supabase Auth's URL Configuration. For this local frontend, use `FRONTEND_PUBLIC_URL=http://localhost:5173` and allow `http://localhost:5173/**` in Supabase. For an empty Supabase project, run `supabase/setup.sql` once, then every dated migration in filename order. Existing projects should run each migration after their current version, through `202611040001_clio_activity_audit.sql`. Do not replay migrations already applied.

Auth failures are mapped to safe actionable messages and correlated with the API request ID; credentials and email addresses are not logged. Signup confirmation can be resent from the sign-in dialog. The resend response is deliberately generic so it does not reveal whether an account exists.

The API exposes typed operations rather than a generic RPC dispatcher, derives firm scope from the authenticated user, and returns request/run IDs for diagnostics. Firm roles are owner/admin/reviewer/sender/viewer, enforced by backend checks and RLS. CSV imports are validated before writes and protected by a database-backed idempotency key; reply and resume events are also deduplicated. LangGraph owns the bounded eligibility → draft → human-review sequence plus deterministic approval, delivery-authorization, and reply-routing transitions. External email/Clio calls remain guarded API actions; the graph cannot send or mutate Clio by itself. After confirmed delivery, the backend logs the email as a Clio Communication and, when a matter is linked, a separate non-billable, no-charge TimeEntry audit marker. It never creates a Bill or billable Activity.

## Firm policy, approvals, dashboard, and operations

Apply the policy/dashboard migration `202611030001_policy_dashboard_audit.sql` after `202611020004_invoice_review_delete.sql`, then `202611040001_clio_activity_audit.sql` for Activity tracking and legacy RPC revokes. New firms receive a policy row automatically; existing firms receive conservative defaults:

- Invoice review: owner/admin/reviewer.
- Reminder draft review: owner/admin/reviewer. An invoice must first have an approved intake decision.
- Send: owner/admin/sender, only after separate human review and an explicit send action.
- Policy changes and suppression reinstatement: owner/admin.
- Initial reminder: due date reached by default. Gentle follow-up: at least 7 days after the prior contact. Firm reminder: at least 21 days overdue.
- Send window: weekdays 09:00–17:00 in firm timezone. Only an explicit send request is checked; there is no scheduler.
- Invoice snapshot must be complete and no older than 24 hours. Owners/admins can change bounded timing/freshness values through `PUT /api/cloud/policy`; `manual_send_required` is permanently true in the API.
- Distinct approver/sender separation can be enabled for firms with enough staff. It defaults off to avoid blocking a single-person firm.
- A confirmed opt-out remains firm-wide suppressed. Only an owner/admin can reinstate it, and the 10–500 character reason is saved to immutable audit history. Reinstatement never resumes invoice outreach.

Key frontend API contracts:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/dashboard` | Authoritative metrics, firm-local date, source freshness, integration readiness, open review queues, and recent audit events. Currency totals are grouped by currency. |
| `GET/PUT /api/cloud/policy` | Read policy or save the complete policy object. PUT is owner/admin-only and audits changes transactionally. |
| `PUT /api/cloud/firm/settings` | Owner/admin updates the firm's IANA timezone. |
| `POST /api/cloud/invoices/{invoice_id}/review` | Backend-mediated invoice approve/reject/restore; reviewer roles only. |
| `DELETE /api/cloud/invoices` | Backend-mediated owner/admin deletion for 1–500 invoice IDs; history guards still apply. |
| `GET /api/audit-events?limit=50` | Owner/admin/reviewer audit view, maximum 200 events. |
| `GET /api/contacts/suppressions` | Read firm-wide suppressions. |
| `POST /api/contacts/suppressions/reinstate` | Owner/admin correction with a required reason; does not resume outreach. |
| `GET /api/ops/readiness` | Owner/admin setup and migration status. It never returns secrets; production deployment is always reported as unreviewed. |
| `POST /api/auth/password-reset` | Generic account-recovery request; response does not disclose whether an email exists. |
| `POST /api/auth/password-update` | Set a new password using the authenticated Supabase recovery session. |

The dashboard count means invoices newly marked paid in Ledgerly this month from an authoritative unpaid-to-paid source update. It is not a cash-received date or amount. Older paid invoices are not backfilled. Audit and paid-transition history are append-only. `/api/health` is liveness only; use `/api/ops/readiness` for authenticated setup checks.

The frontend currently calls Supabase REST directly for invoice review status, review decisions, and deletes. The backend now exposes equivalent authenticated routes; switch those calls to the API before relying on one consistent authorization/error path. The frontend should also call `/api/dashboard` instead of calculating metrics from local seed state, and expose policy, timezone, audit, suppression correction, readiness, and account recovery controls.

## Integration preparation

The backend exposes authenticated AI routes for CSV header suggestions and reply-classification suggestions. The production-facing reminder review now uses `POST /api/workflows/reminder-drafts` and `POST /api/workflows/reminder-drafts/{run_id}/review`; these routes run the bounded LangGraph flow and persist draft/review state. The legacy `POST /api/ai/reminder-draft` remains a direct, unsent suggestion route. Header mapping sends header names only; reply classification remains non-persistent. Set `OPENAI_API_KEY`, `OPENAI_MODEL=gpt-5.4-mini`, and `AI_FEATURES_ENABLED=true` to enable AI. This API key is separate from any ChatGPT subscription.

The Gmail variables are for a Google Cloud OAuth Web application. Register the exact `GMAIL_OAUTH_REDIRECT_URI` value in Google Cloud. Apply the email delivery and team/reply migrations, configure a Fernet key in `INTEGRATION_TOKEN_ENCRYPTION_KEY` (or use the existing `CLIO_TOKEN_ENCRYPTION_KEY`), then set `GMAIL_FEATURES_ENABLED=true`. Sending also requires `EMAIL_SEND_ENABLED=true`; keep it false until the Gmail and Clio accounts are connected and you are ready for a human to click **Send approved email**. OAuth credentials/tokens remain server-side and encrypted. An ambiguous delivery is never retried automatically; after a five-minute wait, a staff member must check Gmail Sent and confirm whether the email is absent.

## Clio Manage integration

The Clio backend supports the OAuth authorization-code flow, encrypted token storage, connection status/disconnect, and a manual read-only Bills sync. After Gmail confirms a send, the backend creates one `EmailCommunication` record in Clio for an exact unique contact email match. If the bill has a matter ID, it also creates a `TimeEntry` Activity with `non_billable=true` and `no_charge=true`; it supplies no rate, duration, charge, message body, or invoice narrative. The note contains only a stable workflow marker used for reconciliation. Bills are never written. An uncertain Activity result is marked `unknown`; the reconcile action only searches Clio for the exact marker and never retries a create. Bills sync snapshots are recorded as `source_system=clio`; AI reminder drafting accepts either a complete fresh CSV import or a complete Clio sync within the policy age window. A bill without a valid client email is imported for review and cannot be drafted. A CSV invoice without an associated Clio matter receives no Activity record.

### Required environment values

Add these to `Ledgerly/.env` (backend-only; do not add them to `Frontend/.env` or prefix them with `VITE_`):

| Variable | What to enter |
| --- | --- |
| `CLIO_CLIENT_ID` | Client ID from your Clio Manage Developer App. |
| `CLIO_CLIENT_SECRET` | Client secret from the same app; keep it server-side. |
| `CLIO_REDIRECT_URI` | Exact registered callback: `http://127.0.0.1:8000/api/integrations/clio/callback` for local development. |
| `CLIO_REGION` | `us`, `eu`, `ca`, or `au`; match the firm's Clio Manage region. |
| `CLIO_DEFAULT_CURRENCY` | Three-letter billing currency, e.g. `USD`. Clio's bill feed does not provide a reliable top-level currency code in the fields used by this sync, so set this to the firm's currency. |
| `CLIO_TOKEN_ENCRYPTION_KEY` | New Fernet encryption key generated with the command below. Keep a secure backup; existing stored tokens cannot be decrypted if this key is lost or changed. |
| `CLIO_FEATURES_ENABLED` | Set to `true` only after applying the migration and filling all values. |
| `SUPABASE_SECRET_KEY` or `SUPABASE_SERVICE_ROLE_KEY` | Backend-only Supabase elevated key for one-time OAuth state and encrypted token rows. This project already has the legacy `SUPABASE_SERVICE_ROLE_KEY` setting; you can keep using it. Never expose it to the browser because it bypasses RLS. |

Generate the encryption key from `Ledgerly/backend` after installing requirements:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Copy the output into `CLIO_TOKEN_ENCRYPTION_KEY`. Do not paste the value into chat or commit it. Supabase recommends its server-only secret key for backend code; the current legacy service-role key is still supported by this implementation. See [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys).

### Clio Developer App setup

In the **Clio Manage** Developer Portal, register the callback URI exactly as in `.env` (scheme, host, port, and path must match). Bill sync and contact/matter matching need **Billing: Read**, **Contacts: Read**, and **Users: Read**. The confirmed-send audit path also needs **Communications: Write** to log the already-sent email and **Activities: Read and Write** to find/create the non-billable Activity marker. Clio write permissions can allow create, update, and delete, so enable only the required scopes; Ledgerly does not use Billing Write or Tasks Write. If permissions change after authorization, reconnect so Clio issues a token with the new permissions. Clio also enforces the connected user's account role. See [Clio authorization](https://docs.developers.clio.com/api-docs/clio-manage/authorization/) and [Clio permissions](https://docs.developers.clio.com/api-docs/clio-manage/permissions/).

### Connect and sync

After applying the migrations, installing requirements, filling the credentials, setting `CLIO_FEATURES_ENABLED=true`, and restarting Uvicorn, sign in from the Ledgerly profile control. Open **Import invoices** to connect Clio or sync bills. The callback opens in a separate window; close it and return to Ledgerly to refresh connection status. Sync follows Clio's cursor pagination and imports unpaid, paid, and void bills. Draft and awaiting-approval bills are ignored. Bill records remain read-only. After Gmail confirms a reminder send, Ledgerly writes a Communication and, when a matter is linked, a non-billable/no-charge Activity with an opaque workflow marker; it does not write or create a Bill.

A successful complete sync creates a fresh snapshot. An eligible unpaid invoice can then open the persisted reminder-draft review panel. `/docs` remains available for direct API inspection. Clio bill sync remains read-only; the explicit send stage logs a Communication and safe audit Activity only after Gmail confirms delivery.

`POST /api/integrations/clio/disconnect` revokes the current Clio token and removes its encrypted local record. The callback consumes a random, one-use, ten-minute OAuth state. The service key and Clio tokens stay in backend-only configuration/storage; logs exclude tokens, authorization codes, and invoice contents.

Dependencies for LangChain/OpenAI, Gmail API OAuth, and plain-text Jinja templates are listed in `requirements.txt`. Prompt files and deterministic initial/gentle/firm message templates are in `templates/`. `integrations.py` exposes guarded structured-output helpers and template rendering; it does not send mail. The existing CSV importer and row validation remain deterministic and do not require an LLM. Header mapping is an optional suggestion for the review UI; it never imports the data itself.

### Frontend workflow contract

The frontend reuses the existing review panel and calls the persisted LangGraph workflow:

```http
POST /api/workflows/reminder-drafts
Authorization: Bearer <supabase-access-token>
Idempotency-Key: <stable key for this user action>
Content-Type: application/json

{"invoice_id":"<invoice UUID>","message_type":"initial"}
```

The API validates firm scope, invoice status/balance/recipient, the reminder stage, and that the invoice belongs to a complete snapshot no older than 24 hours. The graph returns a persisted `awaiting_review` run with `workflow_run_id`, `draft_version`, and an unsent draft. An active review for the same invoice is reused, and idempotency-key reuse with a different invoice/stage is rejected.

`GET /api/workflows/reminder-drafts` restores active and approved-pending-delivery status after refresh. The review action is:

```http
POST /api/workflows/reminder-drafts/<workflow_run_id>/review
Authorization: Bearer <supabase-access-token>
Content-Type: application/json

{"decision":"approve","draft_version":"<version returned by the server>","subject":"<edited subject>","body":"<edited body>"}
```

Use `decision: "reject"` to discard; approval requires a non-empty subject/body and an unchanged version. The backend rechecks the source snapshot and invoice before accepting approval. If source data changed, the run becomes `stale`; the reviewer must refresh the source and create a new draft. The run and reviewer decision are durable in Supabase. Browser clients can read firm-owned runs through RLS but cannot write approval/status fields directly; only the backend's elevated key can mutate the table.

Approved runs stop at `approved_pending_delivery` until an owner/admin/sender clicks **Send approved email**. The backend checks the snapshot again, claims a single durable delivery row, sends through the connected Gmail mailbox, and records the sent email as a Clio Communication. A Clio logging failure does not resend the message; an owner/admin/sender can enter an existing Communication ID for verification against type, subject, and contact. Replies can be manually polled from threads Ledgerly sent; every reply is deduplicated, logged as `needs_review`, and pauses invoice outreach before staff action. An owner/admin/reviewer confirms the classification and any promise/return date; confirmed opt-outs are persisted as firm-wide suppressions. Replies do not trigger client responses or automatically resume outreach.

## Clio Activity audit behavior

Clio Bill sync remains read-only. After Gmail confirms a send, Ledgerly logs the sent email as a Clio Communication. If the source invoice includes a linked Clio matter, it creates a separate `TimeEntry` Activity with `non_billable=true`, `no_charge=true`, a firm-local date, and an opaque workflow marker. It does not include duration, rate, email body, or billable narrative and does not create or update a Bill. Activities Read and Write permissions are required for marker lookup/reconciliation and creation. If Clio reports an ambiguous create result, Ledgerly records `unknown` before the external request and performs read-only exact-marker reconciliation; it will not automatically repeat the create. The marker is based on the workflow run and should be retained when reconciling.

Remaining production work is operational: firm-specific policy/template approval, provider data-handling review, invitation email delivery, reply polling/webhook scheduling and monitoring, audit retention/export decisions, production deployment and secret-management setup, and a production security review. Automatic sending and automated client replies remain disabled. Payment-state changes still require a fresh authoritative source check.

The draft sends limited invoice facts (client name, invoice number, balance, currency, due date, status, and firm name) to the configured OpenAI API. Approve provider/privacy settings before using real client data.
