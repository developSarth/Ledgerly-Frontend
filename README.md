# Ledgerly invoice follow-up workflow

Ledgerly is a human-approved invoice follow-up workflow for law firms. The FastAPI backend authenticates firm users, reads invoice sources, prepares a reminder draft through a bounded LangGraph workflow, pauses for human review, and sends only after a separate authorized send action. A confirmed email is logged as a Clio Communication and, when a matter is linked, a separate non-billable/no-charge Clio Activity. Ledgerly does not create or modify Clio Bills.

## Project layout

- `Frontend/` — Vite app. It calls FastAPI for business data and actions; it does not call Supabase REST/RPC directly.
- `backend/` — FastAPI, LangChain integrations, LangGraph orchestration, Clio/Gmail adapters, and authorization checks.
- `supabase/` — base schema and ordered migrations.
- `docs/DATABASE_DESIGN.md` — schema, RLS, RPC, and integration reference.
- `docs/WORKFLOW_MAP.md` — end-user flow, roles, states, and operating boundaries.
- `legacy-node/` — preserved original Node.js prototype, not part of the running app.

## Local setup

1. Configure backend environment variables in `Ledgerly/.env`. Required Supabase settings are `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and backend-only `SUPABASE_SECRET_KEY` or `SUPABASE_SERVICE_ROLE_KEY`. Add the configured model, Gmail, Clio, encryption, and frontend-origin values described in `backend/README.md` and `.env.example`.
2. For a new Supabase project, run `supabase/setup.sql`, then every migration in filename order. Existing projects should apply only unapplied migrations, including `202611040001_clio_activity_audit.sql` for the Activity audit path. Do not replay migrations already applied.
3. In `backend/`, install `requirements.txt` and run `uvicorn main:app --reload --host 127.0.0.1 --port 8000`.
4. In `Frontend/`, run `npm ci` and `npm run dev`, then open the Vite URL. The frontend needs only the optional `VITE_LEDGERLY_API_BASE_URL` when the API is on a separate origin. Supabase credentials must never be placed in Vite variables.

## Current behavior and boundaries

- CSV rows are parsed and validated deterministically. Unfamiliar headers can be suggested from header names only; a staff member confirms the mapping before import.
- Clio Bill sync is read-only. After a confirmed Gmail send, Ledgerly logs an EmailCommunication and then attempts a TimeEntry Activity only when a linked matter exists. The Activity includes `non_billable=true`, `no_charge=true`, and an opaque workflow marker; it contains no duration, rate, email body, or billable narrative. Clio app access requires Activities Read and Write for creation and reconciliation.
- Invoice intake decisions and reminder draft review are distinct. Draft approval is not sending. A separate authorized person action sends the reviewed message; source freshness, firm policy, suppression, role, and delivery idempotency are checked again at send time.
- The LangGraph workflow is bounded and stateful. The model can assist with draft text, CSV header suggestions, and reply categorization; deterministic backend logic owns permissions, state transitions, and external side effects.
- Gmail replies are manually synchronized, deduplicated, and held for staff review. A new reply pauses outreach. The system does not auto-reply or automatically resume a paused invoice.
- Roles are owner, admin, reviewer, sender, and viewer. The configured policy can require a different sender from the approver. Firm-local timezone and policy settings are managed through the API.
- Dashboard data comes from the authenticated backend and persisted firm records. No sample invoices or sample client activity are seeded into the live UI; a new firm sees empty states until it imports or syncs a source.
- The browser stores authentication tokens and a non-sensitive CSV idempotency key only. Invoice, client, workflow, reply, and audit records are not retained as a local demo ledger.
- Uncertain Gmail sends are not retried automatically. Clio Communication and Activity reconciliation are read-only checks of exact records and do not create duplicates.
- Clio Billing writes, automated/scheduled sending, and automated client replies are disabled.

The firm should use synthetic records until it has reviewed provider data handling, workflow policy, opt-out handling, and production deployment controls. See [backend setup and API details](backend/README.md), [database and security design](docs/DATABASE_DESIGN.md), and [workflow map](docs/WORKFLOW_MAP.md).
