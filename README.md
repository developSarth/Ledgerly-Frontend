# Ledgerly invoice follow-up demo

Ledgerly has a Vite browser frontend and a Python/FastAPI backend. The original demo behavior is preserved: email connection, reminders, approvals, replies, and payment actions are simulated. No email or SMS is sent and there is no background scheduler. Backend integration scaffolding is prepared for GPT-5.4 mini, Gmail OAuth, and plain-text email/prompt templates, but it is not yet connected to the UI or live mailboxes.

## Project layout

- `Frontend/` — HTML, CSS, and browser JavaScript, built with Vite.
- `backend/` — Python API, Supabase auth verification, and database calls.
- `supabase/migrations/` — database schema, Row Level Security, and atomic workflow RPCs.
- `legacy-node/` — untouched copies of the original root-level JavaScript files.

## Run locally

1. Configure `SUPABASE_URL` and `SUPABASE_ANON_KEY` in `Ledgerly/.env` for cloud sign-in and persistence. Keep service-role keys out of this app. The backend also accepts the previous `VITE_SUPABASE_*` names.
2. For a new Supabase project, run `supabase/setup.sql` once in the SQL Editor. It contains both migrations in the required order. If applying migrations individually, run `202610250001_invoice_csv_imports.sql` before `202610300001_workflow_safety.sql`.
3. In one terminal, create a Python environment in `backend/`, install `backend/requirements.txt`, then run `uvicorn main:app --reload --host 127.0.0.1 --port 8000` from that folder.
4. In a second terminal, run `npm ci` and `npm run dev` from `Frontend/`, then open the Vite URL.

5. For optional integration development, copy the blank OpenAI and Gmail variables from `.env.example` into `.env`. Install the added Python packages with `pip install -r backend/requirements.txt`. Keep `AI_FEATURES_ENABLED`, `GMAIL_FEATURES_ENABLED`, and `EMAIL_SEND_ENABLED` false until the corresponding authenticated routes and safeguards are implemented. Never place OpenAI or Google client secrets in `Frontend/.env` or any `VITE_*` variable.

The Vite development server proxies `/api` requests to FastAPI. For deployment, set `FRONTEND_ORIGINS` on the API to the exact frontend origins and `VITE_API_BASE_URL` in the frontend build if the API is hosted separately.

## Demo behavior

- Without Supabase configuration, fictional sample invoices and simulated actions run locally in the browser.
- With Supabase configured, sign-in, firm data, invoice imports, reply summaries, and workflow events are stored in the firm's Supabase project. API calls use the signed-in user's JWT and anon/publishable key, so database Row Level Security remains active.
- CSV imports support the existing common header aliases and retain extra source columns. Empty/oversized files, malformed rows, ambiguous dates, duplicate headers or invoice IDs, invalid currency/status/email/amount values, and unmapped required columns are held with row-specific feedback; imports are all-or-nothing. Replaying the same pending upload is idempotent.
- Cloud API operations use typed request models and derive firm scope from the authenticated user. Each API response includes a request ID for support diagnostics; repeated reply and resume actions are safely deduplicated.
- Stage 1 and later reminders are simulations. The demo approval gate, weekly advance control, reply types, status freshness checks, dashboard, and activity feed remain available.

Clio API access, live mailbox access, real email delivery, payment processing, and production scheduling are not implemented. Use synthetic data unless the firm has approved the project's data-handling and security setup.
