-- Durable, firm-scoped workflow state for the bounded LangGraph draft/review flow.
-- Mutations use the backend-only Supabase service key after FastAPI derives the
-- firm from the authenticated user. Browser clients can read their own runs but
-- cannot forge workflow status, draft approval, or reviewer metadata.

create table if not exists public.workflow_runs (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  invoice_id uuid not null references public.invoices(id) on delete cascade,
  initiated_by uuid not null references auth.users(id),
  idempotency_key text not null check (length(idempotency_key) between 8 and 128),
  message_type text not null check (message_type in ('initial', 'gentle', 'firm')),
  status text not null default 'running'
    check (status in ('running', 'awaiting_review', 'approved_pending_delivery', 'discarded', 'stale', 'failed')),
  current_step text not null default 'eligibility_check'
    check (current_step in ('eligibility_check', 'draft_preparation', 'human_review', 'delivery_not_configured', 'complete')),
  source_snapshot_id uuid references public.invoice_imports(id) on delete set null,
  source_updated_at timestamptz,
  draft jsonb check (draft is null or jsonb_typeof(draft) = 'object'),
  draft_version text check (draft_version is null or length(draft_version) = 64),
  review_decision text check (review_decision is null or review_decision in ('approve', 'reject')),
  reviewed_by uuid references auth.users(id),
  reviewed_at timestamptz,
  error_code text check (error_code is null or length(error_code) <= 80),
  error_message text check (error_message is null or length(error_message) <= 500),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (firm_id, idempotency_key),
  check ((status <> 'awaiting_review') or (draft is not null and draft_version is not null)),
  check ((review_decision is null) or (reviewed_by is not null and reviewed_at is not null))
);

create index if not exists workflow_runs_firm_status_updated_idx
  on public.workflow_runs (firm_id, status, updated_at desc);
create index if not exists workflow_runs_firm_invoice_updated_idx
  on public.workflow_runs (firm_id, invoice_id, updated_at desc);
create unique index if not exists workflow_runs_one_active_review_per_invoice_idx
  on public.workflow_runs (firm_id, invoice_id)
  where status in ('running', 'awaiting_review');

alter table public.workflow_runs enable row level security;
revoke all on public.workflow_runs from public, anon, authenticated;
grant select on public.workflow_runs to authenticated;
grant select, insert, update on public.workflow_runs to service_role;

drop policy if exists "Firm owner can read own workflow runs" on public.workflow_runs;
create policy "Firm owner can read own workflow runs"
  on public.workflow_runs for select to authenticated
  using (exists (
    select 1 from public.firms f
    where f.id = workflow_runs.firm_id and f.owner_user_id = (select auth.uid())
  ));

comment on table public.workflow_runs is
  'Durable Ledgerly LangGraph run state. Draft approval is recorded here; delivery is intentionally not performed by this workflow stage.';
