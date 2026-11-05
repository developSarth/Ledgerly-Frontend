-- Human-triggered delivery outbox and private Gmail OAuth storage.
-- One delivery record per reviewed draft prevents duplicate sends on refresh/retry.

alter table public.workflow_runs drop constraint if exists workflow_runs_status_check;
alter table public.workflow_runs add constraint workflow_runs_status_check
  check (status in ('running', 'awaiting_review', 'approved_pending_delivery',
                    'sending', 'sent', 'delivery_unknown', 'discarded', 'stale', 'failed'));
alter table public.workflow_runs drop constraint if exists workflow_runs_current_step_check;
alter table public.workflow_runs add constraint workflow_runs_current_step_check
  check (current_step in ('eligibility_check', 'draft_preparation', 'human_review', 'delivery',
                          'delivery_not_configured', 'complete'));

create table if not exists public.gmail_oauth_states (
  state_hash text primary key check (length(state_hash) = 64),
  firm_id uuid not null references public.firms(id) on delete cascade,
  initiated_by uuid not null references auth.users(id) on delete cascade,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.gmail_connections (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null unique references public.firms(id) on delete cascade,
  email_address text not null,
  encrypted_access_token text not null,
  encrypted_refresh_token text not null,
  access_token_expires_at timestamptz not null,
  connected_by uuid not null references auth.users(id),
  connected_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.workflow_deliveries (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  workflow_run_id uuid not null unique references public.workflow_runs(id) on delete cascade,
  invoice_id uuid not null references public.invoices(id) on delete cascade,
  status text not null check (status in ('sending', 'sent', 'delivery_unknown', 'failed')),
  recipient text not null,
  gmail_message_id text,
  gmail_thread_id text,
  clio_communication_id text,
  clio_log_status text not null default 'not_attempted'
    check (clio_log_status in ('not_attempted', 'logged', 'failed')),
  invoice_state_recorded boolean not null default false,
  error_code text check (error_code is null or length(error_code) <= 80),
  error_phase text check (error_phase is null or error_phase in ('pre_send', 'send_unknown', 'post_send_log')),
  sent_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists workflow_deliveries_firm_sent_idx
  on public.workflow_deliveries (firm_id, sent_at desc);

create table if not exists public.gmail_reply_intake (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  invoice_id uuid not null references public.invoices(id) on delete cascade,
  workflow_run_id uuid not null references public.workflow_runs(id) on delete cascade,
  gmail_message_id text not null,
  sender text not null,
  sender_email text not null,
  subject text not null default '',
  received_at timestamptz,
  category text not null check (category in ('promise','question','help','dispute','ooo','payment_claim','opt_out','other')),
  summary text not null check (length(summary) between 1 and 1000),
  evidence_excerpt text not null default '',
  human_review_required boolean not null default true check (human_review_required),
  status text not null default 'needs_review' check (status in ('needs_review','resolved')),
  created_at timestamptz not null default now(),
  unique (firm_id, gmail_message_id)
);

create index if not exists gmail_reply_intake_firm_status_idx
  on public.gmail_reply_intake (firm_id, status, created_at desc);

create or replace function public.record_email_delivery(
  p_firm_id uuid,
  p_invoice_id uuid,
  p_workflow_run_id uuid,
  p_message_type text,
  p_sent_at timestamptz
) returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_invoice public.invoices%rowtype;
  v_latest_id uuid;
  v_latest_at timestamptz;
  v_covers_all boolean;
  v_day date;
  v_timezone text;
  v_action_key text;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_message_type not in ('initial','gentle','firm') or p_sent_at is null then
    raise exception 'Invalid delivery record';
  end if;
  select timezone into v_timezone from public.firms f
    where f.id=p_firm_id and f.owner_user_id=auth.uid() for update;
  if not found then raise exception 'Firm not found or access denied'; end if;
  v_action_key := 'email-sent:' || p_workflow_run_id::text;
  select id, imported_at, covers_all_invoices into v_latest_id, v_latest_at, v_covers_all
    from public.invoice_imports where firm_id=p_firm_id order by imported_at desc,id desc limit 1;
  select * into v_invoice from public.invoices where id=p_invoice_id and firm_id=p_firm_id for update;
  if not found then raise exception 'Invoice not found'; end if;
  v_day := (p_sent_at at time zone v_timezone)::date;
  insert into public.invoice_events(firm_id,invoice_id,event_type,action_key,summary,metadata)
  values(p_firm_id,p_invoice_id,'email_sent',v_action_key,'Approved invoice reminder sent by Ledgerly.',
    jsonb_build_object('workflow_run_id',p_workflow_run_id,'message_type',p_message_type,'sent_at',p_sent_at))
  on conflict(firm_id,action_key) do nothing;
  if not found then return jsonb_build_object('ok',true,'reason','duplicate_action'); end if;
  if v_invoice.status <> 'unpaid' or v_invoice.amount_due <= 0 then
    return jsonb_build_object('ok',true,'reason','invoice_changed_after_send');
  end if;
  update public.invoices set
    outreach_state='active',
    first_contacted_on=coalesce(first_contacted_on,v_day),
    last_contacted_on=v_day,
    next_action_on=null,
    last_action='Approved reminder sent; next step requires review',
    updated_at=now()
  where id=p_invoice_id and firm_id=p_firm_id;
  if v_latest_id is null or not coalesce(v_covers_all,false)
     or v_latest_at < now()-interval '24 hours'
     or v_invoice.last_import_id is distinct from v_latest_id then
    return jsonb_build_object('ok',true,'reason','sent_source_changed');
  end if;
  return jsonb_build_object('ok',true,'reason','recorded');
end;
$$;

revoke all on function public.record_email_delivery(uuid,uuid,uuid,text,timestamptz) from public,anon;
grant execute on function public.record_email_delivery(uuid,uuid,uuid,text,timestamptz) to authenticated;

alter table public.gmail_oauth_states enable row level security;
alter table public.gmail_connections enable row level security;
alter table public.workflow_deliveries enable row level security;
alter table public.gmail_reply_intake enable row level security;
revoke all on public.gmail_oauth_states, public.gmail_connections, public.workflow_deliveries,
  public.gmail_reply_intake
  from public, anon, authenticated;
grant all on public.gmail_oauth_states, public.gmail_connections, public.workflow_deliveries,
  public.gmail_reply_intake
  to service_role;

comment on table public.gmail_connections is
  'Backend-only Gmail OAuth tokens encrypted at rest; never readable by browser clients.';
comment on table public.workflow_deliveries is
  'Idempotent per-workflow email delivery and Clio Communication audit record; no bill or time-entry mutations.';
comment on table public.gmail_reply_intake is
  'Deduplicated reply classification results; every received reply pauses outreach for staff review. Raw email bodies are not persisted here.';
