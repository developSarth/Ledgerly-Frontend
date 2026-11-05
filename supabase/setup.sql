-- Ledgerly Supabase setup: run once in the Supabase SQL Editor on an empty project.
-- Includes base schema, workflow safety objects, and durable draft-review runs.

create extension if not exists pgcrypto;

create table if not exists public.firms (
  id uuid primary key default gen_random_uuid(),
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (length(trim(name)) between 1 and 160),
  timezone text not null default 'UTC',
  automation_enabled boolean not null default false,
  automation_started_at timestamptz,
  created_at timestamptz not null default now(),
  unique (owner_user_id)
);

create table if not exists public.invoice_imports (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  uploaded_by uuid not null references auth.users(id),
  file_name text not null,
  received_rows integer not null default 0 check (received_rows >= 0),
  accepted_rows integer not null default 0 check (accepted_rows >= 0),
  duplicate_rows integer not null default 0 check (duplicate_rows >= 0),
  invalid_rows integer not null default 0 check (invalid_rows >= 0),
  covers_all_invoices boolean not null default false,
  imported_at timestamptz not null default now()
);

create table if not exists public.invoices (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  invoice_number text not null,
  client_name text not null,
  client_email text not null,
  amount numeric(14,2) not null check (amount >= 0),
  amount_due numeric(14,2) not null check (amount_due >= 0),
  currency char(3) not null default 'USD',
  issue_date date,
  due_date date not null,
  status text not null check (status in ('unpaid', 'paid', 'void')),
  source_data jsonb not null default '{}'::jsonb,
  last_import_id uuid references public.invoice_imports(id) on delete set null,
  source_updated_at timestamptz not null default now(),
  outreach_state text not null default 'new' check (outreach_state in ('new','active','paused','needs_review','needs_status_check','closed')),
  first_contacted_on date,
  last_contacted_on date,
  next_action_on date,
  pause_until date,
  promise_date date,
  reply_memory jsonb not null default '[]'::jsonb,
  last_action text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (firm_id, invoice_number)
);

create index if not exists invoices_firm_status_due_idx
  on public.invoices (firm_id, status, due_date);

create table if not exists public.invoice_events (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  invoice_id uuid not null references public.invoices(id) on delete cascade,
  event_type text not null,
  action_key text,
  summary text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (firm_id, action_key)
);
create index if not exists invoice_events_firm_created_idx
  on public.invoice_events (firm_id, created_at desc);

alter table public.firms enable row level security;
alter table public.invoice_imports enable row level security;
alter table public.invoices enable row level security;
alter table public.invoice_events enable row level security;

grant select, insert, update on public.firms to authenticated;
grant select, insert, update on public.invoice_imports to authenticated;
grant select, insert, update on public.invoices to authenticated;
grant select, insert on public.invoice_events to authenticated;

create policy "Firm owner can read own firm"
  on public.firms for select to authenticated
  using (owner_user_id = (select auth.uid()));
create policy "User can create own firm"
  on public.firms for insert to authenticated
  with check (owner_user_id = (select auth.uid()));
create policy "Firm owner can update own firm"
  on public.firms for update to authenticated
  using (owner_user_id = (select auth.uid()))
  with check (owner_user_id = (select auth.uid()));

create policy "Firm owner can read own imports"
  on public.invoice_imports for select to authenticated
  using (exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())));
create policy "Firm owner can add own imports"
  on public.invoice_imports for insert to authenticated
  with check (uploaded_by = (select auth.uid()) and exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())));
create policy "Firm owner can update own import summaries"
  on public.invoice_imports for update to authenticated
  using (uploaded_by = (select auth.uid()) and exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())))
  with check (uploaded_by = (select auth.uid()) and exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())));

create policy "Firm owner can read own invoices"
  on public.invoices for select to authenticated
  using (exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())));
create policy "Firm owner can add own invoices"
  on public.invoices for insert to authenticated
  with check (exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())));
create policy "Firm owner can update own invoices"
  on public.invoices for update to authenticated
  using (exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())))
  with check (exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())));
create policy "Firm owner can read own invoice events"
  on public.invoice_events for select to authenticated
  using (exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())));
create policy "Firm owner can add own invoice events"
  on public.invoice_events for insert to authenticated
  with check (exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid()))
    and exists (select 1 from public.invoices i where i.id = invoice_id and i.firm_id = firm_id));

create or replace function public.import_invoice_csv(
  p_firm_id uuid,
  p_file_name text,
  p_rows jsonb
) returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_import_id uuid;
  v_item jsonb;
  v_seen text[] := array[]::text[];
  v_invoice_number text;
  v_client_name text;
  v_client_email text;
  v_amount numeric(14,2);
  v_amount_due numeric(14,2);
  v_currency text;
  v_issue_date date;
  v_due_date date;
  v_status text;
  v_inserted integer := 0;
  v_duplicates integer := 0;
  v_invalid integer := 0;
  v_received integer := 0;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;
  if not exists (select 1 from public.firms f where f.id = p_firm_id and f.owner_user_id = auth.uid()) then
    raise exception 'Firm not found or access denied';
  end if;
  perform 1 from public.firms where id = p_firm_id for update;
  if jsonb_typeof(p_rows) <> 'array' then
    raise exception 'Rows must be a JSON array';
  end if;

  v_received := jsonb_array_length(p_rows);
  insert into public.invoice_imports (firm_id, uploaded_by, file_name, received_rows)
  values (p_firm_id, auth.uid(), left(coalesce(p_file_name, 'invoices.csv'), 255), v_received)
  returning id into v_import_id;

  for v_item in select value from jsonb_array_elements(p_rows)
  loop
    begin
      v_invoice_number := nullif(trim(v_item->>'invoice_number'), '');
      v_client_name := nullif(trim(v_item->>'client_name'), '');
      v_client_email := lower(nullif(trim(v_item->>'client_email'), ''));
      v_amount := nullif(v_item->>'amount', '')::numeric;
      v_amount_due := coalesce(nullif(v_item->>'amount_due', '')::numeric, v_amount);
      v_currency := upper(coalesce(nullif(trim(v_item->>'currency'), ''), 'USD'));
      v_issue_date := nullif(v_item->>'issue_date', '')::date;
      v_due_date := nullif(v_item->>'due_date', '')::date;
      v_status := lower(coalesce(nullif(trim(v_item->>'status'), ''), 'unpaid'));

      if v_status in ('paid', 'fully paid', 'complete', 'completed', 'closed') or v_amount_due = 0 then
        v_status := 'paid';
        v_amount_due := 0;
      elsif v_status in ('void', 'cancelled', 'canceled') then
        v_status := 'void';
      else
        v_status := 'unpaid';
      end if;

      if v_invoice_number is null or v_client_name is null or v_client_email is null
        or v_amount is null or v_amount < 0 or v_amount_due is null or v_amount_due < 0
        or v_due_date is null or length(v_currency) <> 3 then
        v_invalid := v_invalid + 1;
        continue;
      end if;
      if v_invoice_number = any(v_seen) then
        v_duplicates := v_duplicates + 1;
        continue;
      end if;
      v_seen := array_append(v_seen, v_invoice_number);

      insert into public.invoices as current_invoice (
        firm_id, invoice_number, client_name, client_email, amount, amount_due,
        currency, issue_date, due_date, status, source_data, last_import_id,
        source_updated_at, updated_at
      ) values (
        p_firm_id, v_invoice_number, v_client_name, v_client_email, v_amount, v_amount_due,
        v_currency, v_issue_date, v_due_date, v_status, v_item, v_import_id,
        now(), now()
      )
      on conflict (firm_id, invoice_number) do update set
        client_name = excluded.client_name,
        client_email = excluded.client_email,
        amount = excluded.amount,
        amount_due = excluded.amount_due,
        currency = excluded.currency,
        issue_date = excluded.issue_date,
        due_date = excluded.due_date,
        status = excluded.status,
        source_data = excluded.source_data,
        last_import_id = excluded.last_import_id,
        source_updated_at = excluded.source_updated_at,
        outreach_state = case
          when excluded.status in ('paid', 'void') then 'closed'
          when current_invoice.status in ('paid', 'void') and excluded.status = 'unpaid' then 'needs_review'
          else current_invoice.outreach_state
        end,
        next_action_on = case when excluded.status in ('paid', 'void') then null else current_invoice.next_action_on end,
        pause_until = case when excluded.status in ('paid', 'void') then null else current_invoice.pause_until end,
        last_action = case
          when excluded.status = 'paid' then 'Payment confirmed by latest CSV'
          when excluded.status = 'void' then 'Invoice marked void by latest CSV'
          when current_invoice.status in ('paid', 'void') and excluded.status = 'unpaid' then 'Source changed from paid/void to unpaid; review required'
          else current_invoice.last_action
        end,
        updated_at = excluded.updated_at;
      v_inserted := v_inserted + 1;
    exception when others then
      v_invalid := v_invalid + 1;
    end;
  end loop;

  update public.invoice_imports set
    accepted_rows = v_inserted,
    duplicate_rows = v_duplicates,
    invalid_rows = v_invalid,
    covers_all_invoices = (v_invalid = 0 and v_duplicates = 0)
  where id = v_import_id;

  return jsonb_build_object(
    'import_id', v_import_id,
    'received_rows', v_received,
    'accepted_rows', v_inserted,
    'duplicate_rows', v_duplicates,
    'invalid_rows', v_invalid
  );
end;
$$;

-- Demo action recorder: it records planned/simulated outreach only and never sends mail or SMS.
create or replace function public.record_demo_outreach(
  p_firm_id uuid,
  p_invoice_id uuid,
  p_action_key text,
  p_message_type text,
  p_simulated_day date
) returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_invoice public.invoices%rowtype;
  v_latest_import_id uuid;
  v_latest_imported_at timestamptz;
  v_covers_all boolean;
  v_timezone text;
  v_enabled boolean;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  select timezone, automation_enabled into v_timezone, v_enabled from public.firms
    where id = p_firm_id and owner_user_id = auth.uid() for update;
  if not found then raise exception 'Firm not found or access denied'; end if;
  if not v_enabled then return jsonb_build_object('ok', false, 'reason', 'automation_not_enabled'); end if;
  select id, imported_at, covers_all_invoices into v_latest_import_id, v_latest_imported_at, v_covers_all
    from public.invoice_imports where firm_id = p_firm_id order by imported_at desc, id desc limit 1;
  if v_latest_import_id is null or not coalesce(v_covers_all, false)
    or v_latest_imported_at < now() - interval '24 hours' then
    return jsonb_build_object('ok', false, 'reason', 'stale_snapshot');
  end if;
  select * into v_invoice from public.invoices where id = p_invoice_id and firm_id = p_firm_id for update;
  if not found then return jsonb_build_object('ok', false, 'reason', 'invoice_not_found'); end if;
  if v_invoice.last_import_id is distinct from v_latest_import_id then
    return jsonb_build_object('ok', false, 'reason', 'not_in_latest_snapshot');
  end if;
  if v_invoice.status in ('paid', 'void') or v_invoice.amount_due <= 0 then
    return jsonb_build_object('ok', false, 'reason', 'already_paid_or_closed');
  end if;
  if v_invoice.outreach_state in ('needs_review', 'needs_status_check', 'closed') then
    return jsonb_build_object('ok', false, 'reason', 'paused_or_review');
  end if;
  if v_invoice.outreach_state = 'paused' then
    if v_invoice.pause_until is null or v_invoice.pause_until >= p_simulated_day then
      return jsonb_build_object('ok', false, 'reason', 'paused_or_review');
    end if;
    update public.invoices set outreach_state='active', pause_until=null, promise_date=null
      where id=p_invoice_id and firm_id=p_firm_id;
  end if;
  if v_invoice.next_action_on is not null and v_invoice.next_action_on > p_simulated_day then
    return jsonb_build_object('ok', false, 'reason', 'not_due');
  end if;
  if p_message_type not in ('initial', 'gentle', 'firm') then
    raise exception 'Unsupported message type';
  end if;
  if p_message_type = 'firm' and p_simulated_day < v_invoice.due_date + 21 then
    return jsonb_build_object('ok', false, 'reason', 'too_early_for_firm');
  end if;
  if p_message_type = 'gentle' and v_invoice.first_contacted_on is not null
    and p_simulated_day >= v_invoice.due_date + 21 then
    return jsonb_build_object('ok', false, 'reason', 'firmer_message_required');
  end if;
  insert into public.invoice_events (firm_id, invoice_id, event_type, action_key, summary, metadata)
  values (p_firm_id, p_invoice_id, 'outreach_simulated', p_action_key,
    'Outreach recorded in demo; no message sent.', jsonb_build_object('message_type', p_message_type, 'simulated_day', p_simulated_day))
  on conflict (firm_id, action_key) do nothing;
  if not found then return jsonb_build_object('ok', false, 'reason', 'duplicate_action'); end if;
  update public.invoices set
    outreach_state = 'active',
    first_contacted_on = coalesce(first_contacted_on, p_simulated_day),
    last_contacted_on = p_simulated_day,
    next_action_on = p_simulated_day + 7,
    last_action = case p_message_type when 'initial' then 'Initial invoice note simulated' when 'firm' then 'Firmer reminder simulated' else 'Friendly weekly reminder simulated' end,
    updated_at = now()
  where id = p_invoice_id and firm_id = p_firm_id;
  return jsonb_build_object('ok', true, 'reason', 'recorded', 'next_action_on', p_simulated_day + 7);
end;
$$;

create or replace function public.save_invoice_reply(
  p_firm_id uuid,
  p_invoice_id uuid,
  p_action_key text,
  p_reply_type text,
  p_summary text,
  p_promise_date date default null,
  p_pause_until date default null
) returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_timezone text;
  v_invoice public.invoices%rowtype;
  v_new_state text;
  v_day date;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  select timezone into v_timezone from public.firms
    where id = p_firm_id and owner_user_id = auth.uid() for update;
  if not found then raise exception 'Firm not found or access denied'; end if;
  select * into v_invoice from public.invoices where id = p_invoice_id and firm_id = p_firm_id for update;
  if not found then return jsonb_build_object('ok', false, 'reason', 'invoice_not_found'); end if;
  if p_reply_type not in ('promise','question','help','dispute','ooo','payment_claim','opt_out','other') then
    raise exception 'Unsupported reply type';
  end if;
  v_day := (now() at time zone v_timezone)::date;
  if p_reply_type = 'promise' and (p_promise_date is null or p_promise_date <= v_day) then
    raise exception 'A future promise date is required';
  end if;
  if p_reply_type = 'ooo' and (p_pause_until is null or p_pause_until <= v_day) then
    raise exception 'A future pause date is required';
  end if;
  insert into public.invoice_events (firm_id, invoice_id, event_type, action_key, summary, metadata)
  values (p_firm_id, p_invoice_id, 'reply_received', p_action_key, left(coalesce(p_summary, 'Client replied.'), 1000),
    jsonb_build_object('reply_type', p_reply_type, 'promise_date', p_promise_date, 'pause_until', p_pause_until));
  if v_invoice.status in ('paid','void') or v_invoice.amount_due <= 0 then
    return jsonb_build_object('ok', true, 'reason', 'invoice_already_closed');
  end if;
  v_new_state := case
    when p_reply_type = 'payment_claim' then 'needs_status_check'
    when p_reply_type in ('question','help','dispute','other') then 'needs_review'
    else 'paused'
  end;
  update public.invoices set
    outreach_state = v_new_state,
    promise_date = case when p_reply_type = 'promise' then p_promise_date else null end,
    pause_until = case when p_reply_type = 'promise' then p_promise_date when p_reply_type = 'ooo' then p_pause_until else null end,
    next_action_on = null,
    reply_memory = reply_memory || jsonb_build_array(jsonb_build_object(
      'date', v_day, 'reply_type', p_reply_type, 'summary', left(coalesce(p_summary, 'Client replied.'), 1000),
      'promise_date', p_promise_date, 'pause_until', p_pause_until
    )),
    last_action = case p_reply_type
      when 'promise' then 'Paused until promised payment date'
      when 'payment_claim' then 'Client says payment was sent; verify against fresh CSV'
      when 'opt_out' then 'Client opted out; outreach paused'
      else 'Client reply saved; human follow-up needed'
    end,
    updated_at = now()
  where id = p_invoice_id and firm_id = p_firm_id;
  return jsonb_build_object('ok', true, 'reason', 'saved', 'outreach_state', v_new_state);
end;
$$;

create or replace function public.resume_invoice_outreach(
  p_firm_id uuid,
  p_invoice_id uuid,
  p_action_key text
) returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_invoice public.invoices%rowtype;
  v_latest_import_id uuid;
  v_latest_imported_at timestamptz;
  v_covers_all boolean;
  v_timezone text;
  v_day date;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  select timezone into v_timezone from public.firms
    where id = p_firm_id and owner_user_id = auth.uid() for update;
  if not found then raise exception 'Firm not found or access denied'; end if;
  select id, imported_at, covers_all_invoices into v_latest_import_id, v_latest_imported_at, v_covers_all
    from public.invoice_imports where firm_id = p_firm_id order by imported_at desc, id desc limit 1;
  select * into v_invoice from public.invoices where id = p_invoice_id and firm_id = p_firm_id for update;
  if not found then return jsonb_build_object('ok', false, 'reason', 'invoice_not_found'); end if;
  if v_latest_import_id is null or not coalesce(v_covers_all,false) or v_latest_imported_at < now()-interval '24 hours'
    or v_invoice.last_import_id is distinct from v_latest_import_id then
    return jsonb_build_object('ok', false, 'reason', 'stale_snapshot');
  end if;
  if v_invoice.status <> 'unpaid' or v_invoice.amount_due <= 0 then
    return jsonb_build_object('ok', false, 'reason', 'already_paid_or_closed');
  end if;
  v_day := (now() at time zone v_timezone)::date;
  insert into public.invoice_events (firm_id, invoice_id, event_type, action_key, summary)
  values (p_firm_id, p_invoice_id, 'outreach_resumed', p_action_key, 'Firm resumed invoice follow-up.');
  update public.invoices set outreach_state='active', pause_until=null, promise_date=null,
    next_action_on=v_day+1, last_action='Follow-up resumed by firm', updated_at=now()
  where id=p_invoice_id and firm_id=p_firm_id;
  return jsonb_build_object('ok', true, 'reason', 'resumed', 'next_action_on', v_day+1);
end;
$$;

create or replace function public.enable_firm_automation(p_firm_id uuid)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  update public.firms set automation_enabled=true,
    automation_started_at=coalesce(automation_started_at, now())
  where id=p_firm_id and owner_user_id=auth.uid();
  if not found then raise exception 'Firm not found or access denied'; end if;
  return jsonb_build_object('ok', true, 'automation_enabled', true);
end;
$$;

revoke all on function public.import_invoice_csv(uuid, text, jsonb) from public, anon;
grant execute on function public.import_invoice_csv(uuid, text, jsonb) to authenticated;
revoke all on function public.record_demo_outreach(uuid, uuid, text, text, date) from public, anon;
grant execute on function public.record_demo_outreach(uuid, uuid, text, text, date) to authenticated;
revoke all on function public.save_invoice_reply(uuid, uuid, text, text, text, date, date) from public, anon;
grant execute on function public.save_invoice_reply(uuid, uuid, text, text, text, date, date) to authenticated;
revoke all on function public.resume_invoice_outreach(uuid, uuid, text) from public, anon;
grant execute on function public.resume_invoice_outreach(uuid, uuid, text) to authenticated;
revoke all on function public.enable_firm_automation(uuid) from public, anon;
grant execute on function public.enable_firm_automation(uuid) to authenticated;

-- Durable, firm-scoped workflow state for the bounded LangGraph draft/review flow.
-- Apply the matching dated migration for an existing Supabase project.
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


-- Workflow safety, idempotency, and reply/resume deduplication.

-- Reliability hardening for the Ledgerly demo. This migration does not change
-- reminder stages, approval policy, or opt-out behavior.

create table if not exists public.invoice_import_requests (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  idempotency_key text not null check (length(idempotency_key) between 8 and 128),
  result jsonb,
  created_at timestamptz not null default now(),
  unique (firm_id, idempotency_key)
);

alter table public.invoice_import_requests enable row level security;
revoke all on public.invoice_import_requests from public, anon, authenticated;

drop policy if exists "Firm owner can read own import requests" on public.invoice_import_requests;
create policy "Firm owner can read own import requests"
  on public.invoice_import_requests for select to authenticated
  using (exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())));
drop policy if exists "Firm owner can add own import requests" on public.invoice_import_requests;
create policy "Firm owner can add own import requests"
  on public.invoice_import_requests for insert to authenticated
  with check (exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())));
drop policy if exists "Firm owner can update own import requests" on public.invoice_import_requests;
create policy "Firm owner can update own import requests"
  on public.invoice_import_requests for update to authenticated
  using (exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())))
  with check (exists (select 1 from public.firms f where f.id = firm_id and f.owner_user_id = (select auth.uid())));

create or replace function public.import_invoice_csv_idempotent(
  p_firm_id uuid,
  p_file_name text,
  p_rows jsonb,
  p_idempotency_key text
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_request_id uuid;
  v_result jsonb;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if not exists (select 1 from public.firms f where f.id = p_firm_id and f.owner_user_id = auth.uid()) then
    raise exception 'Firm not found or access denied';
  end if;
  if p_idempotency_key is null or length(p_idempotency_key) not between 8 and 128 then
    raise exception 'A valid idempotency key is required';
  end if;
  if p_file_name is null or length(trim(p_file_name)) not between 1 and 255 then
    raise exception 'A valid file name is required';
  end if;
  if jsonb_typeof(p_rows) <> 'array' or jsonb_array_length(p_rows) = 0 then
    raise exception 'At least one invoice row is required';
  end if;
  if jsonb_array_length(p_rows) > 5000 then
    raise exception 'An import cannot exceed 5000 invoice rows';
  end if;

  insert into public.invoice_import_requests (firm_id, idempotency_key)
  values (p_firm_id, p_idempotency_key)
  on conflict (firm_id, idempotency_key) do nothing
  returning id into v_request_id;

  if v_request_id is null then
    select result into v_result from public.invoice_import_requests
      where firm_id = p_firm_id and idempotency_key = p_idempotency_key;
    if v_result is null then raise exception 'Import request is not yet available'; end if;
    return v_result || jsonb_build_object('duplicate_submission', true);
  end if;

  v_result := public.import_invoice_csv(p_firm_id, p_file_name, p_rows);
  update public.invoice_import_requests set result = v_result where id = v_request_id;
  return v_result || jsonb_build_object('duplicate_submission', false);
end;
$$;

revoke all on function public.import_invoice_csv_idempotent(uuid, text, jsonb, text) from public, anon;
grant execute on function public.import_invoice_csv_idempotent(uuid, text, jsonb, text) to authenticated;
revoke execute on function public.import_invoice_csv(uuid, text, jsonb) from public, anon, authenticated;

create or replace function public.save_invoice_reply(
  p_firm_id uuid,
  p_invoice_id uuid,
  p_action_key text,
  p_reply_type text,
  p_summary text,
  p_promise_date date default null,
  p_pause_until date default null
) returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_timezone text;
  v_invoice public.invoices%rowtype;
  v_new_state text;
  v_day date;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_action_key is null or length(p_action_key) not between 1 and 160 then raise exception 'A valid action key is required'; end if;
  select timezone into v_timezone from public.firms
    where id = p_firm_id and owner_user_id = auth.uid() for update;
  if not found then raise exception 'Firm not found or access denied'; end if;
  select * into v_invoice from public.invoices where id = p_invoice_id and firm_id = p_firm_id for update;
  if not found then return jsonb_build_object('ok', false, 'reason', 'invoice_not_found'); end if;
  if p_reply_type not in ('promise','question','help','dispute','ooo','payment_claim','opt_out','other') then
    raise exception 'Unsupported reply type';
  end if;
  v_day := (now() at time zone v_timezone)::date;
  if p_reply_type = 'promise' and (p_promise_date is null or p_promise_date <= v_day) then
    raise exception 'A future promise date is required';
  end if;
  if p_reply_type = 'ooo' and (p_pause_until is null or p_pause_until <= v_day) then
    raise exception 'A future pause date is required';
  end if;
  insert into public.invoice_events (firm_id, invoice_id, event_type, action_key, summary, metadata)
  values (p_firm_id, p_invoice_id, 'reply_received', p_action_key, left(coalesce(p_summary, 'Client replied.'), 1000),
    jsonb_build_object('reply_type', p_reply_type, 'promise_date', p_promise_date, 'pause_until', p_pause_until))
  on conflict (firm_id, action_key) do nothing;
  if not found then return jsonb_build_object('ok', true, 'reason', 'duplicate_action'); end if;
  if v_invoice.status in ('paid','void') or v_invoice.amount_due <= 0 then
    return jsonb_build_object('ok', true, 'reason', 'invoice_already_closed');
  end if;
  v_new_state := case
    when p_reply_type = 'payment_claim' then 'needs_status_check'
    when p_reply_type in ('question','help','dispute','other') then 'needs_review'
    else 'paused'
  end;
  update public.invoices set
    outreach_state = v_new_state,
    promise_date = case when p_reply_type = 'promise' then p_promise_date else null end,
    pause_until = case when p_reply_type = 'promise' then p_promise_date when p_reply_type = 'ooo' then p_pause_until else null end,
    next_action_on = null,
    reply_memory = reply_memory || jsonb_build_array(jsonb_build_object(
      'date', v_day, 'reply_type', p_reply_type, 'summary', left(coalesce(p_summary, 'Client replied.'), 1000),
      'promise_date', p_promise_date, 'pause_until', p_pause_until
    )),
    last_action = case p_reply_type
      when 'promise' then 'Paused until promised payment date'
      when 'payment_claim' then 'Client says payment was sent; verify against fresh CSV'
      when 'opt_out' then 'Client opted out; outreach paused'
      else 'Client reply saved; human follow-up needed'
    end,
    updated_at = now()
  where id = p_invoice_id and firm_id = p_firm_id;
  return jsonb_build_object('ok', true, 'reason', 'saved', 'outreach_state', v_new_state);
end;
$$;

create or replace function public.resume_invoice_outreach(
  p_firm_id uuid,
  p_invoice_id uuid,
  p_action_key text
) returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_invoice public.invoices%rowtype;
  v_latest_import_id uuid;
  v_latest_imported_at timestamptz;
  v_covers_all boolean;
  v_timezone text;
  v_day date;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_action_key is null or length(p_action_key) not between 1 and 160 then raise exception 'A valid action key is required'; end if;
  select timezone into v_timezone from public.firms
    where id = p_firm_id and owner_user_id = auth.uid() for update;
  if not found then raise exception 'Firm not found or access denied'; end if;
  select id, imported_at, covers_all_invoices into v_latest_import_id, v_latest_imported_at, v_covers_all
    from public.invoice_imports where firm_id = p_firm_id order by imported_at desc, id desc limit 1;
  select * into v_invoice from public.invoices where id = p_invoice_id and firm_id = p_firm_id for update;
  if not found then return jsonb_build_object('ok', false, 'reason', 'invoice_not_found'); end if;
  if v_latest_import_id is null or not coalesce(v_covers_all,false) or v_latest_imported_at < now()-interval '24 hours'
    or v_invoice.last_import_id is distinct from v_latest_import_id then
    return jsonb_build_object('ok', false, 'reason', 'stale_snapshot');
  end if;
  if v_invoice.status <> 'unpaid' or v_invoice.amount_due <= 0 then
    return jsonb_build_object('ok', false, 'reason', 'already_paid_or_closed');
  end if;
  v_day := (now() at time zone v_timezone)::date;
  insert into public.invoice_events (firm_id, invoice_id, event_type, action_key, summary)
  values (p_firm_id, p_invoice_id, 'outreach_resumed', p_action_key, 'Firm resumed invoice follow-up.')
  on conflict (firm_id, action_key) do nothing;
  if not found then return jsonb_build_object('ok', true, 'reason', 'duplicate_action'); end if;
  update public.invoices set outreach_state='active', pause_until=null, promise_date=null,
    next_action_on=v_day+1, last_action='Follow-up resumed by staff', updated_at=now()
  where id=p_invoice_id and firm_id=p_firm_id;
  return jsonb_build_object('ok', true, 'reason', 'resumed', 'next_action_on', v_day+1);
end;
$$;

revoke all on function public.save_invoice_reply(uuid, uuid, text, text, text, date, date) from public, anon;
grant execute on function public.save_invoice_reply(uuid, uuid, text, text, text, date, date) to authenticated;
revoke all on function public.resume_invoice_outreach(uuid, uuid, text) from public, anon;
grant execute on function public.resume_invoice_outreach(uuid, uuid, text) to authenticated;
