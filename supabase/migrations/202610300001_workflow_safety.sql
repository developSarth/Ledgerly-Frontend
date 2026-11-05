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
