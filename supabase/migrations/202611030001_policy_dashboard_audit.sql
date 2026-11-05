-- Firm policy, trustworthy dashboard metrics, and operational audit trail.
-- All defaults are conservative and manual. No scheduled or automatic sending.

create table if not exists public.firm_workflow_policies (
  firm_id uuid primary key references public.firms(id) on delete cascade,
  snapshot_max_age_hours integer not null default 24 check (snapshot_max_age_hours between 1 and 72),
  initial_min_days_overdue integer not null default 0 check (initial_min_days_overdue between 0 and 90),
  gentle_interval_days integer not null default 7 check (gentle_interval_days between 1 and 90),
  firm_min_days_overdue integer not null default 21 check (firm_min_days_overdue between 7 and 180),
  send_window_start time not null default '09:00',
  send_window_end time not null default '17:00',
  weekdays_only boolean not null default true,
  require_distinct_approver_sender boolean not null default false,
  manual_send_required boolean not null default true check (manual_send_required),
  updated_by uuid,
  updated_at timestamptz not null default now(),
  check (send_window_start < send_window_end),
  check (firm_min_days_overdue >= initial_min_days_overdue)
);

create table if not exists public.ledgerly_audit_events (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  actor_user_id uuid,
  event_type text not null check (length(event_type) between 1 and 80),
  target_type text not null check (length(target_type) between 1 and 80),
  target_id text,
  summary text not null check (length(summary) between 1 and 500),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists ledgerly_audit_firm_created_idx
  on public.ledgerly_audit_events(firm_id, created_at desc);

create table if not exists public.invoice_paid_transitions (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  invoice_id uuid not null references public.invoices(id) on delete cascade,
  invoice_number text not null,
  balance_at_confirmation numeric(14,2) not null check (balance_at_confirmation >= 0),
  currency char(3) not null,
  source_system text not null,
  recorded_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
alter table public.workflow_deliveries
  add column if not exists sent_by uuid references auth.users(id),
  add column if not exists approved_by uuid references auth.users(id);
create index if not exists invoice_paid_transitions_firm_paid_idx
  on public.invoice_paid_transitions(firm_id, recorded_at desc);

alter table public.firm_workflow_policies enable row level security;
alter table public.ledgerly_audit_events enable row level security;
alter table public.invoice_paid_transitions enable row level security;
revoke all on public.firm_workflow_policies,public.ledgerly_audit_events,public.invoice_paid_transitions
  from public,anon,authenticated;
grant all on public.firm_workflow_policies,public.ledgerly_audit_events,public.invoice_paid_transitions to service_role;

-- Existing firms receive policy records; firm timezone remains the source of local time.
insert into public.firm_workflow_policies(firm_id)
select id from public.firms on conflict (firm_id) do nothing;

create or replace function public.create_default_firm_workflow_policy()
returns trigger language plpgsql security definer set search_path=''
as $$
begin
  insert into public.firm_workflow_policies(firm_id) values(new.id) on conflict(firm_id) do nothing;
  return new;
end $$;
drop trigger if exists firms_create_default_workflow_policy on public.firms;
create trigger firms_create_default_workflow_policy after insert on public.firms
  for each row execute function public.create_default_firm_workflow_policy();

create or replace function public.set_firm_workflow_policy(
  p_firm_id uuid,
  p_snapshot_max_age_hours integer,
  p_initial_min_days_overdue integer,
  p_gentle_interval_days integer,
  p_firm_min_days_overdue integer,
  p_send_window_start time,
  p_send_window_end time,
  p_weekdays_only boolean,
  p_require_distinct_approver_sender boolean
) returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_actor uuid := auth.uid(); v_policy public.firm_workflow_policies%rowtype;
begin
  if v_actor is null or not public.has_firm_role(p_firm_id,array['owner','admin']) then
    raise exception 'Only firm owners and administrators can change workflow policy';
  end if;
  if p_snapshot_max_age_hours not between 1 and 72
    or p_initial_min_days_overdue not between 0 and 90
    or p_gentle_interval_days not between 1 and 90
    or p_firm_min_days_overdue not between 7 and 180
    or p_firm_min_days_overdue < p_initial_min_days_overdue
    or p_send_window_start is null or p_send_window_end is null
    or p_send_window_start >= p_send_window_end then
    raise exception 'Workflow policy values are invalid';
  end if;
  insert into public.firm_workflow_policies(
    firm_id,snapshot_max_age_hours,initial_min_days_overdue,gentle_interval_days,
    firm_min_days_overdue,send_window_start,send_window_end,weekdays_only,
    require_distinct_approver_sender,manual_send_required,updated_by,updated_at
  ) values (
    p_firm_id,p_snapshot_max_age_hours,p_initial_min_days_overdue,p_gentle_interval_days,
    p_firm_min_days_overdue,p_send_window_start,p_send_window_end,p_weekdays_only,
    p_require_distinct_approver_sender,true,v_actor,now()
  ) on conflict(firm_id) do update set
    snapshot_max_age_hours=excluded.snapshot_max_age_hours,
    initial_min_days_overdue=excluded.initial_min_days_overdue,
    gentle_interval_days=excluded.gentle_interval_days,
    firm_min_days_overdue=excluded.firm_min_days_overdue,
    send_window_start=excluded.send_window_start,
    send_window_end=excluded.send_window_end,
    weekdays_only=excluded.weekdays_only,
    require_distinct_approver_sender=excluded.require_distinct_approver_sender,
    manual_send_required=true,updated_by=v_actor,updated_at=now()
  returning * into v_policy;
  insert into public.ledgerly_audit_events(firm_id,actor_user_id,event_type,target_type,target_id,summary,metadata)
  values(p_firm_id,v_actor,'workflow_policy_updated','firm',p_firm_id::text,
    'Firm reminder and approval policy updated.',jsonb_build_object(
      'snapshot_max_age_hours',v_policy.snapshot_max_age_hours,
      'initial_min_days_overdue',v_policy.initial_min_days_overdue,
      'gentle_interval_days',v_policy.gentle_interval_days,
      'firm_min_days_overdue',v_policy.firm_min_days_overdue,
      'send_window_start',v_policy.send_window_start,
      'send_window_end',v_policy.send_window_end,
      'weekdays_only',v_policy.weekdays_only,
      'require_distinct_approver_sender',v_policy.require_distinct_approver_sender,
      'manual_send_required',true));
  return to_jsonb(v_policy);
end $$;
revoke all on function public.set_firm_workflow_policy(uuid,integer,integer,integer,integer,time,time,boolean,boolean) from public,anon;
grant execute on function public.set_firm_workflow_policy(uuid,integer,integer,integer,integer,time,time,boolean,boolean) to authenticated;

create or replace function public.reinstate_contact_suppression(
  p_firm_id uuid,p_email text,p_reason text
) returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_actor uuid := auth.uid(); v_email text := lower(trim(coalesce(p_email,'')));
  v_reason text := trim(coalesce(p_reason,'')); v_count integer;
begin
  if v_actor is null or not public.has_firm_role(p_firm_id,array['owner','admin']) then
    raise exception 'Only firm owners and administrators can reinstate a suppressed contact';
  end if;
  if v_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' or length(v_reason) < 10 or length(v_reason) > 500 then
    raise exception 'A valid email and a 10 to 500 character correction reason are required';
  end if;
  delete from public.contact_suppressions where firm_id=p_firm_id and email=v_email;
  get diagnostics v_count = row_count;
  if v_count=0 then return jsonb_build_object('reinstated',false,'reason','not_suppressed'); end if;
  insert into public.ledgerly_audit_events(firm_id,actor_user_id,event_type,target_type,target_id,summary,metadata)
  values(p_firm_id,v_actor,'contact_suppression_reinstated','contact',v_email,
    'Firm-wide contact suppression removed after documented review.',jsonb_build_object('reason',v_reason));
  return jsonb_build_object('reinstated',true,'email',v_email);
end $$;
revoke all on function public.reinstate_contact_suppression(uuid,text,text) from public,anon;
grant execute on function public.reinstate_contact_suppression(uuid,text,text) to authenticated;

-- Capture authoritative unpaid → paid status transitions going forward. A
-- balance reduction by itself may be a credit/adjustment, not a payment.
create or replace function public.capture_invoice_payment_transition()
returns trigger language plpgsql security definer set search_path=''
as $$
declare v_event_id uuid;
begin
  if old.status <> 'paid' and new.status = 'paid' and old.amount_due > 0 then
    insert into public.invoice_paid_transitions(
      firm_id,invoice_id,invoice_number,balance_at_confirmation,currency,source_system,recorded_at
    ) values (
      new.firm_id,new.id,new.invoice_number,old.amount_due,
      new.currency::char(3),coalesce(new.source_system,'unknown'),now()
    ) returning id into v_event_id;
    insert into public.invoice_events(firm_id,invoice_id,event_type,action_key,summary,metadata)
      values(new.firm_id,new.id,'payment_confirmed','payment-transition:'||v_event_id::text,
        'Invoice marked paid by an authoritative source transition.',
        jsonb_build_object('balance_at_confirmation',old.amount_due,'currency',new.currency,'source_system',coalesce(new.source_system,'unknown')));
  end if;
  return new;
end $$;
drop trigger if exists invoices_capture_payment_transition on public.invoices;
create trigger invoices_capture_payment_transition
  after update of status,amount_due on public.invoices
  for each row execute function public.capture_invoice_payment_transition();

create or replace function public.prevent_ledgerly_history_mutation()
returns trigger language plpgsql set search_path=''
as $$ begin
  if pg_trigger_depth()>1 then return old; end if;
  raise exception 'Ledgerly audit and payment history is append-only';
end $$;
drop trigger if exists ledgerly_audit_events_append_only on public.ledgerly_audit_events;
create trigger ledgerly_audit_events_append_only before update or delete on public.ledgerly_audit_events
  for each row execute function public.prevent_ledgerly_history_mutation();
drop trigger if exists invoice_paid_transitions_append_only on public.invoice_paid_transitions;
create trigger invoice_paid_transitions_append_only before update or delete on public.invoice_paid_transitions
  for each row execute function public.prevent_ledgerly_history_mutation();

-- Make intake decisions part of the same transaction as their audit event.
create or replace function public.record_invoice_review(
  p_firm_id uuid,p_invoice_id uuid,p_decision text
) returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_invoice public.invoices%rowtype; v_outreach_state text; v_actor uuid := auth.uid();
begin
  if v_actor is null then raise exception 'Authentication required'; end if;
  if p_decision is null or p_decision not in ('approved','rejected','pending') then raise exception 'Invalid invoice decision'; end if;
  if not public.has_firm_role(p_firm_id,array['owner','admin','reviewer']) then raise exception 'Firm role cannot review invoices'; end if;
  select * into v_invoice from public.invoices where id=p_invoice_id and firm_id=p_firm_id for update;
  if not found then raise exception 'Invoice not found in this firm'; end if;
  if v_invoice.status<>'unpaid' or v_invoice.amount_due<=0 then raise exception 'Only open unpaid invoices can be reviewed'; end if;
  if v_invoice.first_contacted_on is not null or exists(
      select 1 from public.workflow_deliveries d where d.invoice_id=p_invoice_id and d.firm_id=p_firm_id and d.status in ('sending','sent','delivery_unknown')
    ) or exists(select 1 from public.gmail_reply_intake r where r.invoice_id=p_invoice_id and r.firm_id=p_firm_id) then
    raise exception 'An invoice with prior outreach or replies cannot be changed by invoice review';
  end if;
  if p_decision='rejected' and exists(select 1 from public.workflow_runs w where w.invoice_id=p_invoice_id and w.firm_id=p_firm_id and w.status in ('running','awaiting_review','approved_pending_delivery','sending')) then
    raise exception 'Discard or reconcile the active reminder workflow before rejecting this invoice';
  end if;
  v_outreach_state:=case when p_decision='rejected' then 'closed' when v_invoice.outreach_state='closed' then 'new' else v_invoice.outreach_state end;
  update public.invoices set staff_review_status=p_decision,
    staff_reviewed_by=case when p_decision='pending' then null else v_actor end,
    staff_reviewed_at=case when p_decision='pending' then null else now() end,
    outreach_state=v_outreach_state,
    last_action=case p_decision when 'approved' then 'Invoice approved by staff' when 'rejected' then 'Invoice rejected by staff' else 'Invoice restored to review by staff' end,
    updated_at=now() where id=p_invoice_id and firm_id=p_firm_id;
  insert into public.ledgerly_audit_events(firm_id,actor_user_id,event_type,target_type,target_id,summary,metadata)
    values(p_firm_id,v_actor,'invoice_'||p_decision,'invoice',p_invoice_id::text,
      'Invoice intake review decision recorded.',jsonb_build_object('invoice_number',v_invoice.invoice_number,'decision',p_decision));
  return jsonb_build_object('ok',true,'invoice_id',p_invoice_id,'review_status',p_decision,'outreach_state',v_outreach_state);
end $$;
revoke all on function public.record_invoice_review(uuid,uuid,text) from public,anon;
grant execute on function public.record_invoice_review(uuid,uuid,text) to authenticated;

comment on table public.firm_workflow_policies is
  'Owner/admin-managed firm reminder rules. Sending remains manual and human-approved.';
comment on table public.ledgerly_audit_events is
  'Append-only administrative and operational audit events; contains no message bodies or OAuth secrets.';
comment on table public.invoice_paid_transitions is
  'Authoritative unpaid-to-paid status transitions captured from invoice sync/imports after migration; not a payment transaction ledger.';
