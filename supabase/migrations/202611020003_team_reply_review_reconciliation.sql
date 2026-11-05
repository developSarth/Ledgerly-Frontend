-- Firm membership, least-privilege roles, reply resolution and delivery recovery.
-- Clio Activity audit metadata is added in 202611040001_clio_activity_audit.sql.

create table if not exists public.firm_members (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  user_id uuid not null unique references auth.users(id) on delete cascade,
  email text not null,
  role text not null check (role in ('admin','reviewer','sender','viewer')),
  status text not null default 'active' check (status in ('active','revoked')),
  invited_by uuid not null references auth.users(id),
  joined_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (firm_id,email)
);

create table if not exists public.firm_invitations (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  email text not null,
  role text not null check (role in ('admin','reviewer','sender','viewer')),
  token_hash text not null unique check (length(token_hash)=64),
  status text not null default 'pending' check (status in ('pending','accepted','revoked','expired')),
  invited_by uuid not null references auth.users(id),
  accepted_by uuid references auth.users(id),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  accepted_at timestamptz
);
create unique index if not exists firm_invitations_one_pending_email_idx
  on public.firm_invitations(firm_id,email) where status='pending';

create table if not exists public.contact_suppressions (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.firms(id) on delete cascade,
  email text not null,
  source_reply_id uuid references public.gmail_reply_intake(id) on delete set null,
  reason text not null check (length(reason) between 1 and 500),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  unique (firm_id,email)
);

alter table public.gmail_reply_intake drop constraint if exists gmail_reply_intake_status_check;
alter table public.gmail_reply_intake add constraint gmail_reply_intake_status_check
  check (status in ('needs_review','resolving','resolved'));
alter table public.gmail_reply_intake
  add column if not exists resolved_by uuid references auth.users(id),
  add column if not exists resolved_at timestamptz,
  add column if not exists resolution_note text check (resolution_note is null or length(resolution_note)<=500);

alter table public.firm_members enable row level security;
alter table public.firm_invitations enable row level security;
alter table public.contact_suppressions enable row level security;
revoke all on public.firm_members,public.firm_invitations,public.contact_suppressions
  from public,anon,authenticated;
grant all on public.firm_members,public.firm_invitations,public.contact_suppressions to service_role;

create or replace function public.current_firm_role(p_firm_id uuid)
returns text language sql stable security definer set search_path=''
as $$
  select case when f.owner_user_id=(select auth.uid()) then 'owner'
    else (select m.role from public.firm_members m where m.firm_id=f.id
      and m.user_id=(select auth.uid()) and m.status='active' limit 1)
  end
  from public.firms f where f.id=p_firm_id
$$;
create or replace function public.has_firm_role(p_firm_id uuid,p_roles text[])
returns boolean language sql stable security definer set search_path=''
as $$ select coalesce(public.current_firm_role(p_firm_id)=any(p_roles),false) $$;
revoke all on function public.current_firm_role(uuid),public.has_firm_role(uuid,text[]) from public,anon;
grant execute on function public.current_firm_role(uuid),public.has_firm_role(uuid,text[]) to authenticated,service_role;

drop policy if exists "Firm owner can read own firm" on public.firms;
drop policy if exists "Firm owner can update own firm" on public.firms;
create policy firm_members_read_firm on public.firms for select to authenticated
  using (public.has_firm_role(id,array['owner','admin','reviewer','sender','viewer']));
create policy firm_admin_update_firm on public.firms for update to authenticated
  using (public.has_firm_role(id,array['owner','admin']))
  with check (public.has_firm_role(id,array['owner','admin']));

drop policy if exists "Firm owner can read own imports" on public.invoice_imports;
drop policy if exists "Firm owner can add own imports" on public.invoice_imports;
drop policy if exists "Firm owner can update own import summaries" on public.invoice_imports;
create policy firm_members_read_imports on public.invoice_imports for select to authenticated
  using (public.has_firm_role(firm_id,array['owner','admin','reviewer','sender','viewer']));
create policy firm_admin_insert_imports on public.invoice_imports for insert to authenticated
  with check (uploaded_by=(select auth.uid()) and public.has_firm_role(firm_id,array['owner','admin']));
create policy firm_admin_update_imports on public.invoice_imports for update to authenticated
  using (public.has_firm_role(firm_id,array['owner','admin']))
  with check (public.has_firm_role(firm_id,array['owner','admin']));

drop policy if exists "Firm owner can read own invoices" on public.invoices;
drop policy if exists "Firm owner can add own invoices" on public.invoices;
drop policy if exists "Firm owner can update own invoices" on public.invoices;
create policy firm_members_read_invoices on public.invoices for select to authenticated
  using (public.has_firm_role(firm_id,array['owner','admin','reviewer','sender','viewer']));
create policy firm_admin_insert_invoices on public.invoices for insert to authenticated
  with check (public.has_firm_role(firm_id,array['owner','admin']));
create policy firm_admin_update_invoices on public.invoices for update to authenticated
  using (public.has_firm_role(firm_id,array['owner','admin']))
  with check (public.has_firm_role(firm_id,array['owner','admin']));

drop policy if exists "Firm owner can read own invoice events" on public.invoice_events;
drop policy if exists "Firm owner can add own invoice events" on public.invoice_events;
create policy firm_members_read_invoice_events on public.invoice_events for select to authenticated
  using (public.has_firm_role(firm_id,array['owner','admin','reviewer','sender','viewer']));
create policy firm_staff_insert_invoice_events on public.invoice_events for insert to authenticated
  with check (public.has_firm_role(firm_id,array['owner','admin','reviewer','sender'])
    and exists(select 1 from public.invoices i where i.id=invoice_id and i.firm_id=firm_id));
-- Event writes are performed only through the audited SECURITY DEFINER RPCs.
revoke insert,update,delete on public.invoice_events from authenticated;

drop policy if exists "Firm owner can read own workflow runs" on public.workflow_runs;
create policy firm_members_read_workflow_runs on public.workflow_runs for select to authenticated
  using (public.has_firm_role(firm_id,array['owner','admin','reviewer','sender','viewer']));

drop policy if exists "Firm owner can read own import requests" on public.invoice_import_requests;
drop policy if exists "Firm owner can add own import requests" on public.invoice_import_requests;
drop policy if exists "Firm owner can update own import requests" on public.invoice_import_requests;
create policy firm_members_read_import_requests on public.invoice_import_requests for select to authenticated
  using (public.has_firm_role(firm_id,array['owner','admin','reviewer','sender','viewer']));
create policy firm_admin_write_import_requests on public.invoice_import_requests for all to authenticated
  using (public.has_firm_role(firm_id,array['owner','admin']))
  with check (public.has_firm_role(firm_id,array['owner','admin']));

-- Preserve existing workflow validation while changing only its role gate.
do $$
declare r record; body text; roles_sql text;
begin
  for r in select * from (values
    ('public.import_invoice_csv(uuid,text,jsonb)'::regprocedure, array['owner','admin']::text[]),
    ('public.import_invoice_csv_idempotent(uuid,text,jsonb,text)'::regprocedure, array['owner','admin']::text[]),
    ('public.record_demo_outreach(uuid,uuid,text,text,date)'::regprocedure, array['owner','admin','sender']::text[]),
    ('public.save_invoice_reply(uuid,uuid,text,text,text,date,date)'::regprocedure, array['owner','admin','reviewer']::text[]),
    ('public.resume_invoice_outreach(uuid,uuid,text)'::regprocedure, array['owner','admin','reviewer']::text[]),
    ('public.enable_firm_automation(uuid)'::regprocedure, array['owner','admin']::text[]),
    ('public.record_email_delivery(uuid,uuid,uuid,text,timestamptz)'::regprocedure, array['owner','admin','sender']::text[])
  ) as x(signature,roles)
  loop
    body:=pg_get_functiondef(r.signature);
    select 'ARRAY['||string_agg(quote_literal(v),',')||']' into roles_sql from unnest(r.roles) v;
    body:=replace(body,'f.owner_user_id = auth.uid()','public.has_firm_role(p_firm_id,'||roles_sql||')');
    body:=replace(body,'f.owner_user_id=auth.uid()','public.has_firm_role(p_firm_id,'||roles_sql||')');
    body:=replace(body,'f.owner_user_id = (select auth.uid())','public.has_firm_role(p_firm_id,'||roles_sql||')');
    body:=replace(body,'f.owner_user_id=(select auth.uid())','public.has_firm_role(p_firm_id,'||roles_sql||')');
    body:=replace(body,'owner_user_id = auth.uid()','public.has_firm_role(p_firm_id,'||roles_sql||')');
    body:=replace(body,'owner_user_id=auth.uid()','public.has_firm_role(p_firm_id,'||roles_sql||')');
    body:=replace(body,'SECURITY INVOKER','SECURITY DEFINER');
    execute body;
  end loop;
end $$;

-- Invitation acceptance is one transaction, preventing a membership from being
-- activated while its one-use token remains pending after a partial failure.
create or replace function public.accept_firm_invitation(
  p_token_hash text,p_user_id uuid,p_email text
) returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_invite public.firm_invitations%rowtype;
begin
  select * into v_invite from public.firm_invitations
    where token_hash=p_token_hash and status='pending' and expires_at>now() for update;
  if not found then return jsonb_build_object('ok',false,'reason','invalid_or_expired'); end if;
  if lower(v_invite.email)<>lower(trim(p_email)) then
    return jsonb_build_object('ok',false,'reason','email_mismatch');
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text,0));
  if exists(select 1 from public.firms where owner_user_id=p_user_id)
    or exists(select 1 from public.firm_members where user_id=p_user_id and status='active'
      and firm_id<>v_invite.firm_id) then
    return jsonb_build_object('ok',false,'reason','already_in_another_firm');
  end if;
  insert into public.firm_members(firm_id,user_id,email,role,status,invited_by,joined_at,updated_at)
    values(v_invite.firm_id,p_user_id,lower(trim(p_email)),v_invite.role,'active',v_invite.invited_by,now(),now())
    on conflict(user_id) do update set firm_id=excluded.firm_id,email=excluded.email,
      role=excluded.role,status='active',invited_by=excluded.invited_by,joined_at=now(),updated_at=now();
  update public.firm_invitations set status='accepted',accepted_by=p_user_id,accepted_at=now()
    where id=v_invite.id;
  return jsonb_build_object('ok',true,'firm_id',v_invite.firm_id,'role',v_invite.role);
end $$;
revoke all on function public.accept_firm_invitation(text,uuid,text) from public,anon,authenticated;
grant execute on function public.accept_firm_invitation(text,uuid,text) to service_role;

create or replace function public.pause_invoice_for_inbound_reply(
  p_firm_id uuid,p_invoice_id uuid,p_gmail_message_id text,p_summary text
) returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_invoice public.invoices%rowtype; v_action text;
begin
  if not public.has_firm_role(p_firm_id,array['owner','admin','reviewer']) then
    raise exception 'Firm role cannot process inbound replies';
  end if;
  if p_gmail_message_id is null or length(p_gmail_message_id) not between 1 and 140 then
    raise exception 'Invalid Gmail message identifier';
  end if;
  v_action:='gmail-intake:'||p_gmail_message_id;
  select * into v_invoice from public.invoices where id=p_invoice_id and firm_id=p_firm_id for update;
  if not found then return jsonb_build_object('ok',false,'reason','invoice_not_found'); end if;
  insert into public.invoice_events(firm_id,invoice_id,event_type,action_key,summary,metadata)
  values(p_firm_id,p_invoice_id,'reply_received',v_action,left(coalesce(p_summary,'Client replied; staff review required.'),1000),
    jsonb_build_object('source','gmail_intake','requires_review',true))
  on conflict(firm_id,action_key) do nothing;
  if not found then return jsonb_build_object('ok',true,'reason','duplicate_action'); end if;
  if v_invoice.status='unpaid' and v_invoice.amount_due>0 then
    update public.invoices set outreach_state='needs_review',next_action_on=null,pause_until=null,
      last_action='Client reply received; staff review required',updated_at=now()
    where id=p_invoice_id and firm_id=p_firm_id;
  end if;
  return jsonb_build_object('ok',true,'reason','paused');
end $$;
revoke all on function public.pause_invoice_for_inbound_reply(uuid,uuid,text,text) from public,anon;
grant execute on function public.pause_invoice_for_inbound_reply(uuid,uuid,text,text) to authenticated,service_role;

create or replace function public.record_reply_resolution(
  p_firm_id uuid,p_invoice_id uuid,p_reply_id uuid,p_reply_type text,p_summary text,
  p_promise_date date default null,p_pause_until date default null
) returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_action_key text;
begin
  if not public.has_firm_role(p_firm_id,array['owner','admin','reviewer']) then
    raise exception 'Firm role cannot resolve replies';
  end if;
  if not exists(select 1 from public.gmail_reply_intake where id=p_reply_id
    and firm_id=p_firm_id and invoice_id=p_invoice_id) then
    return jsonb_build_object('ok',false,'reason','reply_not_found');
  end if;
  v_action_key:='gmail-resolve:'||p_reply_id::text;
  return public.save_invoice_reply(p_firm_id,p_invoice_id,v_action_key,p_reply_type,p_summary,p_promise_date,p_pause_until);
end $$;
revoke all on function public.record_reply_resolution(uuid,uuid,uuid,text,text,date,date) from public,anon;
grant execute on function public.record_reply_resolution(uuid,uuid,uuid,text,text,date,date) to authenticated,service_role;

comment on table public.firm_members is
  'One active Ledgerly membership per user. Owner is derived from firms.owner_user_id; other roles are admin, reviewer, sender, viewer.';
comment on table public.firm_invitations is
  'One-use, email-bound, expiring invitation tokens; only token hashes are stored.';
comment on table public.contact_suppressions is
  'Confirmed firm-wide email suppression list for opt-outs; no reminder can send to an active suppressed address.';
