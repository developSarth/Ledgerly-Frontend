-- Invoice-level approve/reject and deliberately guarded invoice deletion.
-- Deletion is only allowed when no workflow, delivery, reply, or audit rows
-- depend on the invoice, so unrelated history is never cascaded away.

alter table public.invoices
  add column if not exists staff_review_status text not null default 'pending',
  add column if not exists staff_reviewed_by uuid references auth.users(id),
  add column if not exists staff_reviewed_at timestamptz;

alter table public.invoices drop constraint if exists invoices_staff_review_status_check;
alter table public.invoices add constraint invoices_staff_review_status_check
  check (staff_review_status in ('pending','approved','rejected'));
-- Keep invoices already contacted under the prior workflow from being sent
-- back through a new intake decision after this migration is applied.
update public.invoices set staff_review_status='approved'
  where first_contacted_on is not null or outreach_state='active';

create or replace function public.record_invoice_review(
  p_firm_id uuid,p_invoice_id uuid,p_decision text
) returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_invoice public.invoices%rowtype; v_outreach_state text;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_decision is null or p_decision not in ('approved','rejected','pending') then raise exception 'Invalid invoice decision'; end if;
  if not public.has_firm_role(p_firm_id,array['owner','admin','reviewer']) then
    raise exception 'Firm role cannot review invoices';
  end if;
  select * into v_invoice from public.invoices
    where id=p_invoice_id and firm_id=p_firm_id for update;
  if not found then raise exception 'Invoice not found in this firm'; end if;
  if v_invoice.status<>'unpaid' or v_invoice.amount_due<=0 then
    raise exception 'Only open unpaid invoices can be reviewed';
  end if;
  if v_invoice.first_contacted_on is not null or exists(
      select 1 from public.workflow_deliveries d where d.invoice_id=p_invoice_id
        and d.firm_id=p_firm_id and d.status in ('sending','sent','delivery_unknown')
    ) or exists(
      select 1 from public.gmail_reply_intake r where r.invoice_id=p_invoice_id and r.firm_id=p_firm_id
    ) then
    raise exception 'An invoice with prior outreach or replies cannot be changed by invoice review';
  end if;
  if p_decision='rejected' and exists(
      select 1 from public.workflow_runs w where w.invoice_id=p_invoice_id
        and w.firm_id=p_firm_id and w.status in ('running','awaiting_review','approved_pending_delivery','sending')
    ) then
    raise exception 'Discard or reconcile the active reminder workflow before rejecting this invoice';
  end if;
  v_outreach_state:=case
    when p_decision='rejected' then 'closed'
    when v_invoice.outreach_state='closed' then 'new'
    else v_invoice.outreach_state
  end;
  update public.invoices set staff_review_status=p_decision,
    staff_reviewed_by=case when p_decision='pending' then null else auth.uid() end,
    staff_reviewed_at=case when p_decision='pending' then null else now() end,
    outreach_state=v_outreach_state,
    last_action=case p_decision
      when 'approved' then 'Invoice approved by staff'
      when 'rejected' then 'Invoice rejected by staff'
      else 'Invoice restored to review by staff'
    end,
    updated_at=now()
  where id=p_invoice_id and firm_id=p_firm_id;
  return jsonb_build_object('ok',true,'invoice_id',p_invoice_id,
    'review_status',p_decision,'outreach_state',v_outreach_state);
end $$;

create or replace function public.delete_invoice_records(
  p_firm_id uuid,p_invoice_ids uuid[]
) returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_id uuid; v_deleted jsonb:='[]'::jsonb; v_blocked jsonb:='[]'::jsonb;
  v_missing jsonb:='[]'::jsonb; v_reason text;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if not public.has_firm_role(p_firm_id,array['owner','admin']) then
    raise exception 'Firm role cannot delete invoices';
  end if;
  if p_invoice_ids is null or cardinality(p_invoice_ids)=0 or cardinality(p_invoice_ids)>500 then
    raise exception 'Select between 1 and 500 invoices';
  end if;
  for v_id in select distinct u.invoice_id from unnest(p_invoice_ids) as u(invoice_id) order by u.invoice_id loop
    perform 1 from public.invoices i where i.id=v_id and i.firm_id=p_firm_id for update;
    if not found then
      v_missing:=v_missing||jsonb_build_array(jsonb_build_object('id',v_id,'reason','not found'));
      continue;
    end if;
    v_reason:=null;
    if exists(select 1 from public.workflow_deliveries d where d.invoice_id=v_id and d.firm_id=p_firm_id)
      or exists(select 1 from public.gmail_reply_intake r where r.invoice_id=v_id and r.firm_id=p_firm_id)
      or exists(select 1 from public.invoice_events e where e.invoice_id=v_id and e.firm_id=p_firm_id)
      or exists(select 1 from public.workflow_runs w where w.invoice_id=v_id and w.firm_id=p_firm_id) then
      v_reason:='Linked workflow or activity history exists; record retained for audit.';
    end if;
    if v_reason is not null then
      v_blocked:=v_blocked||jsonb_build_array(jsonb_build_object('id',v_id,'reason',v_reason));
    else
      delete from public.invoices where id=v_id and firm_id=p_firm_id;
      v_deleted:=v_deleted||jsonb_build_array(v_id);
    end if;
  end loop;
  return jsonb_build_object('deleted_ids',v_deleted,'blocked',v_blocked,'not_found',v_missing);
end $$;

revoke all on function public.record_invoice_review(uuid,uuid,text) from public,anon;
revoke all on function public.delete_invoice_records(uuid,uuid[]) from public,anon;
grant execute on function public.record_invoice_review(uuid,uuid,text) to authenticated;
grant execute on function public.delete_invoice_records(uuid,uuid[]) to authenticated;

comment on column public.invoices.staff_review_status is
  'Staff approval decision for invoice intake; distinct from reminder-draft approval.';
comment on function public.delete_invoice_records(uuid,uuid[]) is
  'Firm-owner/admin deletion that refuses invoices with workflow, delivery, reply, or event history.';
