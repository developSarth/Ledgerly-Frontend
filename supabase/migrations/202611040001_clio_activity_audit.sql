-- Add a separate, idempotent audit Activity after an approved email is sent.
-- Activities are always non-billable/no-charge; no Bill or charge is created.
alter table public.workflow_deliveries
  add column if not exists clio_activity_status text not null default 'not_attempted'
    check (clio_activity_status in ('not_attempted','logged','skipped_no_matter','failed','unknown')),
  add column if not exists clio_activity_id text,
  add column if not exists clio_activity_marker text,
  add column if not exists clio_activity_updated_at timestamptz;

create index if not exists workflow_deliveries_firm_activity_status_idx
  on public.workflow_deliveries(firm_id, clio_activity_status, updated_at desc);

comment on column public.workflow_deliveries.clio_activity_status is
  'Status of the separate non-billable, no-charge Clio TimeEntry audit record. Never a bill or payable activity.';
comment on column public.workflow_deliveries.clio_activity_marker is
  'Deterministic Ledgerly workflow marker used to reconcile an ambiguous Clio Activity create without duplicating it.';

-- The current application no longer calls the simulation/automation RPCs.
-- Keep their definitions for historical compatibility, but remove the
-- authenticated entry points. record_reply_resolution may call the internal
-- save_invoice_reply function as its SECURITY DEFINER owner.
revoke all on function public.record_demo_outreach(uuid,uuid,text,text,date)
  from public, anon, authenticated;
revoke all on function public.save_invoice_reply(uuid,uuid,text,text,text,date,date)
  from public, anon, authenticated;
revoke all on function public.enable_firm_automation(uuid)
  from public, anon, authenticated;

comment on function public.record_demo_outreach(uuid,uuid,text,text,date) is
  'Retired Ledgerly simulation RPC. Execution revoked from public browser roles.';
comment on function public.enable_firm_automation(uuid) is
  'Retired Ledgerly automatic-sending RPC. Execution revoked from public browser roles.';
