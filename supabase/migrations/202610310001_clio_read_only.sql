-- Clio Manage read-only connection and snapshot metadata.
-- OAuth tokens are encrypted by the backend and only the server service role
-- can read the ciphertext. They are never returned to the browser.

alter table public.invoice_imports
  add column if not exists source_system text not null default 'csv'
    check (source_system in ('csv', 'clio')),
  add column if not exists ignored_rows integer not null default 0
    check (ignored_rows >= 0);

alter table public.invoices
  alter column client_email drop not null,
  add column if not exists source_system text not null default 'csv'
    check (source_system in ('csv', 'clio')),
  add column if not exists clio_bill_id text;

create unique index if not exists invoices_firm_clio_bill_idx
  on public.invoices (firm_id, clio_bill_id)
  where clio_bill_id is not null;

create table if not exists public.clio_oauth_states (
  state_hash text primary key check (length(state_hash) = 64),
  firm_id uuid not null references public.firms(id) on delete cascade,
  initiated_by uuid not null references auth.users(id) on delete cascade,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists clio_oauth_states_expiry_idx
  on public.clio_oauth_states (expires_at);

create table if not exists public.clio_connections (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null unique references public.firms(id) on delete cascade,
  clio_user_id text not null,
  clio_user_name text not null default '',
  region text not null check (region in ('us', 'eu', 'ca', 'au')),
  encrypted_access_token text not null,
  encrypted_refresh_token text not null,
  access_token_expires_at timestamptz not null,
  connected_by uuid not null references auth.users(id),
  connected_at timestamptz not null default now(),
  last_synced_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.clio_oauth_states enable row level security;
alter table public.clio_connections enable row level security;
revoke all on public.clio_oauth_states from public, anon, authenticated;
revoke all on public.clio_connections from public, anon, authenticated;
grant all on public.clio_oauth_states to service_role;
grant all on public.clio_connections to service_role;

create or replace function public.set_invoice_source_from_import()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_source text;
begin
  if new.last_import_id is null then
    return new;
  end if;

  select i.source_system into v_source
  from public.invoice_imports i
  where i.id = new.last_import_id and i.firm_id = new.firm_id;

  if v_source is not null then
    new.source_system := v_source;
    if v_source = 'csv' then
      new.clio_bill_id := null;
    end if;
  end if;
  return new;
end;
$$;

revoke all on function public.set_invoice_source_from_import() from public, anon, authenticated;

drop trigger if exists invoices_source_from_import on public.invoices;
create trigger invoices_source_from_import
before insert or update of last_import_id on public.invoices
for each row execute function public.set_invoice_source_from_import();

comment on table public.clio_connections is
  'One server-side Clio Manage OAuth connection per Ledgerly firm; token columns contain Fernet ciphertext only.';
comment on table public.clio_oauth_states is
  'Short-lived, one-use Clio OAuth state records; accessible only through the backend service role.';
