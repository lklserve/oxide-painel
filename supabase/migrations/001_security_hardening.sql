-- =====================================================================
-- LKL — Security Hardening Migration
-- Run ONCE in Supabase SQL Editor after deploying the new application code.
-- Idempotent: safe to re-run (CREATE TABLE IF NOT EXISTS + CREATE OR REPLACE FUNCTION).
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Session tables for cookie-based authentication.
-- ---------------------------------------------------------------------

-- Admin dashboard sessions (painel-revendedor /admin/secret-dashboard)
create table if not exists public.admin_dashboard_sessions (
    token text primary key,
    ip text,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);
create index if not exists admin_dashboard_sessions_expires_at_idx on public.admin_dashboard_sessions(expires_at);

-- Reseller sessions (painel-revendedor reseller login)
create table if not exists public.reseller_sessions (
    token text primary key,
    reseller_id uuid not null references public.resellers(id) on delete cascade,
    ip text,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);
create index if not exists reseller_sessions_reseller_idx on public.reseller_sessions(reseller_id);
create index if not exists reseller_sessions_expires_at_idx on public.reseller_sessions(expires_at);

-- RLS (service role bypasses; deny by default for anon)
alter table public.admin_dashboard_sessions enable row level security;
alter table public.reseller_sessions enable row level security;

-- ---------------------------------------------------------------------
-- 2. Atomic license issuance for resellers.
--    Deducts balance, inserts license, logs transaction in a single TX.
-- ---------------------------------------------------------------------
create or replace function public.reseller_issue_license(
    p_reseller_id uuid,
    p_cost numeric,
    p_license_key text,
    p_duration_type text,
    p_expires_at timestamptz,
    p_max_ips integer,
    p_client_name text,
    p_whatsapp text
) returns table(new_balance numeric, license_id uuid)
language plpgsql
security definer
set search_path = public
as $$
declare
    v_current numeric;
    v_is_active boolean;
    v_new_balance numeric;
    v_license_id uuid;
begin
    -- Lock reseller row
    select coalesce(balance, 0), coalesce(is_active, false)
      into v_current, v_is_active
      from public.resellers
     where id = p_reseller_id
     for update;

    if not found then
        raise exception 'Reseller not found';
    end if;

    if not v_is_active then
        raise exception 'Reseller inactive';
    end if;

    if v_current < p_cost then
        raise exception 'Insufficient balance';
    end if;

    v_new_balance := v_current - p_cost;

    update public.resellers
       set balance = v_new_balance
     where id = p_reseller_id;

    insert into public.licenses (
        license_key, status, duration_type, expires_at, reseller_id,
        created_at, max_ips, used_ips, client_name, whatsapp
    ) values (
        p_license_key, 'active', p_duration_type, p_expires_at, p_reseller_id,
        now(), p_max_ips, '[]'::jsonb, p_client_name, p_whatsapp
    )
    returning id into v_license_id;

    if p_cost > 0 then
        insert into public.credit_transactions (
            reseller_id, amount, type, description, created_at
        ) values (
            p_reseller_id, -p_cost, 'deduct',
            'Created key ' || p_license_key || ' (' || p_duration_type || ')',
            now()
        );
    end if;

    return query select v_new_balance, v_license_id;
end;
$$;

grant execute on function public.reseller_issue_license(uuid, numeric, text, text, timestamptz, integer, text, text) to service_role;

-- ---------------------------------------------------------------------
-- 3. Atomic credit adjustment for admin dashboard.
-- ---------------------------------------------------------------------
create or replace function public.admin_adjust_reseller_balance(
    p_reseller_id uuid,
    p_amount numeric,
    p_type text,
    p_description text
) returns numeric
language plpgsql
security definer
set search_path = public
as $$
declare
    v_current numeric;
    v_new_balance numeric;
    v_delta numeric;
begin
    select coalesce(balance, 0) into v_current
      from public.resellers
     where id = p_reseller_id
     for update;

    if not found then
        raise exception 'Reseller not found';
    end if;

    if p_type = 'add' then
        v_new_balance := v_current + p_amount;
        v_delta := p_amount;
    elsif p_type = 'deduct' then
        v_new_balance := v_current - p_amount;
        v_delta := -p_amount;
    elsif p_type = 'reset' then
        v_new_balance := p_amount;
        v_delta := p_amount - v_current;
    else
        raise exception 'Invalid type';
    end if;

    update public.resellers
       set balance = v_new_balance
     where id = p_reseller_id;

    insert into public.credit_transactions (
        reseller_id, amount, type, description, created_at
    ) values (
        p_reseller_id, v_delta, p_type, coalesce(p_description, 'Manual ' || p_type), now()
    );

    return v_new_balance;
end;
$$;

grant execute on function public.admin_adjust_reseller_balance(uuid, numeric, text, text) to service_role;

-- ---------------------------------------------------------------------
-- 4. Case-insensitive username uniqueness for admins.
--    Run once to normalize and enforce lowercase usernames.
-- ---------------------------------------------------------------------
do $$
begin
    if exists (select 1 from information_schema.tables where table_schema='public' and table_name='admins') then
        update public.admins set username = lower(username) where username <> lower(username);
        create unique index if not exists admins_username_lower_uidx on public.admins ((lower(username)));
    end if;
end $$;

-- ---------------------------------------------------------------------
-- 5. Optional: scheduled cleanup of expired sessions.
--    Requires pg_cron extension (enable in Supabase dashboard first).
-- ---------------------------------------------------------------------
-- select cron.schedule('lkl_cleanup_sessions', '0 * * * *', $$
--     delete from public.admin_dashboard_sessions where expires_at < now();
--     delete from public.reseller_sessions where expires_at < now();
--     delete from public.admin_sessions where expires_at < now();
-- $$);
