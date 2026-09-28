-- =====================================================================
-- LKL — Add "created_by" to licenses (who generated the key)
-- Run ONCE in Supabase SQL Editor.
-- Idempotent: safe to re-run.
-- =====================================================================

-- Stores the display name of whoever generated the key:
--   - admin username (manual creation via dashboard)
--   - 'System (Webhook)' for automatic sales
--   - reseller name is still resolved from reseller_id on the frontend
alter table public.licenses add column if not exists created_by text;

-- Backfill from activity_logs where possible (best-effort).
-- Robust to schema differences: activity_logs may or may not have a
-- dedicated "license_key" column, so we match via the details JSONB
-- ('key' or 'license_key'), and additionally use the column when present.
do $$
begin
    if exists (select 1 from information_schema.tables
               where table_schema='public' and table_name='activity_logs') then

        -- Match by details->>'key' / details->>'license_key' (always available).
        update public.licenses l
           set created_by = sub.admin_name
          from (
              select distinct on (k) k, admin_name
                from (
                    select admin_name, timestamp,
                           coalesce(details->>'key', details->>'license_key') as k
                      from public.activity_logs
                     where action = 'KEY_CREATE'
                ) x
               where k is not null
               order by k, timestamp asc
          ) sub
         where l.license_key = sub.k
           and l.created_by is null;

        -- If activity_logs also has a real "license_key" column, use it too.
        if exists (select 1 from information_schema.columns
                   where table_schema='public' and table_name='activity_logs'
                     and column_name='license_key') then
            update public.licenses l
               set created_by = sub.admin_name
              from (
                  select distinct on (license_key) license_key, admin_name
                    from public.activity_logs
                   where action = 'KEY_CREATE' and license_key is not null
                   order by license_key, timestamp asc
              ) sub
             where l.license_key = sub.license_key
               and l.created_by is null;
        end if;
    end if;
end $$;

-- Mark automatic sales that came through the webhook.
update public.licenses
   set created_by = 'System (Webhook)'
 where created_by is null
   and order_id is not null;
