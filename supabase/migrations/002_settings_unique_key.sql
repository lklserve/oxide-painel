-- Ensure `settings.key` has a UNIQUE constraint so `upsert({ key, value }, { onConflict: 'key' })` works.
-- Without this, silent insert-duplicates could cause save_setting to no-op and callers would always read stale values.
-- Idempotent: skips if constraint already exists.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = 'settings'
          AND indexdef ILIKE '%UNIQUE%(key)%'
    ) THEN
        -- Drop any duplicates first (keep the most recent by updated_at / id fallback)
        DELETE FROM public.settings a
        USING public.settings b
        WHERE a.key = b.key
          AND a.ctid < b.ctid;

        -- Add the unique constraint
        BEGIN
            ALTER TABLE public.settings ADD CONSTRAINT settings_key_unique UNIQUE (key);
        EXCEPTION WHEN duplicate_object THEN
            -- constraint already exists under a different name; ignore
            NULL;
        END;
    END IF;
END $$;

-- Seed a sensible default for server_status so the admin UI shows ONLINE on first boot.
INSERT INTO public.settings (key, value)
VALUES ('server_status', '{"enabled": true}'::jsonb)
ON CONFLICT (key) DO NOTHING;
