-- FIX PERMISSIONS / CORREÇÃO DE PERMISSÕES

-- Disabling RLS on licenses to ensure they are visible
ALTER TABLE licenses DISABLE ROW LEVEL SECURITY;

-- If you prefer RLS enabled, run these instead (Optional):
-- ALTER TABLE licenses ENABLE ROW LEVEL SECURITY;
-- DROP POLICY IF EXISTS "Enable all access for all users" ON licenses;
-- CREATE POLICY "Enable all access for all users" ON licenses FOR ALL USING (true) WITH CHECK (true);

-- Ensure other tables are accessible too
ALTER TABLE resellers DISABLE ROW LEVEL SECURITY;
ALTER TABLE settings DISABLE ROW LEVEL SECURITY;
ALTER TABLE admins DISABLE ROW LEVEL SECURITY;
ALTER TABLE activity_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE blacklist DISABLE ROW LEVEL SECURITY;
