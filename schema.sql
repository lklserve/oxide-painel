-- Create the table for licenses (if it doesn't exist)
CREATE TABLE IF NOT EXISTS licenses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_key TEXT UNIQUE NOT NULL,
    client_username TEXT,
    client_password TEXT,
    whatsapp TEXT,
    status TEXT CHECK (status IN ('active', 'banned', 'expired', 'frozen')),
    duration_type TEXT CHECK (duration_type IN ('daily', 'weekly', 'monthly', 'permanent', 'custom')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    locked_ip TEXT, -- Deprecated in favor of used_ips
    max_ips INTEGER DEFAULT 1,
    used_ips JSONB DEFAULT '[]'::jsonb
);

-- Ensure columns exist (safe to run even if table exists)
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS whatsapp TEXT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS client_username TEXT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS client_password TEXT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS max_ips INTEGER DEFAULT 1;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS used_ips JSONB DEFAULT '[]'::jsonb;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS order_id TEXT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS created_by TEXT;

-- Create settings table for global server status
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value JSONB
);

-- Insert default server status if not exists
INSERT INTO settings (key, value) VALUES ('server_status', '{"enabled": true}') ON CONFLICT DO NOTHING;
INSERT INTO settings (key, value) VALUES ('global_message', '{"message": "Bem-vindo ao LKL XIT", "active": true}') ON CONFLICT DO NOTHING;

-- Create an index on license_key for faster lookups
CREATE INDEX IF NOT EXISTS idx_license_key ON licenses(license_key);

-- Row Level Security (RLS) — NAO e opcional.
-- 🔴 As policies aqui eram `USING (true) WITH CHECK (true)`: RLS ligado, porta
-- escancarada. Qualquer um com a chave anon (publica por design, e vazada no
-- historico do Git) lia `licenses` e `admins` inteiras. Agora so service_role
-- entra -- que e exatamente o que os endpoints em api/ usam.
ALTER TABLE licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;

-- Drop policy if exists to avoid error on recreation
DROP POLICY IF EXISTS "service_role_full_access" ON licenses;
DROP POLICY IF EXISTS "service_role_full_access" ON settings;

CREATE POLICY "service_role_full_access" ON licenses
FOR ALL USING (auth.role() = 'service_role') WITH CHECK (auth.role() = 'service_role');


CREATE POLICY "service_role_full_access" ON settings
FOR ALL USING (auth.role() = 'service_role') WITH CHECK (auth.role() = 'service_role');

-- ==========================================
-- UPDATE 2.0: SECURITY & MANAGEMENT TABLES
-- ==========================================

-- 1. Admins Table (Secure Login)
CREATE TABLE IF NOT EXISTS admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL, -- Storing plain text as requested for simple migration, ideally hash it.
    role TEXT DEFAULT 'admin',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default admins if empty
INSERT INTO admins (username, password) VALUES 
('King', 'Rtydfgxc5202@'),
('Lee', 'Lee53k'),
('Leon', 'Leon5202')
ON CONFLICT (username) DO NOTHING;

-- 2. Activity Logs (Audit)
CREATE TABLE IF NOT EXISTS activity_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_name TEXT,
    action TEXT, -- e.g. "CREATED_KEY", "RESET_HWID"
    details JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Blacklist (Banned Devices)
CREATE TABLE IF NOT EXISTS blacklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id TEXT UNIQUE NOT NULL,
    reason TEXT,
    blocked_by TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Policies for new tables
ALTER TABLE admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE blacklist ENABLE ROW LEVEL SECURITY;

-- Drop policies if they exist to avoid errors
DROP POLICY IF EXISTS "service_role_full_access" ON admins;
DROP POLICY IF EXISTS "service_role_full_access" ON activity_logs;
DROP POLICY IF EXISTS "service_role_full_access" ON blacklist;

CREATE POLICY "service_role_full_access" ON admins FOR ALL USING (auth.role() = 'service_role') WITH CHECK (auth.role() = 'service_role');
CREATE POLICY "service_role_full_access" ON activity_logs FOR ALL USING (auth.role() = 'service_role') WITH CHECK (auth.role() = 'service_role');
CREATE POLICY "service_role_full_access" ON blacklist FOR ALL USING (auth.role() = 'service_role') WITH CHECK (auth.role() = 'service_role');

-- 4. Processed Orders (Fix for Key Regeneration)
-- Stores fulfilled orders permanently, even if key is deleted
CREATE TABLE IF NOT EXISTS processed_orders (
    order_id TEXT PRIMARY KEY,
    license_key TEXT,
    client_name TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE processed_orders ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_full_access" ON processed_orders;
CREATE POLICY "service_role_full_access" ON processed_orders FOR ALL USING (auth.role() = 'service_role') WITH CHECK (auth.role() = 'service_role');
