-- Create table for Telegram Notification Settings
CREATE TABLE IF NOT EXISTS telegram_settings (
    chat_id BIGINT PRIMARY KEY,
    notify_sales BOOLEAN DEFAULT TRUE,
    notify_admin BOOLEAN DEFAULT TRUE,
    notify_security BOOLEAN DEFAULT TRUE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- RLS Policies (Optional but good practice)
ALTER TABLE telegram_settings ENABLE ROW LEVEL SECURITY;

-- Allow anyone to read/insert/update (since the API handles auth via token)
-- In a stricter setup, you'd restrict this, but for this specific app structure:
CREATE POLICY "Allow Service Role" ON telegram_settings
    FOR ALL
    USING (true)
    WITH CHECK (true);
