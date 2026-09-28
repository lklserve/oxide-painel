// Ad-hoc script. DO NOT commit secrets — loads from env only.
// Usage: SUPABASE_URL=... SUPABASE_ANON_KEY=... node test_save.js

const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

if (!supabaseUrl || !anonKey) {
    console.error('Missing env vars: set SUPABASE_URL and SUPABASE_ANON_KEY before running.');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, anonKey);

async function testSave() {
    console.log('Testing SAVE with Anon Key...');
    const payload = {
        aimbot_advanced: false,
        test_timestamp: Date.now()
    };

    const { data, error } = await supabase
        .from('settings')
        .upsert({ key: 'features_config', value: payload })
        .select();

    if (error) {
        console.error('Save Error:', error);
    } else {
        console.log('Save Success! Data:', data);
    }
}

testSave();
