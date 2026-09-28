// Ad-hoc maintenance script to normalize legacy "permanent/lifetime/vitalicio" keys.
// Requires the service-role key (read/write over RLS). DO NOT commit secrets.
// Usage: SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... node update_permanent_keys.js

const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('Missing env vars: set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY before running.');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey, {
    auth: { persistSession: false, autoRefreshToken: false }
});

async function updatePermanentKeys() {
    console.log('Fetching clean-up targets (Permanent/Lifetime keys)...');

    const { data: keys, error } = await supabase
        .from('licenses')
        .select('id, license_key, duration_type')
        .or('duration_type.eq.permanent,duration_type.eq.lifetime,duration_type.eq.vitalicio');

    if (error) {
        console.error('Error fetching keys:', error);
        return;
    }

    console.log(`Found ${keys.length} keys to update.`);

    const now = new Date();
    const newExpiry = new Date();
    newExpiry.setDate(now.getDate() + 365);

    let updatedCount = 0;
    for (const key of keys) {
        console.log(`Updating key ${key.license_key} (${key.duration_type})...`);
        const { error: updateError } = await supabase
            .from('licenses')
            .update({ expires_at: newExpiry.toISOString(), duration_type: 'permanent' })
            .eq('id', key.id);
        if (updateError) console.error(`Failed to update ${key.license_key}:`, updateError);
        else updatedCount++;
    }

    console.log(`Success! Updated ${updatedCount} keys to 365 days duration.`);
}

updatePermanentKeys();
