import { createClient } from '@supabase/supabase-js';

let _client = null;

export function getServiceSupabase() {
    if (_client) return _client;

    const url = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!url || !key) {
        throw new Error(
            'Missing required environment variables: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in the deployment environment.'
        );
    }

    _client = createClient(url, key, {
        auth: { persistSession: false, autoRefreshToken: false }
    });
    return _client;
}
