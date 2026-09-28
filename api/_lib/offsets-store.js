import { getServiceSupabase } from './supabase.js';
import { defaultOffsets } from './offsets-defaults.js';

const SETTINGS_KEY = 'offsets_config';

// Le do Supabase settings(offsets_config); cai no default 18-06 se vazio.
async function loadConfig() {
    try {
        const supabase = getServiceSupabase();
        const { data } = await supabase
            .from('settings').select('value').eq('key', SETTINGS_KEY).single();
        if (data && data.value) {
            return typeof data.value === 'string' ? JSON.parse(data.value) : data.value;
        }
    } catch (e) {
        // fallback abaixo
    }
    return defaultOffsets;
}

async function saveConfig(cfg) {
    const supabase = getServiceSupabase();
    const value = JSON.stringify(cfg);
    const { error } = await supabase
        .from('settings')
        .upsert({ key: SETTINGS_KEY, value }, { onConflict: 'key' });
    if (error) throw error;
}

export { SETTINGS_KEY, loadConfig, saveConfig };
