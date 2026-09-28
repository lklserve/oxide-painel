
async function fetchServerStatus() {
    try {
        const { data } = await supabaseClient.from('settings').select('value').eq('key', 'server_status').single();
        // Default true if missing
        const isEnabled = (data && data.value && data.value.enabled !== undefined) ? data.value.enabled : true;
        const toggle = document.getElementById('serverStatusToggle');
        if (toggle) toggle.checked = isEnabled;
    } catch (e) {
        console.error('Erro ao buscar status do servidor:', e);
    }
}
