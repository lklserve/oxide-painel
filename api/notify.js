import { getServiceSupabase } from './_lib/supabase.js';
import { sendTelegram, escapeTelegramHtml } from './_lib/telegram.js';
import { applyAdminCors, handlePreflight } from './_lib/cors.js';
import { validateSession } from './_lib/auth.js';
import { sanitizePlainText } from './_lib/sanitize.js';

export default async function handler(req, res) {
    applyAdminCors(req, res);
    if (handlePreflight(req, res)) return;
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const session = await validateSession(req);
    if (!session) return res.status(401).json({ error: 'Unauthorized' });
    const adminName = session.username;

    const supabase = getServiceSupabase();
    const { action, message, details } = req.body || {};
    if (!action || !message) return res.status(400).json({ error: 'Missing action or message' });

    const safeAction = sanitizePlainText(action, { maxLength: 80 });
    const safeMessage = sanitizePlainText(message, { maxLength: 2000 });

    await supabase.from('activity_logs').insert({
        admin_name: adminName,
        action: safeAction,
        details: details || {}
    });

    const { data: settingsData } = await supabase
        .from('settings').select('value').eq('key', 'notification_prefs').maybeSingle();
    const prefs = settingsData?.value || {};

    let shouldSend = true;
    if (safeAction === 'CRIAR_KEY' && prefs.create_key === false) shouldSend = false;
    if (['DELETAR_KEY', 'LIMPEZA_KEYS'].includes(safeAction) && prefs.delete_key === false) shouldSend = false;
    if (safeAction === 'ADD_CREDITO' && prefs.credits === false) shouldSend = false;
    if (['BAN_DEVICE', 'UNBAN_DEVICE'].includes(safeAction) && prefs.ban_device === false) shouldSend = false;
    if (['RESET_IP', 'RESET_GLOBAL'].includes(safeAction) && prefs.resets === false) shouldSend = false;
    if (safeAction === 'DELETAR_REVENDA' && prefs.delete_key === false) shouldSend = false;
    if (safeAction === 'STATUS_SERVIDOR' && prefs.login === false) shouldSend = false;

    if (!shouldSend) return res.status(200).json({ success: true, telegram: 'SKIPPED_BY_PREF' });

    const telegramMsg =
        `🔔 <b>Nova Atividade</b>\n\n` +
        `👤 <b>Admin:</b> ${escapeTelegramHtml(adminName)}\n` +
        `⚡ <b>Ação:</b> ${escapeTelegramHtml(safeAction)}\n` +
        `📝 <b>Detalhes:</b> ${escapeTelegramHtml(safeMessage)}`;
    const result = await sendTelegram(telegramMsg);

    return res.status(200).json({ success: true, telegram: result });
}
