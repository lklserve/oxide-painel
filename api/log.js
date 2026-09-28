import { getServiceSupabase } from './_lib/supabase.js';
import { sendTelegram, escapeTelegramHtml } from './_lib/telegram.js';
import { applyPublicCors, applyAdminCors, handlePreflight } from './_lib/cors.js';
import { validateSession } from './_lib/auth.js';
import { sanitizePlainText } from './_lib/sanitize.js';
import { rateLimit } from './_lib/rate-limit.js';
import { getClientIp } from './_lib/ip-utils.js';

export default async function handler(req, res) {
    applyPublicCors(res);
    if (handlePreflight(req, res)) return;

    if (req.method === 'GET') {
        applyAdminCors(req, res);
        const session = await validateSession(req);
        if (!session) return res.status(401).json({ error: 'Unauthorized' });

        const supabase = getServiceSupabase();
        const { data: logs, error } = await supabase
            .from('activity_logs')
            .select('*')
            .order('timestamp', { ascending: false })
            .limit(100);

        if (error) return res.status(500).json({ error: 'Failed to fetch logs' });
        return res.status(200).json(logs);
    }

    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { key, device_id, action, message, details, timestamp } = req.body || {};
    if (!action) return res.status(400).json({ error: 'Missing action' });

    const ip = getClientIp(req);

    const rl = await rateLimit(`log:${ip}`, { windowMs: 60_000, max: 60 });
    if (rl.limited) return res.status(429).json({ error: 'Too many log events' });

    const supabase = getServiceSupabase();

    const safeAction = sanitizePlainText(action, { maxLength: 80 });
    const safeMessage = sanitizePlainText(message, { maxLength: 1000 });
    const safeDetails = sanitizePlainText(details, { maxLength: 1000 });
    const safeDevice = sanitizePlainText(device_id, { maxLength: 128 });
    const safeKey = sanitizePlainText(key, { maxLength: 64 });

    let keyOwner = 'Unknown User';
    if (safeKey) {
        const { data: licenseData } = await supabase
            .from('licenses')
            .select('client_username')
            .eq('license_key', safeKey)
            .maybeSingle();
        if (licenseData) {
            keyOwner = licenseData.client_username || 'Unknown User';
        }
    }

    const dbDetails = {
        device_id: safeDevice || 'Unknown',
        ip,
        user: keyOwner,
        message: safeMessage,
        details: safeDetails,
        timestamp_client: timestamp
    };

    await supabase.from('activity_logs').insert({
        admin_name: safeKey || 'App Security',
        action: safeAction,
        details: dbDetails
    });

    const { data: settingsData } = await supabase
        .from('settings').select('value').eq('key', 'notification_prefs').maybeSingle();
    const prefs = settingsData?.value || {};

    const shouldSend = prefs.security !== false;

    // `telegram` vai na resposta para o envio deixar de falhar calado: antes o
    // endpoint devolvia `success:true` mesmo quando nada era enviado, e nao havia
    // como distinguir "chegou" de "descartado por falta de token".
    let telegram = shouldSend ? null : 'SKIPPED_BY_PREF';

    if (shouldSend) {
        const telegramMsg =
            `🚨 <b>ALERTA DE SEGURANÇA</b>\n\n` +
            `🔑 <b>Key:</b> <code>${escapeTelegramHtml(safeKey || 'N/A')}</code>\n` +
            `👤 <b>Usuário:</b> ${escapeTelegramHtml(keyOwner)}\n` +
            `📱 <b>Device:</b> <code>${escapeTelegramHtml(safeDevice || 'Unknown')}</code>\n` +
            `🌐 <b>IP:</b> <code>${escapeTelegramHtml(ip)}</code>\n` +
            `⚠️ <b>Violação:</b> ${escapeTelegramHtml(safeAction)}\n` +
            `📄 <b>Detalhes:</b> ${escapeTelegramHtml(safeMessage)} ${safeDetails ? '(' + escapeTelegramHtml(safeDetails) + ')' : ''}`;
        const result = await sendTelegram(telegramMsg);
        telegram = result.sent ? `SENT_${result.delivered}/${result.total}` : (result.reason || 'FAILED');
    }

    return res.status(200).json({ success: true, telegram });
}
