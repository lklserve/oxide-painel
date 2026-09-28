import { getServiceSupabase } from './_lib/supabase.js';
import { sendTelegram, escapeTelegramHtml } from './_lib/telegram.js';
import { applyAdminCors, handlePreflight } from './_lib/cors.js';
import { buildSessionCookie, buildClearSessionCookie } from './_lib/cookies.js';
import {
    extractSessionToken,
    generateSessionToken,
    verifyPassword,
    upgradePasswordIfNeeded
} from './_lib/auth.js';
import { rateLimit } from './_lib/rate-limit.js';
import { sanitizePlainText } from './_lib/sanitize.js';
import { getClientIp } from './_lib/ip-utils.js';

const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX = 5;

export default async function handler(req, res) {
    applyAdminCors(req, res);
    if (handlePreflight(req, res)) return;

    const supabase = getServiceSupabase();
    const ip = getClientIp(req);

    if (req.method === 'POST') {
        const { username, password } = req.body || {};
        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Credenciais obrigatórias' });
        }

        const normalizedUsername = String(username).trim().toLowerCase();

        const rl = await rateLimit(`login:${ip}`, { windowMs: LOGIN_WINDOW_MS, max: LOGIN_MAX });
        if (rl.limited) {
            return res.status(429).json({ success: false, message: 'Muitas tentativas. Tente novamente em 15 minutos.' });
        }

        const { data: ipBan } = await supabase.from('ip_blacklist').select('reason').eq('ip', ip).maybeSingle();
        if (ipBan) {
            await sendTelegram(
                `🚫 <b>Login Bloqueado (IP Banido)</b>\nIP: <code>${escapeTelegramHtml(ip)}</code>\nMotivo: ${escapeTelegramHtml(ipBan.reason)}`
            );
            return res.status(403).json({ success: false, message: 'Acesso bloqueado' });
        }

        const { data: user } = await supabase
            .from('admins').select('*').eq('username', normalizedUsername).maybeSingle();

        const safeUsername = escapeTelegramHtml(sanitizePlainText(username, { maxLength: 80 }));
        const safeIp = escapeTelegramHtml(ip);

        if (!user) {
            await sendTelegram(`🚨 <b>Falha de Login</b>\nTentativa: <code>${safeUsername}</code>\nIP: <code>${safeIp}</code>`);
            return res.status(401).json({ success: false, message: 'Credenciais inválidas' });
        }

        const passwordOk = await verifyPassword(password, user.password);
        if (!passwordOk) {
            await sendTelegram(`🚨 <b>Falha de Login</b>\nUsuário: <code>${safeUsername}</code>\nSenha errada.\nIP: <code>${safeIp}</code>`);
            return res.status(401).json({ success: false, message: 'Credenciais inválidas' });
        }

        await upgradePasswordIfNeeded(supabase, user, password);

        const token = generateSessionToken();
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 12);

        await supabase.from('admin_sessions').delete()
            .eq('admin_name', user.username).lt('expires_at', new Date().toISOString());

        const { data: activeSessions } = await supabase
            .from('admin_sessions').select('id, created_at')
            .eq('admin_name', user.username).order('created_at', { ascending: true });

        if (activeSessions && activeSessions.length >= 3) {
            const toRemove = activeSessions.slice(0, activeSessions.length - 2);
            for (const s of toRemove) {
                await supabase.from('admin_sessions').delete().eq('id', s.id);
            }
        }

        const { error: sessionErr } = await supabase.from('admin_sessions').insert({
            token,
            admin_name: user.username,
            admin_role: user.role,
            ip,
            expires_at: expiresAt.toISOString(),
            created_at: new Date().toISOString()
        });

        if (sessionErr) {
            console.error('Session create failed:', sessionErr);
            return res.status(500).json({ success: false, message: 'Erro interno ao criar sessão' });
        }

        await supabase.from('activity_logs').insert({
            admin_name: user.username,
            action: 'LOGIN',
            details: { ip, method: 'session_api' }
        });

        const { data: settingsData } = await supabase
            .from('settings').select('value').eq('key', 'notification_prefs').maybeSingle();
        const prefs = settingsData?.value || {};
        if (prefs.login !== false) {
            await sendTelegram(
                `✅ <b>Login Efetuado</b>\n👤 <b>Admin:</b> ${escapeTelegramHtml(user.username)}\n🌐 <b>IP:</b> <code>${safeIp}</code>`
            );
        }

        res.setHeader('Set-Cookie', buildSessionCookie(token));
        return res.status(200).json({
            success: true,
            user: { id: user.id, username: user.username, role: user.role }
        });
    }

    if (req.method === 'GET') {
        const token = extractSessionToken(req);
        if (!token) {
            return res.status(401).json({ valid: false, message: 'No session' });
        }

        const { data: session } = await supabase
            .from('admin_sessions').select('*').eq('token', token).maybeSingle();

        if (!session || new Date(session.expires_at) < new Date()) {
            if (session) await supabase.from('admin_sessions').delete().eq('token', token);
            res.setHeader('Set-Cookie', buildClearSessionCookie());
            return res.status(401).json({ valid: false, message: 'Sessão expirada' });
        }

        const newExpiry = new Date();
        newExpiry.setHours(newExpiry.getHours() + 12);
        await supabase.from('admin_sessions').update({
            expires_at: newExpiry.toISOString(),
            last_active: new Date().toISOString()
        }).eq('token', token);

        res.setHeader('Set-Cookie', buildSessionCookie(token));
        return res.status(200).json({
            valid: true,
            user: { username: session.admin_name, role: session.admin_role }
        });
    }

    if (req.method === 'DELETE') {
        const token = extractSessionToken(req);
        if (token) {
            const { data: session } = await supabase
                .from('admin_sessions').select('admin_name').eq('token', token).maybeSingle();
            await supabase.from('admin_sessions').delete().eq('token', token);
            if (session) {
                await supabase.from('activity_logs').insert({
                    admin_name: session.admin_name,
                    action: 'LOGOUT',
                    details: { ip }
                });
            }
        }
        res.setHeader('Set-Cookie', buildClearSessionCookie());
        return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: 'Method not allowed' });
}
