import { getServiceSupabase } from './_lib/supabase.js';
import { applyAdminCors, applyPublicCors, handlePreflight } from './_lib/cors.js';
import { validateSession, verifyApiSecret } from './_lib/auth.js';
import { sanitizePlainText } from './_lib/sanitize.js';
import {
    normalizeKeyish, normalizeEmail, invalidatePatternCache,
    matchTrapKey, checkIdentity, enforceBlacklist, notifyTrap
} from './_lib/blacklist-guard.js';

// ===========================================================================
// /api/blacklist — DUAS interfaces no mesmo arquivo:
//
//   1. Admin (sessão)      — GET lista, POST bane, DELETE remove.
//   2. Serviço (?mode=check + x-api-secret) — consulta para o painel-revendedor,
//      que é projeto Vercel separado e não importa _lib/blacklist-guard.js.
//
// 🔴 POR QUE juntas, e não uma rota por arquivo: o plano Hobby da Vercel aceita
// **12 Serverless Functions** por deployment e o painel já tem 12. Criar
// `blacklist-check.js` deu 13 e o build falhou inteiro ("No more than 12
// Serverless Functions can be added"). Cada `api/*.js` é uma function; arquivos
// em `api/_lib/` não contam (prefixo `_`). Rota nova aqui = mover código para
// `_lib/` ou dobrar num handler existente, como este.
// ===========================================================================

export default async function handler(req, res) {
    // ── Interface de serviço ────────────────────────────────────────────────
    // Ramifica ANTES do CORS de admin e da sessão: o chamador é servidor, não
    // navegador, e autentica por segredo compartilhado.
    if (req.query?.mode === 'check') {
        applyPublicCors(res);
        if (handlePreflight(req, res)) return;
        return handleServiceCheck(req, res);
    }

    applyAdminCors(req, res);
    if (handlePreflight(req, res)) return;

    const session = await validateSession(req);
    if (!session) return res.status(401).json({ error: 'Unauthorized' });
    const adminName = session.username;

    const supabase = getServiceSupabase();

    if (req.method === 'GET') {
        const [deviceBans, ipBans, emailBans, keyTraps] = await Promise.all([
            supabase.from('blacklist').select('*').order('created_at', { ascending: false }),
            supabase.from('ip_blacklist').select('*').order('created_at', { ascending: false }),
            supabase.from('email_blacklist').select('*').order('created_at', { ascending: false }),
            supabase.from('key_blacklist').select('*').order('created_at', { ascending: false })
        ]);
        return res.status(200).json({
            devices: deviceBans.data || [],
            ips: ipBans.data || [],
            emails: emailBans.data || [],
            traps: keyTraps.data || []
        });
    }

    if (req.method === 'POST') {
        const { device_id, ip, email, key_pattern, match_mode, reason, ban_type } = req.body || {};
        const safeReason = sanitizePlainText(reason || 'Banido pelo admin', { maxLength: 200 });

        // ── E-mail ──────────────────────────────────────────────────────────
        // Grava a forma normalizada em coluna própria: a comparação no guard
        // acontece nesse espaço, então inserir o texto cru deixaria o ban
        // passar batido para quem digitasse com maiúscula ou espaço.
        if (ban_type === 'email' || (email && !device_id && !ip && !key_pattern)) {
            const norm = normalizeEmail(email);
            if (!norm) return res.status(400).json({ error: 'E-mail obrigatório' });

            const { data, error } = await supabase.from('email_blacklist').insert({
                email_norm: norm,
                email_raw: sanitizePlainText(email, { maxLength: 200 }),
                reason: safeReason,
                blocked_by: adminName,
                source: 'admin'
            }).select();

            if (error) return res.status(500).json({ error: 'Failed to ban email' });

            await supabase.from('activity_logs').insert({
                admin_name: adminName, action: 'BAN_EMAIL',
                details: { email: norm, reason: safeReason }
            });
            return res.status(200).json({ success: true, data, type: 'email' });
        }

        // ── Padrão-armadilha (honeypot) ─────────────────────────────────────
        if (ban_type === 'key_pattern' || (key_pattern && !device_id && !ip)) {
            const norm = normalizeKeyish(key_pattern);
            if (!norm) return res.status(400).json({ error: 'Padrão de chave obrigatório' });

            // 🔴 Piso de 6 caracteres normalizados. Um padrão curto em modo
            // `contains` casaria com keys legítimas: 'lkl' banaria TODAS as
            // chaves do painel na primeira validação, com ban em cascata. O
            // limite não é estético — é o que separa armadilha de autodestruição.
            if (norm.length < 6 && (match_mode || 'contains') === 'contains') {
                return res.status(400).json({
                    error: `Padrão '${norm}' tem ${norm.length} caracteres — curto demais para modo 'contains' ` +
                           `(mínimo 6). Ele casaria com chaves legítimas e as baniria em cascata. ` +
                           `Use match_mode 'exact' ou um padrão mais longo.`
                });
            }

            const { data, error } = await supabase.from('key_blacklist').insert({
                pattern_norm: norm,
                pattern_raw: sanitizePlainText(key_pattern, { maxLength: 128 }),
                match_mode: match_mode === 'exact' ? 'exact' : 'contains',
                reason: safeReason,
                blocked_by: adminName,
                active: true
            }).select();

            if (error) return res.status(500).json({ error: 'Failed to add trap pattern' });

            invalidatePatternCache();   // sem isto o padrão só valeria em 60s
            await supabase.from('activity_logs').insert({
                admin_name: adminName, action: 'BAN_KEY_PATTERN',
                details: { pattern: norm, match_mode: match_mode || 'contains', reason: safeReason }
            });
            return res.status(200).json({ success: true, data, type: 'key_pattern' });
        }

        if (ban_type === 'ip' || (ip && !device_id)) {
            if (!ip) return res.status(400).json({ error: 'IP obrigatório' });
            const ipVal = sanitizePlainText(ip, { maxLength: 64 });
            const { data, error } = await supabase.from('ip_blacklist').insert({
                ip: ipVal,
                reason: safeReason,
                blocked_by: adminName,
                created_at: new Date().toISOString()
            }).select();

            if (error) return res.status(500).json({ error: 'Failed to ban IP' });

            await supabase.from('activity_logs').insert({
                admin_name: adminName,
                action: 'BAN_IP',
                details: { ip: ipVal, reason: safeReason }
            });
            return res.status(200).json({ success: true, data, type: 'ip' });
        }

        if (!device_id) return res.status(400).json({ error: 'Device ID ou IP obrigatório' });
        const devVal = sanitizePlainText(device_id, { maxLength: 128 });

        const { data, error } = await supabase.from('blacklist').insert({
            device_id: devVal, reason: safeReason, blocked_by: adminName
        }).select();

        if (error) return res.status(500).json({ error: 'Failed to ban device' });

        await supabase.from('activity_logs').insert({
            admin_name: adminName,
            action: 'BAN_DEVICE',
            details: { device_id: devVal, reason: safeReason }
        });

        return res.status(200).json({ success: true, data, type: 'device' });
    }

    if (req.method === 'DELETE') {
        const { id, unban_type } = req.body || {};
        if (!id) return res.status(400).json({ error: 'ID obrigatório' });

        if (unban_type === 'ip') {
            const { error } = await supabase.from('ip_blacklist').delete().eq('id', id);
            if (error) return res.status(500).json({ error: 'Failed to unban IP' });
            await supabase.from('activity_logs').insert({
                admin_name: adminName, action: 'UNBAN_IP', details: { id }
            });
        } else if (unban_type === 'email') {
            const query = supabase.from('email_blacklist').delete();
            // Aceita id (uuid) ou o próprio e-mail, normalizado como na gravação.
            const norm = normalizeEmail(id);
            if (norm && norm.includes('@')) query.eq('email_norm', norm);
            else query.eq('id', id);
            const { error } = await query;
            if (error) return res.status(500).json({ error: 'Failed to unban email' });
            await supabase.from('activity_logs').insert({
                admin_name: adminName, action: 'UNBAN_EMAIL', details: { id }
            });
        } else if (unban_type === 'key_pattern') {
            // Desativa em vez de apagar: mantém o histórico de qual padrão
            // estava ativo quando um ban antigo foi aplicado.
            const { error } = await supabase.from('key_blacklist')
                .update({ active: false }).eq('id', id);
            if (error) return res.status(500).json({ error: 'Failed to disable trap pattern' });
            invalidatePatternCache();
            await supabase.from('activity_logs').insert({
                admin_name: adminName, action: 'DISABLE_KEY_PATTERN', details: { id }
            });
        } else {
            const query = supabase.from('blacklist').delete();
            if (typeof id === 'number') query.eq('id', id);
            else query.eq('device_id', id);
            const { error } = await query;
            if (error) return res.status(500).json({ error: 'Failed to unban device' });
            await supabase.from('activity_logs').insert({
                admin_name: adminName, action: 'UNBAN_DEVICE', details: { id }
            });
        }
        return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: 'Method not allowed' });
}

// ===========================================================================
// Consulta de blacklist para OUTROS serviços — POST /api/blacklist?mode=check
//
// O painel-revendedor (projeto Vercel separado, Next.js) não pode importar
// _lib/blacklist-guard.js. As alternativas eram duplicar a regra lá (duas
// cópias divergindo no primeiro padrão novo) ou expor a decisão por HTTP.
// Escolhi HTTP: a regra vive num lugar só, e um padrão novo no banco vale para
// os dois painéis na hora.
//
// 🔴 NÃO é público: exige x-api-secret (API_SECRET). Sem isso qualquer um
// consultaria "este device está banido?" e teria um oráculo de enumeração —
// exatamente o que os erros genéricos das outras rotas evitam.
// ===========================================================================
async function handleServiceCheck(req, res) {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    if (!verifyApiSecret(req)) {
        // 404, não 401: um 401 confirma que a rota existe e o que ela faz.
        return res.status(404).json({ error: 'Not found' });
    }

    try {
        const { key, device_id, ip, email, enforce, route } = req.body || {};

        const trap = key ? await matchTrapKey(key) : null;
        if (trap) {
            let result = null;
            // O serviço chamador decide se a sanção sai daqui ou de lá. O painel
            // do revendedor manda enforce:true — ele não tem device do cliente
            // final, e o e-mail/licença já bastam para punir.
            if (enforce !== false) {
                result = await enforceBlacklist({
                    reason: trap.reason,
                    source: `auto:trap_key:${route || 'remote'}`,
                    licenseKey: String(key).trim(),
                    deviceId: device_id || null,
                    ip: ip || null,
                    // 🔴 `trusted: true` de propósito, e é a ÚNICA rota onde
                    // isto vale. O IP aqui não vem de header: vem no body de um
                    // serviço que provou posse do API_SECRET e que já extraiu o
                    // IP do proxy dele. Tratar como header do cliente faria
                    // todo ban vindo do revendedor virar "origem não confiável"
                    // — e nunca banir IP nenhum por essa porta.
                    ipInfo: ip ? { ip: String(ip).trim(), source: 'service', trusted: true } : null,
                    email: email || null,
                    evidence: { route: route || 'remote', matched_pattern: trap.norm }
                });
                await notifyTrap({ key, deviceId: device_id, ip, email, result, route: route || 'remote' });
            }
            return res.status(200).json({ blocked: true, kind: 'trap_key', enforced: result?.ok ?? false });
        }

        const id = await checkIdentity({ deviceId: device_id, ip, email });
        return res.status(200).json({ blocked: id.blocked, kind: id.kind || null });
    } catch (e) {
        console.error('blacklist check error:', e);
        // 🔑 fail-CLOSED. Um erro aqui não pode virar "liberado": o chamador
        // trata `blocked:true` e a venda/geração para. Falso positivo custa um
        // ticket de suporte; falso negativo entrega uma key ao infrator.
        return res.status(200).json({ blocked: true, kind: 'error', degraded: true });
    }
}
