import { getServiceSupabase } from './_lib/supabase.js';
import { applyAdminCors, handlePreflight } from './_lib/cors.js';
import { validateSession, verifyPassword, hashPassword } from './_lib/auth.js';
import { sanitizePlainText } from './_lib/sanitize.js';
import { canModifyLicense } from './_lib/ownership.js';
import { generateLicenseKey } from './_lib/keygen.js';
import { invalidateTelegramCache, sendTelegram, escapeTelegramHtml } from './_lib/telegram.js';
import {
    matchTrapKey, checkIdentity, enforceBlacklist, extractEmail,
    invalidatePatternCache, normalizeKeyish
} from './_lib/blacklist-guard.js';
import { getClientIp } from './_lib/ip-utils.js';

function logAction(supabase, adminName, action, licenseKey, details, ip) {
    return supabase.from('activity_logs').insert({
        admin_name: adminName,
        action,
        license_key: licenseKey,
        details: { ip, ...details },
        timestamp: new Date().toISOString()
    });
}

// Free Key Policy: cache em memoria se a coluna is_free ja existe no Supabase.
// Quando o admin ainda nao rodou fix_free_key.sql, o insert nao pode falhar -
// fazemos fallback gracioso removendo os campos. Resultado: keys sao criadas
// normalmente, e a politica de free key sera respeitada assim que a coluna
// existir (ate la, g_IsFreeKey do mod fica false para todos).
let freeKeyColumnsCache = null;
async function ensureFreeKeyColumns(supabase) {
    if (freeKeyColumnsCache !== null) return freeKeyColumnsCache;
    try {
        const { data, error } = await supabase
            .from('licenses')
            .select('is_free, key_type')
            .limit(1);
        if (error) {
            // Coluna nao existe (ou qualquer erro de schema). Marca como ausente.
            console.warn('freeKeyColumns detect: ausente ou erro', error.message);
            freeKeyColumnsCache = false;
        } else {
            freeKeyColumnsCache = true;
        }
    } catch (e) {
        console.warn('freeKeyColumns detect exception:', e.message);
        freeKeyColumnsCache = false;
    }
    return freeKeyColumnsCache;
}

export default async function handler(req, res) {
    applyAdminCors(req, res);
    if (handlePreflight(req, res)) return;

    const supabase = getServiceSupabase();
    const ip = getClientIp(req);

    const user = await validateSession(req);
    if (!user) return res.status(401).json({ error: 'Sessão expirada ou inválida.' });

    const adminName = user.username;
    const qType = req.query.type;

    if (req.method === 'GET') {
        if (qType === 'settings') {
            const { key: settingKey } = req.query;
            if (!settingKey) return res.status(400).json({ error: 'Chave obrigatória' });
            const { data, error } = await supabase
                .from('settings').select('value').eq('key', settingKey).maybeSingle();
            if (error) return res.status(500).json({ error: 'DB error' });
            if (data && data.value != null) {
                // 🔴 Segredo nao volta para o navegador. O index.html e servido SEM
                // autenticacao, e este GET tambem entregava o bot_token. O cliente so
                // precisa saber SE existe token salvo; o valor fica no servidor.
                if (settingKey === 'telegram_config') {
                    const v = data.value || {};
                    const { bot_token, ...rest } = v;
                    return res.status(200).json({ ...rest, bot_token_set: Boolean(bot_token) });
                }
                return res.status(200).json(data.value);
            }
            // Safe defaults: server_status defaults to enabled so missing row doesn't force maintenance mode.
            if (settingKey === 'server_status') return res.status(200).json({ enabled: true });
            return res.status(200).json(null);
        }

        if (qType === 'resellers') {
            const { data, error } = await supabase
                .from('resellers').select('*').order('created_at', { ascending: false });
            if (error) return res.status(500).json({ error: 'DB error' });
            return res.status(200).json(data || []);
        }

        if (qType === 'creators') {
            // Resolve who created each key from the audit log (KEY_CREATE).
            // Used as a fallback for older keys whose licenses.created_by is NULL.
            // Ordered oldest-first so the earliest creator wins per key.
            const { data, error } = await supabase
                .from('activity_logs')
                .select('license_key, admin_name, timestamp')
                .eq('action', 'KEY_CREATE')
                .order('timestamp', { ascending: true });
            if (error) return res.status(500).json({ error: 'DB error' });
            const map = {};
            for (const row of (data || [])) {
                const lk = row.license_key;
                if (lk && row.admin_name && map[lk] === undefined) {
                    map[lk] = row.admin_name;
                }
            }
            return res.status(200).json(map);
        }

        const { data, error } = await supabase
            .from('licenses').select('*').order('created_at', { ascending: false });
        if (error) return res.status(500).json({ error: 'DB error' });
        return res.status(200).json(data || []);
    }

    if (req.method === 'POST') {
        const { action, ...body } = req.body || {};

        if (action === 'create') {
            const { key, clientName, clientPass, whatsapp, duration, durationValue, maxIPs, isFree,
                    appVersion, keyInfix } = body;
            const now = new Date();
            let expires = new Date();
            let finalDurationType = duration || 'monthly';

            if (duration === 'daily') expires.setDate(now.getDate() + 1);
            else if (duration === 'weekly') expires.setDate(now.getDate() + 7);
            else if (duration === 'monthly') expires.setDate(now.getDate() + 30);
            else if (duration === 'permanent') expires.setDate(now.getDate() + 365);
            else if (duration === 'custom_hours') {
                expires.setHours(now.getHours() + parseInt(durationValue || 1));
                finalDurationType = 'custom';
            } else if (duration === 'custom_days') {
                expires.setDate(now.getDate() + parseInt(durationValue || 1));
                finalDurationType = 'custom';
            }

            // Prefixo de versao: `OXV1-` / `OXV2-`, com `CUST` como INFIXO
            // (OXV1-CUST-AB12). Sem versao escolhida cai em `OX-`, que e a chave
            // antiga que abre nos DOIS apps -- e o comportamento da base ja emitida.
            //
            // 🔑 Isto e o que faz o gate de `api/x8k2m9a1b.js:213` sair do papel:
            // ele compara `/^OXV([12])-/` da chave com o `app_version` que o app
            // manda, e com `&&` -- chave sem versao NUNCA dispara o bloqueio. Ou
            // seja, enquanto o painel emitiu `OX-`, o gate existia e era inerte.
            const versaoEscolhida = /^[12]$/.test(String(appVersion || '')) ? String(appVersion) : null;
            const infixo = /^[A-Z0-9]{1,8}$/i.test(String(keyInfix || '')) ? String(keyInfix).toUpperCase() : null;
            const prefixoBase = versaoEscolhida ? `OXV${versaoEscolhida}` : 'OX';
            const prefixo = infixo ? `${prefixoBase}-${infixo}` : prefixoBase;

            const licenseKey = (key && String(key).trim()) || generateLicenseKey({ prefix: prefixo });

            // A chave-armadilha não pode existir como licença REAL. Se um admin
            // a criasse (por engano ou por engenharia social), o /validate
            // baniria o cliente legítimo que a recebesse — a armadilha viraria
            // uma arma apontada para dentro. Bloqueio explícito, e aqui a
            // mensagem é específica: o destinatário é o admin, não o infrator.
            const trap = await matchTrapKey(licenseKey);
            if (trap) {
                await logAction(supabase, adminName, 'KEY_CREATE_REJECTED_TRAP', licenseKey, {
                    matched_pattern: trap.norm
                }, ip);
                return res.status(409).json({
                    error: 'Esta chave está na blacklist de armadilhas e não pode ser emitida. Use outra.'
                });
            }

            // Cliente já banido não recebe key nova pelo painel. Sem isto, o
            // ban automático do /validate seria desfeito manualmente sem que
            // ninguém percebesse que aquele e-mail estava na lista.
            const clientEmail = extractEmail(clientName);
            if (clientEmail) {
                const idCheck = await checkIdentity({ email: clientEmail });
                if (idCheck.blocked) {
                    await logAction(supabase, adminName, 'KEY_CREATE_REJECTED_BLACKLIST', licenseKey, {
                        email: clientEmail, reason: idCheck.reason
                    }, ip);
                    return res.status(409).json({
                        error: `Cliente em blacklist (${idCheck.reason}). Remova da blacklist antes de emitir.`
                    });
                }
            }

            const isFreeFlag = isFree === true;
            const hasFreeCols = await ensureFreeKeyColumns(supabase);

            const insertPayload = {
                license_key: licenseKey,
                client_username: sanitizePlainText(clientName, { maxLength: 120 }) || null,
                client_password: clientPass || null,
                whatsapp: sanitizePlainText(whatsapp, { maxLength: 40 }) || null,
                status: 'active',
                duration_type: finalDurationType,
                expires_at: expires.toISOString(),
                max_ips: parseInt(maxIPs || 1),
                used_ips: [],
                created_by: adminName
            };
            if (hasFreeCols) {
                insertPayload.is_free = isFreeFlag;
                insertPayload.key_type = isFreeFlag ? 'FREE' : 'PAID';
            }

            const { data, error } = await supabase.from('licenses').insert(insertPayload).select().single();

            if (error) {
                console.error('Supabase insert (create license) error:', error.message, error.code);
                return res.status(500).json({ error: 'Failed to create license: ' + (error.message || 'unknown') });
            }

            await logAction(supabase, adminName, isFreeFlag ? 'KEY_CREATE_FREE' : 'KEY_CREATE', licenseKey, {
                clientName, duration: finalDurationType, maxIPs, isFree: isFreeFlag, freeKeyColumnsApplied: hasFreeCols
            }, ip);

            return res.status(200).json({ success: true, data });
        }

        if (action === 'save_credit') {
            const { resellerId, amount } = body;
            const { data: resRow } = await supabase
                .from('resellers').select('balance').eq('id', resellerId).maybeSingle();
            const current = Number(resRow?.balance) || 0;
            const delta = Number(amount) || 0;
            const newBalance = current + delta;

            const { error } = await supabase
                .from('resellers').update({ balance: newBalance }).eq('id', resellerId);
            if (error) return res.status(500).json({ error: 'Failed to update balance' });

            await supabase.from('credit_transactions').insert({
                reseller_id: resellerId,
                amount: delta,
                type: delta > 0 ? 'add' : 'deduct',
                description: `Manual adjustment by ${adminName}`
            });

            return res.status(200).json({ success: true, newBalance });
        }

        if (action === 'save_custom_costs') {
            const { resellerId, costs } = body;
            const payload = costs && Object.keys(costs).length > 0 ? costs : null;
            const { error } = await supabase
                .from('resellers').update({ custom_costs: payload }).eq('id', resellerId);
            if (error) return res.status(500).json({ error: 'Failed to save costs' });
            return res.status(200).json({ success: true });
        }

        if (action === 'save_setting') {
            const { settingKey, value } = body;
            if (!settingKey) return res.status(400).json({ error: 'Chave obrigatória' });
            // O formulario nao conhece mais o token (ele nunca desce ao navegador).
            // Salvar sem `bot_token` significa "mantem o que ja esta no banco" --
            // sem isto, salvar so o chat_id APAGARIA o token e mataria as notificacoes.
            let finalValue = value;
            if (settingKey === 'telegram_config') {
                const { data: prev } = await supabase
                    .from('settings').select('value').eq('key', 'telegram_config').maybeSingle();
                const prevToken = prev?.value?.bot_token;
                const incoming = value || {};
                finalValue = incoming.bot_token
                    ? incoming
                    : { ...incoming, ...(prevToken ? { bot_token: prevToken } : {}) };
            }

            const { error } = await supabase
                .from('settings').upsert({ key: settingKey, value: finalValue }, { onConflict: 'key' });
            if (error) return res.status(500).json({ error: 'Failed to save setting' });

            // O token do Telegram fica em cache de 1 min dentro da lib. Sem isto,
            // trocar o token no painel levaria ate 1 min para valer -- e daria a
            // impressao de que o novo token nao funcionou.
            if (settingKey === 'telegram_config') invalidateTelegramCache();

            return res.status(200).json({ success: true });
        }

        // Teste que exercita o MESMO caminho das logs reais (servidor -> Telegram).
        // 🔴 O botao antigo do painel chamava api.telegram.org direto do NAVEGADOR
        // com o token do formulario: passava sempre, mesmo com o servidor incapaz
        // de enviar. Era o motivo de "o teste funciona mas as logs nao chegam".
        if (action === 'test_telegram') {
            invalidateTelegramCache();
            const result = await sendTelegram(
                `✅ <b>Teste pelo SERVIDOR</b>\n\n` +
                `Se esta mensagem chegou, as logs automaticas tambem chegam.\n` +
                `👤 <b>Admin:</b> ${escapeTelegramHtml(adminName)}`
            );

            if (!result.sent) {
                return res.status(200).json({
                    success: false,
                    reason: result.reason || 'FAILED',
                    detail: result.results?.map(r => r.error).filter(Boolean).join('; ') || null
                });
            }
            return res.status(200).json({
                success: true,
                source: result.source,
                delivered: `${result.delivered}/${result.total}`
            });
        }

        if (action === 'change_password') {
            const currentPassword = body?.currentPassword || '';
            const newPassword = body?.newPassword || '';
            if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Senha atual e nova obrigatórias' });
            if (newPassword.length < 8) return res.status(400).json({ error: 'Senha nova deve ter no mínimo 8 caracteres' });

            const { data: dbUser, error: fetchErr } = await supabase
                .from('admins').select('id, password').eq('username', adminName).maybeSingle();
            if (fetchErr || !dbUser) return res.status(401).json({ error: 'Usuário não encontrado' });

            const ok = await verifyPassword(currentPassword, dbUser.password);
            if (!ok) return res.status(401).json({ error: 'Senha atual incorreta' });

            const hashed = await hashPassword(newPassword);
            const { error: updErr } = await supabase
                .from('admins').update({ password: hashed }).eq('id', dbUser.id);
            if (updErr) return res.status(500).json({ error: updErr.message || 'Falha ao atualizar senha' });

            // Invalidate every session for this admin so the old cookie can't be reused.
            await supabase.from('admin_sessions').delete().eq('admin_name', adminName);
            await logAction(supabase, adminName, 'PASSWORD_CHANGE', null, {}, ip);
            return res.status(200).json({ success: true });
        }

        if (action === 'create_reseller') {
            const name = sanitizePlainText(body?.name, { maxLength: 80 });
            const secretKey = sanitizePlainText(body?.secretKey, { maxLength: 128 });
            const initialBalance = Number(body?.balance);
            if (!name || !secretKey) return res.status(400).json({ error: 'Nome e Chave Secreta são obrigatórios' });
            if (secretKey.length < 8) return res.status(400).json({ error: 'Chave Secreta deve ter no mínimo 8 caracteres' });

            const { data: existing } = await supabase
                .from('resellers').select('id').eq('secret_key', secretKey).maybeSingle();
            if (existing) return res.status(400).json({ error: 'Essa Chave Secreta já está em uso.' });

            const { data, error } = await supabase
                .from('resellers')
                .insert({
                    name,
                    secret_key: secretKey,
                    is_active: true,
                    balance: Number.isFinite(initialBalance) && initialBalance > 0 ? initialBalance : 0
                })
                .select()
                .single();
            if (error) return res.status(500).json({ error: error.message || 'Failed to create reseller' });

            await logAction(supabase, adminName, 'RESELLER_CREATE', null, { reseller_id: data?.id, name }, ip);
            return res.status(200).json({ success: true, reseller: data });
        }

        if (action === 'delete_reseller') {
            const { id } = body;
            if (!id) return res.status(400).json({ error: 'ID obrigatório' });
            await supabase.from('licenses').delete().eq('reseller_id', id);
            await supabase.from('credit_transactions').delete().eq('reseller_id', id);
            const { error } = await supabase.from('resellers').delete().eq('id', id);
            if (error) return res.status(500).json({ error: 'Failed to delete' });
            await logAction(supabase, adminName, 'RESELLER_DELETE', null, { id }, ip);
            return res.status(200).json({ success: true });
        }

        if (action === 'reset_all_hwid') {
            const { error } = await supabase
                .from('licenses').update({ used_ips: [] }).neq('status', 'expired');
            if (error) return res.status(500).json({ error: 'Failed to reset' });
            await logAction(supabase, adminName, 'HWID_RESET_ALL', null, {}, ip);
            return res.status(200).json({ success: true });
        }

        if (action === 'clean_expired') {
            const now = new Date().toISOString();
            await supabase.from('licenses').delete().eq('status', 'expired');
            const { error } = await supabase
                .from('licenses').delete().lt('expires_at', now).neq('duration_type', 'permanent');
            if (error) return res.status(500).json({ error: 'Failed to clean' });
            return res.status(200).json({ success: true });
        }

        if (action === 'pause_all') {
            const { error, count } = await supabase
                .from('licenses').update({ status: 'paused' }).eq('status', 'active');
            if (error) return res.status(500).json({ error: 'Falha ao pausar chaves: ' + (error.message || 'unknown') });
            await logAction(supabase, adminName, 'KEY_PAUSE_ALL', null, { affected: count || null }, ip);
            return res.status(200).json({ success: true, message: 'Todas as chaves ativas foram pausadas com sucesso.' });
        }

        if (action === 'unpause_all') {
            const { error, count } = await supabase
                .from('licenses').update({ status: 'active' }).eq('status', 'paused');
            if (error) return res.status(500).json({ error: 'Falha ao reativar chaves: ' + (error.message || 'unknown') });
            await logAction(supabase, adminName, 'KEY_UNPAUSE_ALL', null, { affected: count || null }, ip);
            return res.status(200).json({ success: true, message: 'Todas as chaves pausadas foram reativadas com sucesso.' });
        }

        // ------------------------------------------------------------------
        // extend_all — soma tempo ao vencimento de TODAS as chaves de uma vez.
        //
        // Diferencas deliberadas em relacao ao `extend` de uma chave so:
        //   * NAO mexe no `duration_type`. No extend individual, escolher
        //     "semanal" reescreve o plano da chave; em massa isso rebaixaria
        //     toda chave mensal para semanal. Aqui a unidade e so a aritmetica
        //     do tempo — o plano de cada chave fica como esta.
        //   * NAO aceita 'permanent': tornaria o parque inteiro vitalicio num
        //     clique, sem volta.
        //   * respeita a POSSE (canModifyLicense) chave a chave, ao contrario
        //     de pause_all/unpause_all que sao globais. Quem nao e superadmin
        //     nao estende a chave de outro admin — essas entram em `puladas`.
        // ------------------------------------------------------------------
        if (action === 'extend_all') {
            const { extendType, scope } = body;
            const extendValue = Number(body.extendValue);

            const UNIDADES = new Set(['hours', 'days', 'weekly', 'monthly']);
            if (!UNIDADES.has(extendType)) {
                return res.status(400).json({ error: 'Unidade invalida. Use hours, days, weekly ou monthly.' });
            }
            if (!Number.isInteger(extendValue) || extendValue < 1) {
                return res.status(400).json({ error: 'Quantidade deve ser um inteiro maior que zero.' });
            }
            const TETO = extendType === 'hours' ? 8760 : 3650;
            if (extendValue > TETO) {
                return res.status(400).json({ error: `Quantidade acima do teto (${TETO}) para esta unidade.` });
            }
            const escopo = scope === 'all' ? 'all' : 'active';

            const { data: todas, error: errList } = await supabase
                .from('licenses')
                .select('id, license_key, expires_at, duration_type, status, created_by');
            if (errList) return res.status(500).json({ error: 'Falha ao listar chaves: ' + (errList.message || 'unknown') });

            const agora = new Date();
            const puladas = { permanente: 0, banida: 0, sem_posse: 0, fora_do_escopo: 0 };
            const alvos = [];

            for (const lic of (todas || [])) {
                if (lic.duration_type === 'permanent') { puladas.permanente++; continue; }
                if (lic.status === 'banned') { puladas.banida++; continue; }
                if (!canModifyLicense(lic, user).allowed) { puladas.sem_posse++; continue; }

                const venceEm = new Date(lic.expires_at);
                const vencida = !(venceEm > agora);
                if (escopo === 'active' && (lic.status !== 'active' || vencida)) {
                    puladas.fora_do_escopo++;
                    continue;
                }
                alvos.push(lic);
            }

            // Vencida conta a partir de AGORA (senao somar 7 dias a uma chave
            // vencida ha 3 meses nao a reviveria) e volta a ficar ativa.
            const ALLOWED = new Set(['daily', 'weekly', 'monthly', 'permanent', 'custom']);
            const updates = alvos.map(lic => {
                const venceEm = new Date(lic.expires_at);
                const base = venceEm > agora ? new Date(venceEm) : new Date(agora);

                if (extendType === 'hours') base.setHours(base.getHours() + extendValue);
                else if (extendType === 'days') base.setDate(base.getDate() + extendValue);
                else if (extendType === 'weekly') base.setDate(base.getDate() + 7 * extendValue);
                else if (extendType === 'monthly') base.setDate(base.getDate() + 30 * extendValue);

                const patch = { expires_at: base.toISOString() };
                if (!ALLOWED.has(lic.duration_type)) patch.duration_type = 'custom';
                if (lic.status === 'expired' && base > agora) patch.status = 'active';
                return { id: lic.id, patch };
            });

            // Supabase nao faz update relativo em massa numa query; vao em lotes
            // paralelos para nao estourar o timeout da function (Hobby = 10s).
            const LOTE = 25;
            let ok = 0;
            const falhas = [];
            for (let i = 0; i < updates.length; i += LOTE) {
                const fatia = updates.slice(i, i + LOTE);
                const resultados = await Promise.all(fatia.map(u =>
                    supabase.from('licenses').update(u.patch).eq('id', u.id)
                        .then(r => (r.error ? { id: u.id, erro: r.error.message } : null))
                        .catch(e => ({ id: u.id, erro: e.message }))
                ));
                for (const r of resultados) {
                    if (r) falhas.push(r); else ok++;
                }
            }

            await logAction(supabase, adminName, 'KEY_EXTEND_ALL', null, {
                extendType, extendValue, escopo, aplicadas: ok, falhas: falhas.length, puladas
            }, ip);

            const rotulo = { hours: 'hora(s)', days: 'dia(s)', weekly: 'semana(s)', monthly: 'mes(es)' }[extendType];
            let message = `+${extendValue} ${rotulo} aplicado em ${ok} chave(s).`;
            const detalhe = [];
            if (puladas.permanente) detalhe.push(`${puladas.permanente} permanente(s)`);
            if (puladas.banida) detalhe.push(`${puladas.banida} banida(s)`);
            if (puladas.sem_posse) detalhe.push(`${puladas.sem_posse} de outro admin`);
            if (puladas.fora_do_escopo) detalhe.push(`${puladas.fora_do_escopo} fora do escopo`);
            if (detalhe.length) message += ` Nao tocadas: ${detalhe.join(', ')}.`;
            if (falhas.length) message += ` ⚠️ ${falhas.length} falharam ao gravar.`;

            return res.status(200).json({
                success: true, message,
                aplicadas: ok, falhas: falhas.length, puladas
            });
        }

        return res.status(400).json({ error: 'Ação inválida' });
    }

    if (req.method === 'PUT') {
        const { action, id, ...body } = req.body || {};
        if (!id) return res.status(400).json({ error: 'ID da licença obrigatório' });

        const { data: currentData } = await supabase
            .from('licenses').select('*').eq('id', id).maybeSingle();
        if (!currentData) return res.status(404).json({ error: 'Licenca nao encontrada' });

        // 🔴 IDOR: aqui so se validava "existe sessao?". Sem esta checagem de POSSE,
        // um admin mandava o `id` de qualquer licenca e editava/banir/estendia/reduzia
        // a chave de outro admin. Ver api/_lib/ownership.js para o modelo de posse.
        const ownership = canModifyLicense(currentData, user);
        if (!ownership.allowed) {
            await logAction(supabase, adminName, 'IDOR_BLOQUEADO', currentData.license_key, {
                acao: action, dono: currentData.created_by || null
            }, ip);
            return res.status(403).json({ error: 'Esta licenca pertence a outro administrador' });
        }

        let result = { error: null };

        if (action === 'update') {
            const updates = {};
            if (body.clientPassword !== undefined) updates.client_password = body.clientPassword;
            if (body.whatsapp !== undefined) updates.whatsapp = sanitizePlainText(body.whatsapp, { maxLength: 40 });
            if (body.maxIPs !== undefined) updates.max_ips = parseInt(body.maxIPs);
            if (body.clientName !== undefined) updates.client_username = sanitizePlainText(body.clientName, { maxLength: 120 });
            if (body.isFree !== undefined) {
                const hasFreeCols = await ensureFreeKeyColumns(supabase);
                if (hasFreeCols) {
                    updates.is_free = body.isFree === true;
                    updates.key_type = body.isFree === true ? 'FREE' : 'PAID';
                }
            }

            result = await supabase.from('licenses').update(updates).eq('id', id);
            await logAction(supabase, adminName, 'KEY_EDIT', currentData.license_key, {
                before: { clientName: currentData.client_username, max_ips: currentData.max_ips, is_free: currentData.is_free },
                after: { clientName: body.clientName, max_ips: body.maxIPs, is_free: body.isFree }
            }, ip);
        } else if (action === 'toggle_free') {
            const hasFreeCols = await ensureFreeKeyColumns(supabase);
            if (!hasFreeCols) {
                return res.status(400).json({ error: 'Coluna is_free nao existe no banco. Rode fix_free_key.sql.' });
            }
            const newIsFree = !(currentData.is_free === true);
            result = await supabase.from('licenses').update({
                is_free: newIsFree,
                key_type: newIsFree ? 'FREE' : 'PAID'
            }).eq('id', id);
            await logAction(supabase, adminName, 'KEY_TOGGLE_FREE', currentData.license_key, {
                from: currentData.is_free === true, to: newIsFree
            }, ip);
        } else if (action === 'extend') {
            const { extendType, extendValue } = body;
            const expiresAt = new Date(currentData.expires_at);
            const now = new Date();
            const baseDate = expiresAt > now ? new Date(expiresAt) : now;

            if (extendType === 'hours') baseDate.setHours(baseDate.getHours() + Number(extendValue || 0));
            else if (extendType === 'days') baseDate.setDate(baseDate.getDate() + Number(extendValue || 0));
            else if (extendType === 'weekly') baseDate.setDate(baseDate.getDate() + 7);
            else if (extendType === 'monthly') baseDate.setDate(baseDate.getDate() + 30);
            else if (extendType === 'permanent') baseDate.setFullYear(baseDate.getFullYear() + 100);

            // licenses.duration_type has a CHECK constraint that only allows
            // ('daily','weekly','monthly','permanent','custom'). Map extend choices
            // accordingly: hours/days fall back to 'custom' so the constraint passes.
            const ALLOWED = new Set(['daily', 'weekly', 'monthly', 'permanent', 'custom']);
            let nextDurationType = currentData.duration_type;
            if (extendType === 'permanent') nextDurationType = 'permanent';
            else if (ALLOWED.has(extendType)) nextDurationType = extendType;
            else if (extendType === 'hours' || extendType === 'days') nextDurationType = 'custom';

            result = await supabase.from('licenses').update({
                expires_at: baseDate.toISOString(),
                duration_type: nextDurationType
            }).eq('id', id);

            await logAction(supabase, adminName, 'KEY_EXTEND', currentData.license_key, {
                oldExpiry: currentData.expires_at, newExpiry: baseDate.toISOString(), extendType, extendValue
            }, ip);
        } else if (action === 'reduce') {
            const { reduceType, reduceValue } = body;
            const expiresAt = new Date(currentData.expires_at);
            const now = new Date();
            // Reduce always subtracts from the current expiry date.
            const baseDate = new Date(expiresAt);

            if (reduceType === 'hours') baseDate.setHours(baseDate.getHours() - Number(reduceValue || 0));
            else if (reduceType === 'days') baseDate.setDate(baseDate.getDate() - Number(reduceValue || 0));
            else if (reduceType === 'weekly') baseDate.setDate(baseDate.getDate() - 7);
            else if (reduceType === 'monthly') baseDate.setDate(baseDate.getDate() - 30);

            // Never let the expiry go before "now": floor it at the current moment,
            // which effectively expires the key immediately.
            if (baseDate < now) baseDate.setTime(now.getTime());

            // If the key was permanent and we reduce it, it becomes time-bound again.
            const ALLOWED = new Set(['daily', 'weekly', 'monthly', 'permanent', 'custom']);
            let nextDurationType = currentData.duration_type;
            if (currentData.duration_type === 'permanent') nextDurationType = 'custom';
            else if (!ALLOWED.has(nextDurationType)) nextDurationType = 'custom';

            result = await supabase.from('licenses').update({
                expires_at: baseDate.toISOString(),
                duration_type: nextDurationType
            }).eq('id', id);

            await logAction(supabase, adminName, 'KEY_REDUCE', currentData.license_key, {
                oldExpiry: currentData.expires_at, newExpiry: baseDate.toISOString(), reduceType, reduceValue
            }, ip);
        } else if (action === 'ban') {
            result = await supabase.from('licenses').update({
                status: 'banned',
                banned_reason: sanitizePlainText(body.reason, { maxLength: 200 }) || 'Banido pelo admin',
                banned_at: new Date().toISOString()
            }).eq('id', id);
            await logAction(supabase, adminName, 'KEY_BAN', currentData.license_key, {}, ip);
        } else if (action === 'ban_full') {
            // Ban de identidade: além da licença, grava device(s)/e-mail na
            // blacklist e revoga em cascata as outras licenças do mesmo dono.
            // É a versão manual do que o /validate faz na armadilha.
            const reason = sanitizePlainText(body.reason, { maxLength: 200 }) || 'Banido pelo admin (identidade)';
            const devices = Array.isArray(currentData.used_ips) ? currentData.used_ips : [];
            const email = extractEmail(currentData.client_username);

            // Um device por chamada: a RPC é transacional por identidade, e um
            // device que falhe não pode abortar os outros. Sequencial de
            // propósito — a cascata do 1º já pode banir as keys que o 2º veria.
            const applied = [];
            for (const dev of (devices.length ? devices : [null])) {
                const r = await enforceBlacklist({
                    reason,
                    source: 'admin:ban_full',
                    licenseKey: currentData.license_key,
                    deviceId: dev,
                    ip: body.ban_ip === true ? ip : null,
                    email,
                    evidence: { by: adminName, license_id: id },
                    actor: adminName,
                    banIp: body.ban_ip === true
                });
                applied.push(r);
            }

            const failed = applied.filter(r => !r.ok);
            const cascade = applied.reduce((n, r) => n + (r.cascade_count || 0), 0);

            await logAction(supabase, adminName, 'KEY_BAN_FULL', currentData.license_key, {
                devices: devices.length, email, cascade, failed: failed.length
            }, ip);

            // Veredito explícito, nunca número solto: se alguma RPC falhou o
            // admin precisa saber que o ban está PARCIAL.
            if (failed.length) {
                return res.status(500).json({
                    error: `Ban PARCIAL: ${failed.length} de ${applied.length} identidades falharam. ` +
                           `Verifique a blacklist manualmente.`,
                    details: failed.map(f => f.error)
                });
            }
            return res.status(200).json({
                success: true,
                message: `Ban aplicado: licença + ${devices.length} device(s) + ${cascade} licença(s) em cascata.`,
                devices_banned: devices.length,
                cascade_count: cascade
            });
        } else if (action === 'shadowban') {
            // Shadowban: NÃO nega o login. A licença segue válida e o painel do
            // mod abre normal, mas /validate entrega o blob com `names` vazio e
            // as features por nome ficam inertes (ver validate.js e LKL_Gate.h).
            const on = body.enabled !== false;
            result = await supabase.from('licenses').update({
                shadowbanned: on,
                shadowban_at: on ? new Date().toISOString() : null
            }).eq('id', id);
            await logAction(supabase, adminName, on ? 'KEY_SHADOWBAN' : 'KEY_SHADOWBAN_OFF',
                currentData.license_key, { reason: body.reason || null }, ip);
        } else if (action === 'unban') {
            // Só reativa a licença. Device/IP/e-mail continuam na blacklist de
            // propósito: desfazer um ban de identidade é decisão separada, pelo
            // endpoint /api/blacklist (DELETE). Reativar tudo junto aqui faria
            // um "unban" de rotina apagar silenciosamente um ban de armadilha.
            result = await supabase.from('licenses').update({
                status: 'active', banned_reason: null, banned_at: null
            }).eq('id', id);
            await logAction(supabase, adminName, 'KEY_UNBAN', currentData.license_key, {}, ip);
        } else if (action === 'pause') {
            result = await supabase.from('licenses').update({ status: 'paused' }).eq('id', id);
            await logAction(supabase, adminName, 'KEY_PAUSE', currentData.license_key, {}, ip);
        } else if (action === 'unpause') {
            result = await supabase.from('licenses').update({ status: 'active' }).eq('id', id);
            await logAction(supabase, adminName, 'KEY_UNPAUSE', currentData.license_key, {}, ip);
        } else if (action === 'reset_ip') {
            result = await supabase.from('licenses').update({ used_ips: [] }).eq('id', id);
            await logAction(supabase, adminName, 'KEY_RESET_IP', currentData.license_key, {
                removedIPs: currentData.used_ips || []
            }, ip);
        } else {
            return res.status(400).json({ error: `Ação '${action}' não suportada` });
        }

        if (result.error) {
            console.error(`license-actions ${action} failed:`, result.error);
            return res.status(500).json({ error: result.error.message || 'Failed to update' });
        }
        return res.status(200).json({ success: true });
    }

    if (req.method === 'DELETE') {
        const { action, id } = req.body || {};
        const targetId = id || req.body?.id;

        if (action === 'delete' || req.query.action === 'delete') {
            if (!targetId) return res.status(400).json({ error: 'ID obrigatório' });

            // Traz `created_by` tambem: o DELETE e a acao mais destrutiva e era a
            // que menos checava (qualquer admin apagava a chave de qualquer outro).
            const { data: lic } = await supabase
                .from('licenses').select('license_key, client_username, created_by, reseller_id').eq('id', targetId).maybeSingle();
            if (!lic) return res.status(404).json({ error: 'Licenca nao encontrada' });

            const delOwnership = canModifyLicense(lic, user);
            if (!delOwnership.allowed) {
                await logAction(supabase, adminName, 'IDOR_BLOQUEADO', lic.license_key, {
                    acao: 'delete', dono: lic.created_by || null
                }, ip);
                return res.status(403).json({ error: 'Esta licenca pertence a outro administrador' });
            }

            const { error } = await supabase.from('licenses').delete().eq('id', targetId);
            if (error) return res.status(500).json({ error: 'Failed to delete' });

            await logAction(supabase, adminName, 'KEY_DELETE', lic.license_key, {
                clientName: lic.client_username
            }, ip);

            return res.status(200).json({ success: true });
        }

        if (action === 'delete_reseller') {
            if (!targetId) return res.status(400).json({ error: 'ID obrigatório' });
            await supabase.from('licenses').delete().eq('reseller_id', targetId);
            await supabase.from('credit_transactions').delete().eq('reseller_id', targetId);
            const { error } = await supabase.from('resellers').delete().eq('id', targetId);
            if (error) return res.status(500).json({ error: 'Failed to delete' });
            await logAction(supabase, adminName, 'RESELLER_DELETE', null, { id: targetId }, ip);
            return res.status(200).json({ success: true });
        }

        return res.status(400).json({ error: 'Ação obrigatória' });
    }

    return res.status(405).json({ error: 'Method not allowed' });
}
