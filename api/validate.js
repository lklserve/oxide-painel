import { getServiceSupabase } from './_lib/supabase.js';
import { sendTelegram, escapeTelegramHtml } from './_lib/telegram.js';
import { applyPublicCors, handlePreflight } from './_lib/cors.js';
import { rateLimit, recordFailure } from './_lib/rate-limit.js';
import { encryptLicenseBlob, signLicensePayload, deriveLicenseSeed, encodeOffsetGuard, OG_STATIC_OFFSET } from './_lib/crypto-lkl.js';
import { NAMES_TABLE } from './_lib/lkl-names-07-08.js';
import { guardEntry, checkIdentity, extractEmail } from './_lib/blacklist-guard.js';
import { getClientIpInfo } from './_lib/ip-utils.js';

// ---------------------------------------------------------------------------
// Tabela de nomes ofuscados servida ao mod (KingRonni).
//
// POR QUE o servidor manda isto: antes a resposta era só `valid:true` e o mod já
// tinha todos os nomes compilados dentro. Resultado: o mod funcionava inteiro sem
// o servidor, e a trava era um `if` — 1 byte. Agora o material de resolução vem
// daqui. Sem blob válido o mod não tem o que resolver: não há branch para inverter.
//
// ⚠️ Vem de um MÓDULO (.js), não de um .json lido com readFileSync: a Vercel
// transpila ESM->CJS (não há "type":"module" no package.json) e nesse modo o
// import.meta.url é reescrito — o new URL('./x.json', import.meta.url) resolvia
// para um caminho inexistente e a função morria com FUNCTION_INVOCATION_FAILED,
// com o build passando limpo. Import estático o bundler rastreia.
// Gerado de LKL_ObfNames.h — ao trocar de versão do jogo, regerar junto do header.
// ---------------------------------------------------------------------------
function getNamesTable() {
    return NAMES_TABLE;
}

const VALIDATE_RATE_MAX = 30;
const VALIDATE_WINDOW_MS = 5 * 60 * 1000;
const VALIDATE_FAIL_MAX = 10;
const VALIDATE_FAIL_WINDOW_MS = 10 * 60 * 1000;

export default async function handler(req, res) {
    applyPublicCors(res);
    if (handlePreflight(req, res)) return;

    try {
        const body = req.body || {};
        let rawKey = body.key || req.query.key;
        let rawDeviceId = body.device_id || req.query.device_id;

        if (!rawKey || !rawDeviceId) {
            return res.status(400).json({ valid: false, message: 'Chave ou ID do dispositivo ausente' });
        }

        const key = String(rawKey).trim();
        const deviceId = String(rawDeviceId).trim();

        // Nonce sorteado pelo mod. Ausente = cliente legado (APK antigo) -> resposta
        // sem assinatura. Validado como hex de 8..64 bytes: entra na derivação da
        // chave AES, então lixo aqui só produziria um blob que não decifra.
        const rawNonce = body.nonce || req.query.nonce;
        const nonce = (rawNonce && /^[0-9a-fA-F]{16,128}$/.test(String(rawNonce).trim()))
            ? String(rawNonce).trim()
            : null;

        const supabase = getServiceSupabase();
        const ipInfo = getClientIpInfo(req);
        const clientIp = ipInfo.ip;

        // Busca prefs NO INÍCIO para usar em todas as notificações
        const { data: sData } = await supabase
            .from('settings').select('value').eq('key', 'notification_prefs').maybeSingle();
        const prefs = sData?.value || {};
        const shouldNotify = prefs.client_login !== false;
        const shouldAlert = prefs.security !== false;

        const rl = await rateLimit(`validate:${clientIp}`, {
            windowMs: VALIDATE_WINDOW_MS,
            max: VALIDATE_RATE_MAX,
            failWindowMs: VALIDATE_FAIL_WINDOW_MS,
            maxFails: VALIDATE_FAIL_MAX
        });
        if (rl.limited) {
            return res.status(429).json({ valid: false, message: 'Muitas tentativas. Aguarde alguns minutos.' });
        }

        // ───────────────────────────────────────────────────────────────────
        // PRIORIDADE MÁXIMA: armadilha + blacklist de identidade.
        //
        // Vem antes de tudo (status da licença, server_status, expiração) de
        // propósito: qualquer um desses checks pode encerrar o pedido com outro
        // erro, e aí a chave-armadilha teria sido usada sem aplicar sanção.
        //
        // 🔴 A resposta é `404 Chave inválida` — o MESMO par que este arquivo
        // já devolve para key inexistente (mais abaixo). Dizer "Dispositivo
        // Banido" como antes entregava o mecanismo: bastava trocar de device
        // até a mensagem mudar para saber exatamente o que estava filtrado.
        // Quem precisa do detalhe é o admin, e ele o recebe no Telegram.
        // ───────────────────────────────────────────────────────────────────
        const guard = await guardEntry({
            route: 'validate',
            key,
            deviceId,
            ip: clientIp,
            ipInfo,
            extraEvidence: { user_agent: req.headers['user-agent'] || null }
        });
        if (guard) {
            // Device/IP já banido também notifica — mas só quando NÃO é
            // armadilha (essa já mandou o alerta detalhado dentro do guard).
            if (!guard.trapped && shouldAlert) {
                const msg =
                    `🔴 <b>ACESSO BLOQUEADO (${escapeTelegramHtml(String(guard.blockedKind || '').toUpperCase())} EM BLACKLIST)</b>\n\n` +
                    `🔑 <b>Key:</b> <code>${escapeTelegramHtml(key)}</code>\n` +
                    `📱 <b>Device:</b> <code>${escapeTelegramHtml(deviceId)}</code>\n` +
                    `🌐 <b>IP:</b> <code>${escapeTelegramHtml(clientIp)}</code>\n` +
                    `⚠️ <b>Resposta ao cliente:</b> erro genérico (não revela o motivo)`;
                sendTelegram(msg).catch(err => console.error('sendTelegram error:', err));
            }
            await recordFailure(`validate:${clientIp}`);
            return res.status(guard.status).json(guard.body);
        }

        const { data: settings } = await supabase
            .from('settings').select('value').eq('key', 'server_status').maybeSingle();
        if (settings && settings.value && settings.value.enabled === false) {
            return res.status(503).json({ valid: false, message: 'Servidor está offline' });
        }

        const { data: license, error } = await supabase
            .from('licenses').select('*').eq('license_key', key).maybeSingle();

        if (error) {
            console.error('Supabase Error (validate):', error);
            return res.status(500).json({ valid: false, message: 'Erro temporário. Tente novamente.' });
        }

        if (!license) {
            await recordFailure(`validate:${clientIp}`);
            // 🔴 KEY INEXISTENTE — notifica imediatamente
            if (shouldAlert) {
                const msg =
                    `🔴 <b>KEY INVÁLIDA / NÃO ENCONTRADA</b>\n\n` +
                    `🔑 <b>Key:</b> <code>${escapeTelegramHtml(key)}</code>\n` +
                    `📱 <b>Device:</b> <code>${escapeTelegramHtml(deviceId)}</code>\n` +
                    `🌐 <b>IP:</b> <code>${escapeTelegramHtml(clientIp)}</code>\n` +
                    `⚠️ <b>Ação:</b> Tentativa de uso com key inexistente`;
                sendTelegram(msg).catch(err => console.error('sendTelegram error:', err));
            }
            return res.status(404).json({ valid: false, message: 'Chave não encontrada' });
        }

        if (license.status !== 'active') {
            // 🔴 KEY INATIVA — notifica
            if (shouldAlert) {
                const msg =
                    `🔴 <b>KEY INATIVA</b>\n\n` +
                    `🔑 <b>Key:</b> <code>${escapeTelegramHtml(key)}</code>\n` +
                    `👤 <b>Cliente:</b> ${escapeTelegramHtml(license.client_username || 'N/A')}\n` +
                    `📱 <b>Device:</b> <code>${escapeTelegramHtml(deviceId)}</code>\n` +
                    `🌐 <b>IP:</b> <code>${escapeTelegramHtml(clientIp)}</code>\n` +
                    `⚠️ <b>Status:</b> ${escapeTelegramHtml(license.status || 'desconhecido')}\n` +
                    `📅 <b>Motivo:</b> Chave desativada ou suspensa`;
                sendTelegram(msg).catch(err => console.error('sendTelegram error:', err));
            }
            return res.status(403).json({ valid: false, message: 'A chave está ' + license.status });
        }

        const now = new Date();
        const expires = new Date(license.expires_at);
        if (now > expires) {
            // 🔴 KEY EXPIRADA — notifica
            if (shouldAlert) {
                const msg =
                    `🔴 <b>KEY EXPIRADA</b>\n\n` +
                    `🔑 <b>Key:</b> <code>${escapeTelegramHtml(key)}</code>\n` +
                    `👤 <b>Cliente:</b> ${escapeTelegramHtml(license.client_username || 'N/A')}\n` +
                    `📱 <b>Device:</b> <code>${escapeTelegramHtml(deviceId)}</code>\n` +
                    `🌐 <b>IP:</b> <code>${escapeTelegramHtml(clientIp)}</code>\n` +
                    `⚠️ <b>Vencimento:</b> ${expires.toLocaleString('pt-BR')}\n` +
                    `📅 <b>Há:</b> ${Math.floor((now - expires) / 60000)} minutos atrás`;
                sendTelegram(msg).catch(err => console.error('sendTelegram error:', err));
            }
            return res.status(403).json({ valid: false, message: 'Chave expirada' });
        }

        let usedDevices = license.used_ips || [];
        // Default 2 pelo mesmo motivo do create.js: ANDROID_ID e por app, entao
        // 1 slot nunca cabe APK + lib. Vale para chave legada com `max_ips` nulo
        // -- inclusive as de revendedor emitidas antes de 30-08.
        const maxDevices = license.max_ips || 2;

        // ⚠️ NAO REMOVER: `duration` entra no baseSuccessPayload logo abaixo.
        // Em 14-08 eu apaguei este bloco ao consolidar a busca de prefs e todo
        // login de key VALIDA passou a responder 500 "Erro interno"
        // (ReferenceError capturado pelo catch do handler).
        const diffMs = expires - now;
        const diffDays = Math.floor(diffMs / 86400000);
        const diffHours = Math.floor((diffMs % 86400000) / 3600000);
        const diffMinutes = Math.floor((diffMs % 3600000) / 60000);
        const duration = {
            days: diffDays, hours: diffHours, minutes: diffMinutes,
            formatted: `${diffDays}d ${diffHours}h ${diffMinutes}m`
        };

        const isFreeKey = license.is_free === true;

        const baseSuccessPayload = {
            valid: true,
            message: 'Acesso permitido',
            duration,
            permanent: ['permanent', 'lifetime', 'vitalicio'].includes(license.duration_type),
            is_free_key: isFreeKey,
            key_type: isFreeKey ? 'FREE' : 'PAID',
            expires_at: license.expires_at
        };

        // ───────────────────────────────────────────────────────────────────
        // Resposta assinada para o mod nativo.
        //
        // Só é emitida quando o mod manda `nonce` (o APK antigo não manda, e
        // segue recebendo a resposta legada — compatibilidade para trás).
        //
        // ⚠️ Assina a STRING e embute a MESMA string por concatenação. Não usar
        // JSON.stringify({payload: obj, ...}): o mod verifica a assinatura sobre
        // os bytes exatos que extrai do corpo, então qualquer reserialização
        // (ordem de chave, espaço) invalidaria tudo com "ASSINATURA INVALIDA".
        // ───────────────────────────────────────────────────────────────────
        const sendSigned = (extra) => {
            const merged = { ...baseSuccessPayload, ...extra };
            if (!nonce) return res.status(200).json(merged);   // cliente legado

            try {
                const table = getNamesTable();
                // ───────────────────────────────────────────────────────────
                // SHADOWBAN: licença marcada recebe blob VÁLIDO com `names`
                // vazio. A assinatura confere, o AES-GCM decifra, o gate abre
                // (`g_licenseOk = true`) e o painel do mod aparece normal — mas
                // LKL_Name() devolve nullptr para toda chave fora da tabela
                // (LKL_Gate.h:100), então as features que resolvem por nome
                // ficam inertes. Nada no cliente distingue isso de um update
                // do jogo que quebrou os nomes.
                //
                // 🔑 Por que blob vazio e não erro: o mod é fail-closed, então
                // erro faz ele mostrar tela de login e o infrator percebe na
                // hora. Blob válido-mas-vazio não dá esse sinal.
                // ───────────────────────────────────────────────────────────
                const shadow = license.shadowbanned === true;
                // Pilar 3: seed derivada + offset guardado. Viajam DENTRO do
                // blob AES-GCM (cifrado + assinado + amarrado a device+nonce).
                // Shadowban mantém seed/og válidos — não fundir shadowban com
                // a guarda de crash (senão shadowban vira crash e entrega o mecanismo).
                const seed = deriveLicenseSeed(key, deviceId);
                const og   = encodeOffsetGuard(OG_STATIC_OFFSET, seed);
                const blobPlain = JSON.stringify({
                    gv: table.gv,
                    // Marca d'água: amarra o blob a quem baixou. Se um blob vazar,
                    // dá para saber de qual licença/device ele saiu.
                    wm: `${key}|${deviceId}`,
                    names: shadow ? {} : table.names,
                    seed,
                    og
                });
                const blob = encryptLicenseBlob(blobPlain, key, deviceId, nonce);

                if (shadow) {
                    // Registra no servidor o que o cliente nunca vai ver.
                    console.warn(`validate.js: SHADOWBAN servido — key=${key} device=${deviceId} (names=0)`);
                    supabase.from('activity_logs').insert({
                        admin_name: 'System (Shadowban)',
                        action: 'SHADOWBAN_SERVED',
                        license_key: key,
                        details: { device_id: deviceId, ip: clientIp, names_served: 0 }
                    }).then(({ error }) => {
                        if (error) console.error('shadowban log:', error.message);
                    });
                }

                const payloadStr = JSON.stringify({ ...merged, nonce, blob });
                const sig = signLicensePayload(payloadStr);

                res.setHeader('Content-Type', 'application/json');
                return res.status(200).send(
                    `{"payload":${payloadStr},"sig":"${sig}"}`
                );
            } catch (err) {
                // Falha de assinatura (env var ausente) NÃO pode virar "acesso
                // liberado sem prova": o mod é fail-closed, então devolver a
                // resposta legada aqui deixaria o cliente sem blob e sem features.
                // Melhor um erro explícito, que aparece no log do painel.
                console.error('validate.js: falha ao assinar payload:', err.message);
                return res.status(500).json({
                    valid: false,
                    message: 'Erro de assinatura no servidor'
                });
            }
        };

        if (usedDevices.includes(deviceId)) {
            await supabase.from('activity_logs').insert({
                admin_name: license.client_username || key,
                action: 'KEY_LOGIN',
                details: { device_id: deviceId, ip: clientIp, is_free: isFreeKey }
            });

            if (shouldNotify) {
                const msg =
                    `🔓 <b>Login de Usuário</b>\n\n` +
                    `👤 <b>Cliente:</b> ${escapeTelegramHtml(license.client_username || 'Desconhecido')}\n` +
                    `🔑 <b>Key:</b> <code>${escapeTelegramHtml(key)}</code>\n` +
                    `📱 <b>Device:</b> <code>${escapeTelegramHtml(deviceId)}</code>\n` +
                    `📅 <b>Vencimento:</b> ${escapeTelegramHtml(expires.toLocaleDateString('pt-BR'))}\n` +
                    `🏷 <b>Tipo:</b> ${isFreeKey ? 'GRÁTIS' : 'PAGA'}`;
                sendTelegram(msg).catch(err => console.error(err));
            }

            return sendSigned({});
        }

        if (usedDevices.length < maxDevices) {
            usedDevices.push(deviceId);
            const { error: updateError } = await supabase
                .from('licenses').update({ used_ips: usedDevices }).eq('id', license.id);

            if (updateError) {
                return res.status(500).json({ valid: false, message: 'Falha ao registrar dispositivo' });
            }

            await supabase.from('activity_logs').insert({
                admin_name: license.client_username || key,
                action: 'KEY_REGISTER_DEVICE',
                details: { device_id: deviceId, ip: clientIp, is_free: isFreeKey }
            });

            if (shouldNotify) {
                const msg =
                    `🆕 <b>Novo Dispositivo Registrado</b>\n\n` +
                    `👤 <b>Cliente:</b> ${escapeTelegramHtml(license.client_username || 'Desconhecido')}\n` +
                    `🔑 <b>Key:</b> <code>${escapeTelegramHtml(key)}</code>\n` +
                    `📱 <b>Device:</b> <code>${escapeTelegramHtml(deviceId)}</code>\n` +
                    `⚠️ <b>Slot:</b> ${usedDevices.length}/${maxDevices}\n` +
                    `🏷 <b>Tipo:</b> ${isFreeKey ? 'GRÁTIS' : 'PAGA'}`;
                sendTelegram(msg).catch(err => console.error(err));
            }

            return sendSigned({ message: 'Acesso permitido (Novo dispositivo registrado)' });
        }

        // 🔴 LIMITE DE DISPOSITIVOS ATINGIDO — notifica
        if (shouldAlert) {
            const msg =
                `🔴 <b>LIMITE DE DISPOSITIVOS ATINGIDO</b>\n\n` +
                `🔑 <b>Key:</b> <code>${escapeTelegramHtml(key)}</code>\n` +
                `👤 <b>Cliente:</b> ${escapeTelegramHtml(license.client_username || 'N/A')}\n` +
                `📱 <b>Device:</b> <code>${escapeTelegramHtml(deviceId)}</code>\n` +
                `🌐 <b>IP:</b> <code>${escapeTelegramHtml(clientIp)}</code>\n` +
                `⚠️ <b>Slot:</b> ${usedDevices.length}/${maxDevices}\n` +
                `🏷 <b>Tipo:</b> ${isFreeKey ? 'GRÁTIS' : 'PAGA'}`;
            sendTelegram(msg).catch(err => console.error(err));
        }
        return res.status(403).json({ valid: false, message: 'Limite de dispositivos atingido' });
    } catch (e) {
        console.error('validate.js error:', e);
        return res.status(500).json({ valid: false, message: 'Erro interno' });
    }
}

