import { getServiceSupabase } from './_lib/supabase.js';
import { sendTelegram, escapeTelegramHtml } from './_lib/telegram.js';
import { applyPublicCors, handlePreflight } from './_lib/cors.js';
import { readRawBody, verifyWebhook } from './_lib/webhook.js';
import { generateLicenseKey } from './_lib/keygen.js';
import { sanitizePlainText } from './_lib/sanitize.js';
import { checkIdentity, normalizeEmail } from './_lib/blacklist-guard.js';

export const config = { api: { bodyParser: false } };

async function readBuffer(req) {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8');
}

export default async function handler(req, res) {
    applyPublicCors(res);
    if (handlePreflight(req, res)) return;
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const rawBody = await readBuffer(req);
    let body;
    try {
        body = rawBody ? JSON.parse(rawBody) : {};
    } catch {
        return res.status(400).json({ error: 'Invalid JSON' });
    }

    req.body = body;

    const verified = verifyWebhook(req, rawBody);
    if (!verified.ok) {
        console.warn('Webhook rejected: missing/invalid signature');
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const supabase = getServiceSupabase();

    const status = body.status || body.payment_status
        || (body.order && body.order.status)
        || (body.transaction && body.transaction.status);

    const ignoredStatuses = ['pending', 'processing', 'created', 'updated', 'waiting_payment', 'in_process', 'authorized'];

    if (status) {
        const normalizedStatus = String(status).toLowerCase();
        if (ignoredStatuses.includes(normalizedStatus)) {
            return res.status(200).json({ message: 'Ignored: Status not approved' });
        }
    }

    let clientName = body.client_name || body.name
        || body.customer?.name
        || body.payer?.first_name;
    let clientEmail = body.email || body.client_email
        || body.payer?.email
        || body.customer?.email
        || body.data?.payer?.email;
    let clientPhone = body.whatsapp || body.phone || body.mobile
        || body.customer?.phone
        || body.customer?.mobile
        || body.payer?.phone?.number;
    let durationInput = body.duration || body.plan
        || body.product?.name
        || body.additional_info?.items?.[0]?.title;

    let orderId = body.order_id || body.id
        || body.order?.id
        || body.data?.id
        || body.external_reference;

    if (clientEmail) {
        if (clientName && clientName !== 'Cliente Site') {
            clientName = `${clientName} (${clientEmail})`;
        } else {
            clientName = clientEmail;
        }
    } else if (!clientName || clientName === 'Cliente Site') {
        clientName = `Cliente Erby ${generateLicenseKey({ prefix: '', length: 4 })}`;
    }

    clientName = sanitizePlainText(clientName, { maxLength: 160 });
    clientPhone = sanitizePlainText(clientPhone, { maxLength: 40 });

    if (!orderId) {
        return res.status(200).json({
            success: false,
            error: 'Missing order_id (unique identifier). Payment ignored to avoid duplicates.'
        });
    }

    const orderIdStr = String(orderId);

    // ───────────────────────────────────────────────────────────────────────
    // BLOQUEIO DE RECOMPRA: e-mail em blacklist não gera key nova.
    //
    // Este era o furo principal — banir o device pelo /validate não impedia a
    // mesma pessoa de comprar de novo e receber uma chave limpa em segundos.
    // O e-mail é o único identificador que o webhook tem antes de existir
    // qualquer device, e é o que sobrevive à reinstalação do app.
    //
    // Responde 200, não 403: o gateway de pagamento reenfileira em erro 4xx/5xx
    // e ficaria retentando a mesma compra indefinidamente. 200 encerra a
    // entrega do webhook sem criar licença.
    // ───────────────────────────────────────────────────────────────────────
    const emailNorm = normalizeEmail(clientEmail);
    if (emailNorm) {
        const idCheck = await checkIdentity({ email: emailNorm });
        if (idCheck.blocked) {
            console.warn(`create.js: venda BLOQUEADA — e-mail em blacklist (order=${orderIdStr})`);

            await supabase.from('activity_logs').insert({
                admin_name: 'System (Webhook)',
                action: 'SALE_BLOCKED_BLACKLIST',
                details: { order_id: orderIdStr, email: emailNorm, reason: idCheck.reason, kind: idCheck.kind }
            });

            await sendTelegram(
                `🚫 <b>VENDA BLOQUEADA — COMPRADOR EM BLACKLIST</b>\n\n` +
                `📧 <b>E-mail:</b> <code>${escapeTelegramHtml(emailNorm)}</code>\n` +
                `🆔 <b>Pedido:</b> <code>${escapeTelegramHtml(orderIdStr)}</code>\n` +
                `⚠️ <b>Motivo do ban:</b> ${escapeTelegramHtml(idCheck.reason)}\n` +
                `💡 <b>Ação:</b> nenhuma key gerada — avaliar reembolso manualmente`
            );

            return res.status(200).json({
                success: false,
                error: 'Não foi possível concluir o pedido. Entre em contato com o suporte.',
                key: null
            });
        }
    }

    const { data: processedOrder } = await supabase
        .from('processed_orders').select('*').eq('order_id', orderIdStr).maybeSingle();

    if (processedOrder) {
        const { data: activeLicense } = await supabase
            .from('licenses').select('*').eq('order_id', orderIdStr).maybeSingle();

        if (activeLicense) {
            return res.status(200).json({
                success: true,
                key: activeLicense.license_key,
                expires_at: activeLicense.expires_at,
                data: activeLicense,
                message: 'Key recuperada do banco de dados'
            });
        }
        return res.status(200).json({
            success: false,
            error: 'Esta compra já foi processada e a chave foi revogada/deletada pelo administrador.',
            key: null
        });
    }

    const { data: existingKey } = await supabase
        .from('licenses').select('*').eq('order_id', orderIdStr).maybeSingle();

    if (existingKey) {
        return res.status(200).json({
            success: true, key: existingKey.license_key,
            expires_at: existingKey.expires_at, data: existingKey,
            message: 'Key recuperada do banco de dados (Legacy)'
        });
    }

    const licenseKey = generateLicenseKey();

    const now = new Date();
    let expires = new Date();
    let finalDurationType = 'monthly';

    if (durationInput) {
        const d = String(durationInput).toLowerCase();
        if (d.includes('semanal') || d.includes('weekly') || d.includes('7 dias')) {
            expires.setDate(now.getDate() + 7);
            finalDurationType = 'weekly';
        } else if (d.includes('diario') || d.includes('daily') || d.includes('1 dia') || d.includes('24h')) {
            expires.setDate(now.getDate() + 1);
            finalDurationType = 'daily';
        } else if (d.includes('permanente') || d.includes('lifetime') || d.includes('vitalicio')) {
            expires.setDate(now.getDate() + 365);
            finalDurationType = 'permanent';
        } else {
            expires.setDate(now.getDate() + 30);
        }
    } else {
        expires.setDate(now.getDate() + 30);
    }

    const { data, error } = await supabase.from('licenses').insert({
        license_key: licenseKey,
        client_username: clientName,
        client_password: null,
        whatsapp: clientPhone || null,
        status: 'active',
        duration_type: finalDurationType,
        expires_at: expires.toISOString(),
        // 🔴 30-08: era 1 e o cliente levava "Limite de dispositivos atingido" no
        // PROPRIO celular. `device_id` = ANDROID_ID, que no Android 8+ e POR APP:
        // o APK do LKL tem um valor, a lib injetada no processo do JOGO tem outro.
        // 2 = 1 app + 1 lib, NAO "2 celulares" -- e bug de contagem, nao limite
        // generoso. Corrigido em 23-08 na pasta `painel-lkl-principal`, que e a
        // MORTA (a Vercel serve `lklserve/kr-kfjenjn` = esta pasta), entao a
        // correcao nunca chegou em producao e o sintoma voltou.
        max_ips: 2,
        used_ips: [],
        order_id: orderIdStr,
        created_by: 'System (Webhook)'
    }).select().single();

    if (error) {
        if (error.code === '23505' || error.message?.includes('unique_order_id')) {
            const { data: retryKey } = await supabase
                .from('licenses').select('*').eq('order_id', orderIdStr).maybeSingle();
            if (retryKey) {
                return res.status(200).json({
                    success: true, key: retryKey.license_key,
                    expires_at: retryKey.expires_at, data: retryKey,
                    message: 'Key recuperada após conflito de concorrência'
                });
            }
        }
        console.error('Supabase Error (create):', error);
        return res.status(500).json({ error: 'Failed to create license' });
    }

    const { data: settingsData } = await supabase
        .from('settings').select('value').eq('key', 'notification_prefs').maybeSingle();
    const prefs = settingsData?.value || {};

    if (prefs.create_key !== false) {
        const msg =
            `✅ <b>Nova Venda Aprovada</b>\n\n` +
            `🔑 <b>Key:</b> <code>${escapeTelegramHtml(licenseKey)}</code>\n` +
            `👤 <b>Cliente:</b> ${escapeTelegramHtml(clientName)}\n` +
            `📅 <b>Duração:</b> ${escapeTelegramHtml(finalDurationType)}\n` +
            `💰 <b>Valor:</b> R$ ${escapeTelegramHtml(body.transaction_amount || '?')}\n` +
            `🆔 <b>Pedido:</b> <code>${escapeTelegramHtml(orderIdStr)}</code>`;
        await sendTelegram(msg);
    }

    await supabase.from('activity_logs').insert({
        admin_name: 'System (Webhook)',
        action: 'SALE_APPROVED',
        details: { key: licenseKey, client: clientName, orderId: orderIdStr }
    });

    await supabase.from('processed_orders').insert({
        order_id: orderIdStr,
        license_key: licenseKey,
        client_name: clientName
    });

    return res.status(200).json({
        success: true,
        key: licenseKey,
        expires_at: expires.toISOString(),
        data
    });
}
