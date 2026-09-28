import crypto from 'crypto';

function timingSafeHex(a, b) {
    try {
        const ba = Buffer.from(a, 'hex');
        const bb = Buffer.from(b, 'hex');
        if (ba.length !== bb.length) return false;
        return crypto.timingSafeEqual(ba, bb);
    } catch {
        return false;
    }
}

export async function readRawBody(req) {
    if (typeof req.body === 'string') return req.body;
    if (Buffer.isBuffer(req.body)) return req.body.toString('utf8');
    if (req.body && typeof req.body === 'object') return JSON.stringify(req.body);
    return '';
}

export function verifyGenericHmac(req, rawBody) {
    const secret = process.env.WEBHOOK_SIGNING_SECRET;
    if (!secret) return false;

    const signature = req.headers['x-api-signature'];
    const timestamp = req.headers['x-api-timestamp'];
    if (!signature || !timestamp) return false;

    const ts = parseInt(timestamp, 10);
    if (!Number.isFinite(ts)) return false;
    const ageSec = Math.abs(Date.now() / 1000 - ts);
    if (ageSec > 300) return false;

    const mac = crypto.createHmac('sha256', secret)
        .update(`${timestamp}.${rawBody}`)
        .digest('hex');

    return timingSafeHex(mac, String(signature));
}

export function verifyMercadoPagoSignature(req, paymentId) {
    const secret = process.env.MP_WEBHOOK_SECRET;
    if (!secret) return false;

    const sigHeader = req.headers['x-signature'];
    const requestId = req.headers['x-request-id'];
    if (!sigHeader || !requestId || !paymentId) return false;

    const parts = {};
    for (const kv of String(sigHeader).split(',')) {
        const [k, v] = kv.split('=').map(s => s && s.trim());
        if (k && v) parts[k] = v;
    }
    const { ts, v1 } = parts;
    if (!ts || !v1) return false;

    const manifest = `id:${paymentId};request-id:${requestId};ts:${ts};`;
    const mac = crypto.createHmac('sha256', secret).update(manifest).digest('hex');
    return timingSafeHex(mac, v1);
}

export function verifyWebhook(req, rawBody) {
    if (verifyGenericHmac(req, rawBody)) return { ok: true, scheme: 'generic' };

    const body = safeParse(rawBody);
    const paymentId = body?.data?.id || body?.id;
    if (paymentId && verifyMercadoPagoSignature(req, paymentId)) {
        return { ok: true, scheme: 'mercadopago' };
    }
    return { ok: false };
}

function safeParse(raw) {
    try { return JSON.parse(raw); } catch { return null; }
}
