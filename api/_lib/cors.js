function getAllowedOrigins() {
    const raw = process.env.CORS_ALLOWED_ORIGINS || '';
    return raw.split(',').map(s => s.trim()).filter(Boolean);
}

export function applyAdminCors(req, res) {
    const allowed = getAllowedOrigins();
    const origin = req.headers.origin;

    if (origin && allowed.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-auth-token, x-api-secret');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
}

export function applyPublicCors(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-signature, x-api-timestamp');
    res.setHeader('X-Content-Type-Options', 'nosniff');
}

export function handlePreflight(req, res) {
    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return true;
    }
    return false;
}
