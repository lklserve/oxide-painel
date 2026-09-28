const SESSION_COOKIE = 'lkl_admin_session';
const SESSION_MAX_AGE = 12 * 60 * 60;

export function parseCookies(header) {
    if (!header || typeof header !== 'string') return {};
    return header.split(';').reduce((acc, pair) => {
        const idx = pair.indexOf('=');
        if (idx < 0) return acc;
        const key = pair.slice(0, idx).trim();
        const val = pair.slice(idx + 1).trim();
        if (!key) return acc;
        try {
            acc[key] = decodeURIComponent(val);
        } catch {
            acc[key] = val;
        }
        return acc;
    }, {});
}

export function buildSessionCookie(token) {
    const parts = [
        `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
        'HttpOnly',
        'SameSite=Strict',
        'Path=/',
        `Max-Age=${SESSION_MAX_AGE}`
    ];
    if (process.env.NODE_ENV !== 'development') parts.push('Secure');
    return parts.join('; ');
}

export function buildClearSessionCookie() {
    const parts = [
        `${SESSION_COOKIE}=`,
        'HttpOnly',
        'SameSite=Strict',
        'Path=/',
        'Max-Age=0'
    ];
    if (process.env.NODE_ENV !== 'development') parts.push('Secure');
    return parts.join('; ');
}

export function getSessionCookieName() {
    return SESSION_COOKIE;
}
