import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { getServiceSupabase } from './supabase.js';
import { parseCookies, getSessionCookieName } from './cookies.js';

export function extractSessionToken(req) {
    const cookies = parseCookies(req.headers.cookie || '');
    const cookieToken = cookies[getSessionCookieName()];
    if (cookieToken) return cookieToken;

    const authHeader = req.headers.authorization || req.headers['x-auth-token'];
    if (!authHeader) return null;
    return authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
}

export async function validateSession(req) {
    const token = extractSessionToken(req);
    if (!token) return null;

    const supabase = getServiceSupabase();
    const { data: session } = await supabase
        .from('admin_sessions')
        .select('*')
        .eq('token', token)
        .single();

    if (!session || new Date(session.expires_at) < new Date()) {
        if (session) {
            await supabase.from('admin_sessions').delete().eq('token', token);
        }
        return null;
    }

    const newExpiry = new Date();
    newExpiry.setHours(newExpiry.getHours() + 12);
    await supabase.from('admin_sessions').update({
        expires_at: newExpiry.toISOString(),
        last_active: new Date().toISOString()
    }).eq('token', token);

    return { username: session.admin_name, role: session.admin_role, token };
}

export function timingSafeEqualStr(a, b) {
    const ba = Buffer.from(String(a));
    const bb = Buffer.from(String(b));
    if (ba.length !== bb.length) return false;
    try {
        return crypto.timingSafeEqual(ba, bb);
    } catch {
        return false;
    }
}

export function verifyApiSecret(req) {
    const envSecret = process.env.API_SECRET;
    if (!envSecret) return false;
    const provided = req.headers['x-api-secret'];
    if (!provided) return false;
    return timingSafeEqualStr(provided, envSecret);
}

export async function authenticateRequest(req) {
    const session = await validateSession(req);
    if (session) return { type: 'session', admin: session.username, session };
    if (verifyApiSecret(req)) return { type: 'api', admin: 'API' };
    return null;
}

export function generateSessionToken() {
    return crypto.randomBytes(48).toString('base64url');
}

const BCRYPT_PREFIX_RE = /^\$2[aby]\$/;

export function isBcryptHash(value) {
    return typeof value === 'string' && BCRYPT_PREFIX_RE.test(value);
}

export async function hashPassword(plain) {
    return bcrypt.hash(plain, 12);
}

export async function verifyPassword(plain, stored) {
    if (!stored || typeof stored !== 'string') return false;
    if (isBcryptHash(stored)) {
        return bcrypt.compare(plain, stored);
    }
    // Legacy plaintext - constant-time compare to avoid timing leak
    return timingSafeEqualStr(plain, stored);
}

export async function upgradePasswordIfNeeded(supabase, user, plainPassword) {
    if (isBcryptHash(user.password)) return;
    try {
        const hashed = await hashPassword(plainPassword);
        await supabase.from('admins').update({ password: hashed }).eq('id', user.id);
    } catch (e) {
        console.error('Password upgrade failed:', e);
    }
}
