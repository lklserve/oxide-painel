import crypto from 'crypto';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function generateRandomKey(length = 6) {
    const bytes = crypto.randomBytes(length * 2);
    let out = '';
    let i = 0;
    while (out.length < length && i < bytes.length) {
        const idx = bytes[i] & 0x1F;
        if (idx < ALPHABET.length) out += ALPHABET[idx];
        i++;
    }
    while (out.length < length) {
        out += ALPHABET[crypto.randomInt(0, ALPHABET.length)];
    }
    return out;
}

export function generateLicenseKey({ prefix = 'OX', length = 6 } = {}) {
    return `${prefix}-${generateRandomKey(length)}`;
}
