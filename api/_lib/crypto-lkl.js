import crypto from 'crypto';

/**
 * Espelho em Node do SecurityUtils.aesDecrypt do APK.
 *
 * Esquema (igual ao Android):
 *   - chave  = SHA-256("LKL_MOD_MENU_SECRET_2025")  -> 32 bytes (AES-256)
 *   - cifra  = AES-256-GCM, IV de 12 bytes
 *   - saida  = hex( IV(12) || ciphertext || authTag(16) )
 *
 * O APK lê: iv = bytes[0..12], ciphertext = bytes[12..]. Em GCM o Java/BouncyCastle
 * espera o authTag (16B) ANEXADO ao final do ciphertext, que é exatamente o que
 * Cipher.doFinal() produz. Por isso concatenamos ciphertext || authTag.
 */

const PASSPHRASE = 'LKL_MOD_MENU_SECRET_2025';

function getKey() {
    return crypto.createHash('sha256').update(PASSPHRASE, 'utf8').digest(); // 32 bytes
}

/** Cifra texto -> hex (IV || ciphertext || tag). Lido por aesDecrypt() no APK. */
export function aesEncryptLkl(plaintext) {
    const key = getKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag(); // 16 bytes
    return Buffer.concat([iv, ct, tag]).toString('hex');
}

/** Decifra hex (IV || ciphertext || tag) -> texto. Útil para round-trip/testes. */
export function aesDecryptLkl(hexString) {
    const combined = Buffer.from(hexString, 'hex');
    if (combined.length < 12 + 16) return '';
    const iv = combined.subarray(0, 12);
    const tag = combined.subarray(combined.length - 16);
    const ct = combined.subarray(12, combined.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

// ===========================================================================
// BLOB DE LICENÇA — usado por /api/validate para o KingRonni (libLKL.so)
//
// Diferente do par acima (que serve o APK com passphrase fixa), aqui a chave é
// derivada por licença+device+nonce. Motivo: com passphrase fixa, um blob
// capturado de QUALQUER usuário decifra para todos. Derivando, o blob de um
// device não serve em outro nem numa segunda sessão.
//
// Contrato com o C (Components/Encrypt/LKL_License.h):
//   chave = SHA-256( secret | "|" | key | "|" | device | "|" | nonce )
//   blob  = hex( IV(12) || ciphertext || tag(16) ),  AAD = nonce | "|" | device
// Mudar QUALQUER separador aqui quebra a decifragem no mod (fail-closed).
// ===========================================================================

const BLOB_SECRET = process.env.LKL_BLOB_SECRET || 'LKL-2026-blob-v1-trocar-em-producao';

/** Mesma derivação de LKL_DeriveKey() no C. */
function deriveBlobKey(licenseKey, deviceId, nonce) {
    return crypto.createHash('sha256')
        .update(`${BLOB_SECRET}|${licenseKey}|${deviceId}|${nonce}`, 'utf8')
        .digest();
}

/** Cifra o material da sessão. Lido por LKL_DecryptBlob() no mod. */
export function encryptLicenseBlob(plaintext, licenseKey, deviceId, nonce) {
    const key = deriveBlobKey(licenseKey, deviceId, nonce);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    // AAD amarra o blob ao par nonce+device: alterar um deles invalida a tag.
    cipher.setAAD(Buffer.from(`${nonce}|${deviceId}`, 'utf8'));
    const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, ct, tag]).toString('hex');
}

/**
 * Assina os bytes EXATOS do payload com a chave privada P-256 (ECDSA/SHA-256).
 *
 * 🔑 Esta é a trava real. O blob usa segredo compartilhado (extraível do .so por
 * quem se dispuser); a assinatura usa chave privada que NUNCA sai do servidor.
 * Sem ela, quem extraísse o segredo forjaria respostas.
 *
 * ⚠️ O mod verifica sobre a serialização EXATA que sai daqui. Quem chama deve
 * assinar a MESMA string que envia — reserializar (ordem/espaços) invalida.
 */
/**
 * Normaliza a PEM vinda de variável de ambiente.
 *
 * POR QUE isto existe: PEM é multi-linha, env var é uma linha. Dependendo do
 * caminho (importar .env na Vercel, colar no textarea, `vercel env add`, Docker)
 * a chave chega de 3 formas diferentes:
 *   1. com \n reais         -> já funciona
 *   2. com \n escapado      -> vem do .env entre aspas; createPrivateKey rejeita
 *   3. envolta em aspas     -> o parser de .env às vezes preserva as aspas
 * Sem tratar, o sintoma é `error:0909006C:PEM routines:get_name:no start line`
 * em produção e ninguém consegue logar — com o mod fail-closed, isso é downtime
 * total. Tratar aqui é mais barato que descobrir pelo suporte.
 */
function normalizePem(raw) {
    let pem = String(raw).trim();
    if ((pem.startsWith('"') && pem.endsWith('"')) ||
        (pem.startsWith("'") && pem.endsWith("'"))) {
        pem = pem.slice(1, -1);
    }
    if (pem.includes('\\n')) pem = pem.replace(/\\n/g, '\n');
    return pem.trim();
}

export function signLicensePayload(payloadJsonString) {
    const pem = process.env.LKL_SIGN_PRIVATE_KEY
        ? normalizePem(process.env.LKL_SIGN_PRIVATE_KEY)
        : null;
    if (!pem) throw new Error('LKL_SIGN_PRIVATE_KEY ausente no ambiente');
    const signer = crypto.createSign('SHA256');
    signer.update(Buffer.from(payloadJsonString, 'utf8'));
    signer.end();
    // DER: é o formato que Signature.verify() do Java espera (o mod verifica via JNI).
    return signer.sign(crypto.createPrivateKey(pem)).toString('hex');
}

// ---------------------------------------------------------------------------
// Pilar 3 — rolling key / seed do servidor (17-09-2026)
//
// A seed é DERIVADA (determinística): mesma em toda revalidação para o mesmo
// par key+device. Não precisa de coluna no Supabase. O segredo LKL_SEED_SECRET
// é independente de LKL_BLOB_SECRET — se um vazar, o outro não cai junto.
//
// O "offset guardado" (og) é um offset estático do mod, cifrado com a seed.
// O cliente SÓ decifra: sem a seed correta, recupera lixo → crash no boot.
// Diferente do blob-secret, aqui NÃO há fail-open — é dependência matemática.
// ---------------------------------------------------------------------------

/**
 * Deriva a seed por-licença a partir do segredo do servidor.
 *   seed = SHA-256( LKL_SEED_SECRET | "|" | key | "|" | deviceId )  → hex
 *
 * Espelha deriveBlobKey() acima, com segredo independente.
 */
export function deriveLicenseSeed(key, deviceId) {
    const secret = process.env.LKL_SEED_SECRET;
    if (!secret) throw new Error('LKL_SEED_SECRET ausente no ambiente');
    return crypto.createHash('sha256')
        .update(`${secret}|${key}|${deviceId}`)
        .digest('hex');
}

/**
 * Cifra um offset estático com a seed → hex do valor XOR.
 *   word = SHA-256( seed | "|og" ) [0..8]  (little-endian u64)
 *   og   = staticOffset XOR word
 *
 * O cliente espelha este cálculo em KR_RollingKey.h:KR_OffsetGuardWord().
 */
export function encodeOffsetGuard(staticOffset, seed) {
    const h = crypto.createHash('sha256').update(`${seed}|og`).digest();
    // Primeiros 8 bytes como u64 little-endian
    let word = 0n;
    for (let i = 0; i < 8; i++) word |= BigInt(h[i]) << BigInt(8 * i);
    const enc = BigInt(staticOffset) ^ word;
    return enc.toString(16);
}

// Offset estático do CarController::OnTriggerEnter. Tem de casar com o hardcode do
// cliente (Offsets.h:118). Sentinela no cliente (main.cpp:581): 1a instr = 0xFC1B0FEA.
// 🔴 19-09: 18-09 moveu de 0x26BD4F8 (11-09, caia em MEIO de funcao -> PROVA PARCIAL)
// para 0x26BDF70 (entrada validada). Atualizar SEMPRE junto do update de lib.
export const OG_STATIC_OFFSET = 0x26BDF70;

/** Nonce hex de 16 bytes — usado só em teste/round-trip; em produção vem do mod. */
export function genNonceHex() {
    return crypto.randomBytes(16).toString('hex');
}
