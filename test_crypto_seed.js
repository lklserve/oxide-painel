import crypto from 'crypto';
import { deriveLicenseSeed, encodeOffsetGuard, OG_STATIC_OFFSET } from './api/_lib/crypto-lkl.js';

process.env.LKL_SEED_SECRET = 'TEST_SECRET_123';

const key = "test-key-01";
const deviceId = "abcd-1234-xyz";

const seed1 = deriveLicenseSeed(key, deviceId);
const seed2 = deriveLicenseSeed(key, deviceId);

console.log("Seed 1:", seed1);
console.log("Seed 2:", seed2);
if(seed1 !== seed2) {
    console.error("ERRO: deriveLicenseSeed nao eh deterministico!");
    process.exit(1);
}
console.log("OK: Seed deterministica.");

const og = encodeOffsetGuard(OG_STATIC_OFFSET, seed1);
console.log("OG gerado (hex):", og);

// Decodificar espelhando o cliente
const h = crypto.createHash('sha256').update(`${seed1}|og`).digest();
let word = 0n;
for (let i = 0; i < 8; i++) word |= BigInt(h[i]) << BigInt(8 * i);

const recuperado = BigInt("0x" + og) ^ word;

console.log(`Original: 0x${OG_STATIC_OFFSET.toString(16)}`);
console.log(`Recuperado: 0x${recuperado.toString(16)}`);

if(recuperado !== BigInt(OG_STATIC_OFFSET)) {
    console.error("ERRO: recuperacao nao bate com o original!");
    process.exit(1);
}
console.log("OK: Round-trip funcionou.");
