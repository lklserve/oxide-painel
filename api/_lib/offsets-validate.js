import { PATCH_TYPES, BLOCKED_OFFSETS } from './offsets-defaults.js';

// Valida a estrutura do offsets_config vindo do painel/GUI.
// Rejeita offsets proibidos e tipos desconhecidos (regra do projeto).
export function validateOffsetsConfig(cfg) {
    if (!cfg || typeof cfg !== 'object') return { ok: false, error: 'config invalido' };
    if (!cfg.patches || typeof cfg.patches !== 'object') return { ok: false, error: 'campo patches ausente' };

    const blocked = new Set(BLOCKED_OFFSETS.map(o => o.toUpperCase()));

    for (const [key, list] of Object.entries(cfg.patches)) {
        if (!Array.isArray(list)) return { ok: false, error: `patches.${key} deve ser lista` };
        for (const item of list) {
            if (!Array.isArray(item) || item.length !== 2)
                return { ok: false, error: `entrada invalida em ${key}` };
            const [off, type] = item;
            if (typeof off !== 'string' || !/^0x[0-9A-Fa-f]+$/.test(off))
                return { ok: false, error: `offset invalido em ${key}: ${off}` };
            if (blocked.has(off.toUpperCase()))
                return { ok: false, error: `offset PROIBIDO em ${key}: ${off}` };
            if (!PATCH_TYPES[type])
                return { ok: false, error: `tipo desconhecido em ${key}: ${type}` };
        }
    }
    return { ok: true };
}
