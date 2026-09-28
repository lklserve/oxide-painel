// ===========================================================================
// Teste de fluxo do guard, com Supabase SIMULADO.
//
//   node tools/test_blacklist_flow.mjs
//
// O test_blacklist_guard.mjs cobre só a normalização. Este cobre a DECISÃO:
// dado um pedido, o guard bloqueia? aplica ban? a resposta é indistinguível de
// um erro comum? São exatamente as perguntas que "31 casos passaram" não
// responde — normalizar certo e decidir errado é perfeitamente possível.
//
// Simula o cliente do Supabase interceptando `_lib/supabase.js` e
// `_lib/telegram.js` pelo loader de módulos, então nada toca banco nem rede.
// ===========================================================================

import { register } from 'node:module';
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';

// ── Loader que substitui os dois módulos de I/O por mocks ───────────────────
const loaderSrc = `
export async function resolve(spec, ctx, next) {
    if (spec.endsWith('supabase.js')) return { url: 'mock:supabase', shortCircuit: true, format: 'module' };
    if (spec.endsWith('telegram.js')) return { url: 'mock:telegram', shortCircuit: true, format: 'module' };
    return next(spec, ctx);
}
export async function load(url, ctx, next) {
    if (url === 'mock:supabase') {
        return { format: 'module', shortCircuit: true, source: \`
            export function getServiceSupabase() { return globalThis.__mockSupabase; }
        \` };
    }
    if (url === 'mock:telegram') {
        return { format: 'module', shortCircuit: true, source: \`
            export async function sendTelegram(msg) {
                (globalThis.__sentTelegram ||= []).push(msg);
                return { sent: true };
            }
            export function escapeTelegramHtml(v) { return String(v ?? ''); }
        \` };
    }
    return next(url, ctx);
}
`;
register(`data:text/javascript,${encodeURIComponent(loaderSrc)}`, pathToFileURL('./'));

// A mensagem esperada e EXTRAIDA do validate.js, nao escrita aqui: um assert
// com string fixa mentiu em 21-08 -- dizia 'IDENTICA' comparando 'Chave invalida'
// contra 'Chave nao encontrada', que era exatamente o oraculo em producao.
const CANON_MSG = readFileSync(new URL('../api/validate.js', import.meta.url), 'utf8')
    .match(/status\(404\)\.json\(\{[^}]*message:\s*'([^']+)'/)?.[1];
if (!CANON_MSG) { console.log('FALHOU — resposta canonica nao achada no validate.js'); process.exit(1); }

// ── Mock do cliente Supabase ────────────────────────────────────────────────
// Guarda o estado em memória e registra cada chamada de RPC, para podermos
// afirmar que o ban foi REALMENTE disparado — não que "provavelmente foi".
function makeMock({ traps = [], devices = [], ips = [], emails = [], rpcFails = false } = {}) {
    const calls = { rpc: [], inserts: [] };
    const tables = {
        key_blacklist: traps,
        blacklist: devices.map(d => ({ device_id: d, reason: 'banido' })),
        ip_blacklist: ips.map(i => ({ ip: i, reason: 'banido' })),
        email_blacklist: emails.map(e => ({ email_norm: e, reason: 'banido' }))
    };

    const builder = (name) => {
        const filters = [];
        const api = {
            select() { return api; },
            eq(col, val) { filters.push([col, val]); return api; },
            order() { return api; },
            insert(row) { calls.inserts.push({ table: name, row }); return { select: async () => ({ data: [row] }), then: (r) => r({ error: null }) }; },
            async maybeSingle() {
                const rows = tables[name] || [];
                const hit = rows.find(r => filters.every(([c, v]) => r[c] === v));
                return { data: hit || null, error: null };
            },
            // key_blacklist é lido sem maybeSingle (lista inteira via await)
            then(resolve) { return resolve({ data: tables[name] || [], error: null }); }
        };
        return api;
    };

    return {
        from: (name) => builder(name),
        rpc: async (fn, args) => {
            calls.rpc.push({ fn, args });
            if (rpcFails) return { data: null, error: { message: 'simulated DB failure' } };
            return { data: { ok: true, keys_banned: 1, device_added: 1, ip_added: 0, email_added: 1, cascade_count: 2, cascade_keys: ['LKL-AAA111', 'LKL-BBB222'] }, error: null };
        },
        __calls: calls
    };
}

let pass = 0, fail = 0;
function check(cond, label, extra) {
    if (cond) pass++;
    else { fail++; console.log(`  FALHOU  ${label}${extra ? `\n          ${extra}` : ''}`); }
}

const TRAP_ROW = { pattern_norm: 'avienoffical', match_mode: 'contains', reason: 'honeypot' };

// ── Cenário 1: chave-armadilha no /validate ─────────────────────────────────
console.log('Cenário 1 — chave-armadilha aciona ban e responde erro genérico:');
{
    globalThis.__mockSupabase = makeMock({ traps: [TRAP_ROW] });
    globalThis.__sentTelegram = [];
    const { guardEntry, invalidatePatternCache } = await import('../api/_lib/blacklist-guard.js');
    invalidatePatternCache();

    const r = await guardEntry({
        route: 'validate', key: '@AvienOffical',
        deviceId: 'DEV-INFRATOR', ip: '1.2.3.4', email: 'infrator@mail.com'
    });

    check(r !== null, 'bloqueou (retorno não-nulo)');
    check(r?.trapped === true, 'marcou como armadilha');
    check(r?.status === 404, `status 404 (obtido: ${r?.status})`);
    check(r?.body?.message === CANON_MSG,
          `mensagem genérica (obtido: ${JSON.stringify(r?.body?.message)})`);

    const rpc = globalThis.__mockSupabase.__calls.rpc;
    check(rpc.length === 1 && rpc[0].fn === 'lkl_enforce_blacklist', 'chamou lkl_enforce_blacklist');
    check(rpc[0]?.args?.p_license_key === '@AvienOffical', 'passou a licença da tentativa');
    check(rpc[0]?.args?.p_device_id === 'DEV-INFRATOR', 'passou o device');
    check(rpc[0]?.args?.p_email === 'infrator@mail.com', 'passou o e-mail normalizado');
    // Este cenário chama guardEntry SEM `ipInfo` (só a string), que é o
    // chamador legado. Nesse caso não se sabe se o IP veio do proxy ou de um
    // header forjado pelo cliente, e a política é fail-safe: não bane.
    //
    // 🔴 O rótulo antigo aqui era "IP NÃO banido por default" e virou mentira
    // em 23-08, quando o default passou a ser LIGADO: o `null` continuava
    // aparecendo — por ausência de ipInfo — e o assert seguia verde descrevendo
    // uma garantia que já não existia. Quem cobre a política de verdade é
    // tools/test_ip_ban_policy.mjs, com os dois lados (confiável x forjado).
    check(rpc[0]?.args?.p_ip === null,
          `sem ipInfo o IP não é banido, fail-safe (obtido: ${JSON.stringify(rpc[0]?.args?.p_ip)})`);
    check(globalThis.__sentTelegram.length === 1, 'notificou o admin');
    check(/BAN APLICADO/.test(globalThis.__sentTelegram[0] || ''), 'alerta diz BAN APLICADO');
}

// ── Cenário 2: variante da armadilha ────────────────────────────────────────
console.log('\nCenário 2 — variantes também são pegas:');
for (const variante of ['@avien_offical', 'AVIEN OFFICAL', 'lkl-AvienOffical', 'Avi3nOffical']) {
    globalThis.__mockSupabase = makeMock({ traps: [TRAP_ROW] });
    globalThis.__sentTelegram = [];
    const { guardEntry, invalidatePatternCache } = await import('../api/_lib/blacklist-guard.js');
    invalidatePatternCache();
    const r = await guardEntry({ route: 'validate', key: variante, deviceId: 'D1', ip: '1.1.1.1' });
    check(r?.trapped === true, `'${variante}' acionou a armadilha`);
}

// ── Cenário 3: chave legítima passa ─────────────────────────────────────────
console.log('\nCenário 3 — chave legítima NÃO é bloqueada nem punida:');
{
    globalThis.__mockSupabase = makeMock({ traps: [TRAP_ROW] });
    globalThis.__sentTelegram = [];
    const { guardEntry, invalidatePatternCache } = await import('../api/_lib/blacklist-guard.js');
    invalidatePatternCache();

    const r = await guardEntry({ route: 'validate', key: 'LKL-A7K2M9', deviceId: 'DEV-OK', ip: '9.9.9.9' });
    check(r === null, 'liberou (retorno nulo)');
    check(globalThis.__mockSupabase.__calls.rpc.length === 0, 'NÃO chamou enforce');
    check(globalThis.__sentTelegram.length === 0, 'NÃO notificou');
}

// ── Cenário 4: device já na blacklist ───────────────────────────────────────
console.log('\nCenário 4 — device banido: mesma resposta da chave inválida:');
{
    globalThis.__mockSupabase = makeMock({ traps: [TRAP_ROW], devices: ['DEV-BANIDO'] });
    const { guardEntry, invalidatePatternCache } = await import('../api/_lib/blacklist-guard.js');
    invalidatePatternCache();

    const r = await guardEntry({ route: 'validate', key: 'LKL-A7K2M9', deviceId: 'DEV-BANIDO', ip: '9.9.9.9' });
    check(r?.trapped === false, 'não é armadilha');
    check(r?.blockedKind === 'device', `identificou o tipo p/ log (obtido: ${r?.blockedKind})`);
    check(r?.status === 404 && r?.body?.message === CANON_MSG,
          'resposta IDÊNTICA à de chave inexistente');
    // Ban de device não re-aplica sanção: já está banido.
    check(globalThis.__mockSupabase.__calls.rpc.length === 0, 'não re-aplica ban');
}

// ── Cenário 5: e-mail na blacklist (bloqueia recompra) ──────────────────────
console.log('\nCenário 5 — e-mail banido bloqueia (caminho do webhook de venda):');
{
    globalThis.__mockSupabase = makeMock({ traps: [TRAP_ROW], emails: ['reincidente@mail.com'] });
    const { checkIdentity } = await import('../api/_lib/blacklist-guard.js');

    const hit = await checkIdentity({ email: '  Reincidente@Mail.COM ' });
    check(hit.blocked === true, 'pega o e-mail mesmo com maiúscula e espaço');
    check(hit.kind === 'email', `tipo email (obtido: ${hit.kind})`);

    const miss = await checkIdentity({ email: 'cliente@mail.com' });
    check(miss.blocked === false, 'e-mail limpo passa');
}

// ── Cenário 6: banco degradado (fail-closed + fallback) ─────────────────────
console.log('\nCenário 6 — banco degradado:');
{
    // key_blacklist vazio (tabela não migrada) mas a armadilha AINDA pega,
    // pelo fallback compilado. Sem isso, um deploy antes da migração abriria
    // a porta que a feature existe para fechar.
    globalThis.__mockSupabase = makeMock({ traps: [] });
    globalThis.__sentTelegram = [];
    const { guardEntry, invalidatePatternCache } = await import('../api/_lib/blacklist-guard.js');
    invalidatePatternCache();
    const r = await guardEntry({ route: 'validate', key: '@AvienOffical', deviceId: 'D9', ip: '2.2.2.2' });
    check(r?.trapped === true, 'fallback compilado pega a armadilha sem a tabela');

    // Se a própria RPC falhar, o alerta tem de dizer FALHOU — não "aplicado".
    globalThis.__mockSupabase = makeMock({ traps: [TRAP_ROW], rpcFails: true });
    globalThis.__sentTelegram = [];
    invalidatePatternCache();
    const r2 = await guardEntry({ route: 'validate', key: '@AvienOffical', deviceId: 'D9', ip: '2.2.2.2' });
    check(r2?.status === 404, 'ainda NEGA o acesso quando o ban falha');
    check(/BAN FALHOU/.test(globalThis.__sentTelegram[0] || ''),
          'alerta diz BAN FALHOU (não mente sobre o resultado)',
          `alerta: ${(globalThis.__sentTelegram[0] || '').split('\n')[0]}`);
}

console.log(`\n${fail === 0 ? 'OK' : 'FALHOU'} — ${pass} passaram, ${fail} falharam`);
process.exit(fail === 0 ? 0 : 1);
