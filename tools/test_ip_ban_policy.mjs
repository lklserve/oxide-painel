// ===========================================================================
// Politica de ban de IP.
//
//   node tools/test_ip_ban_policy.mjs
//
// POR QUE existe: o alerta de 23-08 mostrou "🌐 IP na blacklist: nao aplicado
// (ver LKL_BAN_IP_ON_TRAP)" para um IP do Iraque -- um /24 alocado, nada de
// CGNAT. A flag estava desligada por um risco (CGNAT movel brasileiro) que nao
// era o caso daquele endereco, e a mensagem apontava sempre para a flag,
// escondendo qualquer outro motivo.
//
// Ligar a flag, porem, arma um tiro no proprio pe: os endpoints extraiam o IP
// de `x-forwarded-for`.split(',')[0], que e a ponta que o CLIENTE escreve.
// Com ban ligado, `X-Forwarded-For: <ip-do-cliente-pagante>` + chave-armadilha
// = o painel bane a vitima.
//
// Este teste cobre as duas metades: a EXTRACAO (de onde veio o IP) e a DECISAO
// (posso banir?), mais o caminho ponta-a-ponta pelo guard com Supabase simulado.
// ===========================================================================

import { register } from 'node:module';
import { pathToFileURL } from 'node:url';

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
            export async function sendTelegram(msg) { (globalThis.__sentTelegram ||= []).push(msg); return { sent: true }; }
            export function escapeTelegramHtml(v) { return String(v ?? ''); }
        \` };
    }
    return next(url, ctx);
}
`;
register(`data:text/javascript,${encodeURIComponent(loaderSrc)}`, pathToFileURL('./'));

const { getClientIp, getClientIpInfo, isPrivateOrReservedIp, canBanIp } =
    await import('../api/_lib/ip-utils.js');

let pass = 0, fail = 0;
function check(cond, label, extra) {
    if (cond) pass++;
    else { fail++; console.log(`  FALHOU  ${label}${extra ? `\n          ${extra}` : ''}`); }
}

const mkReq = (headers, socketIp) => ({ headers: headers || {}, socket: socketIp ? { remoteAddress: socketIp } : undefined });

// ── 1. Extracao: quem ganha quando os dois headers existem ──────────────────
console.log('1 — extração do IP e origem:');
{
    // 🔴 O caso do ataque: o cliente manda x-forwarded-for tentando se passar
    // por outro IP, e o proxy da Vercel escreve o header dele. O valor do PROXY
    // tem de vencer -- se o do cliente ganhasse, o ban iria para a vitima.
    const i = getClientIpInfo(mkReq({
        'x-forwarded-for': '203.0.113.9',            // forjado pelo cliente
        'x-vercel-forwarded-for': '185.158.22.5'     // real, escrito pelo proxy
    }));
    check(i.ip === '185.158.22.5', `proxy vence o header do cliente (obtido: ${i.ip})`);
    check(i.source === 'vercel', `origem = vercel (obtido: ${i.source})`);
    check(i.trusted === true, 'marcado como confiável');

    const only = getClientIpInfo(mkReq({ 'x-forwarded-for': '203.0.113.9' }));
    check(only.ip === '203.0.113.9', 'sem proxy, usa x-forwarded-for');
    check(only.trusted === false, 'x-forwarded-for NÃO é confiável');
    check(only.source === 'xff', `origem = xff (obtido: ${only.source})`);

    const sock = getClientIpInfo(mkReq({}, '::ffff:198.51.100.7'));
    check(sock.ip === '198.51.100.7', `desembrulha IPv4-mapped (obtido: ${sock.ip})`);
    check(sock.trusted === false, 'socket não é confiável');

    const none = getClientIpInfo(mkReq({}));
    check(none.ip === 'Unknown' && none.source === 'none', 'sem nada = Unknown');

    // Cadeia com varios hops e header repetido (Node entrega array).
    check(getClientIpInfo(mkReq({ 'x-vercel-forwarded-for': '9.9.9.9, 10.0.0.1' })).ip === '9.9.9.9',
          'primeiro hop da cadeia');
    check(getClientIpInfo(mkReq({ 'x-vercel-forwarded-for': ['7.7.7.7', '8.8.8.8'] })).ip === '7.7.7.7',
          'header repetido (array)');

    // Compatibilidade: getClientIp continua devolvendo string.
    check(getClientIp(mkReq({ 'x-forwarded-for': '1.2.3.4' })) === '1.2.3.4', 'getClientIp devolve string');
}

// ── 2. Faixas que nao identificam ninguem ───────────────────────────────────
console.log('\n2 — endereços privados/reservados:');
for (const ip of ['10.0.0.1', '192.168.1.1', '172.16.5.4', '172.31.255.255', '127.0.0.1',
                  '169.254.1.1', '100.64.0.1', '100.127.255.255', '::1', 'fe80::1', 'fd00::1',
                  '224.0.0.1', '0.0.0.0', 'Unknown', '']) {
    check(isPrivateOrReservedIp(ip) === true, `'${ip}' é privado/reservado`);
}
// 🔑 100.64/10 e CGNAT (RFC6598) e ESTA fora; 172.15 e 172.32 estao FORA da
// faixa privada e precisam passar, senao o filtro come IP publico legitimo.
for (const ip of ['185.158.22.5', '8.8.8.8', '172.15.0.1', '172.32.0.1', '100.63.255.255',
                  '100.128.0.1', '2001:db8::1']) {
    check(isPrivateOrReservedIp(ip) === false, `'${ip}' é público (não deve ser recusado)`);
}

// ── 3. A decisao, com motivo ────────────────────────────────────────────────
console.log('\n3 — canBanIp: veredito + motivo:');
{
    const ok = canBanIp({ ip: '185.158.22.5', source: 'vercel', trusted: true });
    check(ok.ok === true, 'IP público de origem confiável PODE ser banido');

    // 🔴 O coração do teste: mesmo IP, mesma flag, origem forjável -> NEGA.
    const forged = canBanIp({ ip: '185.158.22.5', source: 'xff', trusted: false });
    check(forged.ok === false, 'IP de x-forwarded-for NÃO pode ser banido');
    check(/não confiável|forjar/i.test(forged.reason), `motivo cita a origem (obtido: ${forged.reason})`);

    const cgnat = canBanIp({ ip: '100.64.0.1', source: 'vercel', trusted: true });
    check(cgnat.ok === false, 'CGNAT recusado mesmo vindo do proxy');
    check(/privado|reservado/i.test(cgnat.reason), `motivo cita o endereço (obtido: ${cgnat.reason})`);

    check(canBanIp({ ip: 'Unknown', source: 'none', trusted: false }).ok === false, 'Unknown recusado');
    check(canBanIp(null).ok === false, 'null recusado (não estoura)');

    // Os motivos tem de ser DIFERENTES entre si: o alerta do Telegram imprime
    // este texto, e foi justamente um motivo generico ("ver LKL_BAN_IP_ON_TRAP")
    // que fez um ban faltando passar por comportamento esperado.
    const reasons = new Set([forged.reason, cgnat.reason, canBanIp({ ip: 'Unknown' }).reason]);
    check(reasons.size === 3, `3 recusas, 3 motivos distintos (obtido: ${reasons.size})`);
}

// ── 4. Ponta a ponta pelo guard ─────────────────────────────────────────────
function makeMock() {
    const calls = { rpc: [] };
    const builder = (name) => {
        const filters = [];
        const api = {
            select: () => api, eq: (c, v) => { filters.push([c, v]); return api; }, order: () => api,
            async maybeSingle() { return { data: null, error: null }; },
            then(resolve) { return resolve({ data: [], error: null }); }
        };
        return api;
    };
    return {
        from: builder,
        rpc: async (fn, args) => {
            calls.rpc.push({ fn, args });
            return { data: { ok: true, keys_banned: 1, device_added: 1,
                             ip_added: args.p_ip ? 1 : 0, email_added: 0,
                             cascade_count: 0, cascade_keys: [] }, error: null };
        },
        __calls: calls
    };
}

const TRAP = '@AvienOffical';

console.log('\n4 — guardEntry ponta a ponta:');
{
    // 4a. Origem confiável: o IP TEM de chegar na RPC.
    globalThis.__mockSupabase = makeMock();
    globalThis.__sentTelegram = [];
    const { guardEntry, invalidatePatternCache } = await import('../api/_lib/blacklist-guard.js');
    invalidatePatternCache();
    await guardEntry({
        route: 'validate', key: TRAP, deviceId: '89adc0acc143b396',
        ip: '185.158.22.5', ipInfo: { ip: '185.158.22.5', source: 'vercel', trusted: true }
    });
    const a = globalThis.__mockSupabase.__calls.rpc[0]?.args;
    check(a?.p_ip === '185.158.22.5', `IP banido quando confiável (obtido: ${JSON.stringify(a?.p_ip)})`);
    check(/GRAVADO/.test((globalThis.__sentTelegram[0] || '').split('\n').find(l => /IP na blacklist/.test(l)) || ''),
          'alerta diz GRAVADO');

    // 4b. 🔴 O ataque: header forjado. O IP NÃO pode ir para a RPC.
    globalThis.__mockSupabase = makeMock();
    globalThis.__sentTelegram = [];
    invalidatePatternCache();
    await guardEntry({
        route: 'validate', key: TRAP, deviceId: 'DEV-X',
        ip: '203.0.113.9', ipInfo: { ip: '203.0.113.9', source: 'xff', trusted: false }
    });
    const b = globalThis.__mockSupabase.__calls.rpc[0]?.args;
    check(b?.p_ip === null, `IP forjado NÃO é banido (obtido: ${JSON.stringify(b?.p_ip)})`);
    // O device continua sendo punido: recusar o IP não pode desarmar a sanção.
    check(b?.p_device_id === 'DEV-X', 'device ainda é banido');
    check(b?.p_license_key === TRAP, 'licença ainda é banida');
    // A evidência guarda o IP visto, para investigação manual.
    check(b?.p_evidence?.ip_seen === '203.0.113.9', 'IP visto fica na evidência');
    check(b?.p_evidence?.ip_source === 'xff', 'origem fica na evidência');
    const linha = (globalThis.__sentTelegram[0] || '').split('\n').find(l => /IP na blacklist/.test(l)) || '';
    check(/não aplicado/.test(linha) && /confiável|forjar/i.test(linha),
          'alerta explica POR QUE não aplicou', `linha: ${linha}`);

    // 4c. Chamador legado (só a string, sem ipInfo) = fail-safe, não bane.
    globalThis.__mockSupabase = makeMock();
    globalThis.__sentTelegram = [];
    invalidatePatternCache();
    await guardEntry({ route: 'validate', key: TRAP, deviceId: 'DEV-Y', ip: '185.158.22.5' });
    check(globalThis.__mockSupabase.__calls.rpc[0]?.args?.p_ip === null,
          'sem ipInfo não bane (fail-safe)');
}

// ── 5. O default da flag ────────────────────────────────────────────────────
// Lido do FONTE, não reescrito aqui: um assert que repete a constante do código
// concorda consigo mesmo enquanto o sistema divergiu (lição de 21-08).
console.log('\n5 — default de LKL_BAN_IP_ON_TRAP:');
{
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(new URL('../api/_lib/blacklist-guard.js', import.meta.url), 'utf8');
    const m = src.match(/const BAN_IP_ON_TRAP\s*=\s*(.+);/);
    check(!!m, 'achou a definição no fonte');
    check(/!==\s*'0'/.test(m?.[1] || ''),
          'ligado por default, desligável com =0', `obtido: ${m?.[1]}`);
}

console.log(`\n${fail === 0 ? 'OK' : 'FALHOU'} — ${pass} passaram, ${fail} falharam`);
process.exit(fail === 0 ? 0 : 1);
