// ===========================================================================
// Teste do ROTEAMENTO de api/blacklist.js — o handler tem duas interfaces no
// mesmo arquivo (admin por sessão, serviço por ?mode=check + x-api-secret) e o
// risco novo é o desvio: serviço caindo no caminho de admin, ou pior, o
// caminho de admin acessível pelo segredo de serviço.
//
//   node tools/test_blacklist_route.mjs
//
// POR QUE existe: a rota de serviço era um arquivo próprio
// (api/blacklist-check.js) até o build da Vercel falhar por passar de 12
// Serverless Functions no plano Hobby. Dobrar as duas num handler resolveu o
// limite, mas trocou "dois arquivos isolados" por "um `if` que decide" — e o
// `if` é código novo que ninguém testou.
// ===========================================================================

import { register } from 'node:module';
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';

const loaderSrc = [
    'export async function resolve(spec, ctx, next) {',
    '  if (spec.endsWith("supabase.js")) return { url: "mock:sb", shortCircuit: true, format: "module" };',
    '  if (spec.endsWith("telegram.js")) return { url: "mock:tg", shortCircuit: true, format: "module" };',
    '  if (spec.includes("_lib") && spec.endsWith("auth.js")) return { url: "mock:auth", shortCircuit: true, format: "module" };',
    '  return next(spec, ctx);',
    '}',
    'export async function load(url, ctx, next) {',
    '  if (url === "mock:sb") return { format: "module", shortCircuit: true,',
    '    source: "export function getServiceSupabase() { return globalThis.__sb; }" };',
    '  if (url === "mock:tg") return { format: "module", shortCircuit: true,',
    '    source: "export async function sendTelegram(m) { (globalThis.__tg ||= []).push(m); return { sent: true }; }" +',
    '            "\\nexport function escapeTelegramHtml(v) { return String(v ?? \\"\\"); }" };',
    '  if (url === "mock:auth") return { format: "module", shortCircuit: true,',
    '    source: "export function verifyApiSecret(req) { return req.headers?.[\\"x-api-secret\\"] === \\"segredo\\"; }" +',
    '            "\\nexport async function validateSession() { return globalThis.__sess || null; }" };',
    '  return next(url, ctx);',
    '}'
].join('\n');

register(`data:text/javascript,${encodeURIComponent(loaderSrc)}`, pathToFileURL('./'));

// Supabase simulado: key_blacklist tem a armadilha, o resto vazio.
globalThis.__sb = {
    from(table) {
        const filters = [];
        const api = {
            select: () => api,
            eq: (c, v) => { filters.push([c, v]); return api; },
            order: () => api,
            insert: (row) => ({ select: async () => ({ data: [row] }), then: (r) => r({ error: null }) }),
            delete: () => api,
            async maybeSingle() { return { data: null, error: null }; },
            then(resolve) {
                const rows = table === 'key_blacklist'
                    ? [{ pattern_norm: 'avienoffical', match_mode: 'contains', reason: 'trap' }]
                    : [];
                return resolve({ data: rows, error: null });
            }
        };
        return api;
    },
    rpc: async (fn, args) => {
        (globalThis.__rpc ||= []).push({ fn, args });
        return { data: { ok: true, keys_banned: 1 }, error: null };
    }
};

const handler = (await import('../api/blacklist.js')).default;

const mkReq = (query, headers, body, method = 'POST') =>
    ({ method, query, headers: headers || {}, body: body || {} });
const mkRes = () => ({
    code: 0, payload: null,
    status(c) { this.code = c; return this; },
    json(p) { this.payload = p; return this; },
    setHeader() {}, end() { return this; }
});

let pass = 0, fail = 0;
const ck = (cond, label, extra) => {
    if (cond) pass++;
    else { fail++; console.log(`  FALHOU  ${label}${extra ? ` — ${extra}` : ''}`); }
};

console.log('roteamento de /api/blacklist:');

// 1. Serviço sem segredo: 404, e sem revelar o que a rota faz.
globalThis.__sess = null;
let res = mkRes();
await handler(mkReq({ mode: 'check' }, {}, { key: 'x' }), res);
ck(res.code === 404, 'sem segredo devolve 404 (não 401)', `obtido ${res.code}`);
ck(!/blacklist|ban|trap/i.test(JSON.stringify(res.payload)),
   'corpo do 404 não menciona blacklist', JSON.stringify(res.payload));

// 2. Serviço com segredo + armadilha: bloqueia e pune.
globalThis.__rpc = []; globalThis.__tg = [];
res = mkRes();
await handler(mkReq({ mode: 'check' }, { 'x-api-secret': 'segredo' },
                    { key: '@AvienOffical', email: 'x@y.com', route: 'reseller' }), res);
ck(res.code === 200, 'com segredo responde 200', `obtido ${res.code}`);
ck(res.payload?.blocked === true, 'bloqueou a armadilha', JSON.stringify(res.payload));
ck(res.payload?.kind === 'trap_key', 'kind = trap_key', String(res.payload?.kind));
ck((globalThis.__rpc || []).some(c => c.fn === 'lkl_enforce_blacklist'), 'aplicou o ban via RPC');

// 2b. 🔴 O IP desta rota TEM de chegar na RPC. Ele não vem de header: vem no
//     body de um serviço que provou posse do API_SECRET e já extraiu o IP do
//     proxy dele. Se o guard tratasse isto como header do cliente, todo ban
//     vindo do revendedor sairia sem IP — e o único jeito de notar seria ler o
//     alerta do Telegram e reparar na linha "não aplicado".
globalThis.__rpc = []; globalThis.__tg = [];
res = mkRes();
await handler(mkReq({ mode: 'check' }, { 'x-api-secret': 'segredo' },
                    { key: '@AvienOffical', ip: '185.158.22.5', route: 'reseller' }), res);
{
    const args = (globalThis.__rpc || []).find(c => c.fn === 'lkl_enforce_blacklist')?.args;
    ck(args?.p_ip === '185.158.22.5', 'IP do serviço é banido', `obtido ${JSON.stringify(args?.p_ip)}`);
    ck(args?.p_evidence?.ip_source === 'service', 'evidência registra a origem "service"',
       JSON.stringify(args?.p_evidence?.ip_source));
}

// 2c. IP privado NÃO passa nem por esta rota: um serviço mal configurado
//     mandando 10.x encheria a ip_blacklist de endereço que não identifica
//     ninguém — e o próximo cliente atrás daquele NAT levaria o bloqueio.
globalThis.__rpc = [];
res = mkRes();
await handler(mkReq({ mode: 'check' }, { 'x-api-secret': 'segredo' },
                    { key: '@AvienOffical', ip: '10.0.0.5', route: 'reseller' }), res);
{
    const args = (globalThis.__rpc || []).find(c => c.fn === 'lkl_enforce_blacklist')?.args;
    ck(args?.p_ip === null, 'IP privado recusado mesmo na rota de serviço', JSON.stringify(args?.p_ip));
    ck(args?.p_license_key === '@AvienOffical', 'a licença continua sendo banida');
}

// 3. Chave limpa: passa, e NÃO dispara sanção.
globalThis.__rpc = [];
res = mkRes();
await handler(mkReq({ mode: 'check' }, { 'x-api-secret': 'segredo' }, { key: 'LKL-A7K2M9' }), res);
ck(res.payload?.blocked === false, 'chave limpa passa', JSON.stringify(res.payload));
ck((globalThis.__rpc || []).length === 0, 'não aplicou ban em chave limpa');

// 4. Método errado na interface de serviço.
res = mkRes();
await handler(mkReq({ mode: 'check' }, { 'x-api-secret': 'segredo' }, {}, 'GET'), res);
ck(res.code === 405, 'GET em mode=check devolve 405', `obtido ${res.code}`);

// 5. 🔴 O desvio inverso: o segredo de serviço NÃO pode abrir o caminho de
//    admin. Sem esta asserção, dobrar as rotas poderia ter transformado o
//    x-api-secret numa credencial de administrador — a lista completa de bans,
//    e o DELETE que desbane, atrás de um segredo pensado para consulta.
globalThis.__sess = null;
res = mkRes();
await handler(mkReq({}, { 'x-api-secret': 'segredo' }, {}, 'GET'), res);
ck(res.code === 401, 'caminho admin exige sessão mesmo com o segredo', `obtido ${res.code}`);

// 6. Admin legítimo continua funcionando (não quebrei a interface original).
globalThis.__sess = { username: 'ronni' };
res = mkRes();
await handler(mkReq({}, {}, {}, 'GET'), res);
ck(res.code === 200, 'admin com sessão lista normalmente', `obtido ${res.code}`);
ck(Array.isArray(res.payload?.traps), 'GET devolve as 4 listas', JSON.stringify(Object.keys(res.payload || {})));


// ===========================================================================
// ORACULO DE RESPOSTA — o corpo do bloqueio tem de ser IDENTICO ao de key
// inexistente. Medido em producao 21-08: o guard devolvia
//   {"valid":false,"success":false,"message":"Chave inválida"}
// e validate.js devolvia
//   {"valid":false,"message":"Chave não encontrada"}
// Ambos 404, corpos DIFERENTES -> bastava comparar a string para descobrir se
// um device estava banido. Erro generico que difere nao e generico.
// ===========================================================================
{
    const guardSrc = readFileSync(new URL('../api/_lib/blacklist-guard.js', import.meta.url), 'utf8');
    const validateSrc = readFileSync(new URL('../api/validate.js', import.meta.url), 'utf8');

    const canon = validateSrc.match(/return res\.status\(404\)\.json\((\{[^}]*\})\)/);
    ck(!!canon, 'validate.js tem resposta 404 de key inexistente');

    const norm = o => o.replace(/\s+/g, ' ').trim();
    const canonBody = canon ? norm(canon[1]) : null;

    const guardBodies = [...guardSrc.matchAll(/body:\s*(\{[^}]*\})/g)].map(m => norm(m[1]));
    ck(guardBodies.length >= 2, 'guard devolve ao menos 2 corpos de bloqueio', String(guardBodies.length));

    for (const b of guardBodies) {
        ck(b === canonBody, 'corpo do guard identico ao de key inexistente', `${b} != ${canonBody}`);
    }

    ck(!/body:[^}]*success/.test(guardSrc), 'guard nao devolve success:false (delator)');
}

console.log(`\n${fail === 0 ? 'OK' : 'FALHOU'} — ${pass} passaram, ${fail} falharam`);
process.exit(fail === 0 ? 0 : 1);
