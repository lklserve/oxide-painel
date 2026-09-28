// ===========================================================================
// Teste do guard de blacklist. Roda SEM banco (só a normalização em memória).
//
//   node tools/test_blacklist_guard.mjs
//
// POR QUE existe: a normalização vive em DOIS lugares — normalizeKeyish() no
// _lib/blacklist-guard.js e lkl_normalize_keyish() na migração 004 — porque o
// painel-revendedor é outro projeto Vercel e só alcança a versão SQL. Se as
// duas divergirem, a variante escapa do bloqueio sem erro nenhum: o log diz
// "verificado", a resposta diz "liberado", e nada aponta para a causa.
//
// Este arquivo trava as duas contra a MESMA lista de casos. A checagem do SQL
// exige banco, então ela é opcional (ver o fim do arquivo).
// ===========================================================================

import { normalizeKeyish, normalizeEmail, extractEmail } from '../api/_lib/blacklist-guard.js';

let pass = 0, fail = 0;

function eq(actual, expected, label) {
    const ok = actual === expected;
    if (ok) { pass++; } else {
        fail++;
        console.log(`  FALHOU  ${label}\n          esperado: ${JSON.stringify(expected)}\n          obtido:   ${JSON.stringify(actual)}`);
    }
}

// ── normalizeKeyish: variantes que DEVEM colapsar no mesmo valor ────────────
const TRAP = 'avienoffical';
const shouldMatch = [
    '@AvienOffical',
    'AvienOffical',
    'avienoffical',
    'AVIENOFFICAL',
    '@avien_offical',
    'avien offical',
    'avien-offical',
    '@Avien.Offical',
    'Avi3nOffical',       // 3 -> e
    '@AvienOffic4l',      // 4 -> a
    'AvienOff1cal',       // 1 -> l ... 'offical' tem l, não i: vira offlcal
    '  @AvienOffical  '
];

console.log('normalizeKeyish — variantes da armadilha:');
for (const v of shouldMatch) {
    const n = normalizeKeyish(v);
    // 'contains' é o modo do padrão cadastrado: basta conter.
    const hit = n.includes(TRAP);
    // AvienOff1cal normaliza para 'avienofflcal' (1->l), que NÃO contém o
    // padrão. Documentado de propósito: a substituição de homoglifos cobre o
    // caso comum de digitação, não é um matcher de distância de edição.
    const expectedHit = v !== 'AvienOff1cal';
    eq(hit, expectedHit, `${JSON.stringify(v)} -> ${JSON.stringify(n)} contém '${TRAP}'`);
}

// ── Chaves legítimas: NÃO podem casar ───────────────────────────────────────
// 🔴 O teste que importa. Um falso positivo aqui não é um bug de borda: o guard
// aplica ban + cascata, então uma key real que case derruba o cliente pagante
// E todas as outras licenças do mesmo device.
console.log('\nnormalizeKeyish — chaves legítimas (nenhuma pode casar):');
const legit = [
    'LKL-A7K2M9', 'LKL-XYZ234', 'LKL-99AAAA', 'LKL-2K3M4N5P',
    'LKL-AVIEN2', 'LKL-AV1EN3',           // prefixo parecido, curto: seguro
    'lkl-hjklmn', 'LKL-PQRSTU'
];
for (const k of legit) {
    eq(normalizeKeyish(k).includes(TRAP), false, `${k} NÃO casa`);
}

// ── Entradas degeneradas ────────────────────────────────────────────────────
console.log('\nnormalizeKeyish — entradas degeneradas:');
eq(normalizeKeyish(null), '', 'null -> string vazia');
eq(normalizeKeyish(undefined), '', 'undefined -> string vazia');
eq(normalizeKeyish(''), '', 'vazio -> vazio');
eq(normalizeKeyish('@@@___...'), '', 'só pontuação -> vazio');
// String vazia nunca deve casar: 'x'.includes('') é true em JS, então um
// padrão vazio no banco casaria com TODA chave. loadPatterns() descarta
// padrões vazios (`if (!norm) continue`) exatamente por isto.
eq('LKL-A7K2M9'.includes(normalizeKeyish('')), true,
   "sanidade: includes('') é true — por isso loadPatterns descarta padrão vazio");

// ── E-mail ──────────────────────────────────────────────────────────────────
console.log('\nnormalizeEmail / extractEmail:');
eq(normalizeEmail('  Joao@Gmail.COM '), 'joao@gmail.com', 'trim + lowercase');
eq(normalizeEmail(''), null, 'vazio -> null');
eq(normalizeEmail(null), null, 'null -> null');
eq(extractEmail('Joao Silva (Joao@Gmail.com)'), 'joao@gmail.com', 'extrai do formato do webhook');
eq(extractEmail('Cliente Erby X4B2'), null, 'sem e-mail -> null');
eq(extractEmail(null), null, 'null -> null');

// ── Paridade com o SQL (opcional, exige banco) ──────────────────────────────
// Rode com as env vars do Supabase para validar que lkl_normalize_keyish()
// produz o MESMO valor que normalizeKeyish() para cada caso acima:
//
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... node tools/test_blacklist_guard.mjs --sql
//
if (process.argv.includes('--sql')) {
    console.log('\nParidade JS <-> SQL (lkl_normalize_keyish):');
    const { getServiceSupabase } = await import('../api/_lib/supabase.js');
    const supabase = getServiceSupabase();
    for (const v of [...shouldMatch, ...legit, '@@@___...', '']) {
        const { data, error } = await supabase.rpc('lkl_normalize_keyish', { p_value: v });
        if (error) { console.log(`  ERRO RPC: ${error.message}`); fail++; break; }
        eq(data, normalizeKeyish(v), `SQL == JS para ${JSON.stringify(v)}`);
    }
} else {
    console.log('\n(paridade com SQL não verificada — rode com --sql e as env vars do Supabase)');
}

console.log(`\n${fail === 0 ? 'OK' : 'FALHOU'} — ${pass} passaram, ${fail} falharam`);
process.exit(fail === 0 ? 0 : 1);
