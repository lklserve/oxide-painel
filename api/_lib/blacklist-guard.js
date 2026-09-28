import { getServiceSupabase } from './supabase.js';
import { sendTelegram, escapeTelegramHtml } from './telegram.js';
import { canBanIp } from './ip-utils.js';

// ===========================================================================
// Guard de blacklist — prioridade maxima em TODA porta de entrada.
//
// Chamado por:
//   api/validate.js               login do mod (KingRonni)
//   api/create.js                 webhook de venda (gera key automatica)
//   api/license-actions.js        criacao manual pelo admin
//   painel-revendedor .../generate rota do revendedor (via HTTP, ver nota no fim)
//
// REGRA DE OURO desta camada: a resposta ao infrator e SEMPRE a mesma que um
// erro comum produz. Mensagem especifica ("voce esta banido", "chave proibida")
// ensina o que evitar na proxima tentativa; erro genérico nao ensina nada.
// Quem precisa saber o que aconteceu e o admin, e ele descobre pelo Telegram e
// pelo activity_logs -- nao pelo corpo da resposta HTTP.
// ===========================================================================

// Quanto tempo a lista de padroes-armadilha fica em memoria. Sem cache, cada
// login gastaria 1 SELECT extra no caminho quente; com 60s, um padrao novo
// cadastrado pelo painel entra em vigor em no maximo 1 minuto.
const PATTERN_CACHE_MS = 60_000;

// Fallback compilado. POR QUE existe: se o SELECT em key_blacklist falhar
// (tabela ainda nao migrada, banco intermitente), a armadilha NAO pode virar
// login liberado. Este array garante que o padrao critico funciona mesmo com o
// banco degradado. O banco serve para ADICIONAR padroes, nao para habilitar o
// mecanismo.
const HARDCODED_TRAPS = [
    { pattern_norm: 'avienoffical', match_mode: 'contains',
      reason: 'Chave-armadilha (honeypot) — uso indica tentativa de acesso indevido' }
];

// Banir IP por uso da CHAVE-ARMADILHA. Ligado por default desde 23-08.
//
// 🔴 O risco que manteve isto desligado e real, mas e de OUTRO tipo de ban:
// IP movel brasileiro e CGNAT (RFC6598), dezenas de milhares de assinantes no
// mesmo endereco -- banir derruba cliente pagante que nunca tocou na armadilha,
// e o sintoma no suporte e "parou do nada", sem pista nenhuma ligando ao ban.
//
// O que mudou: o gatilho aqui nao e "errou a senha", e digitar uma chave que
// NAO EXISTE e nunca existiu. Ninguem chega em `@AvienOffical` por acidente.
// E as duas defesas abaixo cobrem justamente o caso CGNAT:
//   * `isPrivateOrReservedIp` recusa a faixa 100.64/10 (o CGNAT em si)
//   * `canBanIp` exige que o IP tenha vindo do proxy da Vercel
// Continua desligavel: LKL_BAN_IP_ON_TRAP=0.
//
// 🔑 Ban de IP NAO substitui device/e-mail, soma. IP identifica a rota; device
// e e-mail identificam a pessoa, e sao esses que sobrevivem a troca de rede.
const BAN_IP_ON_TRAP = process.env.LKL_BAN_IP_ON_TRAP !== '0';

let _patternCache = null;
let _patternCacheAt = 0;

/**
 * Normaliza uma chave para o espaco de comparacao da armadilha.
 *
 * Objetivo: uma variante trivial ("@Avien_Offical", "AVIEN0FFICAL", "avien
 * offical") tem de cair no MESMO valor que o padrao cadastrado. Sem isto o
 * bloqueio vira um jogo de escrever diferente.
 *
 * Passos, nesta ordem:
 *   1. minusculas
 *   2. remove tudo que nao e letra/digito  (@ _ - . espaco somem)
 *   3. dobra homoglifos de teclado: 0->o, 1->l, 3->e, 4->a, 5->s, 7->t
 *
 * ⚠️ O passo 3 e aplicado ao PADRAO tambem (ver loadPatterns) -- normalizar
 * so um lado dos dois faria a comparacao falhar justamente na variante.
 */
export function normalizeKeyish(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .toLowerCase()
        .replace(/[^a-z0-9]/g, '')
        .replace(/0/g, 'o')
        .replace(/1/g, 'l')
        .replace(/3/g, 'e')
        .replace(/4/g, 'a')
        .replace(/5/g, 's')
        .replace(/7/g, 't');
}

/** E-mail normalizado: minusculas + trim. Espelha email_blacklist.email_norm. */
export function normalizeEmail(value) {
    if (value === null || value === undefined) return null;
    const s = String(value).trim().toLowerCase();
    return s.length ? s : null;
}

/**
 * Extrai e-mail de um texto livre. O webhook de venda grava
 * client_username como "Nome (email@dominio)" (create.js:73), entao o e-mail
 * de uma licenca antiga so existe embutido nesse campo.
 */
export function extractEmail(value) {
    if (!value) return null;
    const m = String(value).match(/[\w.+-]+@[\w-]+\.[\w.-]+/);
    return m ? normalizeEmail(m[0]) : null;
}

async function loadPatterns() {
    const now = Date.now();
    if (_patternCache && now - _patternCacheAt < PATTERN_CACHE_MS) return _patternCache;

    let rows = [];
    try {
        const supabase = getServiceSupabase();
        const { data, error } = await supabase
            .from('key_blacklist')
            .select('pattern_norm, match_mode, reason')
            .eq('active', true);
        if (error) throw new Error(error.message);
        rows = data || [];
    } catch (e) {
        // Nao silenciar: se isto virar rotina, o admin precisa ver no log.
        console.error('blacklist-guard: key_blacklist indisponivel, usando fallback compilado:', e.message);
    }

    // Une banco + fallback e normaliza o PADRAO no mesmo espaco da entrada.
    const merged = [...rows, ...HARDCODED_TRAPS];
    const seen = new Set();
    const out = [];
    for (const r of merged) {
        const norm = normalizeKeyish(r.pattern_norm);
        if (!norm || seen.has(norm)) continue;
        seen.add(norm);
        out.push({
            norm,
            mode: r.match_mode === 'exact' ? 'exact' : 'contains',
            reason: r.reason || 'Chave em blacklist'
        });
    }

    _patternCache = out;
    _patternCacheAt = now;
    return out;
}

export function invalidatePatternCache() {
    _patternCache = null;
    _patternCacheAt = 0;
}

/**
 * A chave informada casa com algum padrao-armadilha?
 * Retorna o padrao que casou, ou null.
 */
export async function matchTrapKey(rawKey) {
    const norm = normalizeKeyish(rawKey);
    if (!norm) return null;
    const patterns = await loadPatterns();
    for (const p of patterns) {
        if (p.mode === 'exact' ? norm === p.norm : norm.includes(p.norm)) return p;
    }
    return null;
}

/**
 * Consulta as tres blacklists de identidade em paralelo.
 * Retorna { blocked: bool, kind, reason } — `kind` para o log, nunca para a
 * resposta HTTP.
 */
export async function checkIdentity({ deviceId, ip, email } = {}) {
    const supabase = getServiceSupabase();
    const emailNorm = normalizeEmail(email);

    const queries = [
        deviceId
            ? supabase.from('blacklist').select('reason').eq('device_id', String(deviceId).trim()).maybeSingle()
            : Promise.resolve({ data: null }),
        ip && ip !== 'Unknown'
            ? supabase.from('ip_blacklist').select('reason').eq('ip', ip).maybeSingle()
            : Promise.resolve({ data: null }),
        emailNorm
            ? supabase.from('email_blacklist').select('reason').eq('email_norm', emailNorm).maybeSingle()
            : Promise.resolve({ data: null })
    ];

    const [dev, ipRow, mail] = await Promise.all(queries);

    if (dev?.data)   return { blocked: true, kind: 'device', reason: dev.data.reason || 'Violação de Termos' };
    if (ipRow?.data) return { blocked: true, kind: 'ip',     reason: ipRow.data.reason || 'Violação de Termos' };
    if (mail?.data)  return { blocked: true, kind: 'email',  reason: mail.data.reason || 'Violação de Termos' };

    return { blocked: false };
}

/**
 * Aplica o banimento. Uma unica chamada RPC = uma transacao no Postgres.
 *
 * 🔑 O `await` aqui e proposital, ao contrario das notificacoes do Telegram
 * (que sao fire-and-forget). Em serverless, uma promessa nao aguardada pode ser
 * cortada quando o handler responde -- e um ban pela metade e pior que nenhum:
 * a licenca cai e o device fica livre. Notificacao perdida custa uma mensagem;
 * ban perdido custa o furo inteiro.
 */
export async function enforceBlacklist({
    reason,
    source = 'auto:trap_key',
    licenseKey = null,
    deviceId = null,
    ip = null,
    ipInfo = null,
    email = null,
    evidence = {},
    actor = 'System (Guard)',
    banIp = BAN_IP_ON_TRAP
} = {}) {
    const supabase = getServiceSupabase();

    // Decisao do ban de IP, com MOTIVO. Antes era `banIp ? ip : null`: quando
    // nao aplicava, ninguem sabia se a causa foi a flag, a origem do header ou
    // o endereco -- o alerta dizia "nao aplicado (ver LKL_BAN_IP_ON_TRAP)"
    // mesmo quando a flag estava ligada e o problema era outro.
    let ipToBan = null;
    let ipSkipReason = null;
    if (!banIp) {
        ipSkipReason = 'desligado por LKL_BAN_IP_ON_TRAP=0';
    } else {
        // `ipInfo` traz a origem (proxy confiavel x header do cliente). Sem ele
        // -- chamador antigo passando so a string -- tratamos como NAO
        // confiavel: preferimos nao banir a banir a vitima de um header forjado.
        const info = ipInfo || { ip, source: 'legacy', trusted: false };
        const verdict = canBanIp(info);
        if (verdict.ok) ipToBan = info.ip;
        else ipSkipReason = verdict.reason;
    }

    try {
        const { data, error } = await supabase.rpc('lkl_enforce_blacklist', {
            p_reason: reason,
            p_source: source,
            p_license_key: licenseKey,
            p_device_id: deviceId,
            p_ip: ipToBan,
            p_email: normalizeEmail(email),
            p_evidence: { ...evidence, ip_seen: ip || null, ip_source: ipInfo?.source || 'legacy' },
            p_actor: actor
        });
        if (error) throw new Error(error.message);
        return { ok: true, ip_skip_reason: ipSkipReason, ...(data || {}) };
    } catch (e) {
        console.error('blacklist-guard: lkl_enforce_blacklist FALHOU:', e.message);
        return { ok: false, error: e.message, ip_skip_reason: ipSkipReason };
    }
}

/**
 * Alerta do Telegram para armadilha acionada.
 *
 * Imprime o RESULTADO de cada acao (quantas keys, quantos ids), nao "ban
 * aplicado". Numero solto ou frase otimista nao carrega veredito -- se a RPC
 * falhar, a mensagem tem de dizer FALHOU, senao o log passa a mentir.
 */
export async function notifyTrap({ key, deviceId, ip, email, result, route }) {
    // 30-08: TRES estados, nao dois. A RPC passou a isolar cada passo (migration
    // 006), entao "licenca revogada mas device fora da blacklist" e um resultado
    // possivel -- e anunciar isso como "APLICADO" faria o alerta mentir do mesmo
    // jeito que "BAN FALHOU" mentia quando o ban tinha funcionado.
    const head = !result?.ok
        ? '🔴 <b>CHAVE-ARMADILHA ACIONADA — BAN FALHOU (agir manualmente)</b>'
        : result?.partial
            ? '⚠️ <b>CHAVE-ARMADILHA ACIONADA — BAN PARCIAL (conferir)</b>'
            : '🪤 <b>CHAVE-ARMADILHA ACIONADA — BAN APLICADO</b>';

    const lines = [
        head, '',
        `🔑 <b>Key:</b> <code>${escapeTelegramHtml(key || '-')}</code>`,
        `📍 <b>Rota:</b> <code>${escapeTelegramHtml(route || '-')}</code>`,
        `📱 <b>Device:</b> <code>${escapeTelegramHtml(deviceId || '-')}</code>`,
        `🌐 <b>IP:</b> <code>${escapeTelegramHtml(ip || '-')}</code>`,
        `📧 <b>E-mail:</b> <code>${escapeTelegramHtml(email || '-')}</code>`
    ];

    if (result?.ok) {
        lines.push(
            '',
            `🚫 <b>Licença da tentativa:</b> ${result.keys_banned ? 'BANIDA' : 'já estava banida/não existe'}`,
            `📱 <b>Device na blacklist:</b> ${result.device_added ? 'GRAVADO' : 'já constava / não informado'}`,
            // Diz o MOTIVO de nao ter banido. "não aplicado (ver
            // LKL_BAN_IP_ON_TRAP)" apontava sempre para a flag, inclusive
            // quando ela estava ligada e o bloqueio vinha de outro lugar --
            // foi assim que um ban de IP faltando passou por "comportamento
            // esperado" em 23-08.
            `🌐 <b>IP na blacklist:</b> ${
                result.ip_added ? 'GRAVADO'
                : result.ip_skip_reason ? `não aplicado — ${escapeTelegramHtml(result.ip_skip_reason)}`
                : 'já constava'
            }`,
            `📧 <b>E-mail na blacklist:</b> ${result.email_added ? 'GRAVADO' : 'já constava / não informado'}`,
            `⛓ <b>Cascata:</b> ${result.cascade_count || 0} licença(s) revogada(s)`
        );
        const cascade = Array.isArray(result.cascade_keys) ? result.cascade_keys : [];
        if (cascade.length) {
            lines.push(`   ${cascade.map(k => `<code>${escapeTelegramHtml(k)}</code>`).join(', ')}`);
        }

        // Passos que falharam sem derrubar o ban. Imprime o SQLSTATE porque foi
        // ele (42P10, "no unique or exclusion constraint") que identificou a causa
        // do ban falhado de 30-08 -- mensagem sem codigo custa uma rodada.
        const failed = Array.isArray(result.failed) ? result.failed : [];
        if (failed.length) {
            lines.push('', `⚠️ <b>Passos que falharam (${failed.length}):</b>`);
            for (const f of failed) {
                lines.push(`   • <code>${escapeTelegramHtml(f?.step || '?')}</code> — ${escapeTelegramHtml(f?.sqlstate || '?')}: ${escapeTelegramHtml(f?.error || '?')}`);
            }
        }
    } else {
        lines.push('', `⚠️ <b>Erro:</b> ${escapeTelegramHtml(result?.error || 'desconhecido')}`);
    }

    // Fire-and-forget: notificacao nao pode atrasar nem derrubar a resposta.
    return sendTelegram(lines.join('\n')).catch(err => console.error('notifyTrap:', err));
}

/**
 * Ponto unico de entrada. Devolve `null` quando esta liberado, ou um objeto
 * { status, body } que o chamador deve responder tal e qual.
 *
 * ⚠️ O corpo devolvido e DELIBERADAMENTE indistinguivel de uma falha comum:
 * 'Chave nao encontrada' com 404 -- copia BYTE A BYTE de validate.js:140, a
 * resposta de key inexistente. Medido em producao: a versao anterior dizia
 * 'Chave invalida' + success:false e o corpo DIFERENTE virava oraculo (bastava
 * comparar a string para saber se o device estava banido). Se validate.js mudar
 * essa linha, esta TEM de mudar junto -- test_blacklist_route.mjs compara as duas.
 * inexistente. Quem sonda o endpoint nao consegue separar "chave errada" de
 * "estou na blacklist" -- e sem essa separacao nao ha o que enumerar.
 */
export async function guardEntry({
    route,
    key = null,
    deviceId = null,
    ip = null,
    ipInfo = null,
    email = null,
    extraEvidence = {}
} = {}) {
    // 1º a armadilha: ela aplica sancao, entao vem antes de qualquer coisa
    // que possa devolver outro erro e encerrar o pedido sem punir.
    const trap = key ? await matchTrapKey(key) : null;
    if (trap) {
        const result = await enforceBlacklist({
            reason: trap.reason,
            source: `auto:trap_key:${route}`,
            licenseKey: String(key).trim(),
            deviceId,
            ip,
            ipInfo,
            email,
            evidence: { route, matched_pattern: trap.norm, raw_key: String(key).slice(0, 128), ...extraEvidence }
        });

        await notifyTrap({ key, deviceId, ip, email, result, route });

        return {
            trapped: true,
            status: 404,
            body: { valid: false, message: 'Chave não encontrada' }
        };
    }

    // 2º a identidade: device / IP / e-mail ja registrados.
    const id = await checkIdentity({ deviceId, ip, email });
    if (id.blocked) {
        return {
            trapped: false,
            blockedKind: id.kind,
            status: 404,
            body: { valid: false, message: 'Chave não encontrada' }
        };
    }

    return null;
}

// ---------------------------------------------------------------------------
// NOTA sobre o painel-revendedor
//
// Ele e um projeto Vercel SEPARADO (prj_3rYwhak…, Next.js/TS) e nao consegue
// importar este arquivo. Para nao manter duas copias da regra divergindo com o
// tempo, la ele chama as funcoes SQL da migracao 004 por RPC
// (`lkl_check_blacklist` / `lkl_enforce_blacklist`), que sao a fonte unica.
// Ver painel-revendedor/lib/blacklist-guard.ts.
//
// Existe TAMBEM a rota de servico POST /api/blacklist?mode=check (x-api-secret),
// para quem nao tiver acesso ao banco. Ela vive dentro de api/blacklist.js
// porque o plano Hobby limita o deployment a 12 Serverless Functions e cada
// `api/*.js` conta uma — um arquivo novo derruba o build inteiro.
// ---------------------------------------------------------------------------
