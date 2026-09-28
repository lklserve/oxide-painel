// ===========================================================================
// Extracao de IP do cliente — fonte unica para todos os endpoints.
//
// POR QUE existe: cinco endpoints repetiam
//     (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
// e `[0]` e a ponta que o CLIENTE escreve. Enquanto o IP so servia para
// rate-limit e log, o pior caso era um contador furado. No momento em que o IP
// passa a ser BANIDO, essa mesma linha vira arma apontada para dentro: basta
// mandar `X-Forwarded-For: <ip-de-um-cliente-pagante>` junto da chave-armadilha
// para o painel banir a vitima e nao o infrator.
//
// A Vercel resolve isso com `x-vercel-forwarded-for`, que o proxy dela escreve
// e sobrescreve — o cliente nao consegue forjar. Este modulo distingue as duas
// fontes e diz, explicitamente, se o valor e bom o suficiente para punir.
//
// 🔑 Duas perguntas DIFERENTES, duas funcoes: "qual IP e este?" (log, rate
// limit — serve qualquer palpite) e "posso banir este IP?" (precisa de origem
// confiavel). Colapsar as duas foi o que deixou a porta aberta.
// ===========================================================================

/** Header escrito pelo proxy da Vercel. Nao forjavel pelo cliente. */
const TRUSTED_HEADER = 'x-vercel-forwarded-for';

/** Header convencional: util, mas a primeira posicao vem do cliente. */
const UNTRUSTED_HEADER = 'x-forwarded-for';

function firstHop(value) {
    if (!value) return '';
    // Header repetido chega como array no Node.
    const raw = Array.isArray(value) ? value[0] : value;
    return String(raw).split(',')[0].trim();
}

/** ::ffff:1.2.3.4 -> 1.2.3.4 · [::1]:5 -> ::1 */
function unwrap(ip) {
    if (!ip) return '';
    let out = String(ip).trim();
    if (out.startsWith('[')) out = out.slice(1, out.indexOf(']') > 0 ? out.indexOf(']') : undefined);
    if (out.toLowerCase().startsWith('::ffff:')) out = out.slice(7);
    return out;
}

/**
 * IP do cliente + de onde ele veio.
 *
 * @returns {{ ip: string, source: 'vercel'|'xff'|'socket'|'none', trusted: boolean }}
 *          `trusted` = veio do proxy da Vercel. So isso autoriza um ban.
 */
export function getClientIpInfo(req) {
    const headers = req?.headers || {};

    const viaProxy = unwrap(firstHop(headers[TRUSTED_HEADER]));
    if (viaProxy) return { ip: viaProxy, source: 'vercel', trusted: true };

    const viaXff = unwrap(firstHop(headers[UNTRUSTED_HEADER]));
    if (viaXff) return { ip: viaXff, source: 'xff', trusted: false };

    const viaSocket = unwrap(req?.socket?.remoteAddress || req?.connection?.remoteAddress);
    if (viaSocket) return { ip: viaSocket, source: 'socket', trusted: false };

    return { ip: 'Unknown', source: 'none', trusted: false };
}

/**
 * IP como string, para log e rate-limit. Substitui a linha duplicada nos
 * endpoints; o comportamento observavel e o mesmo de antes quando o header
 * confiavel nao existe (dev local, outro host).
 */
export function getClientIp(req) {
    return getClientIpInfo(req).ip;
}

/**
 * Endereco que NAO identifica uma pessoa: loopback, rede privada (RFC1918),
 * link-local, CGNAT (RFC6598 100.64/10) e afins. Banir qualquer um destes nao
 * atinge o infrator e pode derrubar terceiros.
 */
export function isPrivateOrReservedIp(ip) {
    if (!ip) return true;
    const v = unwrap(ip).toLowerCase();
    if (!v || v === 'unknown') return true;

    // IPv6 local / unico-local / nao especificado
    if (v === '::' || v === '::1') return true;
    if (/^f[cd][0-9a-f]{2}:/.test(v)) return true;   // fc00::/7
    if (/^fe[89ab][0-9a-f]:/.test(v)) return true;   // fe80::/10

    const m = v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return false;                            // IPv6 publico segue adiante
    const [a, b] = [Number(m[1]), Number(m[2])];
    if ([a, b, Number(m[3]), Number(m[4])].some(n => n > 255)) return true;

    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;          // link-local
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT RFC6598
    if (a >= 224) return true;                        // multicast / reservado
    return false;
}

/**
 * Este IP pode entrar na `ip_blacklist`?
 *
 * Exige as DUAS condicoes, e devolve o motivo quando nega — o alerta do
 * Telegram imprime esse motivo em vez de "nao aplicado", que nao dizia se a
 * causa foi a flag, a origem ou o endereco.
 *
 * @returns {{ ok: boolean, reason: string }}
 */
export function canBanIp(info) {
    if (!info || !info.ip || info.ip === 'Unknown') {
        return { ok: false, reason: 'IP ausente na requisição' };
    }
    if (!info.trusted) {
        return { ok: false, reason: `origem não confiável (${info.source}: cliente pode forjar o header)` };
    }
    if (isPrivateOrReservedIp(info.ip)) {
        return { ok: false, reason: 'endereço privado/reservado (não identifica ninguém)' };
    }
    return { ok: true, reason: 'origem confiável e endereço público' };
}
