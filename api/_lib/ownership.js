/**
 * Controle de posse de licenca (prevencao de IDOR).
 *
 * 🔴 Sem isto, qualquer admin autenticado editava, banir, estendia ou DELETAVA a
 * licenca de outro admin apenas mandando o `id` no corpo -- o handler validava a
 * sessao (ha sessao valida?) mas nunca a autorizacao (esta licenca e sua?).
 *
 * Modelo de posse real do painel, medido no schema e no frontend:
 *   - `licenses.created_by` = username do admin que criou (aba "Minhas chaves");
 *   - `licenses.reseller_id` = criada por revendedor (aba "Revendedores");
 *   - chaves antigas podem ter `created_by` NULL, e vendas automaticas gravam
 *     'System (Webhook)'.
 *
 * Regras:
 *   - role `superadmin` passa por tudo (auditoria e suporte);
 *   - dono (`created_by` == admin da sessao) passa;
 *   - `created_by` NULL/legado e 'System (Webhook)' ficam liberados para qualquer
 *     admin: sao chaves sem dono definido e bloquear isso quebraria o painel
 *     (chaves antigas e vendas automaticas ficariam intocaveis);
 *   - qualquer outro caso => 403.
 */

// 🔴 28-08: `'loja'` FALTAVA aqui e travou TODA chave vendida pela loja.
// A loja e outro repo (`lklserve/lkl-shop`) e grava seu proprio rotulo em
// `created_by` (`src/lib/checkout.server.ts:203`: `created_by: "loja"`). Eu havia
// coberto so o webhook DESTE repo ('System (Webhook)', `api/create.js:204`), entao
// chave de loja caia em `not_owner` -> 403 "pertence a outro administrador" nas
// **11** acoes que passam por `canModifyLicense` (update, toggle_free, extend,
// reduce, ban, ban_full, shadowban, unban, pause, unpause, reset_ip) + o delete.
// Venda automatica nao tem dono humano: mesmo tratamento do webhook.
//
// ⚠️ A chave de REVENDEDOR passa aqui **por acidente**: o RPC
// `reseller_issue_license` (supabase/migrations/001_security_hardening.sql) insere
// `reseller_id` e NAO `created_by`, entao fica NULL e o `null` abaixo a engole. O
// docstring acima cita `reseller_id` como criterio de posse, mas `canModifyLicense`
// **nunca le esse campo**. No dia em que o RPC passar a gravar `created_by`, toda
// chave de revendedor trava de uma vez -- somar o rotulo dele a este Set.
const OWNERLESS = new Set([null, undefined, '', 'System (Webhook)', 'System', 'loja']);

export function isSuperAdmin(session) {
    return session?.role === 'superadmin';
}

/**
 * @returns {{ allowed: boolean, reason?: string }}
 */
export function canModifyLicense(license, session) {
    if (!license) return { allowed: false, reason: 'not_found' };
    if (isSuperAdmin(session)) return { allowed: true };

    const owner = license.created_by;
    if (OWNERLESS.has(owner)) return { allowed: true };
    if (owner === session?.username) return { allowed: true };

    return { allowed: false, reason: 'not_owner' };
}

/**
 * Busca a licenca e decide a posse numa so ida ao banco.
 * @returns {{ license: object|null, allowed: boolean, reason?: string }}
 */
export async function loadLicenseForWrite(supabase, id, session) {
    const { data: license } = await supabase
        .from('licenses')
        .select('*')
        .eq('id', id)
        .maybeSingle();
    const verdict = canModifyLicense(license, session);
    return { license: license || null, ...verdict };
}
