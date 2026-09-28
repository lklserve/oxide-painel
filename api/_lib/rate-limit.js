import { getServiceSupabase } from './supabase.js';

/**
 * Rate limit persistente (tabela `rate_limits` no Supabase).
 *
 * 🔴 A versao anterior guardava os contadores num `Map()` de processo. Em serverless
 * (Vercel Hobby) cada invocacao pode cair numa instancia nova e frias comecam com o
 * Map vazio -- ou seja, o limite de 5 tentativas de login por IP era contornavel
 * so insistindo: o atacante recebia instancias novas e o contador voltava a zero.
 * Nao havia brute-force protection de verdade nos endpoints de autenticacao.
 *
 * Agora o estado vive no banco, compartilhado por todas as instancias. A tabela e
 * criada por `rate_limit.sql` (ou pelo fix_all.sql).
 *
 * Fail-open x fail-closed: se o banco falhar, liberamos a requisicao (fail-open) --
 * indisponibilidade do contador nao pode derrubar o login do painel inteiro. O
 * evento vai para o console para nao passar silencioso.
 */

const TABLE = 'rate_limits';

// Fallback em memoria: cobre o intervalo entre o deploy do codigo e a criacao da
// tabela, e o caso de erro do banco. Nao substitui a persistencia (ver comentario
// acima) -- e so para nao ficar sem NENHUM limite.
const memory = new Map();

function memoryLimit(key, { windowMs, max, failWindowMs, maxFails = Infinity }) {
    const now = Date.now();
    let rec = memory.get(key);
    if (!rec || now - rec.firstAttempt > windowMs) {
        rec = { count: 1, fails: 0, firstAttempt: now, firstFail: now };
        memory.set(key, rec);
        return { limited: false, record: rec, backend: 'memory' };
    }
    rec.count++;
    if (rec.count > max) return { limited: true, record: rec, reason: 'rate', backend: 'memory' };
    if (failWindowMs && now - rec.firstFail > failWindowMs) {
        rec.fails = 0;
        rec.firstFail = now;
    }
    if (rec.fails > maxFails) return { limited: true, record: rec, reason: 'fails', backend: 'memory' };
    return { limited: false, record: rec, backend: 'memory' };
}

/**
 * Consome uma tentativa e diz se a requisicao deve ser bloqueada.
 * ASSINCRONA: os chamadores precisam usar `await`.
 */
export async function rateLimit(key, { windowMs, max, failWindowMs, maxFails = Infinity }) {
    const nowMs = Date.now();
    const now = new Date(nowMs).toISOString();

    let supabase;
    try {
        supabase = getServiceSupabase();
    } catch (e) {
        console.error('[rate-limit] Supabase indisponivel, usando memoria:', e.message);
        return memoryLimit(key, { windowMs, max, failWindowMs, maxFails });
    }

    try {
        const { data: rec, error } = await supabase
            .from(TABLE)
            .select('bucket_key, count, fails, first_attempt, first_fail')
            .eq('bucket_key', key)
            .maybeSingle();

        // Tabela ausente ou sem permissao: nao dar de graca o endpoint, cair na memoria.
        if (error) {
            console.error('[rate-limit] leitura falhou, usando memoria:', error.message);
            return memoryLimit(key, { windowMs, max, failWindowMs, maxFails });
        }

        const janelaExpirou = !rec || (nowMs - new Date(rec.first_attempt).getTime() > windowMs);

        if (janelaExpirou) {
            // Janela nova: zera contadores. upsert cobre tanto o 1o acesso quanto o reset.
            const { error: upErr } = await supabase.from(TABLE).upsert({
                bucket_key: key,
                count: 1,
                fails: 0,
                first_attempt: now,
                first_fail: now,
                updated_at: now
            }, { onConflict: 'bucket_key' });
            if (upErr) {
                console.error('[rate-limit] upsert falhou, usando memoria:', upErr.message);
                return memoryLimit(key, { windowMs, max, failWindowMs, maxFails });
            }
            return { limited: false, record: { count: 1, fails: 0 }, backend: 'supabase' };
        }

        const count = (rec.count || 0) + 1;
        let fails = rec.fails || 0;
        let firstFail = rec.first_fail || now;
        if (failWindowMs && nowMs - new Date(firstFail).getTime() > failWindowMs) {
            fails = 0;
            firstFail = now;
        }

        await supabase.from(TABLE).update({
            count, fails, first_fail: firstFail, updated_at: now
        }).eq('bucket_key', key);

        if (count > max) return { limited: true, record: { count, fails }, reason: 'rate', backend: 'supabase' };
        if (fails > maxFails) return { limited: true, record: { count, fails }, reason: 'fails', backend: 'supabase' };
        return { limited: false, record: { count, fails }, backend: 'supabase' };
    } catch (e) {
        console.error('[rate-limit] erro inesperado, usando memoria:', e.message);
        return memoryLimit(key, { windowMs, max, failWindowMs, maxFails });
    }
}

/**
 * Marca uma falha de autenticacao (senha/chave errada) no bucket.
 * ASSINCRONA: usar `await`.
 */
export async function recordFailure(key) {
    const mem = memory.get(key);
    if (mem) mem.fails++;

    try {
        const supabase = getServiceSupabase();
        const { data: rec } = await supabase
            .from(TABLE).select('fails').eq('bucket_key', key).maybeSingle();
        if (!rec) return;
        await supabase.from(TABLE)
            .update({ fails: (rec.fails || 0) + 1, updated_at: new Date().toISOString() })
            .eq('bucket_key', key);
    } catch (e) {
        console.error('[rate-limit] recordFailure falhou:', e.message);
    }
}

/** Limpeza de buckets velhos (chamar de um cron, opcional). */
export async function pruneRateLimits(olderThanMs = 24 * 60 * 60 * 1000) {
    try {
        const supabase = getServiceSupabase();
        const cutoff = new Date(Date.now() - olderThanMs).toISOString();
        await supabase.from(TABLE).delete().lt('updated_at', cutoff);
    } catch (e) {
        console.error('[rate-limit] prune falhou:', e.message);
    }
}
