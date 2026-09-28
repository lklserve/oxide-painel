import { escapeTelegramHtml } from './sanitize.js';
import { getServiceSupabase } from './supabase.js';

// ---------------------------------------------------------------------------
// De onde sai o token (a ordem importa)
//
// 1º  settings.telegram_config no banco  -- o que o painel realmente escreve
//     quando voce clica "Salvar" (license-actions -> save_setting).
// 2º  env vars TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_IDS  -- fallback.
//
// 🔴 POR QUE ISSO EXISTE: antes esta lib lia SO a env var. Como as env vars nao
// estavam na Vercel, todo `sendTelegram` do servidor devolvia
// `{sent:false, reason:'Telegram not configured'}` e NENHUM chamador olhava esse
// retorno -- os endpoints respondiam `success:true` e nada era enviado.
// O botao "Testar" do painel continuava funcionando porque ele chama a API do
// Telegram DIRETO DO NAVEGADOR com o token do formulario (index.html), sem tocar
// no servidor. Ou seja: o teste passar nunca provou que as logs sairiam.
// ---------------------------------------------------------------------------

let cache = null;
let cacheAt = 0;
const CACHE_MS = 60_000;   // 1 min: evita 1 SELECT por evento em pico de login

function fromEnv() {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const raw = process.env.TELEGRAM_CHAT_IDS || '';
    const chatIds = raw.split(',').map(s => s.trim()).filter(Boolean);
    return { token, chatIds, source: 'env' };
}

async function fromDatabase() {
    try {
        const supabase = getServiceSupabase();
        const { data } = await supabase
            .from('settings').select('value').eq('key', 'telegram_config').maybeSingle();

        const cfg = data?.value;
        if (!cfg || cfg.enabled === false) return null;

        const token = (cfg.bot_token || '').trim();
        // O painel salva `chat_id` (singular). Aceita string com virgulas ou array,
        // para o admin poder cadastrar mais de um destino sem mudar o painel.
        const rawIds = cfg.chat_ids ?? cfg.chat_id ?? '';
        const chatIds = (Array.isArray(rawIds) ? rawIds : String(rawIds).split(','))
            .map(s => String(s).trim())
            .filter(Boolean);

        if (!token || !chatIds.length) return null;
        return { token, chatIds, source: 'db' };
    } catch (e) {
        console.error('telegram: falha ao ler settings.telegram_config:', e.message);
        return null;
    }
}

async function getConfig() {
    if (cache && Date.now() - cacheAt < CACHE_MS) return cache;

    const cfg = (await fromDatabase()) || fromEnv();
    if (cfg.token && cfg.chatIds.length) {
        cache = cfg;
        cacheAt = Date.now();
    }
    return cfg;
}

export function invalidateTelegramCache() {
    cache = null;
    cacheAt = 0;
}

export async function sendTelegram(message, { parseMode = 'HTML' } = {}) {
    const { token, chatIds, source } = await getConfig();

    if (!token || !chatIds.length) {
        // 🔴 Nao silenciar: era exatamente isto que fazia as logs desaparecerem
        // sem deixar rastro nenhum no painel nem no log da funcao.
        console.error(
            'telegram: NAO CONFIGURADO -- mensagem descartada. ' +
            'Configure em Ajustes > Telegram (grava settings.telegram_config) ' +
            'ou defina TELEGRAM_BOT_TOKEN e TELEGRAM_CHAT_IDS.'
        );
        return { sent: false, reason: 'Telegram not configured' };
    }

    const results = await Promise.all(chatIds.map(async (chatId) => {
        try {
            const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: parseMode })
            });

            if (!response.ok) {
                // A API do Telegram responde 400 com a razao no corpo (chat_id
                // errado, bot bloqueado, HTML mal formado). Sem ler isto, um
                // parse_mode invalido viraria "sumiu a mensagem" outra vez.
                let why = '';
                try {
                    const body = await response.json();
                    why = body?.description || '';
                } catch { /* corpo nao-JSON: fica so o status */ }
                console.error(`telegram: chat ${chatId} recusou (HTTP ${response.status}) ${why}`);
                return { chatId, ok: false, status: response.status, error: why };
            }

            return { chatId, ok: true };
        } catch (e) {
            console.error(`Telegram Error for ${chatId}:`, e);
            return { chatId, ok: false, error: e.message };
        }
    }));

    const okCount = results.filter(r => r.ok).length;
    return { sent: okCount > 0, source, delivered: okCount, total: results.length, results };
}

export { escapeTelegramHtml };
