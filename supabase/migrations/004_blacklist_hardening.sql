-- =====================================================================
-- LKL — Blacklist de identidade + enforcement atomico
-- Rodar UMA VEZ no SQL Editor do Supabase. Idempotente (safe re-run).
--
-- POR QUE existe: a blacklist antiga cobria device_id e ip em tabelas
-- separadas, sem ligacao com a licenca nem com quem foi banido junto.
-- Banir era 1 INSERT manual pelo painel; nada impedia o mesmo device de
-- comprar/gerar key nova no minuto seguinte -- create.js (webhook de venda)
-- e o painel do revendedor nao consultavam blacklist nenhuma.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. ip_blacklist — a tabela EXISTE em producao (criada a mao, ver
--    memory/decisions.md:96) mas nunca teve migracao. Sem isto um banco
--    novo/clone quebra em validate.js e auth.js, que fazem SELECT nela no
--    caminho de login.
-- ---------------------------------------------------------------------
create table if not exists public.ip_blacklist (
    id         uuid primary key default gen_random_uuid(),
    ip         text unique not null,
    reason     text,
    blocked_by text,
    created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- 2. Colunas de evidencia. Sem elas o ban e um device_id solto: nao da
--    para saber com que key ele apareceu, de que IP, nem se foi humano.
-- ---------------------------------------------------------------------
alter table public.blacklist add column if not exists license_key text;
alter table public.blacklist add column if not exists ip          text;
alter table public.blacklist add column if not exists email       text;
alter table public.blacklist add column if not exists source      text;   -- 'admin' | 'auto:trap_key' | 'auto:cascade'
alter table public.blacklist add column if not exists evidence    jsonb default '{}'::jsonb;
alter table public.blacklist add column if not exists permanent   boolean default false;

alter table public.ip_blacklist add column if not exists source   text;
alter table public.ip_blacklist add column if not exists evidence jsonb default '{}'::jsonb;

-- activity_logs.license_key: license-actions.js:9 ja insere nesta coluna, mas
-- ela nao esta no schema.sql -- so existe em producao porque foi criada a mao
-- (a migracao 003 chega a testar se existe). A RPC do item 7 escreve nela.
alter table public.activity_logs add column if not exists license_key text;

-- ---------------------------------------------------------------------
-- 3. Blacklist de e-mail e de chave.
--
--    email_blacklist: o e-mail e o unico identificador que sobrevive a
--    reinstalacao do app E a troca de IP, e e o que o webhook de venda tem
--    em maos antes de gerar qualquer key.
--    ⚠️ Guarda o e-mail NORMALIZADO em coluna propria: "Joao@Gmail.com " e
--    "joao@gmail.com" sao a mesma pessoa, e comparar cru deixaria passar.
--
--    key_blacklist: chaves-armadilha (honeypot). No banco em vez de
--    hardcoded para adicionar variante nova sem redeploy. `pattern_norm`
--    guarda a forma normalizada por normalizeKeyish() (_lib/blacklist-guard.js)
--    -- a comparacao acontece nesse espaco, nunca no texto cru.
-- ---------------------------------------------------------------------
create table if not exists public.email_blacklist (
    id         uuid primary key default gen_random_uuid(),
    email_norm text unique not null,
    email_raw  text,
    reason     text,
    blocked_by text,
    source     text,
    evidence   jsonb default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create table if not exists public.key_blacklist (
    id           uuid primary key default gen_random_uuid(),
    pattern_norm text unique not null,
    pattern_raw  text,
    match_mode   text not null default 'contains' check (match_mode in ('exact', 'contains')),
    reason       text,
    blocked_by   text,
    active       boolean not null default true,
    created_at   timestamptz not null default now()
);

-- Semente: a chave-armadilha. `contains` no espaco normalizado pega
-- "@AvienOffical", "avien offical", "LKL-AvienOffical" e as trocas de
-- caractere parecido (4->a, 1->l, 0->o) que normalizeKeyish() dobra.
-- Nao ha risco de falso positivo: as keys reais sao PREFIXO-6..8 chars do
-- alfabeto sem vogais ambiguas, curtas demais para conter um padrao de 12.
insert into public.key_blacklist (pattern_norm, pattern_raw, match_mode, reason, blocked_by)
values ('avienoffical', '@AvienOffical', 'contains',
        'Chave-armadilha (honeypot) — uso indica tentativa de acesso indevido',
        'System (migration 004)')
on conflict (pattern_norm) do nothing;

-- ---------------------------------------------------------------------
-- 4. Shadowban por licenca.
--
--    Diferente de status='banned' (que nega o login): a licenca continua
--    validando e o painel do mod abre normal, mas o servidor entrega o blob
--    com `names` VAZIO. LKL_Name() devolve nullptr para toda chave fora da
--    tabela, entao as ~90% de features que resolvem por nome ficam inertes
--    -- sem mensagem de erro e sem branch para inverter.
--    Ver KingRonni/src/main/jni/Components/Encrypt/LKL_Gate.h:100.
-- ---------------------------------------------------------------------
-- client_name: criada por painel-revendedor/migrations/add_client_info.sql, que
-- e de OUTRO projeto. lkl_enforce_blacklist referencia esta coluna na cascata
-- por e-mail; se a outra migracao nao rodou neste banco, a funcao falharia em
-- runtime com "column does not exist" -- ou seja, o ban quebraria justamente na
-- hora de punir. Garantimos a existencia aqui.
alter table public.licenses add column if not exists client_name   text;

alter table public.licenses add column if not exists shadowbanned  boolean default false;
alter table public.licenses add column if not exists shadowban_at  timestamptz;
alter table public.licenses add column if not exists banned_reason text;
alter table public.licenses add column if not exists banned_at     timestamptz;

-- ---------------------------------------------------------------------
-- 5. CHECK de status: o codigo grava 'paused' (license-actions.js:423), mas
--    a constraint de schema.sql:8 so aceita active/banned/expired/frozen.
--    Pausar hoje falha com 23514 -- ou passa, se a constraint nunca foi
--    aplicada naquele banco. Alinhamos ao que o codigo usa de fato.
-- ---------------------------------------------------------------------
alter table public.licenses drop constraint if exists licenses_status_check;
alter table public.licenses add  constraint licenses_status_check
    check (status in ('active', 'banned', 'expired', 'frozen', 'paused', 'revoked'));

-- ---------------------------------------------------------------------
-- 6. Indices dos caminhos quentes (todo login faz estes SELECT).
-- ---------------------------------------------------------------------
create index if not exists blacklist_device_idx      on public.blacklist (device_id);
create index if not exists blacklist_license_key_idx on public.blacklist (license_key);
create index if not exists ip_blacklist_ip_idx       on public.ip_blacklist (ip);
create index if not exists email_blacklist_norm_idx  on public.email_blacklist (email_norm);
create index if not exists key_blacklist_active_idx  on public.key_blacklist (pattern_norm) where active;
create index if not exists licenses_shadowban_idx    on public.licenses (shadowbanned) where shadowbanned;

-- RLS: service_role sempre passa; nega por padrao para anon/authenticated.
alter table public.email_blacklist enable row level security;
alter table public.key_blacklist   enable row level security;
alter table public.ip_blacklist    enable row level security;

-- ---------------------------------------------------------------------
-- 7. lkl_enforce_blacklist — banimento em UMA transacao.
--
--    POR QUE RPC e nao 6 chamadas do Node: em serverless a funcao pode ser
--    morta no meio (timeout, deploy, cold start abortado). Passo a passo, um
--    kill entre "marcou a licenca" e "gravou o device" deixa o infrator
--    banido de uma key e livre para pegar outra -- exatamente o furo que
--    isto fecha. Aqui e tudo ou nada.
--
--    Idempotente: ON CONFLICT DO NOTHING em toda insercao e UPDATE
--    naturalmente idempotente. Chamar 50x = mesmo estado.
--
--    Retorna jsonb com o que foi EFETIVAMENTE aplicado, para o chamador
--    logar numero real em vez de "provavelmente funcionou".
-- ---------------------------------------------------------------------
create or replace function public.lkl_enforce_blacklist(
    p_reason      text,
    p_source      text  default 'auto:trap_key',
    p_license_key text  default null,
    p_device_id   text  default null,
    p_ip          text  default null,
    p_email       text  default null,
    p_evidence    jsonb default '{}'::jsonb,
    p_actor       text  default 'System (Guard)'
) returns jsonb
language plpgsql
security definer
set search_path = public
as $fn$
declare
    v_email_norm   text;
    v_key          text;
    v_device       text;
    v_ip           text;
    v_keys_banned  int := 0;
    v_dev_added    int := 0;
    v_ip_added     int := 0;
    v_mail_added   int := 0;
    v_n            int := 0;
    v_cascade      int := 0;
    v_cascade_keys text[] := '{}'::text[];
    v_batch        text[];
begin
    v_email_norm := nullif(lower(trim(coalesce(p_email, ''))), '');
    v_key        := nullif(trim(coalesce(p_license_key, '')), '');
    v_device     := nullif(trim(coalesce(p_device_id, '')), '');
    v_ip         := nullif(trim(coalesce(p_ip, '')), '');
    if v_ip = 'Unknown' then v_ip := null; end if;

    -- 7.1 A licenca usada na tentativa.
    if v_key is not null then
        update public.licenses
           set status        = 'banned',
               banned_reason = p_reason,
               banned_at     = now()
         where license_key = v_key
           and status <> 'banned';
        get diagnostics v_keys_banned = row_count;
    end if;

    -- 7.2 Identificadores -> blacklists.
    if v_device is not null then
        insert into public.blacklist
            (device_id, license_key, ip, email, reason, blocked_by, source, evidence, permanent)
        values
            (v_device, v_key, v_ip, v_email_norm, p_reason, p_actor, p_source, p_evidence, true)
        on conflict (device_id) do nothing;
        get diagnostics v_dev_added = row_count;
    end if;

    -- ⚠️ O IP entra apenas quando o chamador manda. IP movel e CGNAT sao
    -- COMPARTILHADOS: banir o IP de quem usou a armadilha pode derrubar
    -- cliente pagante da mesma operadora. Quem decide e o guard do Node
    -- (LKL_BAN_IP_ON_TRAP), nao esta funcao.
    if v_ip is not null then
        insert into public.ip_blacklist (ip, reason, blocked_by, source, evidence)
        values (v_ip, p_reason, p_actor, p_source, p_evidence)
        on conflict (ip) do nothing;
        get diagnostics v_ip_added = row_count;
    end if;

    if v_email_norm is not null then
        insert into public.email_blacklist (email_norm, email_raw, reason, blocked_by, source, evidence)
        values (v_email_norm, p_email, p_reason, p_actor, p_source, p_evidence)
        on conflict (email_norm) do nothing;
        get diagnostics v_mail_added = row_count;
    end if;

    -- 7.3 Revogacao em cascata: toda licenca ATIVA que compartilhe o device
    --     (used_ips e array jsonb de device_ids) ou o e-mail (o webhook
    --     grava "Nome (email@dominio)" em client_username) cai junto.
    if v_device is not null then
        with hit as (
            update public.licenses
               set status        = 'banned',
                   banned_reason = coalesce(p_reason, '') || ' [cascata: device]',
                   banned_at     = now()
             where status = 'active'
               and used_ips ? v_device
            returning license_key
        )
        select count(*)::int, coalesce(array_agg(license_key), '{}'::text[])
          into v_n, v_batch
          from hit;
        v_cascade      := v_cascade + v_n;
        v_cascade_keys := v_cascade_keys || v_batch;
    end if;

    -- ⚠️ DUAS colunas de nome, nao uma. O painel-principal grava em
    -- `client_username` (create.js, license-actions.js) e o painel-revendedor
    -- em `client_name` (reseller_issue_license, migracao 001). Olhar so a
    -- primeira deixaria TODA licenca emitida por revendedor fora da cascata --
    -- e e justamente por revendedor que o banido tenta voltar.
    if v_email_norm is not null then
        with hit as (
            update public.licenses
               set status        = 'banned',
                   banned_reason = coalesce(p_reason, '') || ' [cascata: email]',
                   banned_at     = now()
             where status = 'active'
               and (   position(v_email_norm in lower(coalesce(client_username, ''))) > 0
                    or position(v_email_norm in lower(coalesce(client_name,     ''))) > 0 )
            returning license_key
        )
        select count(*)::int, coalesce(array_agg(license_key), '{}'::text[])
          into v_n, v_batch
          from hit;
        v_cascade      := v_cascade + v_n;
        v_cascade_keys := v_cascade_keys || v_batch;
    end if;

    -- 7.4 Trilha de auditoria (o painel le activity_logs).
    insert into public.activity_logs (admin_name, action, license_key, details, timestamp)
    values (
        p_actor,
        'BLACKLIST_ENFORCE',
        v_key,
        jsonb_build_object(
            'reason',        p_reason,
            'source',        p_source,
            'device_id',     v_device,
            'ip',            v_ip,
            'email',         v_email_norm,
            'keys_banned',   v_keys_banned,
            'cascade_count', v_cascade,
            'cascade_keys',  to_jsonb(v_cascade_keys),
            'evidence',      p_evidence
        ),
        now()
    );

    return jsonb_build_object(
        'ok',            true,
        'keys_banned',   v_keys_banned,
        'device_added',  v_dev_added,
        'ip_added',      v_ip_added,
        'email_added',   v_mail_added,
        'cascade_count', v_cascade,
        'cascade_keys',  to_jsonb(v_cascade_keys)
    );
end;
$fn$;

grant execute on function public.lkl_enforce_blacklist(text, text, text, text, text, text, jsonb, text) to service_role;

-- ---------------------------------------------------------------------
-- 8. lkl_normalize_keyish — normalizacao CANONICA da chave.
--
--    Tem de ser byte-a-byte identica a normalizeKeyish() do
--    _lib/blacklist-guard.js. Existe nos dois lados porque o painel-principal
--    normaliza em memoria (com cache, no caminho quente do login) e o
--    painel-revendedor -- projeto Vercel separado, que nao importa aquele
--    arquivo -- chama esta funcao por RPC.
--
--    🔴 Divergir as duas e o modo de falha silencioso desta feature: um lado
--    dobra '0'->'o' e o outro nao, e a variante escapa sem erro nenhum.
--    tools/test_blacklist_guard.mjs compara as duas contra a mesma lista de
--    casos; rode-o ao mexer em qualquer das duas.
-- ---------------------------------------------------------------------
create or replace function public.lkl_normalize_keyish(p_value text)
returns text
language sql
immutable
set search_path = public
as $fn$
    select translate(
               regexp_replace(lower(coalesce(p_value, '')), '[^a-z0-9]', '', 'g'),
               '0134' || '57',
               'olea' || 'st'
           );
$fn$;

-- ---------------------------------------------------------------------
-- 9. lkl_check_blacklist — consulta unica (armadilha + identidade).
--    Usada pelo painel-revendedor. Nao aplica sancao: quem decide punir e
--    o chamador, via lkl_enforce_blacklist.
-- ---------------------------------------------------------------------
create or replace function public.lkl_check_blacklist(
    p_key       text default null,
    p_device_id text default null,
    p_ip        text default null,
    p_email     text default null
) returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $fn$
declare
    v_norm  text;
    v_mail  text;
    v_trap  record;
begin
    v_norm := public.lkl_normalize_keyish(p_key);
    v_mail := nullif(lower(trim(coalesce(p_email, ''))), '');

    if v_norm <> '' then
        select pattern_norm, reason into v_trap
          from public.key_blacklist
         where active
           and ( (match_mode = 'exact'    and v_norm =  pattern_norm)
              or (match_mode = 'contains' and position(pattern_norm in v_norm) > 0) )
         limit 1;
        if found then
            return jsonb_build_object('blocked', true, 'kind', 'trap_key',
                                      'reason', v_trap.reason, 'pattern', v_trap.pattern_norm);
        end if;
    end if;

    if nullif(trim(coalesce(p_device_id, '')), '') is not null
       and exists (select 1 from public.blacklist where device_id = trim(p_device_id)) then
        return jsonb_build_object('blocked', true, 'kind', 'device');
    end if;

    if nullif(trim(coalesce(p_ip, '')), '') is not null and p_ip <> 'Unknown'
       and exists (select 1 from public.ip_blacklist where ip = p_ip) then
        return jsonb_build_object('blocked', true, 'kind', 'ip');
    end if;

    if v_mail is not null
       and exists (select 1 from public.email_blacklist where email_norm = v_mail) then
        return jsonb_build_object('blocked', true, 'kind', 'email');
    end if;

    return jsonb_build_object('blocked', false);
end;
$fn$;

grant execute on function public.lkl_normalize_keyish(text) to service_role;
grant execute on function public.lkl_check_blacklist(text, text, text, text) to service_role;

-- ---------------------------------------------------------------------
-- 10. Backfill: quem ja esta na blacklist de device sem `permanent` fica
--     marcado como permanente (o comportamento que o painel sempre teve).
-- ---------------------------------------------------------------------
update public.blacklist set permanent = true where permanent is null;
update public.blacklist set source    = 'admin' where source is null;
update public.ip_blacklist set source = 'admin' where source is null;
