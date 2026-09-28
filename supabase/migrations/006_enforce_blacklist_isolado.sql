-- ===========================================================================
-- 006 — `lkl_enforce_blacklist`: um passo que falha NAO pode desfazer os outros
--
-- A `005` corrige a causa imediata do "BAN FALHOU" (faltava UNIQUE em
-- `blacklist.device_id`). Esta migration corrige a AMPLIFICACAO -- o motivo de
-- um erro num insert secundario ter zerado o ban inteiro.
--
-- 🔴 O QUE ACONTECIA: plpgsql roda a funcao inteira em UMA transacao. A ordem
--    na 004 e: (7.1) banir a licenca -> (7.2) device -> IP -> e-mail -> (7.3)
--    cascata -> (7.4) auditoria. O 42P10 no passo 7.2 abortou a transacao, e o
--    `update licenses set status='banned'` do 7.1 -- que JA tinha rodado com
--    sucesso -- voltou atras. Resultado medido em 30-08: cracker acionou a
--    armadilha e continuou com a licenca ATIVA.
--
-- 🔑 A licao: o passo mais importante (revogar a licenca) era o mais fragil,
--    porque dependia do sucesso de 4 passos posteriores e menos criticos. Ban
--    parcial e MUITO melhor que ban nenhum -- entao cada bloco ganha seu
--    proprio EXCEPTION e o resultado reporta o que passou e o que falhou.
--
--    Isso tambem muda o veredito do alerta do Telegram: `ok:true` deixa de
--    significar "tudo funcionou" e passa a significar "a licenca foi revogada".
--    O array `failed` diz o resto. Numero solto nao carrega veredito; o guard
--    do Node ja segue essa regra e agora tem dado para isso.
--
-- Tambem corrige a cascata por e-mail: `position(email in client_username) > 0`
-- e busca por SUBSTRING. Um e-mail curto ou generico (ex. `a@b.co`) casaria
-- dentro do nome/e-mail de OUTRO cliente e o banirian por coincidencia de
-- texto -- ban colateral silencioso, do tipo que o Ronni relatou ("banido do
-- nada"). Passa a exigir o e-mail delimitado: igual ao campo, ou entre
-- parenteses no formato que o webhook grava (`Nome (email@dominio)`).
-- ===========================================================================

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
    v_failed       jsonb := '[]'::jsonb;   -- passos que falharam, com o erro
begin
    v_email_norm := nullif(lower(trim(coalesce(p_email, ''))), '');
    v_key        := nullif(trim(coalesce(p_license_key, '')), '');
    v_device     := nullif(trim(coalesce(p_device_id, '')), '');
    v_ip         := nullif(trim(coalesce(p_ip, '')), '');
    if v_ip = 'Unknown' then v_ip := null; end if;

    -- =======================================================================
    -- 7.1 A licenca da tentativa. PASSO CRITICO: e o unico que efetivamente
    --     tira o acesso de quem acionou a armadilha. Sem EXCEPTION proprio de
    --     propósito -- se ISTO falhar, a funcao deve estourar e o guard tem de
    --     gritar FALHOU, porque nao ha ban nenhum.
    -- =======================================================================
    if v_key is not null then
        update public.licenses
           set status        = 'banned',
               banned_reason = p_reason,
               banned_at     = now()
         where license_key = v_key
           and status <> 'banned';
        get diagnostics v_keys_banned = row_count;
    end if;

    -- =======================================================================
    -- 7.2 Identificadores -> blacklists. Cada um isolado: erro aqui nao pode
    --     desfazer o 7.1 nem impedir os irmaos.
    -- =======================================================================
    if v_device is not null then
        begin
            insert into public.blacklist
                (device_id, license_key, ip, email, reason, blocked_by, source, evidence, permanent)
            values
                (v_device, v_key, v_ip, v_email_norm, p_reason, p_actor, p_source, p_evidence, true)
            on conflict (device_id) do nothing;
            get diagnostics v_dev_added = row_count;
        exception when others then
            v_failed := v_failed || jsonb_build_object(
                'step', 'blacklist.device', 'sqlstate', SQLSTATE, 'error', SQLERRM);
        end;
    end if;

    -- ⚠️ O IP entra apenas quando o chamador manda. IP movel e CGNAT sao
    -- COMPARTILHADOS: banir o IP de quem usou a armadilha pode derrubar
    -- cliente pagante da mesma operadora. Quem decide e o guard do Node
    -- (LKL_BAN_IP_ON_TRAP), nao esta funcao.
    if v_ip is not null then
        begin
            insert into public.ip_blacklist (ip, reason, blocked_by, source, evidence)
            values (v_ip, p_reason, p_actor, p_source, p_evidence)
            on conflict (ip) do nothing;
            get diagnostics v_ip_added = row_count;
        exception when others then
            v_failed := v_failed || jsonb_build_object(
                'step', 'ip_blacklist', 'sqlstate', SQLSTATE, 'error', SQLERRM);
        end;
    end if;

    if v_email_norm is not null then
        begin
            insert into public.email_blacklist (email_norm, email_raw, reason, blocked_by, source, evidence)
            values (v_email_norm, p_email, p_reason, p_actor, p_source, p_evidence)
            on conflict (email_norm) do nothing;
            get diagnostics v_mail_added = row_count;
        exception when others then
            v_failed := v_failed || jsonb_build_object(
                'step', 'email_blacklist', 'sqlstate', SQLSTATE, 'error', SQLERRM);
        end;
    end if;

    -- =======================================================================
    -- 7.3 Revogacao em cascata.
    -- =======================================================================
    if v_device is not null then
        begin
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
        exception when others then
            v_failed := v_failed || jsonb_build_object(
                'step', 'cascata.device', 'sqlstate', SQLSTATE, 'error', SQLERRM);
        end;
    end if;

    -- ⚠️ DUAS colunas de nome, nao uma. O painel-principal grava em
    -- `client_username` (create.js, license-actions.js) e o painel-revendedor
    -- em `client_name` (reseller_issue_license, migracao 001). Olhar so a
    -- primeira deixaria TODA licenca emitida por revendedor fora da cascata --
    -- e e justamente por revendedor que o banido tenta voltar.
    --
    -- 🔴 30-08: era `position(v_email_norm in lower(campo)) > 0` -- SUBSTRING.
    -- `a@b.co` casa dentro de `outro-a@b.com.br`, e o dono desse outro e-mail
    -- era banido por coincidencia de texto, sem infracao nenhuma. Agora exige
    -- delimitacao: campo igual ao e-mail, ou o formato `Nome (email)` que o
    -- webhook grava. `like` com escape porque `_` e `%` sao curinga e existem
    -- em e-mail real (`nome_sobrenome@...`).
    if v_email_norm is not null then
        begin
            with hit as (
                update public.licenses
                   set status        = 'banned',
                       banned_reason = coalesce(p_reason, '') || ' [cascata: email]',
                       banned_at     = now()
                 where status = 'active'
                   and (
                          lower(trim(coalesce(client_username, ''))) = v_email_norm
                       or lower(trim(coalesce(client_name,     ''))) = v_email_norm
                       or lower(coalesce(client_username, '')) like '%(' || replace(replace(v_email_norm,'_','\_'),'%','\%') || ')%'
                       or lower(coalesce(client_name,     '')) like '%(' || replace(replace(v_email_norm,'_','\_'),'%','\%') || ')%'
                   )
                returning license_key
            )
            select count(*)::int, coalesce(array_agg(license_key), '{}'::text[])
              into v_n, v_batch
              from hit;
            v_cascade      := v_cascade + v_n;
            v_cascade_keys := v_cascade_keys || v_batch;
        exception when others then
            v_failed := v_failed || jsonb_build_object(
                'step', 'cascata.email', 'sqlstate', SQLSTATE, 'error', SQLERRM);
        end;
    end if;

    -- =======================================================================
    -- 7.4 Trilha de auditoria. Isolada tambem: perder o log e ruim, perder o
    --     ban por causa do log e pior.
    -- =======================================================================
    begin
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
                'failed_steps',  v_failed,
                'evidence',      p_evidence
            ),
            now()
        );
    exception when others then
        v_failed := v_failed || jsonb_build_object(
            'step', 'activity_logs', 'sqlstate', SQLSTATE, 'error', SQLERRM);
    end;

    -- `ok:true` = a licenca foi revogada (o que importa). `failed` diz o resto:
    -- o guard do Node decide o texto do alerta com base nele.
    return jsonb_build_object(
        'ok',            true,
        'keys_banned',   v_keys_banned,
        'device_added',  v_dev_added,
        'ip_added',      v_ip_added,
        'email_added',   v_mail_added,
        'cascade_count', v_cascade,
        'cascade_keys',  to_jsonb(v_cascade_keys),
        'failed',        v_failed,
        'partial',       (jsonb_array_length(v_failed) > 0)
    );
end;
$fn$;

-- A 004 ja concedeu execute; repetido aqui porque `create or replace` mantem as
-- permissoes mas esta migration pode rodar num banco onde a 004 falhou no meio.
revoke all on function public.lkl_enforce_blacklist(text,text,text,text,text,text,jsonb,text) from public, anon, authenticated;
grant execute on function public.lkl_enforce_blacklist(text,text,text,text,text,text,jsonb,text) to service_role;
