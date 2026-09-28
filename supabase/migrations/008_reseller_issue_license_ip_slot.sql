-- ===========================================================================
-- 008 — `reseller_issue_license` grava o slot de IP na emissao
--
-- A `007` criou `used_ip`/`max_ip_slots` e subiu os devices para 2. Falta a
-- emissao do revendedor definir o slot de IP na chave nova, senao toda chave
-- emitida por revendedor nasce no default da coluna e o painel nao tem como
-- conceder um limite diferente.
--
-- ⚠️ ASSINATURA NOVA, funcao antiga PRESERVADA. Postgres identifica funcao por
--    (nome + tipos dos argumentos), entao adicionar `p_max_ip_slots` cria uma
--    SOBRECARGA -- a versao de 8 argumentos continua existindo. Isso e
--    deliberado: enquanto a Vercel nao terminar o deploy, o codigo antigo ainda
--    chama a de 8 e precisa funcionar. Um `drop function` aqui derrubaria a
--    emissao de chave em producao durante a janela de deploy.
--
-- 🔑 A de 8 argumentos passa a DELEGAR para a de 9 (com default), em vez de ter
--    o corpo duplicado. Duas copias do mesmo INSERT divergem no primeiro fix
--    que alguem aplicar em so uma -- foi o que aconteceu com `max_ips` entre a
--    loja, o painel-principal e este painel.
-- ===========================================================================

create or replace function public.reseller_issue_license(
    p_reseller_id   uuid,
    p_cost          numeric,
    p_license_key   text,
    p_duration_type text,
    p_expires_at    timestamptz,
    p_max_ips       integer,
    p_client_name   text,
    p_whatsapp      text,
    p_max_ip_slots  integer
) returns table(new_balance numeric, license_id uuid)
language plpgsql
security definer
set search_path = public
as $fn$
declare
    v_current     numeric;
    v_is_active   boolean;
    v_new_balance numeric;
    v_license_id  uuid;
    v_devices     int;
    v_ip_slots    int;
begin
    -- Sanidade dos limites ANTES de debitar credito. `max_ips` vindo 0/negativo
    -- geraria chave que nao abre em lugar nenhum, e o revendedor teria pago por
    -- ela. Piso 2 em device (1 APK + 1 lib, ANDROID_ID e por app) e 1 em IP.
    v_devices  := greatest(coalesce(p_max_ips, 2), 2);
    v_ip_slots := greatest(coalesce(p_max_ip_slots, 1), 1);

    select coalesce(balance, 0), coalesce(is_active, false)
      into v_current, v_is_active
      from public.resellers
     where id = p_reseller_id
     for update;

    if not found then
        raise exception 'Reseller not found';
    end if;

    if not v_is_active then
        raise exception 'Reseller inactive';
    end if;

    if v_current < p_cost then
        raise exception 'Insufficient balance';
    end if;

    v_new_balance := v_current - p_cost;

    update public.resellers
       set balance = v_new_balance
     where id = p_reseller_id;

    insert into public.licenses (
        license_key, status, duration_type, expires_at, reseller_id,
        created_at, max_ips, used_ips, client_name, whatsapp,
        max_ip_slots, used_ip
    ) values (
        p_license_key, 'active', p_duration_type, p_expires_at, p_reseller_id,
        now(), v_devices, '[]'::jsonb, p_client_name, p_whatsapp,
        v_ip_slots, null           -- used_ip NULL: registra no 1o login
    )
    returning id into v_license_id;

    if p_cost > 0 then
        insert into public.credit_transactions (
            reseller_id, amount, type, description, created_at
        ) values (
            p_reseller_id, -p_cost, 'deduct',
            'Created key ' || p_license_key || ' (' || p_duration_type || ')',
            now()
        );
    end if;

    return query select v_new_balance, v_license_id;
end;
$fn$;

revoke all on function public.reseller_issue_license(uuid,numeric,text,text,timestamptz,integer,text,text,integer) from public, anon, authenticated;
grant execute on function public.reseller_issue_license(uuid,numeric,text,text,timestamptz,integer,text,text,integer) to service_role;

-- ---------------------------------------------------------------------------
-- A de 8 argumentos vira um encaminhador. Mantem o codigo em deploy antigo
-- funcionando E com o mesmo comportamento novo (2 devices / 1 IP).
-- ---------------------------------------------------------------------------
create or replace function public.reseller_issue_license(
    p_reseller_id   uuid,
    p_cost          numeric,
    p_license_key   text,
    p_duration_type text,
    p_expires_at    timestamptz,
    p_max_ips       integer,
    p_client_name   text,
    p_whatsapp      text
) returns table(new_balance numeric, license_id uuid)
language sql
security definer
set search_path = public
as $fn$
    select * from public.reseller_issue_license(
        p_reseller_id, p_cost, p_license_key, p_duration_type, p_expires_at,
        p_max_ips, p_client_name, p_whatsapp, 1
    );
$fn$;

grant execute on function public.reseller_issue_license(uuid,numeric,text,text,timestamptz,integer,text,text) to service_role;

-- ---------------------------------------------------------------------------
-- CONTROLE POSITIVO: emite de verdade com um revendedor de teste e confere os
-- dois limites na linha gravada, pelas DUAS assinaturas. Depois desfaz tudo.
-- ---------------------------------------------------------------------------
do $$
declare
    v_rid  uuid;
    v_lid  uuid;
    v_dev  int;
    v_ip   int;
    v_key  text := '__probe008_' || extract(epoch from now())::bigint;
begin
    insert into public.resellers (name, secret_key, balance, is_active)
    values ('__probe008__', v_key || '_sk', 999, true)
    returning id into v_rid;

    -- assinatura NOVA (9 args)
    select license_id into v_lid from public.reseller_issue_license(
        v_rid, 0, v_key || '_a', 'monthly', now() + interval '30 days',
        2, 'probe', null, 1);
    select max_ips, max_ip_slots into v_dev, v_ip from public.licenses where id = v_lid;
    if v_dev <> 2 or v_ip <> 1 then
        raise exception '008: FALHOU (9 args) -- devices=% ip_slots=% (esperado 2/1)', v_dev, v_ip;
    end if;

    -- assinatura ANTIGA (8 args) tem de dar o MESMO resultado
    select license_id into v_lid from public.reseller_issue_license(
        v_rid, 0, v_key || '_b', 'monthly', now() + interval '30 days',
        1, 'probe', null);
    select max_ips, max_ip_slots into v_dev, v_ip from public.licenses where id = v_lid;
    if v_dev <> 2 or v_ip <> 1 then
        raise exception '008: FALHOU (8 args) -- devices=% ip_slots=% (esperado 2/1, piso aplicado)', v_dev, v_ip;
    end if;

    delete from public.credit_transactions where reseller_id = v_rid;
    delete from public.licenses where reseller_id = v_rid;
    delete from public.resellers where id = v_rid;
    raise notice '008: OK -- 2 devices / 1 IP nas duas assinaturas (probe removido)';
exception when others then
    if v_rid is not null then
        delete from public.credit_transactions where reseller_id = v_rid;
        delete from public.licenses where reseller_id = v_rid;
        delete from public.resellers where id = v_rid;
    end if;
    raise;
end $$;
