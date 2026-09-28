-- ===========================================================================
-- 007 — separar slot de DEVICE de slot de IP (2 devices + 1 IP)
--
-- PEDIDO DO RONNI (30-08): "quando eles for criar tem que ter 2 slot pra id e
-- 1 pra ip".
--
-- 🔴 A ARMADILHA DO NOME: `licenses.used_ips` **NAO guarda IP**. Guarda device
--    id -- `x8k2m9a1b.js:353` faz `usedDevices.push(deviceId)`, e `max_ips` e o
--    limite de DEVICES (`const maxDevices = license.max_ips || 1`). O nome
--    sobrou de uma versao antiga em que o controle era por IP mesmo.
--
--    Consequencia medida: **o IP nunca foi limitado**. Ele aparece no
--    `activity_logs` e no alerta do Telegram, e e so isso -- nenhuma linha
--    recusa acesso por IP. Entao "1 slot de IP" nao e ajustar um numero, e
--    feature nova.
--
-- 🔑 Nao vou renomear `used_ips`/`max_ips`. O rename e a coisa "limpa" e a mais
--    perigosa aqui: essas colunas sao lidas pelas DUAS rotas de validacao, pelo
--    painel-revendedor, pelo painel-principal, pela loja e pelo `index.html`.
--    Um rename silencioso transforma leitura em `undefined`, e `undefined || 1`
--    volta a 1 slot **sem erro nenhum** -- o modo de falha que ja custou o
--    "limite de dispositivos" em 23-08. Colunas NOVAS com nome honesto, e o
--    legado fica com o comentario explicando o que ele realmente e.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. Documentar o legado no proprio banco, para o proximo a olhar nao cair na
--    mesma leitura errada que eu cai.
-- ---------------------------------------------------------------------------
comment on column public.licenses.used_ips is
    'HISTORICO: apesar do nome, guarda DEVICE IDs (ANDROID_ID), nao IPs. Limite = max_ips. Para IP use used_ip/max_ip_slots.';
comment on column public.licenses.max_ips is
    'HISTORICO: limite de DEVICES (nao de IPs). 2 = 1 APK + 1 lib injetada no jogo, porque ANDROID_ID e por app no Android 8+.';

-- ---------------------------------------------------------------------------
-- 2. Slot de IP: uma coluna de texto (1 IP) + o limite, para nao ficar magico.
--
--    `used_ip` NULL = chave nunca registrou IP. Decisao do Ronni (30-08): as
--    chaves que ja existem comecam a contar do PROXIMO login -- ninguem ativo
--    e interrompido pela mudanca.
-- ---------------------------------------------------------------------------
alter table public.licenses
    add column if not exists used_ip       text,
    add column if not exists max_ip_slots  integer not null default 1,
    add column if not exists ip_updated_at timestamptz;

comment on column public.licenses.used_ip is
    'IP atual da chave (1 slot). NULL = ainda nao registrado; o proximo login registra.';
comment on column public.licenses.max_ip_slots is
    'Quantos IPs distintos a chave aceita ao mesmo tempo. 1 = comportamento pedido em 30-08.';
comment on column public.licenses.ip_updated_at is
    'Quando o IP foi trocado pela ultima vez. Alimenta a deteccao de troca frequente (chave compartilhada).';

-- ---------------------------------------------------------------------------
-- 3. Devices: 2 slots como piso, e SO PARA CIMA.
--
--    ⚠️ `least(max_ips, 2)` seria o "corrigir para o valor certo" e estaria
--    ERRADO: existe chave com limite maior concedido de proposito (cliente que
--    pediu 3 aparelhos, conta de teste). Baixar limite de quem ja usa e tirar
--    acesso de cliente pagante sem ele ter feito nada.
--
--    Nao mexe em chave `banned`/`paused`: aumentar slot de chave bloqueada e
--    afrouxar bloqueio pela porta de tras.
-- ---------------------------------------------------------------------------
do $$
declare
    v_n int;
begin
    update public.licenses
       set max_ips = 2
     where coalesce(max_ips, 1) < 2
       and coalesce(status, '') not in ('banned', 'paused');
    get diagnostics v_n = row_count;
    raise notice '007: % chave(s) ativa(s) subiram para 2 slots de device', v_n;

    select count(*) into v_n
      from public.licenses
     where coalesce(max_ips, 1) < 2
       and coalesce(status, '') in ('banned', 'paused');
    if v_n > 0 then
        raise notice '007: % chave(s) banida(s)/pausada(s) preservada(s) em 1 slot (de proposito)', v_n;
    end if;
end $$;

alter table public.licenses
    alter column max_ips set default 2;

-- ---------------------------------------------------------------------------
-- 4. Registrar/rotacionar o IP num lugar so.
--
--    A rotacao e a decisao do Ronni (30-08): IP de 4G troca a cada reconexao e
--    Wi-Fi muda no reboot do roteador. Travar o primeiro IP geraria "limite
--    atingido" em cliente legitimo e suporte manual.
--
--    O que isto AINDA pega: uso simultaneo em lugares diferentes aparece como
--    troca de IP a cada request, e `ip_switches_24h` mede isso -- e o sinal de
--    chave compartilhada, sem recusar ninguem por trocar de rede.
--
--    Devolve jsonb (nao boolean) porque quem chama precisa saber se ROTACIONOU
--    para poder alertar; boolean daria "ok" e perderia o motivo.
-- ---------------------------------------------------------------------------
create or replace function public.lkl_touch_license_ip(
    p_license_id uuid,
    p_ip         text
) returns jsonb
language plpgsql
security definer
set search_path = public
as $fn$
declare
    v_prev      text;
    v_max       int;
    v_switches  int := 0;
    v_rotated   boolean := false;
begin
    if p_ip is null or btrim(p_ip) = '' or p_ip = 'Unknown' then
        -- Sem IP confiavel nao se registra nada. Gravar 'Unknown' queimaria o
        -- unico slot com um valor que nunca casa de novo.
        return jsonb_build_object('ok', true, 'skipped', 'ip_indisponivel');
    end if;

    select used_ip, coalesce(max_ip_slots, 1)
      into v_prev, v_max
      from public.licenses
     where id = p_license_id
     for update;

    if not found then
        return jsonb_build_object('ok', false, 'error', 'license_nao_encontrada');
    end if;

    if v_prev is null then
        update public.licenses
           set used_ip = p_ip, ip_updated_at = now()
         where id = p_license_id;
        return jsonb_build_object('ok', true, 'registered', true, 'rotated', false, 'ip', p_ip);
    end if;

    if v_prev = p_ip then
        return jsonb_build_object('ok', true, 'registered', false, 'rotated', false, 'ip', p_ip);
    end if;

    -- IP diferente: rotaciona (1 slot) e conta a troca.
    update public.licenses
       set used_ip = p_ip, ip_updated_at = now()
     where id = p_license_id;
    v_rotated := true;

    -- Quantas trocas nas ultimas 24h? Le do proprio activity_logs, que ja grava
    -- `details->>'ip'` em todo login -- nao precisa de tabela nova.
    select count(distinct details->>'ip')::int
      into v_switches
      from public.activity_logs
     where action = 'KEY_LOGIN'
       and license_key = (select license_key from public.licenses where id = p_license_id)
       and timestamp > now() - interval '24 hours'
       and details->>'ip' is not null;

    return jsonb_build_object(
        'ok', true, 'registered', false, 'rotated', true,
        'ip', p_ip, 'previous_ip', v_prev,
        'ip_switches_24h', v_switches,
        'max_ip_slots', v_max
    );
end;
$fn$;

revoke all on function public.lkl_touch_license_ip(uuid, text) from public, anon, authenticated;
grant execute on function public.lkl_touch_license_ip(uuid, text) to service_role;

-- ---------------------------------------------------------------------------
-- 5. CONTROLE POSITIVO: provar registro, no-op e rotacao numa licenca de
--    verdade, e desfazer. Sem isto a migration diria "ok" e o primeiro login
--    real seria o teste.
-- ---------------------------------------------------------------------------
do $$
declare
    v_id    uuid;
    v_bkp   text;
    v_bkpat timestamptz;
    v_r     jsonb;
begin
    select id, used_ip, ip_updated_at into v_id, v_bkp, v_bkpat
      from public.licenses order by created_at desc limit 1;

    if v_id is null then
        raise notice '007: sem licencas na base -- controle positivo pulado';
        return;
    end if;

    update public.licenses set used_ip = null, ip_updated_at = null where id = v_id;

    v_r := public.lkl_touch_license_ip(v_id, '203.0.113.10');
    if (v_r->>'registered') is distinct from 'true' then
        raise exception '007: FALHOU no registro inicial -> %', v_r;
    end if;

    v_r := public.lkl_touch_license_ip(v_id, '203.0.113.10');
    if (v_r->>'rotated') is distinct from 'false' then
        raise exception '007: FALHOU -- mesmo IP deveria ser no-op -> %', v_r;
    end if;

    v_r := public.lkl_touch_license_ip(v_id, '203.0.113.99');
    if (v_r->>'rotated') is distinct from 'true' then
        raise exception '007: FALHOU -- IP novo deveria rotacionar -> %', v_r;
    end if;

    v_r := public.lkl_touch_license_ip(v_id, 'Unknown');
    if (v_r->>'skipped') is null then
        raise exception '007: FALHOU -- IP Unknown deveria ser ignorado -> %', v_r;
    end if;

    -- restaura o estado original da licenca usada no teste
    update public.licenses set used_ip = v_bkp, ip_updated_at = v_bkpat where id = v_id;
    raise notice '007: OK -- registro, no-op, rotacao e Unknown corretos (licenca restaurada)';
exception when others then
    if v_id is not null then
        update public.licenses set used_ip = v_bkp, ip_updated_at = v_bkpat where id = v_id;
    end if;
    raise;
end $$;
