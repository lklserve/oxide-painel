-- ===========================================================================
-- 005 — UNIQUE em `blacklist.device_id`: o ban automatico da armadilha FALHAVA
--
-- SINTOMA (30-08, alerta real do Telegram):
--   🔴 CHAVE-ARMADILHA ACIONADA — BAN FALHOU (agir manualmente)
--      Key: @AvienOffical · Device: 9b99f19b849ca707
--      Erro: there is no unique or exclusion constraint matching the
--            ON CONFLICT specification
--
-- CAUSA: a RPC `lkl_enforce_blacklist` (004, ~linha 205) faz
--        `insert into public.blacklist ... on conflict (device_id) do nothing`.
--        O Postgres exige um indice UNIQUE para casar o ON CONFLICT; sem ele
--        levanta 42P10 e **aborta a transacao inteira**.
--
-- 🔴 POR QUE ISSO DOI MAIS DO QUE PARECE: o insert do device e o PRIMEIRO dos
--    tres. Falhando ali, a funcao morre antes de banir IP, e-mail e antes da
--    cascata -- e o `update licenses set status='banned'` (passo 7.1, que rodou
--    ANTES) volta atras junto, porque plpgsym executa tudo numa transacao. Ou
--    seja: quem acionou a armadilha ficava com a licenca INTACTA. O alerta
--    dizia "agir manualmente" e estava certo: nada foi aplicado.
--
-- Mesma familia de erro do `002_settings_unique_key.sql`: codigo usando
-- ON CONFLICT numa coluna sem UNIQUE. Ali o efeito era ler valor velho; aqui e
-- cracker nao-banido.
--
-- ⚠️ `schema.sql:90` DECLARA `device_id TEXT UNIQUE NOT NULL` — e o erro do
--    Postgres prova que no banco real a constraint NAO existe. `CREATE TABLE IF
--    NOT EXISTS` nao altera tabela pre-existente: a `blacklist` provavelmente
--    nasceu antes dessa linha e nunca foi migrada. **O banco e a autoridade, o
--    .sql do repo e so intencao.** Por isso esta migration checa `pg_index` em
--    vez de confiar no schema (e por isso e segura de rodar mesmo se a
--    constraint ja existir).
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. Deduplicar antes de indexar. Sem UNIQUE, a tabela pode ter o mesmo device
--    varias vezes (cada armadilha acionada inseriu uma linha nova). Criar o
--    indice com duplicatas presentes falharia.
--
--    Mantem a linha MAIS ANTIGA de cada device: e a que registra quando o
--    device foi banido pela primeira vez, que e a informacao com valor
--    forense. `created_at` pode ser nulo em linha legada, dai o `nulls last`
--    e o `ctid` como desempate estavel.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_dupes int := 0;
BEGIN
    WITH ranked AS (
        SELECT ctid,
               row_number() OVER (
                   PARTITION BY device_id
                   ORDER BY created_at ASC NULLS LAST, ctid ASC
               ) AS rn
          FROM public.blacklist
         WHERE device_id IS NOT NULL
    ), removed AS (
        DELETE FROM public.blacklist b
         USING ranked r
         WHERE b.ctid = r.ctid
           AND r.rn > 1
        RETURNING 1
    )
    SELECT count(*)::int INTO v_dupes FROM removed;

    IF v_dupes > 0 THEN
        RAISE NOTICE '005: % linha(s) duplicada(s) de device_id removida(s) (mantida a mais antiga)', v_dupes;
    ELSE
        RAISE NOTICE '005: nenhuma duplicata de device_id';
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Criar o UNIQUE se ainda nao houver. Checa `pg_index` (nao `pg_indexes`
--    por texto): olhar `indexdef ILIKE '%UNIQUE%(device_id)%'` erraria com
--    indice composto tipo UNIQUE (device_id, ip) -- que existe e NAO serve
--    para `on conflict (device_id)`.
--
--    Aceita constraint OU indice unico: o ON CONFLICT do Postgres casa com os
--    dois, e a `002` mostrou que a constraint pode existir com outro nome.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM pg_index i
          JOIN pg_class c ON c.oid = i.indrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = 'blacklist'
           AND i.indisunique
           AND i.indnatts = 1                       -- exatamente 1 coluna
           AND i.indkey[0] = (
               SELECT attnum FROM pg_attribute
                WHERE attrelid = c.oid AND attname = 'device_id'
           )
    ) THEN
        RAISE NOTICE '005: UNIQUE(device_id) ja existe -- nada a fazer';
    ELSE
        BEGIN
            ALTER TABLE public.blacklist
                ADD CONSTRAINT blacklist_device_id_unique UNIQUE (device_id);
            RAISE NOTICE '005: UNIQUE(device_id) CRIADA -- on conflict (device_id) passa a funcionar';
        EXCEPTION
            WHEN duplicate_object OR duplicate_table THEN
                RAISE NOTICE '005: constraint/indice ja existia sob outro nome -- ok';
        END;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 3. CONTROLE POSITIVO: provar que o ON CONFLICT agora casa, em vez de
--    assumir que criar a constraint resolveu.
--
--    🔑 O teste roda o MESMO comando que falhava (upsert em device_id) dentro
--    de um savepoint e desfaz. Sem isto, esta migration diria "ok" e o proximo
--    acionamento de armadilha e que descobriria se funcionou -- exatamente o
--    modo de falha que o projeto ja pagou: medidor que nao sabe reprovar.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_probe text := '__probe_005_' || extract(epoch from now())::bigint || '__';
BEGIN
    BEGIN
        -- 1a insercao: entra.
        INSERT INTO public.blacklist (device_id, reason, blocked_by, permanent)
        VALUES (v_probe, 'probe 005 (auto-removido)', 'System (migration)', false)
        ON CONFLICT (device_id) DO NOTHING;

        -- 2a insercao do MESMO device: e aqui que o 42P10 estourava.
        INSERT INTO public.blacklist (device_id, reason, blocked_by, permanent)
        VALUES (v_probe, 'probe 005 repetida', 'System (migration)', false)
        ON CONFLICT (device_id) DO NOTHING;

        DELETE FROM public.blacklist WHERE device_id = v_probe;
        RAISE NOTICE '005: OK -- on conflict (device_id) aceito 2x sem erro (probe removido)';
    EXCEPTION WHEN OTHERS THEN
        DELETE FROM public.blacklist WHERE device_id = v_probe;
        RAISE EXCEPTION '005: FALHOU -- on conflict (device_id) ainda nao casa: % (%)', SQLERRM, SQLSTATE;
    END;
END $$;
