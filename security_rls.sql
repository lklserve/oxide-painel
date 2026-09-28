-- ============================================================================
-- Painel LKL — REATIVACAO DO RLS + tabela de rate limit persistente
-- Rodar no SQL Editor do Supabase. Idempotente: pode rodar mais de uma vez.
-- ============================================================================
--
-- 🔴 EVIDENCIA MEDIDA EM PRODUCAO (23-08-2026, projeto ilwfeyzkaehkfgkxtciq)
-- Testado com a chave ANON -- a mesma que vazou no historico do Git e que, por
-- design, e publica (vai no bundle de qualquer app). Resultado:
--
--   licenses        LEITURA de 144 registros    (chaves + WhatsApp dos clientes)
--   admins          LEITURA de 1 registro       (senha em TEXTO PURO no seed)
--   activity_logs   LEITURA de 136.696 registros
--   blacklist       LEITURA de 78 + ESCRITA CONFIRMADA (INSERT -> HTTP 201)
--   settings        LEITURA liberada
--
-- A escrita foi provada com um INSERT real na blacklist, removido em seguida
-- (DELETE -> 204, verificado: 0 registros restantes). Ou seja: qualquer pessoa
-- com a chave anon podia BANIR device/IP de clientes legitimos.
--
-- 🔴 POR QUE: `fix_all.sql` fazia DISABLE ROW LEVEL SECURITY em 7 tabelas e o
-- `schema.sql` "ativava" o RLS com policies `USING (true)` -- que liberam tudo e
-- nao restringem nada. Com a chave anon (que vazou no historico do Git, e por
-- design e publica) qualquer pessoa lia `licenses` inteira: chaves, WhatsApp dos
-- clientes, e a tabela `admins` -- onde a senha esta EM TEXTO PURO no seed.
--
-- 🔑 O QUE MUDA NA PRATICA: nada para o painel. Medido: o frontend nunca fala com
-- o Supabase direto (zero `createClient` no index.html), so com `/api/*`; e todo
-- endpoint usa `SUPABASE_SERVICE_ROLE_KEY`, e o service_role IGNORA RLS por
-- definicao. Ou seja, as policies abaixo fecham a porta do anon sem tocar no
-- caminho que o painel realmente usa.
--
-- 🔴 MEDIDO NO BANCO (via conexao direta, 23-08): as 15 tabelas de `public` tem
-- grants COMPLETOS para `anon` -- DELETE, UPDATE e TRUNCATE inclusos, nao so
-- SELECT -- e 6 delas carregam uma policy `USING (true)` para o role `public`,
-- chamada "Enable all access for all users". Havia 4 tabelas de SESSAO
-- (`admin_sessions`, `reseller_sessions`, `admin_dashboard_sessions`,
-- `processed_orders`) e 4 de blacklist/config (`system_settings`, `ip_blacklist`,
-- `email_blacklist`, `key_blacklist`) FORA da lista original de 7 tabelas do
-- pedido -- por isso o script agora varre `pg_tables` inteiro em vez de uma
-- lista fixa: enumerar a mao deixaria justamente as tabelas de sessao abertas.
--
-- 🔑 `TO service_role` em vez de `USING (auth.role() = 'service_role')`: a funcao
-- `auth.role()` e um helper do GoTrue e nao existe em todo projeto -- se ela
-- faltar, o bloco DO inteiro aborta e o REVOKE mais abaixo nunca roda, deixando
-- o banco aberto com a falsa impressao de que o script "passou". `TO <role>` e
-- SQL puro do Postgres: a policy so vale para service_role, e `USING (true)`
-- dentro dela nao afrouxa nada porque o alvo ja esta restrito pelo TO.
--
-- Modelo: deny-all para anon/authenticated. Nao criamos policy permissiva nenhuma
-- -- com RLS ligado e sem policy que casa, o Postgres NEGA. As policies explicitas
-- de service_role abaixo sao documentacao e defesa em profundidade.

-- ---------------------------------------------------------------------------
-- 1. Tabela de rate limit persistente (substitui o Map() em memoria)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket_key     TEXT PRIMARY KEY,          -- ex: 'login:203.0.113.7', 'validate:...'
    count          INTEGER NOT NULL DEFAULT 0,
    fails          INTEGER NOT NULL DEFAULT 0,
    first_attempt  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_fail     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_updated_at ON rate_limits (updated_at);

-- ---------------------------------------------------------------------------
-- 2. Reativar RLS em todas as tabelas sensiveis
-- ---------------------------------------------------------------------------
ALTER TABLE licenses            ENABLE ROW LEVEL SECURITY;
ALTER TABLE admins              ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings            ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_logs       ENABLE ROW LEVEL SECURITY;
ALTER TABLE blacklist           ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits         ENABLE ROW LEVEL SECURITY;

-- Tabelas que podem nao existir em instalacoes antigas: nao derrubar o script.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='resellers') THEN
        EXECUTE 'ALTER TABLE resellers ENABLE ROW LEVEL SECURITY';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='credit_transactions') THEN
        EXECUTE 'ALTER TABLE credit_transactions ENABLE ROW LEVEL SECURITY';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='admin_sessions') THEN
        EXECUTE 'ALTER TABLE admin_sessions ENABLE ROW LEVEL SECURITY';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='processed_orders') THEN
        EXECUTE 'ALTER TABLE processed_orders ENABLE ROW LEVEL SECURITY';
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 3. Derrubar as policies permissivas ("Enable all access for all users")
--    Elas eram `USING (true)`: RLS ligado com porta escancarada.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    pol RECORD;
BEGIN
    FOR pol IN
        SELECT schemaname, tablename, policyname
        FROM pg_policies
        WHERE schemaname = 'public'

    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', pol.policyname, pol.tablename);
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 4. Policies restritivas: SO service_role entra
--    (`auth.role()` = 'service_role' quando a request usa a service key)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t TEXT;
BEGIN
    FOR t IN SELECT unnest((SELECT array_agg(tablename) FROM pg_tables WHERE schemaname='public'))
    LOOP
        IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename=t) THEN
            EXECUTE format($f$
                CREATE POLICY "service_role_full_access" ON public.%I
                    FOR ALL
                    TO service_role
                    USING (true)
                    WITH CHECK (true)
            $f$, t);
        END IF;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 5. Tirar o GRANT direto de anon/authenticated (cinto e suspensorio)
--    Sem privilegio de tabela, nem uma policy furada expoe dado.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t TEXT;
BEGIN
    FOR t IN SELECT unnest((SELECT array_agg(tablename) FROM pg_tables WHERE schemaname='public'))
    LOOP
        IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename=t) THEN
            EXECUTE format('REVOKE ALL ON public.%I FROM anon, authenticated', t);
        END IF;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- ---------------------------------------------------------------------------
-- 5b. EXCECAO MEDIDA: `settings.server_status` lido pelo NAVEGADOR
-- ---------------------------------------------------------------------------
-- 🔴 O painel-revendedor (`app/page.tsx:149`, um 'use client') le
-- `settings` com a chave ANON, direto do browser, para mostrar se o servidor
-- esta online. Um REVOKE cego em `settings` quebraria esse indicador -- e pior,
-- em SILENCIO: o `catch` da linha 152 so faz console.error, entao o status
-- ficaria congelado sem erro visivel para o usuario.
--
-- Solucao: manter o deny-all e abrir UMA linha, so leitura. As outras chaves de
-- `settings` (que incluem configuracao sensivel) seguem fechadas.
GRANT SELECT ON public.settings TO anon;

DROP POLICY IF EXISTS "anon_reads_server_status" ON public.settings;
CREATE POLICY "anon_reads_server_status" ON public.settings
    FOR SELECT
    TO anon
    USING (key = 'server_status');

-- 6. VERIFICACAO — rodar e LER a saida. Exigido: rls_ativo = true em todas,
--    e `policies_permissivas` = 0.
-- ---------------------------------------------------------------------------
SELECT
    c.relname                                   AS tabela,
    c.relrowsecurity                            AS rls_ativo,
    COUNT(p.policyname)                         AS policies,
    -- Permissiva = libera para anon/authenticated. Uma policy `USING (true)`
    -- restrita a `{service_role}` NAO e permissiva: o TO ja limita o alcance.
    COUNT(*) FILTER (
        WHERE p.qual = 'true' AND NOT (p.roles::text[] = ARRAY['service_role'])
    )                                           AS policies_permissivas,
    -- O grant e o que estava REALMENTE aberto: RLS ja estava ON em 13 tabelas
    -- e o anon lia tudo igual, porque o GRANT + policy `USING(true)` vencem.
    (SELECT coalesce(string_agg(DISTINCT g.privilege_type, ','), '-')
       FROM information_schema.role_table_grants g
      WHERE g.table_schema = 'public' AND g.grantee = 'anon'
        AND g.table_name = c.relname)             AS grants_anon,
    CASE WHEN c.relrowsecurity THEN 'OK' ELSE 'FALHOU' END AS veredito
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_policies p ON p.tablename = c.relname AND p.schemaname = 'public'
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
GROUP BY c.relname, c.relrowsecurity
ORDER BY c.relname;
