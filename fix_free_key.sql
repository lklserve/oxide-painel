-- ============================================================================
-- LKL Free Key System: adiciona flag is_free na tabela licenses
-- ============================================================================
-- Objetivo:
--   Marcar chaves gratuitas (geradas via painel) para que o mod possa forcar
--   o SpamChat sempre que o ESP for ligado.
--
-- Coluna:
--   is_free BOOLEAN DEFAULT false
--   - false (default): chave paga — comportamento normal
--   - true          : chave gratuita/teste — força SpamChat quando ESP ligado
-- ============================================================================

ALTER TABLE licenses
    ADD COLUMN IF NOT EXISTS is_free BOOLEAN DEFAULT false;

-- Indice parcial para listagens rapidas no painel.
-- DROP + CREATE (sem IF NOT EXISTS) para compatibilidade ampla de Postgres.
DROP INDEX IF EXISTS idx_licenses_is_free;
CREATE INDEX idx_licenses_is_free ON licenses (is_free) WHERE is_free = true;
