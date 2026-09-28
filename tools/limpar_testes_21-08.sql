-- ===========================================================================
-- Remove APENAS os 2 devices que os testes de 21-08 gravaram.
-- Rodar no SQL Editor do Supabase. Seguro: filtra por nome exato, nao por
-- padrao -- nenhum device de cliente casa com estas strings.
--
-- Confira ANTES de apagar (o SELECT nao muda nada):
-- ===========================================================================
SELECT device_id, reason, created_at
  FROM blacklist
 WHERE device_id IN ('TESTE-CLAUDE-NAO-USAR-21-08', 'TESTE-CLAUDE-VARIANTE-21-08');

-- Esperado: 2 linhas, ambas com reason de armadilha. Se aparecer device que
-- voce nao reconhece, PARE e me avise antes de deletar.

DELETE FROM blacklist
 WHERE device_id IN ('TESTE-CLAUDE-NAO-USAR-21-08', 'TESTE-CLAUDE-VARIANTE-21-08');

-- Os logs em activity_logs ficam de proposito: sao a trilha de auditoria de
-- que o mecanismo foi testado e funcionou nesta data.
