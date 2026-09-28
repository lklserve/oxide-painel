-- FIX GERAL E COMPLETO
-- Este script vai garantir que tudo exista e esteja desbloqueado.

-- 1. Garantir que RLS (segurança que bloqueia leitura) esteja DESATIVADO em tudo
ALTER TABLE licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE blacklist ENABLE ROW LEVEL SECURITY;

-- 2. Criar tabela de revendedores que estava faltando
CREATE TABLE IF NOT EXISTS resellers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    email TEXT,
    contact TEXT,
    balance NUMERIC DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    custom_costs JSONB DEFAULT '{}'::jsonb
);
ALTER TABLE resellers ENABLE ROW LEVEL SECURITY;

-- 3. Adicionar coluna reseller_id nas licenses se nÃ£o existir
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS reseller_id UUID REFERENCES resellers(id);

-- 4. Garantir tabela de transações de crédito
CREATE TABLE IF NOT EXISTS credit_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reseller_id UUID REFERENCES resellers(id),
    amount NUMERIC,
    type TEXT CHECK (type IN ('add', 'deduct', 'commission')),
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
ALTER TABLE credit_transactions ENABLE ROW LEVEL SECURITY;
