# Limpeza dos segredos no historico do Git

**Repo:** `lklserve/painel-lkl-principal` · **76 commits** · **16 arquivos** ja contiveram a chave.

Segredos a remover do historico:

| # | segredo | onde nasceu |
|---|---|---|
| 1 | JWT anon do Supabase (`eyJhbGciOiJIUzI1NiIsInR5cC...fXK8qhiM`, 208 ch) | 16 arquivos, commits `0ecda3b`, `f40f2ea` |
| 2 | `i0G67jsJANgm3HUPUaa1QVS8AykeCTvRlWSRPaex` | `api/notify.js` (validSecrets) |
| 3 | `rLLlPvYXvKLxFILR0iagpN8Bxi9foDDfbIMi2VrU` | `api/notify.js` (validSecrets) |
| 4 | `LKL2024` | `api/notify.js` (validSecrets) |
| 5 | senhas do seed de `admins` (texto puro) | `schema.sql` |

---

## 🔴 ANTES DE QUALQUER COMANDO: rotacionar as chaves

Reescrever o historico **nao invalida uma chave que ja vazou**. Quem clonou o repo
antes ja tem os valores. A ordem correta e:

1. **Supabase → Settings → API → "Roll" na chave anon e na service_role.**
2. Atualizar `SUPABASE_SERVICE_ROLE_KEY` nas env vars da Vercel.
3. Trocar as senhas dos admins (`King`, `Lee`, `Leon`) no banco.
4. Só então limpar o historico (higiene, para nao vazar de novo).

Sem o passo 1, os passos 2-4 são teatro: a chave antiga continua valendo.

---

## Passo 1 — Backup (obrigatorio)

```bash
cd "/d/botlibs-telegram/Painel LKL oficial controle de keys"
cp -r painel-principal painel-principal.BACKUP-ANTES-FILTER-$(date +%Y%m%d-%H%M)
```

## Passo 2 — Commitar as correcoes primeiro

O historico so pode ser reescrito com a arvore limpa:

```bash
cd "/d/botlibs-telegram/Painel LKL oficial controle de keys/painel-principal"
git add -A && git commit -m "sec: corrige XSS armazenado, IDOR, rate limit e RLS"
```

## Passo 3 — Instalar git-filter-repo

`git filter-branch` e **deprecado pelo proprio git** (lento e cheio de armadilhas) e o
BFG nao aceita bem os `--replace-text` multiplos que precisamos. `git-filter-repo` e o
recomendado oficial:

```bash
python -m pip install --user git-filter-repo
```

## Passo 4 — Arquivo de substituicoes

```bash
cd "/d/botlibs-telegram/Painel LKL oficial controle de keys/painel-principal"
cat > /tmp/segredos.txt <<'TXT'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imlsd2ZleXprYWVoa2Zna3h0Y2lxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjQ1NDQxNDcsImV4cCI6MjA4MDEyMDE0N30.eK5-Ut91eYVmSgE9-v-zsHZ5lQB7xzVaJZyfXK8qhiM==>***CHAVE_ROTACIONADA***
i0G67jsJANgm3HUPUaa1QVS8AykeCTvRlWSRPaex==>***SEGREDO_REMOVIDO***
rLLlPvYXvKLxFILR0iagpN8Bxi9foDDfbIMi2VrU==>***SEGREDO_REMOVIDO***
LKL2024==>***SEGREDO_REMOVIDO***
Rtydfgxc5202@==>***SENHA_REMOVIDA***
Lee53k==>***SENHA_REMOVIDA***
Leon5202==>***SENHA_REMOVIDA***
TXT
```

## Passo 5 — Reescrever o historico

```bash
git filter-repo --replace-text /tmp/segredos.txt --force
```

## Passo 6 — Conferir que sumiu (LER a saida)

```bash
# Exigido: 0 em TODAS as linhas.
# 🔑 Nao usar `git log -S"<segredo>"`: o pickaxe conta MUDANCA de ocorrencias, nao
# presenca -- ele devolveu 0 para os 6 segredos que comprovadamente estao no
# historico. Varrer os commits com `git grep` e o que realmente verifica.
for seg in "eyJhbGciOiJIUzI1NiIs"            "i0G67jsJANgm3HUPUaa1QVS8AykeCTvRlWSRPaex"            "rLLlPvYXvKLxFILR0iagpN8Bxi9foDDfbIMi2VrU"            "LKL2024" "Rtydfgxc5202@" "Lee53k" "Leon5202"; do
  n=$(git rev-list --all | while read c; do git grep -alF "$seg" "$c" 2>/dev/null; done | wc -l)
  printf "%-44s %4s %s
" "$seg" "$n" "$([ "$n" -eq 0 ] && echo OK || echo FALHOU)"
done
```

## Passo 7 — Push forcado

🔴 `git filter-repo` **remove os remotes** de proposito (evita push acidental). Reconfigurar:

```bash
git remote add origin https://github.com/lklserve/painel-lkl-principal.git
git push origin --force --all
git push origin --force --tags
```

## Passo 8 — Limpar o cache do GitHub

Commits antigos ficam acessiveis por URL direta mesmo apos o force-push. Abrir um ticket
no GitHub Support pedindo garbage collection do repo, ou (mais simples e definitivo)
**deletar e recriar o repositorio** — 76 commits de historico nao valem uma chave viva.

---

## Alternativa com BFG (se preferir nao instalar o filter-repo)

Java 21 ja esta disponivel nesta maquina. Baixar o `bfg.jar` e:

```bash
cd "/d/botlibs-telegram/Painel LKL oficial controle de keys"
git clone --mirror https://github.com/lklserve/painel-lkl-principal.git painel.git
java -jar bfg.jar --replace-text /tmp/segredos.txt painel.git
cd painel.git && git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push --force
```

O BFG **nao mexe no commit que esta em HEAD** por design — como as correcoes serao
commitadas no Passo 2, os segredos ja nao existem lá e isso deixa de ser problema.
