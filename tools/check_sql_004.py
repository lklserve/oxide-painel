# Valida a migracao 004 com o parser REAL do PostgreSQL (pglast/libpg_query).
#
# POR QUE existe: sem Postgres local, "o SQL parece certo" e leitura, nao
# verificacao. pglast usa o parser do proprio servidor, entao um erro de
# sintaxe aqui e o mesmo erro que o Supabase daria -- so que antes do deploy.
#
#   python tools/check_sql_004.py
#
# Limite conhecido: pglast valida SQL, nao a semantica do plpgsql (nomes de
# variavel, fluxo). Os corpos das funcoes sao extraidos e cada comando SQL
# dentro deles e validado individualmente.

import re
import sys
import pglast

PATH = 'supabase/migrations/004_blacklist_hardening.sql'
DOLLAR = '$fn$'

sql = open(PATH, encoding='utf-8').read()

# 1. O arquivo inteiro.
try:
    stmts = pglast.parse_sql(sql)
    print(f'arquivo inteiro           : OK ({len(stmts)} statements)')
except Exception as e:
    print(f'arquivo inteiro           : FALHOU\n{e}')
    sys.exit(1)

# 2. Corpos das funcoes (o parser trata $fn$...$fn$ como string opaca).
bodies = re.findall(re.escape(DOLLAR) + r'(.*?)' + re.escape(DOLLAR), sql, re.S)
print(f'corpos de funcao extraidos: {len(bodies)}')
if not bodies:
    print('VEREDITO: FALHOU - nenhum corpo extraido (regex ou delimitador errado)')
    sys.exit(1)

bad = 0
total_cmds = 0

for i, body in enumerate(bodies, 1):
    body = body.strip()

    # Funcao `language sql` (sem BEGIN): parseia direto.
    if body.lower().startswith('select') and 'begin' not in body.lower():
        try:
            pglast.parse_sql(body)
            print(f'  corpo {i}: OK (funcao SQL pura)')
        except Exception as e:
            print(f'  corpo {i}: FALHOU -> {e}')
            bad += 1
        continue

    # plpgsql: extrai cada comando SQL e valida um a um.
    #
    # 🔴 A indentacao e VARIAVEL: os comandos dentro de `if ... then` ficam a 8
    # espacos, nao 4. A 1a versao deste script exigia `^\s{4}` e por isso achou
    # 1 comando num corpo que tem 8 e ZERO no outro -- imprimindo "OK" para um
    # corpo que nunca foi verificado. Guarda contra isso no fim do laco.
    n = 0
    skipped = 0
    # Fim do ultimo comando consumido. Um `update` aninhado dentro de
    # `with hit as ( update ... )` casa com o regex mas ja foi validado junto
    # com o `with` que o contem -- contar de novo inflaria o total esperado e
    # faria a guarda de cobertura acusar falha num extrator correto.
    consumed_until = -1

    for m in re.finditer(r'^\s+(insert|update|with)\s', body, re.M | re.I):
        if m.start() < consumed_until:
            continue
        frag = body[m.start():]
        depth = 0
        end = None
        for j, ch in enumerate(frag):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            elif ch == ';' and depth == 0:
                end = j
                break
        if end is None:
            continue
        consumed_until = m.start() + end
        cmd = frag[:end].strip()

        # `SELECT ... INTO var` (plpgsql) e sintaxe que o parser SQL rejeita
        # legitimamente. Removemos so essa clausula para validar o RESTO.
        cmd_test = re.sub(r'\n\s*into\s+[\w\s,]+\n', '\n', cmd, flags=re.I)

        # 🔴 O escape para "construcao plpgsql" so vale para SELECT/WITH ... INTO.
        # A 1a versao testava `if 'into' in cmd` -- que casa com TODO
        # `INSERT INTO`. Resultado medido: injetei uma virgula faltando no
        # INSERT do activity_logs e o validador imprimiu OK, porque tratou o
        # erro real como "plpgsql-only, ignorado". Escape largo transforma
        # deteccao em silencio.
        eh_plpgsql_into = bool(re.match(r'^\s*(select|with)\b', cmd, re.I)) and \
                          re.search(r'\binto\b', cmd, re.I) is not None

        try:
            pglast.parse_sql(cmd_test)
            n += 1
            total_cmds += 1
        except Exception as e:
            if eh_plpgsql_into:
                skipped += 1
                continue
            print(f'  corpo {i}: comando FALHOU -> {str(e)[:140]}')
            print(f'           >> {cmd[:110]!r}')
            bad += 1
    note = f', {skipped} plpgsql-only ignorados' if skipped else ''

    # Piso de cobertura: um corpo plpgsql com INSERT/UPDATE no texto tem de
    # produzir comandos validados. Zero significa que o extrator nao casou --
    # nao que o corpo esta correto. Sem esta guarda, "OK (0 comandos)" mente.
    # Conta so os comandos de nivel superior: desconta os que estao dentro de
    # um CTE (`with hit as ( update ... )`), ja cobertos pelo comando externo.
    esperados = 0
    limite = -1
    for mm in re.finditer(r'^\s+(insert|update|with)\s', body, re.M | re.I):
        if mm.start() < limite:
            continue
        esperados += 1
        frag = body[mm.start():]
        depth = 0
        for j, ch in enumerate(frag):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            elif ch == ';' and depth == 0:
                limite = mm.start() + j
                break
    if n + skipped < esperados:
        print(f'  corpo {i}: FALHOU -> extrator cobriu {n + skipped} de {esperados} comandos '
              f'(regex nao casou; NAO tratar como validado)')
        bad += 1
    else:
        print(f'  corpo {i}: OK ({n} comandos SQL validados{note})')

# 3. Guardas de conteudo: coisas que o parser aceita mas que estariam erradas.
print('\nguardas de conteudo:')


def ordem(antes, depois):
    """True se `antes` aparece antes de `depois`. False se algum falta.

    🔴 A 1a versao usava sql.index() direto: quando removi o trecho de
    client_name para testar a guarda, o script morreu com ValueError e o grep
    do controle nao viu FALHOU nenhum -- um defeito real passou como 'sem
    saida'. Guarda que lanca excecao nao reporta.
    """
    return antes in sql and depois in sql and sql.index(antes) < sql.index(depois)


checks = [
    ('semente da armadilha presente',
     "'avienoffical'" in sql),
    # Casa a coluna dentro do coalesce da cascata, nao um espacamento fragil.
    ('cascata cobre client_username E client_name',
     re.search(r'coalesce\(client_username', sql) is not None and
     re.search(r'coalesce\(client_name\s*,', sql) is not None),
    ('client_name garantida antes de ser usada',
     ordem('add column if not exists client_name',
           'coalesce(client_name')),
    ('enforce e SECURITY DEFINER',
     re.search(r'lkl_enforce_blacklist[\s\S]{0,900}?security definer', sql, re.I) is not None),
    ('grant para service_role nas 3 funcoes',
     sql.count('to service_role') >= 3),
    ('constraint de status inclui paused',
     "'paused'" in sql),
    ('search_path fixado nas funcoes (evita hijack de schema)',
     sql.count('set search_path = public') >= 3),
]
for label, ok in checks:
    print(f'  {"OK    " if ok else "FALHOU"}  {label}')
    if not ok:
        bad += 1

print(f'\nVEREDITO: {"OK" if bad == 0 else str(bad) + " FALHARAM"} '
      f'({len(stmts)} statements, {total_cmds} comandos em funcao, {len(checks)} guardas)')
sys.exit(1 if bad else 0)
