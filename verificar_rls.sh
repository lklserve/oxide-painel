#!/usr/bin/env bash
# Verifica, de fora, se o RLS fechou a porta do anon.
# Rodar DEPOIS de executar security_rls.sql no SQL Editor do Supabase.
#
# `select=id` nao serve para todas: `settings` e (key,value), sem coluna id.
# Le as credenciais de ../.env.local (nao recebe segredo por argumento, que
# ficaria no histórico do shell).
set -u
ENV_FILE="${1:-../.env.local}"
[ -f "$ENV_FILE" ] || { echo "env nao encontrado: $ENV_FILE"; exit 1; }

ANON=$(grep -a "^NEXT_PUBLIC_SUPABASE_ANON_KEY=" "$ENV_FILE" | cut -d= -f2- | tr -d '"'"'"' \r')
SRK=$(grep -a "^SUPABASE_SERVICE_ROLE_KEY=" "$ENV_FILE" | cut -d= -f2- | tr -d '"'"'"' \r')
URL=$(grep -a "^NEXT_PUBLIC_SUPABASE_URL=" "$ENV_FILE" | cut -d= -f2- | tr -d '"'"'"' \r')
[ -n "$ANON" ] && [ -n "$SRK" ] && [ -n "$URL" ] || { echo "credenciais incompletas em $ENV_FILE"; exit 1; }

falhas=0
echo "════ ANON deve estar BLOQUEADO (esperado: 0 registros ou 401/403) ════"
for t in licenses admins settings activity_logs blacklist resellers credit_transactions; do
    body=$(curl -s "$URL/rest/v1/$t?select=*&limit=5" -H "apikey: $ANON" -H "Authorization: Bearer $ANON")
    n=$(printf '%s' "$body" | python -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(len(d) if isinstance(d,list) else -1)
except Exception:
    print(-1)
" 2>/dev/null || echo -1)
    if [ "$t" = "settings" ]; then
        # Excecao PROPOSITAL: `app/page.tsx:149` do painel-revendedor le
        # settings.server_status do navegador com a chave anon. A policy libera
        # essa UNICA linha; exigir 0 aqui acusaria falha no comportamento certo.
        keys=$(printf '%s' "$body" | python -c "
import sys,json
try: print(','.join(sorted(r.get('key','?') for r in json.load(sys.stdin))))
except Exception: print('')
" 2>/dev/null)
        if [ "$keys" = "server_status" ] || [ -z "$keys" ]; then
            printf "  %-22s OK (so server_status, excecao prevista)\n" "$t"
        else
            printf "  %-22s FALHOU: anon ve [%s]\n" "$t" "$keys"; falhas=$((falhas+1))
        fi
    elif [ "$n" = "0" ] || [ "$n" = "-1" ]; then
        printf "  %-22s OK (sem dados)\n" "$t"
    else
        printf "  %-22s FALHOU: leu %s registro(s)\n" "$t" "$n"; falhas=$((falhas+1))
    fi
done

echo
echo "════ ANON nao deve ESCREVER (esperado: != 201) ════"
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL/rest/v1/blacklist" \
       -H "apikey: $ANON" -H "Authorization: Bearer $ANON" -H "Content-Type: application/json" \
       -d '{"device_id":"__RLS_CHECK__","ip":"203.0.113.253","reason":"verificacao de RLS"}')
if [ "$code" = "201" ]; then
    echo "  INSERT -> HTTP 201  FALHOU: escrita ainda liberada"; falhas=$((falhas+1))
    curl -s -o /dev/null -X DELETE "$URL/rest/v1/blacklist?device_id=eq.__RLS_CHECK__" \
      -H "apikey: $SRK" -H "Authorization: Bearer $SRK"
    echo "  (registro de teste removido)"
else
    echo "  INSERT -> HTTP $code  OK (bloqueado)"
fi

echo
echo "════ SERVICE_ROLE deve continuar FUNCIONANDO (o painel depende disso) ════"
for t in licenses admins settings activity_logs blacklist; do
    c=$(curl -s -o /dev/null -w "%{http_code}" "$URL/rest/v1/$t?select=*&limit=1" \
        -H "apikey: $SRK" -H "Authorization: Bearer $SRK")
    if [ "$c" = "200" ]; then printf "  %-22s OK (HTTP 200)\n" "$t"
    else printf "  %-22s FALHOU: HTTP %s -- o painel VAI QUEBRAR\n" "$t" "$c"; falhas=$((falhas+1)); fi
done

echo
if [ "$falhas" -eq 0 ]; then echo "════ RESULTADO: RLS OK — anon fechado, painel intacto ════"
else echo "════ RESULTADO: $falhas FALHA(S) — ver acima ════"; exit 1; fi
