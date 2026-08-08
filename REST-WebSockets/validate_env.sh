#!/bin/bash
# Validar_variables.sh - Ejecuta esto directamente como script o copia el cuerpo

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}🔍 Validando variables de entorno${NC}"
echo "========================================================="

pass=0
fail=0

# Validar DATABASE_URL
if [ -z "${DATABASE_URL:-}" ]; then
    echo -e "${RED}❌ DATABASE_URL: NO DEFINIDA (esencial)"
    ((fail++))
else
    if echo "$DATABASE_URL" | grep -q "postgres://"; then
        echo -e "${GREEN}✅ DATABASE_URL: Configurada correctamente"
        ((pass++))
    else
        echo -e "${YELLOW}⚠️  DATABASE_URL: No parece ser PostgreSQL ($DATABASE_URL)"
        ((fail++))
    fi
fi

# Validar JWT_SECRET (debe tener >20 caracteres para entropía adecuada)
if [ -z "${JWT_SECRET:-}" ]; then
    echo -e "${RED}❌ JWT_SECRET: NO DEFINIDA (seguridad crítica)"
    ((fail++))
else
    if [[ ${#JWT_SECRET} -ge 20 ]]; then
        echo -e "${GREEN}✅ JWT_SECRET: Entropía aceptable (${#JWT_SECRET} chars)"
        ((pass++))
    else
        echo -e "${YELLOW}⚠️  JWT_SECRET: Corto para seguridad ($JWT_SECRET) - Recomenda >20"
        ((fail++))
    fi
fi

# Validar PORT
if [ -z "${PORT:-}" ]; then
    echo -e "${GREEN}ℹ️  PORT: No configurado (default: 8080)"
else
    if [[ "$PORT" =~ ^[1-9][0-9]{1,4}$ ]] && (( PORT > 1023 && PORT < 65536 )); then
        echo -e "${GREEN}✅ PORT: $PORT (valido)"
        ((pass++))
    else
        echo -e "${YELLOW}⚠️  PORT: $PORT (fuera del rango válido o no numérico)"
        ((fail++))
    fi
fi

echo "========================================================="
if [ $pass -eq $((${pass} + ${fail})) ]; then
    echo -e "${GREEN}✅ Todas las variables de entorno están válidas"
else
    echo -e "${RED}❌ Found ${fail} problemas (verifica los above)"
fi

exit $((fail))
