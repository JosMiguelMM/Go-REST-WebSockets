#!/bin/bash

# Nombre del binario ejecutable
BINARY_NAME="./Go-REST-WebSockets"

# Inicializar variables por defecto
MODE=""
OPTIMIZE_ZEN5=false
GOAMD64_VAL="v1"

# Procesar los argumentos del script
for arg in "$@"; do
    case "$arg" in
        dev)
            MODE="dev"
            ;;
        prod)
            MODE="prod"
            ;;
        --native|-n)
            OPTIMIZE_ZEN5=true
            GOAMD64_VAL="v4"
            ;;
    esac
done

# Validar que se haya especificado un modo válido
if [ "$MODE" != "dev" ] && [ "$MODE" != "prod" ]; then
    echo "⚠️  Error: Debes especificar un modo ('dev' o 'prod')."
    echo "Uso: $0 [dev|prod] [--native|-n]"
    exit 1
fi

clear
echo "=================================================="
echo "🛠️  Modo seleccionado: $(echo "$MODE" | tr '[:lower:]' '[:upper:]')"
if [ "$OPTIMIZE_ZEN5" = true ]; then
    echo "🚀 Optimización: ACTIVADA (Ryzen 7 9700X / Zen 5 - AVX-512)"
else
    echo "🌐 Optimización: DESACTIVADA (Modo genérico / x86_64 base)"
fi
echo "=================================================="

# ----------------------------------------
# MODO DESARROLLO (DEV) - Live Reloading
# ----------------------------------------
if [ "$MODE" == "dev" ]; then
    echo "👀 Vigilando cambios en los archivos con Air..."

    # Configuramos las variables para que Air las herede al compilar y ejecutar
    export GOAMD64="$GOAMD64_VAL"
    if [ "$OPTIMIZE_ZEN5" = true ]; then
        export GOMAXPROCS=8
    fi

    # Si no existe un archivo de configuración de Air (.air.toml), lo crea con valores óptimos
    if [ ! -f .air.toml ]; then
        echo "📝 Creando configuración inicial para Air (.air.toml)..."
        air init
    fi

    # Ejecutar Air para que controle los reinicios automáticos
    air

# ----------------------------------------
# MODO PRODUCCIÓN (PROD) - Compilación única limpia
# ----------------------------------------
elif [ "$MODE" == "prod" ]; then
    # Limpieza previa
    rm -rf "$BINARY_NAME"
    echo "📦 Compilando binario de producción..."

    # Compilar usando todos los hilos del sistema
    GOAMD64="$GOAMD64_VAL" go build -v -trimpath -ldflags="-s -w"

    if [ $? -eq 0 ]; then
        echo "🚀 Iniciando servidor en producción..."
        if [ "$OPTIMIZE_ZEN5" = true ]; then
            GOMAXPROCS=8 "$BINARY_NAME"
        else
            "$BINARY_NAME"
        fi
    else
        echo "❌ Error: La compilación de producción ha fallado."
        exit 1
    fi
fi
