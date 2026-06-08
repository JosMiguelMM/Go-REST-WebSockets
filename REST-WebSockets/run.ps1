Param(
    [string]$Output,
    [string]$Package = ".",
    [switch]$Tidy
)

$ErrorActionPreference = "Stop"

function Check-Go {
    try {
        & go version > $null 2>&1
    } catch {
        Write-Error "Go no está instalado o no está en el PATH. Ejecuta 'go version' para comprobarlo."
        exit 1
    }
}

Check-Go

# Directorio del script (se asume que el script está en la raíz del proyecto)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Push-Location $ScriptDir

# Nombre/carpeta por defecto para el binario
if (-not $Output) {
    $projectName = (Split-Path -Leaf $ScriptDir)
    $binDir = Join-Path $ScriptDir 'bin'
    $Output = Join-Path $binDir ("$projectName.exe")
} else {
    # Si se dio un Output relativo sin carpeta, lo resolvemos respecto al script
    if (-not (Split-Path $Output -Parent)) {
        $Output = Join-Path $ScriptDir $Output
    }
    $binDir = Split-Path -Parent $Output
    if (-not $binDir) { $binDir = Join-Path $ScriptDir 'bin' }
}

# Asegurar que exista la carpeta bin
if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}

if ($Tidy) {
    Write-Host "Ejecutando 'go mod tidy'..."
    go mod tidy
}

Write-Host "Compilando paquete '$Package' -> $Output"
go build -o $Output $Package

if ($LASTEXITCODE -ne 0) {
    Write-Error "La compilación falló."
    Pop-Location
    exit $LASTEXITCODE
}

Write-Host "Ejecutable creado: $Output"
Write-Host "Iniciando ejecutable..."
& $Output

$exitCode = $LASTEXITCODE
Pop-Location
exit $exitCode
