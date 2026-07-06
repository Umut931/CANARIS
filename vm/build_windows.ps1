<#
.SYNOPSIS
    CANARIS — [HANDOFF-VM] build du composant Windows (driver + service).
.DESCRIPTION
    Vérifie la présence de Visual Studio + WDK, puis build windows\Canaris.sln en
    x64 (Debug par défaut) et rapporte lisiblement les erreurs de compilation.

    NE PRÉTEND RIEN sur le chargement du driver : un build réussi ne prouve ni la
    signature, ni l'absence de BSOD. Voir vm\validate_windows.md pour le protocole
    de chargement et de test (Test Signing, Driver Verifier, snapshots VM).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File vm\build_windows.ps1 -Configuration Debug
#>
param(
    [ValidateSet("Debug","Release")] [string]$Configuration = "Debug",
    [string]$Platform = "x64"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$sln  = Join-Path $root "windows\Canaris.sln"

function Fail($m) { Write-Host "ECHEC: $m" -ForegroundColor Red; exit 1 }

Write-Host "== CANARIS build_windows ($Configuration|$Platform) ==" -ForegroundColor Cyan

if (-not (Test-Path $sln)) { Fail "solution introuvable: $sln" }

# 1. Localiser MSBuild (via vswhere fourni avec VS 2017+).
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Fail "vswhere introuvable — installer Visual Studio 2022 (Desktop C++) + WDK."
}
$vsPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
if (-not $vsPath) { Fail "Visual Studio avec MSBuild introuvable." }
$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
if (-not (Test-Path $msbuild)) { Fail "MSBuild introuvable dans $vsPath" }
Write-Host "MSBuild: $msbuild"

# 2. Vérifier la présence du WDK (composant driver).
$wdkRoots = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
    "$env:ProgramFiles\Windows Kits\10\bin"
) | Where-Object { Test-Path $_ }
if (-not $wdkRoots) {
    Write-Host "AVERTISSEMENT: WDK (Windows Kits\10) non détecté — le projet driver" -ForegroundColor Yellow
    Write-Host "  ne compilera pas sans WDK. Installer 'Windows Driver Kit' assorti au SDK." -ForegroundColor Yellow
}

# 3. Build.
Write-Host "== msbuild ==" -ForegroundColor Cyan
& $msbuild $sln "/t:Build" "/p:Configuration=$Configuration" "/p:Platform=$Platform" `
    "/nologo" "/verbosity:minimal" "/clp:Summary"
if ($LASTEXITCODE -ne 0) {
    Fail "build échoué (code $LASTEXITCODE). Voir les erreurs ci-dessus."
}

# 4. Vérifier les artefacts.
$outDir = Join-Path $root "windows\$Platform\$Configuration"
$sys = Join-Path $outDir "Canaris.sys"
$exe = Join-Path $outDir "CanarisSvc.exe"
Write-Host "== artefacts ==" -ForegroundColor Cyan
foreach ($f in @($sys, $exe)) {
    if (Test-Path $f) { Write-Host "  OK  $f" -ForegroundColor Green }
    else { Write-Host "  MANQUANT  $f" -ForegroundColor Yellow }
}
Write-Host "Build terminé. Chargement/test = vm\validate_windows.md (Test Signing requis)." -ForegroundColor Cyan
