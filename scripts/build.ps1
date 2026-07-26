<#
.SYNOPSIS
  Builds every component and runs the full test suite.
#>
[CmdletBinding()]
param([switch]$SkipTests)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $scriptDir '..')

$env:Path = "C:\Program Files\Go\bin;$env:USERPROFILE\go\bin;$env:Path"
New-Item -ItemType Directory -Force -Path (Join-Path $root 'bin') | Out-Null

function Step($name) { Write-Host "`n==> $name" -ForegroundColor Cyan }

# Run invokes a native command and fails on its exit code rather than on its
# output.
#
# Necessary because $ErrorActionPreference = 'Stop' makes PowerShell treat
# anything a native program writes to stderr as a terminating error. cargo,
# npm and uv all report ordinary progress there, so the script aborted
# mid-build whenever cargo actually had something to compile -- and passed
# whenever the build was already cached, which is why it went unnoticed.
#
# Exit code is the only signal that means failure.
function Run {
    param([Parameter(Mandatory)][string]$Exe, [string[]]$Arguments = @())

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$Exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
        }
    } finally {
        $ErrorActionPreference = $previous
    }
}

Step 'protobuf schema'
Push-Location $root
Run buf @('lint')
Run buf @('generate')
Pop-Location

Step 'forked x/crypto (umac)'
# Separate module, pulled in by a replace directive in node/go.mod. Its tests
# carry the RFC 4418 vectors that are the only evidence the MAC is correct, so
# they have to run here rather than being skipped as vendored code.
Push-Location (Join-Path $root 'third_party\crypto')
if (-not $SkipTests) {
    Run go @('vet', './ssh/...')
    Run go @('test', './ssh/internal/umac/', './ssh/')
}
Pop-Location

Step 'go sensor'
Push-Location (Join-Path $root 'node')
Run go @('build', './...')
Run go @('build', '-o', (Join-Path $root 'bin\honeynode.exe'), './cmd/honeynode')
Run go @('build', '-o', (Join-Path $root 'bin\attacksim.exe'), './cmd/attacksim')
if (-not $SkipTests) {
    Run go @('vet', './...')
    Run go @('test', './...')
}
Pop-Location

Step 'rust collector'
Push-Location (Join-Path $root 'collector')
Run cargo @('build', '--release')
if (-not $SkipTests) {
    Run cargo @('fmt', '--check')
    Run cargo @('clippy', '--all-targets', '--', '-D', 'warnings')
    # The Postgres tests skip themselves unless DATABASE_URL is set; CI sets it.
    Run cargo @('test')
}
Pop-Location

Step 'python profiling pipeline'
Push-Location (Join-Path $root 'ml')
if (-not (Test-Path '.venv')) { Run uv @('venv', '--python', '3.12') }
Run uv @('pip', 'install', '-q', '-e', '.[dev]')
if (-not $SkipTests) { Run '.\.venv\Scripts\python.exe' @('-m', 'pytest', '-q') }
Pop-Location

Step 'operator dashboard'
Push-Location (Join-Path $root 'dashboard')
if (-not (Test-Path 'node_modules')) { Run npm @('install', '--silent') }
if (-not $SkipTests) {
    Run npx @('tsc', '--noEmit')
    Run npm @('test')
}
Run npm @('run', 'build', '--silent')
Pop-Location

Write-Host "`nbuild complete" -ForegroundColor Green
Get-ChildItem (Join-Path $root 'bin') -Filter *.exe |
    ForEach-Object { "  {0,-20} {1,10:N0} bytes" -f $_.Name, $_.Length }
"  {0,-20} {1,10:N0} bytes" -f 'honeynet-collector.exe',
    (Get-Item (Join-Path $root 'collector\target\release\honeynet-collector.exe')).Length
