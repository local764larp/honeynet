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

Step 'protobuf schema'
Push-Location $root
buf lint
buf generate
Pop-Location

Step 'go sensor'
Push-Location (Join-Path $root 'node')
go build ./...
go build -o (Join-Path $root 'bin\honeynode.exe') ./cmd/honeynode
go build -o (Join-Path $root 'bin\attacksim.exe') ./cmd/attacksim
if (-not $SkipTests) { go vet ./...; go test ./... }
Pop-Location

Step 'rust collector'
Push-Location (Join-Path $root 'collector')
cargo build --release
if (-not $SkipTests) { cargo test }
Pop-Location

Step 'python profiling pipeline'
Push-Location (Join-Path $root 'ml')
if (-not (Test-Path '.venv')) { uv venv --python 3.12 }
uv pip install -q -e ".[dev]"
if (-not $SkipTests) { .\.venv\Scripts\python.exe -m pytest -q }
Pop-Location

Write-Host "`nbuild complete" -ForegroundColor Green
Get-ChildItem (Join-Path $root 'bin') -Filter *.exe |
    ForEach-Object { "  {0,-20} {1,10:N0} bytes" -f $_.Name, $_.Length }
"  {0,-20} {1,10:N0} bytes" -f 'honeynet-collector.exe',
    (Get-Item (Join-Path $root 'collector\target\release\honeynet-collector.exe')).Length
