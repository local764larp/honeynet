<#
.SYNOPSIS
  End-to-end acceptance run for the honeynet platform.

.DESCRIPTION
  Stands up the full pipeline locally -- message bus, collector, sensor -- then
  drives it with the attacker simulator and verifies that the observations
  arrive as structured events.

  This is the acceptance gate for design doc slices 1 and 2: an attacker types a
  command at a fake SSH prompt and a validated, normalized row comes out the
  other end.

  No Docker and no Postgres required; the collector writes JSON lines.
#>
[CmdletBinding()]
param(
    [int]    $Runs        = 2,
    [int]    $Parallel    = 3,
    [string] $WorkDir     = '',
    [int]    $SshPort     = 2222,
    [int]    $NatsPort    = 4222,
    [switch] $KeepArtifacts
)

$ErrorActionPreference = 'Stop'

# Resolved here rather than in the param block: under Windows PowerShell 5.1
# $PSScriptRoot is not yet populated when parameter defaults are evaluated.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $scriptDir '..')
if (-not $WorkDir) { $WorkDir = Join-Path $root '.e2e' }

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
    param([string]$Name, [string]$Exe, [string[]]$ArgList, [string]$LogFile)
    Write-Host "  starting $Name" -ForegroundColor DarkGray
    $p = Start-Process -FilePath $Exe -ArgumentList $ArgList -PassThru `
        -RedirectStandardOutput $LogFile -RedirectStandardError "$LogFile.err" `
        -WindowStyle Hidden
    $script:procs += [pscustomobject]@{ Name = $Name; Proc = $p; Log = $LogFile }
    return $p
}

function Stop-Components {
    foreach ($c in ($script:procs | Sort-Object -Descending { $_.Name })) {
        if ($c.Proc -and -not $c.Proc.HasExited) {
            try { Stop-Process -Id $c.Proc.Id -Force -ErrorAction Stop } catch {}
        }
    }
}

function Wait-ForPort {
    param([int]$Port, [int]$TimeoutSec = 20, [string]$What = 'service')
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $ok = Test-NetConnection -ComputerName 127.0.0.1 -Port $Port `
            -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($ok) { return $true }
        Start-Sleep -Milliseconds 250
    }
    throw "$What did not open port $Port within ${TimeoutSec}s"
}

# ---------------------------------------------------------------- setup ----

if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

$eventsFile = Join-Path $WorkDir 'events.jsonl'
$natsExe    = Find-NatsServer
$nodeExe    = Join-Path $root 'bin\honeynode.exe'
$simExe     = Join-Path $root 'bin\attacksim.exe'
$collExe    = Join-Path $root 'collector\target\release\honeynet-collector.exe'

foreach ($e in @($nodeExe, $simExe, $collExe)) {
    if (-not (Test-Path $e)) { throw "missing binary: $e  (run scripts\build.ps1 first)" }
}

Write-Host "`nhoneynet end-to-end run" -ForegroundColor Cyan
Write-Host ("=" * 60)

try {
    # ------------------------------------------------------------ bus ----
    Start-Component -Name 'nats-server' -Exe $natsExe `
        -ArgList @('-p', "$NatsPort", '-a', '127.0.0.1') `
        -LogFile (Join-Path $WorkDir 'nats.log') | Out-Null
    Wait-ForPort -Port $NatsPort -What 'nats-server'

    # ------------------------------------------------------ collector ----
    Start-Component -Name 'collector' -Exe $collExe `
        -ArgList @('--nats-url', "nats://127.0.0.1:$NatsPort",
                   '--events-jsonl', $eventsFile,
                   '--stats-interval', '5') `
        -LogFile (Join-Path $WorkDir 'collector.log') | Out-Null
    Start-Sleep -Milliseconds 800

    # ---------------------------------------------------------- node ----
    $env:HONEYNODE_ID            = 'sensor-e2e-01'
    $env:HONEYNODE_SEED          = 'sensor-e2e-01'
    $env:HONEYNODE_NATS_URL      = "nats://127.0.0.1:$NatsPort"
    $env:HONEYNODE_SSH_ADDR      = "127.0.0.1:$SshPort"
    $env:HONEYNODE_TELNET_ADDR   = ''
    $env:HONEYNODE_SPOOL         = Join-Path $WorkDir 'node.spool'
    $env:HONEYNODE_HOST_KEY      = Join-Path $WorkDir 'hostkey'
    $env:HONEYNODE_HEARTBEAT_SEC = '5'

    Start-Component -Name 'honeynode' -Exe $nodeExe `
        -ArgList @('-config', (Join-Path $WorkDir 'nonexistent.json')) `
        -LogFile (Join-Path $WorkDir 'node.log') | Out-Null
    Wait-ForPort -Port $SshPort -What 'honeynode ssh'

    # ------------------------------------------------------- traffic ----
    #
    # The sensor accepts one password per account, derived from a secret only
    # it holds, so no wordlist reaches a shell -- that is the whole point of
    # the credential design. The harness therefore has to ask the node what it
    # accepts, or every profile would stop at the login and nothing downstream
    # of authentication would ever be exercised.
    #
    # The simulator still sprays its own guesses first; the real credential is
    # offered last, inside the server's auth-try budget.
    $credLine = (& $nodeExe -config (Join-Path $WorkDir 'nonexistent.json') -credentials |
        Where-Object { $_ -like 'root:*' } | Select-Object -First 1)
    if (-not $credLine) { throw "could not read the node's accepted credentials" }
    $simUser, $simPass = $credLine -split ':', 2
    Write-Host "  sensor accepts ${simUser}:${simPass}" -ForegroundColor DarkGray

    Write-Host "`nreplaying attacker profiles" -ForegroundColor Cyan
    & $simExe -addr "127.0.0.1:$SshPort" -runs $Runs -parallel $Parallel -seed 20260725 `
        -username $simUser -password $simPass
    $simExit = $LASTEXITCODE

    # Let the sensor's publisher drain its spool.
    Start-Sleep -Seconds 3

} finally {
    Stop-Components
    Start-Sleep -Milliseconds 500
}

# ----------------------------------------------------------- verify ----

Write-Host "`nverifying collected events" -ForegroundColor Cyan
Write-Host ("=" * 60)

if (-not (Test-Path $eventsFile)) { throw "collector produced no events file" }

$events = Get-Content $eventsFile | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json }
if (-not $events) { throw "collector produced no events" }

$byKind = $events | Group-Object { $_.payload.kind } | Sort-Object Count -Descending
Write-Host "`nevents by type:"
$byKind | ForEach-Object { "  {0,-16} {1,5}" -f $_.Name, $_.Count } | Write-Host

$sessions = $events | Where-Object { $_.session_id } |
    Group-Object session_id | Measure-Object | Select-Object -ExpandProperty Count

$failures = @()

function Assert-Condition {
    param([bool]$Ok, [string]$Message)
    if ($Ok) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else     { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures += $Message }
}

$starts  = @($events | Where-Object { $_.payload.kind -eq 'session_start' })
$auths   = @($events | Where-Object { $_.payload.kind -eq 'auth' })
$cmds    = @($events | Where-Object { $_.payload.kind -eq 'command' })
$arts    = @($events | Where-Object { $_.payload.kind -eq 'artifact' })
$ends    = @($events | Where-Object { $_.payload.kind -eq 'session_end' })

Write-Host ""
Assert-Condition ($events.Count -gt 100)  "collected $($events.Count) events"
Assert-Condition ($sessions -ge 10)       "reconstructed $sessions distinct sessions"
Assert-Condition ($starts.Count -ge 10)   "$($starts.Count) session_start events"
Assert-Condition ($cmds.Count   -ge 30)   "$($cmds.Count) commands captured"
Assert-Condition ($arts.Count   -ge 4)    "$($arts.Count) payload URLs captured"

# Every session opens exactly once and closes exactly once. An SSH connection
# carries many channels and a scripted loader opens one per command, so this is
# the check that catches session lifetime being bound to the wrong object.
Assert-Condition ($ends.Count -eq $starts.Count) `
    "session_start ($($starts.Count)) and session_end ($($ends.Count)) are balanced"

$endsPerSession = $ends | Group-Object session_id | ForEach-Object { $_.Count } | Sort-Object -Unique
Assert-Condition (($endsPerSession.Count -eq 1) -and ($endsPerSession[0] -eq 1)) `
    "exactly one session_end per session"

# Each profile sprays until the node's derived grant threshold is reached, so
# the floor is two attempts per session rather than a fixed fleet-wide number.
Assert-Condition ($auths.Count -ge (2 * $starts.Count)) `
    "$($auths.Count) credential attempts across $($starts.Count) sessions"

# Every sensor identity must be the authenticated one.
$badNode = @($events | Where-Object { $_.node_id -ne 'sensor-e2e-01' })
Assert-Condition ($badNode.Count -eq 0) "all events attributed to the authenticated sensor"

# HASSH must be populated -- it proves the KEXINIT sniffer parsed real traffic.
$hasshes = @($starts | Where-Object { $_.payload.hassh } |
             ForEach-Object { $_.payload.hassh } | Sort-Object -Unique)
Assert-Condition ($hasshes.Count -ge 4) "$($hasshes.Count) distinct HASSH client fingerprints"

# Distinct client banners, one per simulated family.
$banners = @($starts | ForEach-Object { $_.payload.client_banner } | Sort-Object -Unique)
Assert-Condition ($banners.Count -ge 4) "$($banners.Count) distinct client banners"

# The busybox probe must have been answered, or loaders would have bailed.
$busybox = @($cmds | Where-Object { $_.payload.raw -match 'busybox' })
Assert-Condition ($busybox.Count -ge 2) "$($busybox.Count) busybox applet probes recorded"

# Payload infrastructure extracted into queryable fields.
$hosts = @($arts | ForEach-Object { $_.payload.host } | Sort-Object -Unique)
Assert-Condition ($hosts.Count -ge 2) "payload hosts extracted: $($hosts -join ', ')"

# Successful logins are marked, and only at the end of a spray.
$succeeded = @($auths | Where-Object { $_.payload.success })
Assert-Condition ($succeeded.Count -ge 5) "$($succeeded.Count) successful logins recorded"

# Interactive sessions must carry per-keystroke timing; that feature is what
# the bot/human classifier separates on.
$typed = @($cmds | Where-Object { $_.payload.keystroke_deltas_ms.Count -gt 3 })
Assert-Condition ($typed.Count -ge 5) "$($typed.Count) commands carry keystroke timing"

# Scripted sessions must be flagged bulk.
$bulk = @($cmds | Where-Object { $_.payload.bulk_input })
Assert-Condition ($bulk.Count -ge 20) "$($bulk.Count) commands flagged as bulk input"

# Sequence numbers must be unique and gap-free per node.
$seqs = @($events | ForEach-Object { $_.seq } | Sort-Object -Unique)
Assert-Condition ($seqs.Count -eq $events.Count) "sequence numbers are unique (no replay)"
Assert-Condition (($seqs[-1] - $seqs[0] + 1) -eq $seqs.Count) "sequence numbers are gap-free"

# The collector must have rejected nothing.
$collectorLog = Get-Content (Join-Path $WorkDir 'collector.log') -Raw -ErrorAction SilentlyContinue
$rejected = ($collectorLog -split "`n" | Where-Object { $_ -match 'rejected|spoofing' }).Count
Assert-Condition ($collectorLog -notmatch 'identity spoofing') "no identity spoofing detected"

Write-Host "`n" + ("=" * 60)
if ($failures.Count -gt 0) {
    Write-Host "$($failures.Count) CHECK(S) FAILED" -ForegroundColor Red
    if (-not $KeepArtifacts) { Write-Host "artifacts kept at $WorkDir" -ForegroundColor Yellow }
    exit 1
}

Write-Host "END-TO-END PASSED" -ForegroundColor Green
Write-Host "  events:   $eventsFile"
Write-Host "  sessions: $sessions"
Write-Host "  logs:     $WorkDir"

if (-not $KeepArtifacts) {
    Write-Host "`n(pass -KeepArtifacts to preserve the corpus for the ML pipeline)" -ForegroundColor DarkGray
}
exit 0
