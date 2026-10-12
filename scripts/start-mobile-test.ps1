[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

function Stop-LauncherWithVisibleError {
    param([Parameter(Mandatory)] [string]$Message)

    Write-Host ""
    Write-Host "SecureVote mobile-test launcher failed during: preflight checks" -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    Read-Host "Press Enter to close this launcher window"
    exit 1
}

function Test-TcpPortListening {
    param([Parameter(Mandatory)] [int]$Port)

    # Get-NetTCPConnection can require privileges on some Windows setups.
    # netstat is available to ordinary users and works consistently here.
    $listenerPattern = ":$Port\s+.*LISTENING\s+\d+\s*$"
    return [bool](netstat.exe -ano -p TCP | Select-String -Pattern $listenerPattern -Quiet)
}

# Prefer a PATH installation, but support Cloudflare's common Windows installer
# locations without modifying the user's machine-wide or per-user PATH.
$cloudflaredCommand = Get-Command cloudflared -CommandType Application -ErrorAction SilentlyContinue
if ($cloudflaredCommand) {
    $cloudflaredPath = $cloudflaredCommand.Source
}
else {
    $cloudflaredCandidates = @(
        "C:\Program Files (x86)\cloudflared\cloudflared.exe",
        "C:\Program Files\cloudflared\cloudflared.exe"
    )
    $cloudflaredPath = $cloudflaredCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}

if (-not $cloudflaredPath) {
    Stop-LauncherWithVisibleError "cloudflared was not found on PATH or in C:\Program Files (x86)\cloudflared\cloudflared.exe / C:\Program Files\cloudflared\cloudflared.exe. Install the official Cloudflare Tunnel client, then run this launcher again: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
}

Write-Host "Using cloudflared: $cloudflaredPath" -ForegroundColor DarkGray

if (Test-TcpPortListening -Port $Port) {
    Stop-LauncherWithVisibleError "Port $Port is already in use. Stop the existing Django development server, then run this launcher again."
}

$quickTunnelConfig = Join-Path $env:USERPROFILE ".cloudflared\config.yml"
if (Test-Path $quickTunnelConfig) {
    Stop-LauncherWithVisibleError "Quick Tunnels cannot run while $quickTunnelConfig exists. Use your named tunnel workflow or temporarily move that file yourself; this launcher will not modify it."
}

$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("securevote-mobile-" + [guid]::NewGuid())
$standardOutput = Join-Path $temporaryDirectory "cloudflared.out.log"
$standardError = Join-Path $temporaryDirectory "cloudflared.err.log"
$djangoOutput = Join-Path $temporaryDirectory "django.out.log"
$djangoError = Join-Path $temporaryDirectory "django.err.log"
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null

$tunnel = $null
$django = $null
$startupStage = "preflight checks"
$launchFailure = $null
$intentionalShutdown = $false
$cloudflaredOutputLines = 0
$cloudflaredErrorLines = 0
$djangoOutputLines = 0
$djangoErrorLines = 0

function Write-NewLogLines {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label,
        [Parameter(Mandatory)] [ref]$LineCount
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $lines = Get-Content -LiteralPath $Path
    if ($lines.Count -le $LineCount.Value) {
        return
    }

    $lines[$LineCount.Value..($lines.Count - 1)] | ForEach-Object {
        Write-Host "[$Label] $_"
    }
    $LineCount.Value = $lines.Count
}

function Get-ProcessExitDescription {
    param(
        [Parameter(Mandatory)] [System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)] [string]$Name
    )

    $Process.Refresh()
    if ($Process.HasExited) {
        return "$Name exited unexpectedly with exit code $($Process.ExitCode)."
    }
    return $null
}

try {
    $startupStage = "starting the Cloudflare Quick Tunnel"
    # The earlier diagnostic log showed this network drops QUIC/UDP traffic to
    # Cloudflare. HTTP/2 keeps the encrypted tunnel while using TCP instead.
    # This is a cloudflared command option; it does not alter .env or Windows.
    $tunnel = Start-Process -FilePath $cloudflaredPath `
        -ArgumentList @("tunnel", "--protocol", "http2", "--url", "http://127.0.0.1:$Port", "--loglevel", "info") `
        -RedirectStandardOutput $standardOutput -RedirectStandardError $standardError `
        -PassThru -WindowStyle Hidden

    $deadline = (Get-Date).AddSeconds(30)
    $publicUrl = $null
    while ((Get-Date) -lt $deadline -and -not $publicUrl) {
        Write-NewLogLines -Path $standardOutput -Label "cloudflared" -LineCount ([ref]$cloudflaredOutputLines)
        Write-NewLogLines -Path $standardError -Label "cloudflared" -LineCount ([ref]$cloudflaredErrorLines)
        $tunnelFailure = Get-ProcessExitDescription -Process $tunnel -Name "cloudflared"
        if ($tunnelFailure) { throw $tunnelFailure }
        $logText = @(
            foreach ($logFile in @($standardOutput, $standardError)) {
                if (Test-Path $logFile) {
                    Get-Content $logFile -Raw
                }
            }
        ) -join "`n"
        $match = [regex]::Match($logText, 'https://[a-z0-9-]+\.trycloudflare\.com', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($match.Success) {
            $publicUrl = $match.Value.TrimEnd('/')
            break
        }
        Start-Sleep -Milliseconds 500
    }

    if (-not $publicUrl) {
        throw "Timed out waiting for cloudflared to provide a Quick Tunnel URL."
    }

    $publicUri = [Uri]$publicUrl
    if ($publicUri.Scheme -ne "https" -or -not $publicUri.Host) {
        throw "cloudflared did not provide a valid HTTPS hostname."
    }

    # These are process-local overrides. settings.py loads .env using
    # setdefault(), so no persistent local secrets or localhost values change.
    $env:WEBAUTHN_RP_ID = $publicUri.Host
    $env:WEBAUTHN_ORIGIN = $publicUri.GetLeftPart([System.UriPartial]::Authority)
    $env:DJANGO_ALLOWED_HOSTS = "$($publicUri.Host),localhost,127.0.0.1"
    $env:DJANGO_CSRF_TRUSTED_ORIGINS = $env:WEBAUTHN_ORIGIN
    $env:DJANGO_TRUST_X_FORWARDED_PROTO = "true"
    $env:DJANGO_SECURE_COOKIES = "true"

    # A Quick Tunnel URL is not usable until cloudflared has established an
    # edge connection. Without this check Cloudflare returns Error 1033 even
    # though it has already allocated a trycloudflare.com hostname.
    $startupStage = "waiting for Cloudflare edge connectivity"
    $edgeReadyDeadline = (Get-Date).AddSeconds(45)
    $edgeConnected = $false
    while ((Get-Date) -lt $edgeReadyDeadline -and -not $edgeConnected) {
        Write-NewLogLines -Path $standardOutput -Label "cloudflared" -LineCount ([ref]$cloudflaredOutputLines)
        Write-NewLogLines -Path $standardError -Label "cloudflared" -LineCount ([ref]$cloudflaredErrorLines)
        $tunnelFailure = Get-ProcessExitDescription -Process $tunnel -Name "cloudflared"
        if ($tunnelFailure) { throw $tunnelFailure }

        $logText = @(
            foreach ($logFile in @($standardOutput, $standardError)) {
                if (Test-Path $logFile) { Get-Content $logFile -Raw }
            }
        ) -join "`n"
        if ($logText -match 'Registered tunnel connection') {
            $edgeConnected = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }

    if (-not $edgeConnected) {
        throw "cloudflared created a URL but did not establish a Cloudflare edge connection within 45 seconds. See the cloudflared diagnostics above."
    }

    Write-Host ""
    Write-Host "SecureVote mobile test mode is ready." -ForegroundColor Green
    Write-Host "Open this exact HTTPS URL on the phone: $($env:WEBAUTHN_ORIGIN)" -ForegroundColor Cyan
    Write-Host "RP ID: $($env:WEBAUTHN_RP_ID)"
    Write-Host ""
    Write-Warning "This temporary Quick Tunnel exposes this development server publicly. Use only approved test data and stop it immediately after testing."
    Write-Host "Starting Django on http://127.0.0.1:$Port/ ..."

    # Both services are child processes of this launcher.  --noreload avoids a
    # second Django child process, so the supervisor can reliably detect and
    # stop the exact server process that owns the loopback listener.
    $startupStage = "starting Django"
    $django = Start-Process -FilePath "python" `
        -ArgumentList @("manage.py", "runserver", "127.0.0.1:$Port", "--noreload") `
        -RedirectStandardOutput $djangoOutput -RedirectStandardError $djangoError `
        -PassThru -WindowStyle Hidden

    $startupStage = "waiting for Django to listen locally"
    $djangoReadyDeadline = (Get-Date).AddSeconds(30)
    $djangoReady = $false
    while ((Get-Date) -lt $djangoReadyDeadline -and -not $djangoReady) {
        $tunnelFailure = Get-ProcessExitDescription -Process $tunnel -Name "cloudflared"
        if ($tunnelFailure) { throw $tunnelFailure }
        $djangoFailure = Get-ProcessExitDescription -Process $django -Name "Django"
        if ($djangoFailure) { throw $djangoFailure }

        if (Test-TcpPortListening -Port $Port) {
            $djangoReady = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }

    if (-not $djangoReady) {
        throw "Django did not begin listening on 127.0.0.1:$Port within 30 seconds."
    }

    try {
        $localResponse = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/" -UseBasicParsing -TimeoutSec 10
        if ($localResponse.StatusCode -lt 200 -or $localResponse.StatusCode -ge 400) {
            throw "Django returned HTTP $($localResponse.StatusCode)."
        }
    }
    catch {
        throw "Django is listening but its local health request failed: $($_.Exception.Message)"
    }

    Write-Host "Django is listening and responded locally. Both services will remain supervised until Ctrl+C." -ForegroundColor Green
    Write-Host "Press Ctrl+C in this window to stop Django and close the tunnel."

    $startupStage = "supervising the live mobile-testing session"
    while ($true) {
        Write-NewLogLines -Path $standardOutput -Label "cloudflared" -LineCount ([ref]$cloudflaredOutputLines)
        Write-NewLogLines -Path $standardError -Label "cloudflared" -LineCount ([ref]$cloudflaredErrorLines)
        Write-NewLogLines -Path $djangoOutput -Label "django" -LineCount ([ref]$djangoOutputLines)
        Write-NewLogLines -Path $djangoError -Label "django" -LineCount ([ref]$djangoErrorLines)

        $tunnelFailure = Get-ProcessExitDescription -Process $tunnel -Name "cloudflared"
        if ($tunnelFailure) { throw $tunnelFailure }
        $djangoFailure = Get-ProcessExitDescription -Process $django -Name "Django"
        if ($djangoFailure) { throw $djangoFailure }
        Start-Sleep -Milliseconds 500
    }
}
catch {
    if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) {
        $intentionalShutdown = $true
    }
    else {
        $launchFailure = $_
        Write-Host ""
        Write-Host "SecureVote mobile-test launcher failed during: $startupStage" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-NewLogLines -Path $standardOutput -Label "cloudflared" -LineCount ([ref]$cloudflaredOutputLines)
        Write-NewLogLines -Path $standardError -Label "cloudflared" -LineCount ([ref]$cloudflaredErrorLines)
        Write-NewLogLines -Path $djangoOutput -Label "django" -LineCount ([ref]$djangoOutputLines)
        Write-NewLogLines -Path $djangoError -Label "django" -LineCount ([ref]$djangoErrorLines)
    }
}
finally {
    if ($django -and -not $django.HasExited) {
        Stop-Process -Id $django.Id -Force -ErrorAction SilentlyContinue
    }
    if ($tunnel -and -not $tunnel.HasExited) {
        Stop-Process -Id $tunnel.Id -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($launchFailure) {
    Write-Host ""
    Read-Host "Press Enter to close this launcher window"
    exit 1
}

if ($intentionalShutdown) {
    exit 0
}
