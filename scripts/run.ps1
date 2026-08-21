[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Setup', 'Build', 'Start', 'Rebuild', 'Stop', 'Status', 'Logs', 'Open', 'Demo', 'GenerateEnv')]
    [string]$Action = 'Menu'
)

$ErrorActionPreference = 'Stop'
$Version = '3.1'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ProjectRoot

try {
    $Host.UI.RawUI.WindowTitle = "API AC Scanner V$Version - Local Docker Control"
} catch {
    # Some non-interactive hosts do not expose a window title.
}

function New-HexSecret {
    $bytes = New-Object byte[] 32
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    } finally {
        $generator.Dispose()
    }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Get-EnvValue {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $match = [regex]::Match($Content, "(?m)^$([regex]::Escape($Name))=(.*)$")
    if (-not $match.Success) {
        return $null
    }
    return $match.Groups[1].Value.Trim()
}

function Ensure-LocalEnvironment {
    $envPath = Join-Path $ProjectRoot '.env'
    $templatePath = Join-Path $ProjectRoot '.env.example'

    try {
        $created = -not (Test-Path -LiteralPath $envPath -PathType Leaf)
        if ($created -and -not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
            throw '.env.example was not found next to run.bat.'
        }

        $sourcePath = if ($created) { $templatePath } else { $envPath }
        $content = [IO.File]::ReadAllText($sourcePath)
        $original = $content

        $sessionSecret = New-HexSecret
        $adminPassword = New-HexSecret
        $scannerToken = New-HexSecret

        $content = $content.Replace('replace-with-at-least-32-random-characters', $sessionSecret)
        $content = $content.Replace('replace-with-a-long-random-password', $adminPassword)
        $content = $content.Replace('replace-with-another-long-random-secret', $scannerToken)
        $content = [regex]::Replace($content, '(?m)^SESSION_SECRET=\s*$', "SESSION_SECRET=$sessionSecret")
        $content = [regex]::Replace($content, '(?m)^ADMIN_USERNAME=\s*$', 'ADMIN_USERNAME=admin')
        $content = [regex]::Replace($content, '(?m)^ADMIN_PASSWORD=\s*$', "ADMIN_PASSWORD=$adminPassword")
        $content = [regex]::Replace($content, '(?m)^SCANNER_INTERNAL_TOKEN=\s*$', "SCANNER_INTERNAL_TOKEN=$scannerToken")

        if ($content.Contains('replace-with-')) {
            throw 'An unrecognized placeholder remains in .env.'
        }

        $username = Get-EnvValue -Content $content -Name 'ADMIN_USERNAME'
        $loginPassword = Get-EnvValue -Content $content -Name 'ADMIN_PASSWORD'
        $sessionValue = Get-EnvValue -Content $content -Name 'SESSION_SECRET'
        $scannerValue = Get-EnvValue -Content $content -Name 'SCANNER_INTERNAL_TOKEN'

        if ([string]::IsNullOrWhiteSpace($username)) {
            throw 'ADMIN_USERNAME is missing.'
        }
        if ([string]::IsNullOrWhiteSpace($loginPassword)) {
            throw 'ADMIN_PASSWORD is missing.'
        }
        if ($sessionValue.Length -lt 32) {
            throw 'SESSION_SECRET must contain at least 32 characters.'
        }
        if ($scannerValue.Length -lt 32) {
            throw 'SCANNER_INTERNAL_TOKEN must contain at least 32 characters.'
        }

        $changed = $created -or ($content -ne $original)
        if ($changed) {
            $temporaryPath = "$envPath.tmp-$PID"
            $utf8 = New-Object Text.UTF8Encoding($false)
            try {
                [IO.File]::WriteAllText($temporaryPath, $content, $utf8)
                Move-Item -LiteralPath $temporaryPath -Destination $envPath -Force
            } finally {
                if (Test-Path -LiteralPath $temporaryPath) {
                    Remove-Item -LiteralPath $temporaryPath -Force
                }
            }

            Write-Host ''
            Write-Host '[+] .env is ready with secure random secrets.' -ForegroundColor Green
            Write-Host "    Username: $username"
            Write-Host "    Password: $loginPassword"
            Write-Host ''
        }

        return [pscustomobject]@{
            Success = $true
            Changed = $changed
            Username = $username
            Password = $loginPassword
        }
    } catch {
        Write-Host "[!] Automatic .env setup failed: $($_.Exception.Message)" -ForegroundColor Red
        return [pscustomobject]@{
            Success = $false
            Changed = $false
            Username = $null
            Password = $null
        }
    }
}

function Test-DockerPreflight {
    if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot 'compose.yaml') -PathType Leaf)) {
        Write-Host '[!] compose.yaml was not found. Keep run.bat in the project root.' -ForegroundColor Red
        return $false
    }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host '[!] Docker was not found. Install or start Docker Desktop first.' -ForegroundColor Red
        return $false
    }

    & docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[!] Docker Desktop is not running or is not accessible.' -ForegroundColor Red
        return $false
    }

    & docker compose version *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[!] Docker Compose V2 is not available.' -ForegroundColor Red
        return $false
    }

    return $true
}

function Invoke-Compose {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & docker compose @Arguments | Out-Host
    return [int]$LASTEXITCODE
}

function Pause-Control {
    Write-Host ''
    [void](Read-Host 'Press Enter to return to the menu')
}

function Confirm-GeneratedCredentials {
    param($EnvironmentResult)

    if ($EnvironmentResult.Changed) {
        Write-Host '[!] Record the ADMIN password shown above.' -ForegroundColor Yellow
        Write-Host '[*] Choose Setup later if you need to view .env again.'
        Write-Host ''
        [void](Read-Host 'Press Enter to continue')
    }
}

function Invoke-ControlAction {
    param([Parameter(Mandatory = $true)][string]$SelectedAction)

    if ($SelectedAction -eq 'Open') {
        Start-Process 'http://127.0.0.1:3000'
        return 0
    }

    if ($SelectedAction -eq 'Setup' -or $SelectedAction -eq 'GenerateEnv') {
        $environmentResult = Ensure-LocalEnvironment
        if (-not $environmentResult.Success) {
            return 1
        }
        if ($SelectedAction -eq 'Setup') {
            Start-Process notepad.exe -ArgumentList (Join-Path $ProjectRoot '.env')
        }
        return 0
    }

    if (-not (Test-DockerPreflight)) {
        return 1
    }

    $environmentResult = Ensure-LocalEnvironment
    if (-not $environmentResult.Success) {
        return 1
    }
    Confirm-GeneratedCredentials -EnvironmentResult $environmentResult

    switch ($SelectedAction) {
        'Build' {
            Write-Host "[*] Building V$Version images..."
            $code = Invoke-Compose -Arguments @('build')
            if ($code -eq 0) {
                Write-Host '[+] Build completed.' -ForegroundColor Green
            } else {
                Write-Host '[!] Build failed. Review the error above.' -ForegroundColor Red
            }
            return $code
        }
        'Start' {
            Write-Host "[*] Starting V$Version local stack..."
            $code = Invoke-Compose -Arguments @('up', '-d')
            if ($code -eq 0) {
                Write-Host '[+] Started. Open http://127.0.0.1:3000' -ForegroundColor Green
            } else {
                Write-Host '[!] Start failed. Review the error above.' -ForegroundColor Red
            }
            return $code
        }
        'Rebuild' {
            Write-Host '[*] Rebuilding both services...'
            $code = Invoke-Compose -Arguments @('build')
            if ($code -ne 0) {
                Write-Host '[!] Rebuild failed. Existing containers were not recreated.' -ForegroundColor Red
                return $code
            }
            $code = Invoke-Compose -Arguments @('up', '-d', '--force-recreate')
            if ($code -eq 0) {
                Write-Host '[+] Rebuild and restart completed.' -ForegroundColor Green
            } else {
                Write-Host '[!] Images built, but container recreation failed.' -ForegroundColor Red
            }
            return $code
        }
        'Stop' {
            Write-Host "[*] Stopping V$Version stack..."
            $code = Invoke-Compose -Arguments @('--profile', 'demo', 'down', '--remove-orphans')
            if ($code -ne 0) {
                Write-Host '[!] Stop failed. Review the error above.' -ForegroundColor Red
                return $code
            }

            $remaining = & docker compose --profile demo ps -q 2>$null
            if ($LASTEXITCODE -ne 0) {
                Write-Host '[!] Containers were stopped, but the final status check failed.' -ForegroundColor Red
                return 1
            }
            if ($remaining) {
                Write-Host '[!] Compose still reports remaining containers.' -ForegroundColor Red
                return 1
            }

            Write-Host "[+] V$Version containers stopped and removed. Data files were preserved." -ForegroundColor Green
            return 0
        }
        'Status' {
            return Invoke-Compose -Arguments @('--profile', 'demo', 'ps')
        }
        'Logs' {
            return Invoke-Compose -Arguments @('--profile', 'demo', 'logs', '--no-color', '--tail', '50', 'web', 'scanner', 'demo-api', 'demo-db')
        }
        'Demo' {
            Write-Host '[!] Demo credentials and data are disposable and must never be reused outside this local profile.' -ForegroundColor Yellow
            Write-Host "[*] Starting V$Version with the database-backed Order Portal profile..."
            $code = Invoke-Compose -Arguments @('--profile', 'demo', 'up', '-d', '--build')
            if ($code -eq 0) {
                Write-Host '[+] Demo lab started. Portal: http://127.0.0.1:4100 / Scanner target: http://demo-api:4100' -ForegroundColor Green
            } else {
                Write-Host '[!] Demo lab startup failed. Review the error above.' -ForegroundColor Red
            }
            return $code
        }
        default {
            Write-Host "[!] Unsupported action: $SelectedAction" -ForegroundColor Red
            return 1
        }
    }
}

if ($Action -ne 'Menu') {
    exit (Invoke-ControlAction -SelectedAction $Action)
}

while ($true) {
    Clear-Host
    Write-Host '============================================'
    Write-Host "     API Access-Control Scanner V$Version Local"
    Write-Host '============================================'
    Write-Host ''
    Write-Host '  1) Setup    - create, repair, or edit .env'
    Write-Host '  2) Build    - auto-setup on first run, then build images'
    Write-Host '  3) Start    - start the complete stack'
    Write-Host '  4) Rebuild  - rebuild both services and restart'
    Write-Host "  5) Stop     - stop and remove V$Version containers"
    Write-Host '  6) Status   - show container health'
    Write-Host '  7) Logs     - show recent web and scanner logs'
    Write-Host '  8) Open     - open http://127.0.0.1:3000'
    Write-Host '  9) Demo Lab - start the disposable multi-role Order Portal'
    Write-Host '  0) Exit'
    Write-Host ''

    $choice = Read-Host 'Select (0-9)'
    if ([string]::IsNullOrWhiteSpace($choice)) {
        $selectedAction = 'Invalid'
    } else {
        $selectedAction = switch ($choice.Trim()) {
            '1' { 'Setup' }
            '2' { 'Build' }
            '3' { 'Start' }
            '4' { 'Rebuild' }
            '5' { 'Stop' }
            '6' { 'Status' }
            '7' { 'Logs' }
            '8' { 'Open' }
            '9' { 'Demo' }
            '0' { 'Exit' }
            default { 'Invalid' }
        }
    }

    if ($selectedAction -eq 'Exit') {
        exit 0
    }
    if ($selectedAction -eq 'Invalid') {
        Write-Host '[!] Select a number from 0 to 9.' -ForegroundColor Yellow
        Pause-Control
        continue
    }

    [void](Invoke-ControlAction -SelectedAction $selectedAction)
    Pause-Control
}
