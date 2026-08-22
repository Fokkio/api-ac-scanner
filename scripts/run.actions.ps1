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

function Invoke-BuildAction {
    Write-Host "[*] Building V$Version images..."
    $code = Invoke-Compose -Arguments @('build')
    if ($code -eq 0) {
        Write-Host '[+] Build completed.' -ForegroundColor Green
    } else {
        Write-Host '[!] Build failed. Review the error above.' -ForegroundColor Red
    }
    return $code
}

function Invoke-StartAction {
    Write-Host "[*] Starting V$Version local stack..."
    $code = Invoke-Compose -Arguments @('up', '-d')
    if ($code -eq 0) {
        Write-Host '[+] Started. Open http://127.0.0.1:3000' -ForegroundColor Green
    } else {
        Write-Host '[!] Start failed. Review the error above.' -ForegroundColor Red
    }
    return $code
}

function Invoke-RebuildAction {
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

function Invoke-StopAction {
    Write-Host "[*] Stopping V$Version stack..."
    $code = Invoke-Compose -Arguments @('--profile', 'demo', 'down', '--remove-orphans')
    if ($code -ne 0) {
        Write-Host '[!] Stop failed. Review the error above.' -ForegroundColor Red
        return $code
    }
    $remaining = & docker compose --profile demo ps -q 2>$null
    if ($LASTEXITCODE -ne 0 -or $remaining) {
        Write-Host '[!] Final container status check failed.' -ForegroundColor Red
        return 1
    }
    Write-Host "[+] V$Version containers stopped and removed. Data files were preserved." -ForegroundColor Green
    return 0
}

function Invoke-DemoAction {
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

function Invoke-EnvironmentAction {
    param([Parameter(Mandatory = $true)][string]$SelectedAction)
    $environmentResult = Ensure-LocalEnvironment
    if (-not $environmentResult.Success) { return 1 }
    if ($SelectedAction -eq 'Setup') {
        Start-Process notepad.exe -ArgumentList (Join-Path $ProjectRoot '.env')
    }
    return 0
}

function Invoke-ControlAction {
    param([Parameter(Mandatory = $true)][string]$SelectedAction)
    $definition = $ControlActionsByName[$SelectedAction]
    if ($null -eq $definition) {
        Write-Host "[!] Unsupported action: $SelectedAction" -ForegroundColor Red
        return 1
    }
    if ($definition.RequiresDocker) {
        if (-not (Test-DockerPreflight)) { return 1 }
        if (-not (Ensure-LocalEnvironment).Success) { return 1 }
    }
    return & $definition.Handler $SelectedAction
}
$ControlActions = @(
    [pscustomobject]@{ Name = 'Setup'; Key = '1'; Label = 'Setup    - create, repair, or edit .env'; RequiresDocker = $false; Handler = { param($name) Invoke-EnvironmentAction -SelectedAction $name } }
    [pscustomobject]@{ Name = 'Build'; Key = '2'; Label = 'Build    - auto-setup on first run, then build images'; RequiresDocker = $true; Handler = { Invoke-BuildAction } }
    [pscustomobject]@{ Name = 'Start'; Key = '3'; Label = 'Start    - start the complete stack'; RequiresDocker = $true; Handler = { Invoke-StartAction } }
    [pscustomobject]@{ Name = 'Rebuild'; Key = '4'; Label = 'Rebuild  - rebuild both services and restart'; RequiresDocker = $true; Handler = { Invoke-RebuildAction } }
    [pscustomobject]@{ Name = 'Stop'; Key = '5'; Label = "Stop     - stop and remove V$Version containers"; RequiresDocker = $true; Handler = { Invoke-StopAction } }
    [pscustomobject]@{ Name = 'Status'; Key = '6'; Label = 'Status   - show container health'; RequiresDocker = $true; Handler = { Invoke-Compose -Arguments @('--profile', 'demo', 'ps') } }
    [pscustomobject]@{ Name = 'Logs'; Key = '7'; Label = 'Logs     - show recent web and scanner logs'; RequiresDocker = $true; Handler = { Invoke-Compose -Arguments @('--profile', 'demo', 'logs', '--no-color', '--tail', '50', 'web', 'scanner', 'demo-api', 'demo-db') } }
    [pscustomobject]@{ Name = 'Open'; Key = '8'; Label = 'Open     - open http://127.0.0.1:3000'; RequiresDocker = $false; Handler = { Start-Process 'http://127.0.0.1:3000'; return 0 } }
    [pscustomobject]@{ Name = 'Demo'; Key = '9'; Label = 'Demo Lab - start the disposable multi-role Order Portal'; RequiresDocker = $true; Handler = { Invoke-DemoAction } }
    [pscustomobject]@{ Name = 'Exit'; Key = '0'; Label = 'Exit'; RequiresDocker = $false; Handler = { return 0 } }
    [pscustomobject]@{ Name = 'GenerateEnv'; Key = $null; Label = $null; RequiresDocker = $false; Handler = { param($name) Invoke-EnvironmentAction -SelectedAction $name } }
)
$ControlActionsByName = @{}
foreach ($definition in $ControlActions) {
    $ControlActionsByName[$definition.Name] = $definition
}
