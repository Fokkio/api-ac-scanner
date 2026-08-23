[CmdletBinding()]
param(
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$previousLocation = Get-Location
$succeeded = $false
$failure = $null
$cleanupExitCode = 0

. (Join-Path $PSScriptRoot 'run.environment.ps1')

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    Write-Host "[*] $Label"
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Get-ComposeServiceId {
    param([Parameter(Mandatory = $true)][string]$Service)

    $containerId = ([string](& docker compose --profile demo ps -q $Service)).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
        throw "Compose service is missing: $Service"
    }
    return $containerId
}

try {
    Set-Location -LiteralPath $ProjectRoot
    $environmentResult = Ensure-LocalEnvironment
    if (-not $environmentResult.Success) {
        throw 'Could not prepare the local .env file.'
    }

    Invoke-CheckedCommand -Label 'Docker preflight' -Command { docker info --format '{{.ServerVersion}}' }
    Invoke-CheckedCommand -Label 'Compose configuration validation' -Command { docker compose --profile demo config --quiet }
    Invoke-CheckedCommand -Label 'Compose build, start and health wait' -Command {
        docker compose --profile demo up -d --build --wait --wait-timeout 240
    }

    $serviceIds = @{}
    foreach ($service in @('scanner', 'web', 'demo-db', 'demo-api')) {
        $containerId = Get-ComposeServiceId -Service $service
        $state = (& docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' $containerId).Trim()
        if ($LASTEXITCODE -ne 0 -or $state -ne 'running|healthy') {
            throw "Service $service is not running and healthy: $state"
        }
        $serviceIds[$service] = $containerId
    }

    $webBindings = (& docker inspect --format '{{json .HostConfig.PortBindings}}' $serviceIds['web']) | ConvertFrom-Json
    $webPort = $webBindings.'3000/tcp'
    if ($null -eq $webPort -or $webPort.Count -ne 1 -or $webPort[0].HostIp -ne '127.0.0.1' -or $webPort[0].HostPort -ne '3000') {
        throw 'Web must publish exactly 127.0.0.1:3000.'
    }
    $demoBindings = (& docker inspect --format '{{json .HostConfig.PortBindings}}' $serviceIds['demo-api']) | ConvertFrom-Json
    $demoPort = $demoBindings.'4100/tcp'
    if ($null -eq $demoPort -or $demoPort.Count -ne 1 -or $demoPort[0].HostIp -ne '127.0.0.1' -or $demoPort[0].HostPort -ne '4100') {
        throw 'Demo API must publish exactly 127.0.0.1:4100.'
    }
    $scannerBindings = ([string](& docker inspect --format '{{json .HostConfig.PortBindings}}' $serviceIds['scanner'])).Trim()
    if ($scannerBindings -notin @('', 'null', '{}')) {
        throw "Scanner port must remain internal, but Docker reported bindings: $scannerBindings"
    }

    $homeResponse = Invoke-WebRequest -Uri 'http://127.0.0.1:3000/' -UseBasicParsing -TimeoutSec 15
    if ($homeResponse.StatusCode -ne 200 -or $homeResponse.Content -notmatch 'lang="th"') {
        throw 'Web home page did not return the expected Thai HTTP 200 document.'
    }
    $health = Invoke-RestMethod -Uri 'http://127.0.0.1:3000/health' -TimeoutSec 15
    if ($health.status -ne 'ok') {
        throw 'Web health endpoint did not return status=ok.'
    }
    $portal = Invoke-WebRequest -Uri 'http://127.0.0.1:4100/' -UseBasicParsing -TimeoutSec 15
    if ($portal.StatusCode -ne 200) {
        throw 'Demo portal did not return HTTP 200.'
    }
    try {
        Invoke-WebRequest -Uri 'http://127.0.0.1:3000/login' -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop | Out-Null
        throw 'Removed login route unexpectedly returned a successful response.'
    } catch {
        $statusCode = [int]$_.Exception.Response.StatusCode
        if ($statusCode -ne 404) {
            throw
        }
    }

    $npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($null -eq $npmCommand) {
        $npmCommand = Get-Command npm -ErrorAction Stop
    }
    $fixtureRoot = Join-Path (Join-Path $ProjectRoot 'fixtures') 'order-portal'
    Invoke-CheckedCommand -Label 'Demo API dependency install' -Command {
        & $npmCommand.Source --prefix $fixtureRoot ci --ignore-scripts
    }
    Invoke-CheckedCommand -Label 'Demo API contract tests' -Command {
        & $npmCommand.Source --prefix $fixtureRoot run test:contract
    }

    $succeeded = $true
    Write-Output 'COMPOSE_SMOKE_PASS services=4 web=200 portal=200 login=404 demo_contract=9/9'
} catch {
    $failure = $_
} finally {
    $cleanupErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    if (-not $succeeded) {
        & docker compose --profile demo ps | Out-Host
        & docker compose --profile demo logs --no-color --tail 100 | Out-Host
    }
    if (-not $KeepRunning) {
        & docker compose --profile demo down --remove-orphans | Out-Host
        $cleanupExitCode = [int]$LASTEXITCODE
    }
    $ErrorActionPreference = $cleanupErrorPreference
    Set-Location -LiteralPath $previousLocation
}

if ($null -ne $failure) {
    throw $failure
}
if ($cleanupExitCode -ne 0) {
    throw "Compose smoke checks passed, but cleanup failed with exit code $cleanupExitCode"
}
