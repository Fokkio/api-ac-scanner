[CmdletBinding()]
param(
    [string]$Action = 'Menu'
)

$ErrorActionPreference = 'Stop'
$Version = '3.2'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ProjectRoot
. (Join-Path $PSScriptRoot 'run.environment.ps1')
. (Join-Path $PSScriptRoot 'run.actions.ps1')

try {
    $Host.UI.RawUI.WindowTitle = "API AC Scanner V$Version - Local Docker Control"
} catch {
    # Some non-interactive hosts do not expose a window title.
}

function Pause-Control {
    Write-Host ''
    [void](Read-Host 'Press Enter to return to the menu')
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

if ($Action -ne 'Menu') {
    if (-not $ControlActionsByName.ContainsKey($Action)) {
        throw "Unsupported action: $Action"
    }
    exit (Invoke-ControlAction -SelectedAction $Action)
}

while ($true) {
    Clear-Host
    Write-Host '============================================'
    Write-Host "     API Access-Control Scanner V$Version Local"
    Write-Host '============================================'
    Write-Host ''
    $ControlActions | Where-Object { $null -ne $_.Key } | ForEach-Object {
        Write-Host ("  {0}) {1}" -f $_.Key, $_.Label)
    }
    Write-Host ''

    $choice = Read-Host 'Select (0-9)'
    $normalizedChoice = if ([string]::IsNullOrWhiteSpace($choice)) { '' } else { $choice.Trim() }
    $selectedDefinition = $ControlActions | Where-Object { $_.Key -eq $normalizedChoice } | Select-Object -First 1
    $selectedAction = if ($null -eq $selectedDefinition) { 'Invalid' } else { $selectedDefinition.Name }

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
