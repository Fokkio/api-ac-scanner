$ErrorActionPreference = 'Stop'
$previousLocation = Get-Location
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("api-ac-scanner-run-test-" + [guid]::NewGuid().ToString('N'))

try {
    . (Join-Path $PSScriptRoot 'run.ps1')
    $legacyEnvironment = @"
ADMIN_USERNAME=admin
ADMIN_PASSWORD=replace-with-a-long-random-password
PUBLIC_BASE_URL=http://127.0.0.1:3000
SESSION_COOKIE_SECURE=false
SESSION_SECRET=keep-this-session-secret
SCANNER_INTERNAL_TOKEN=keep-this-scanner-token
"@
    $migratedEnvironment = Remove-DeprecatedEnvironmentSettings -Content $legacyEnvironment
    if ($migratedEnvironment -match '(?m)^(ADMIN_USERNAME|ADMIN_PASSWORD|PUBLIC_BASE_URL|SESSION_COOKIE_SECURE)=') {
        throw 'Deprecated login or deployment settings remain after migration.'
    }
    if ($migratedEnvironment -notmatch '(?m)^SESSION_SECRET=keep-this-session-secret\r?$') {
        throw 'SESSION_SECRET was not preserved.'
    }
    if ($migratedEnvironment -notmatch '(?m)^SCANNER_INTERNAL_TOKEN=keep-this-scanner-token\r?$') {
        throw 'SCANNER_INTERNAL_TOKEN was not preserved.'
    }

    New-Item -ItemType Directory -Path $testRoot | Out-Null
    [IO.File]::WriteAllText((Join-Path $testRoot '.env.example'), @"
ADMIN_USERNAME=admin
ADMIN_PASSWORD=obsolete-password
SESSION_SECRET=replace-with-at-least-32-random-characters
SCANNER_INTERNAL_TOKEN=replace-with-another-long-random-secret
"@)
    $ProjectRoot = $testRoot
    $result = Ensure-LocalEnvironment
    $generated = [IO.File]::ReadAllText((Join-Path $testRoot '.env'))
    if (-not $result.Success -or -not $result.Changed) {
        throw 'Ensure-LocalEnvironment did not create the test environment.'
    }
    if ($generated -match '(?m)^(ADMIN_USERNAME|ADMIN_PASSWORD)=' -or $generated -match 'replace-with-') {
        throw 'Generated environment contains deprecated settings or placeholders.'
    }
    $expectedActions = @('Setup', 'QuickStart', 'Build', 'Start', 'Rebuild', 'Stop', 'Status', 'Logs', 'Open', 'Demo', 'Exit', 'SelfTest', 'GenerateEnv')
    if ($ControlActionsByName.Count -ne $expectedActions.Count) {
        throw 'Launcher action registry contains missing or duplicate names.'
    }
    foreach ($expectedAction in $expectedActions) {
        if (-not $ControlActionsByName.ContainsKey($expectedAction)) {
            throw "Launcher action is missing: $expectedAction"
        }
    }
    $menuKeys = @($ControlActions | Where-Object { $null -ne $_.Key } | ForEach-Object { $_.Key })
    if (($menuKeys | Select-Object -Unique).Count -ne $menuKeys.Count) {
        throw 'Launcher action registry contains duplicate menu keys.'
    }
    if ($ControlActionsByName['QuickStart'].Key -ne '2' -or $ControlActionsByName['Build'].Key -ne $null) {
        throw 'Quick Start must own menu key 2 while Build remains available as a command action.'
    }
    Write-Output 'Launcher environment migration PASS'
} finally {
    Set-Location -LiteralPath $previousLocation
    if (Test-Path -LiteralPath $testRoot) {
        $resolvedTestRoot = (Resolve-Path -LiteralPath $testRoot).Path
        $resolvedTempRoot = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath())).Path.TrimEnd('\', '/')
        $resolvedParent = (Split-Path -Parent $resolvedTestRoot).TrimEnd('\', '/')
        if ($resolvedParent -ne $resolvedTempRoot -or (Split-Path -Leaf $resolvedTestRoot) -notlike 'api-ac-scanner-run-test-*') {
            throw "Refusing to remove unexpected test path: $resolvedTestRoot"
        }
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
}
