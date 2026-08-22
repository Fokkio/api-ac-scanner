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

function Remove-DeprecatedEnvironmentSettings {
    param([Parameter(Mandatory = $true)][string]$Content)

    $deprecatedNames = @('ADMIN_USERNAME', 'ADMIN_PASSWORD', 'PUBLIC_BASE_URL', 'SESSION_COOKIE_SECURE')
    foreach ($name in $deprecatedNames) {
        $Content = [regex]::Replace($Content, "(?m)^$([regex]::Escape($name))=.*(?:\r?\n|$)", '')
    }
    return $Content
}

function New-PreparedEnvironmentContent {
    param([Parameter(Mandatory = $true)][string]$Content)

    $sessionSecret = New-HexSecret
    $scannerToken = New-HexSecret
    $Content = Remove-DeprecatedEnvironmentSettings -Content $Content
    $Content = $Content.Replace('replace-with-at-least-32-random-characters', $sessionSecret)
    $Content = $Content.Replace('replace-with-another-long-random-secret', $scannerToken)
    $Content = [regex]::Replace($Content, '(?m)^SESSION_SECRET=\s*$', "SESSION_SECRET=$sessionSecret")
    $Content = [regex]::Replace($Content, '(?m)^SCANNER_INTERNAL_TOKEN=\s*$', "SCANNER_INTERNAL_TOKEN=$scannerToken")
    if ($Content.Contains('replace-with-')) {
        throw 'An unrecognized placeholder remains in .env.'
    }
    if ((Get-EnvValue -Content $Content -Name 'SESSION_SECRET').Length -lt 32) {
        throw 'SESSION_SECRET must contain at least 32 characters.'
    }
    if ((Get-EnvValue -Content $Content -Name 'SCANNER_INTERNAL_TOKEN').Length -lt 32) {
        throw 'SCANNER_INTERNAL_TOKEN must contain at least 32 characters.'
    }
    return $Content
}

function Write-EnvironmentFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $temporaryPath = "$Path.tmp-$PID"
    try {
        [IO.File]::WriteAllText($temporaryPath, $Content, (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Ensure-LocalEnvironment {
    try {
        $envPath = Join-Path $ProjectRoot '.env'
        $templatePath = Join-Path $ProjectRoot '.env.example'
        $created = -not (Test-Path -LiteralPath $envPath -PathType Leaf)
        if ($created -and -not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
            throw '.env.example was not found next to run.bat.'
        }
        $sourcePath = if ($created) { $templatePath } else { $envPath }
        $original = [IO.File]::ReadAllText($sourcePath)
        $content = New-PreparedEnvironmentContent -Content $original
        $changed = $created -or ($content -ne $original)
        if ($changed) {
            Write-EnvironmentFile -Path $envPath -Content $content
            Write-Host "`n[+] .env is ready with secure random secrets.`n" -ForegroundColor Green
        }
        return [pscustomobject]@{ Success = $true; Changed = $changed }
    } catch {
        Write-Host "[!] Automatic .env setup failed: $($_.Exception.Message)" -ForegroundColor Red
        return [pscustomobject]@{ Success = $false; Changed = $false }
    }
}
