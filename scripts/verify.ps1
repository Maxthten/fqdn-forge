[CmdletBinding()]
param(
    [switch]$Stress,
    [ValidateRange(1, 1000)][int]$Repeat = 20
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Split-Path -Parent $scriptRoot)

function Invoke-CargoStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    Write-Host "==> $Name"
    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

function Invoke-ExpectedCargoFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$ExpectedOutput
    )

    Write-Host "==> $Name"
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $captured = & cargo @Arguments 2>&1 | Tee-Object -Variable commandOutput
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $captured | ForEach-Object { Write-Host $_ }
    if ($exitCode -eq 0) {
        throw "$Name unexpectedly succeeded"
    }
    if (($commandOutput | Out-String) -notmatch [regex]::Escape($ExpectedOutput)) {
        throw "$Name did not emit the expected explanation: $ExpectedOutput"
    }
}

function Invoke-GitRangeCheck {
    Write-Host '==> Git range check'
    & git diff --check
    if ($LASTEXITCODE -ne 0) {
        throw "git diff --check failed with exit code $LASTEXITCODE"
    }
    $trackedRequirements = @(git ls-files -- 'JNSEC_LAB_V1_3_REQUIREMENTS.md')
    if ($trackedRequirements.Count -ne 0) {
        throw 'the repository must not track JNSEC_LAB_V1_3_REQUIREMENTS.md'
    }
    & git check-ignore -q artifacts
    if ($LASTEXITCODE -ne 0) {
        throw 'artifacts/ must remain ignored'
    }
}

function Invoke-NetworkIsolationCheck {
    Write-Host '==> Network isolation static check'
    $forbidden = @(rg -n -g '*.rs' '(env::var|var_os|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|lookup_host|ToSocketAddrs|getaddrinfo)' crates)
    if ($LASTEXITCODE -gt 1) {
        throw "network isolation scan failed with exit code $LASTEXITCODE"
    }
    if ($forbidden.Count -ne 0) {
        $forbidden | ForEach-Object { Write-Host $_ }
        throw 'environment proxy access or DNS resolver usage is forbidden'
    }
}

Invoke-CargoStep 'format check' @('fmt', '--all', '--', '--check')
Invoke-CargoStep 'clippy' @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings')
Invoke-CargoStep 'workspace tests' @('test', '--workspace', '--all-targets')
Invoke-CargoStep 'scenario validation' @('run', '-p', 'lab-cli', '--', 'validate')
Invoke-CargoStep 'all scenario regression' @('run', '-p', 'lab-cli', '--', 'run', '--all')
foreach ($group in @('network', 'proxy', 'quota', 'transport')) {
    Invoke-CargoStep "V1.3 $group scenario group" @('run', '-p', 'lab-cli', '--', 'run', '--group', $group)
}
Invoke-CargoStep 'negative self-test' @('run', '-p', 'lab-cli', '--', 'self-test')

Invoke-CargoStep 'large dataset stress verification' @(
    'run', '-p', 'lab-cli', '--', 'run', '--scenario', '019-large-dataset', '--profile', 'stress'
)
if ($Stress) {
    Invoke-CargoStep 'V1.3 quota concurrency stress verification' @(
        'run', '-p', 'lab-cli', '--', 'conformance', '--scenario', '090-quota-concurrent-atomicity'
    )
}

foreach ($scenario in @(
    '061-network-direct-profile',
    '062-proxy-http-forward-success',
    '063-proxy-auth-and-redaction',
    '064-proxy-connect-lifecycle',
    '065-proxy-faults-and-timeouts',
    '066-proxy-egress-and-cross-run-denied',
    '079-deflate-success',
    '080-brotli-success',
    '081-deflate-corrupt-stream',
    '082-brotli-decoded-limit',
    '083-chunked-success',
    '084-chunked-truncated',
    '085-quota-per-source',
    '086-quota-per-key',
    '087-quota-global-run',
    '088-quota-recovery-http-date',
    '089-cache-observable-audit',
    '090-quota-concurrent-atomicity'
)) {
    Invoke-CargoStep "V1.3 black-box conformance: $scenario" @(
        'run', '-p', 'lab-cli', '--', 'conformance', '--scenario', $scenario
    )
}

$strictReport = Get-ChildItem -LiteralPath (Join-Path (Get-Location) 'artifacts\reports') -Filter '079-deflate-success-default-seed-*.json' | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1 -ExpandProperty FullName
if ([string]::IsNullOrEmpty($strictReport)) {
    throw 'strict replay source report was not created'
}
Invoke-CargoStep 'strict replay success' @(
    'run', '-p', 'lab-cli', '--', 'replay', '--strict', '--report', $strictReport
)
$differenceReport = Join-Path (Split-Path -Parent $strictReport) '079-deflate-success-intentional-difference.json'
$differencePayload = Get-Content -LiteralPath $strictReport -Raw | ConvertFrom-Json
$differencePayload.virtual_waited_ms = [long]$differencePayload.virtual_waited_ms + 1
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText(
    $differenceReport,
    ($differencePayload | ConvertTo-Json -Depth 100),
    $utf8NoBom
)
try {
    Invoke-ExpectedCargoFailure 'strict replay difference explanation' @(
        'run', '-p', 'lab-cli', '--', 'replay', '--strict', '--report', $differenceReport
    ) 'first semantic difference:'
}
finally {
    Remove-Item -LiteralPath $differenceReport -Force -ErrorAction SilentlyContinue
}

Invoke-CargoStep "repeat verification ($Repeat rounds)" @(
    'run', '-p', 'lab-cli', '--', 'repeat', '--count', $Repeat
)
Invoke-NetworkIsolationCheck
Invoke-GitRangeCheck

Write-Host 'Verification completed successfully. Reports are in artifacts/reports/.'
