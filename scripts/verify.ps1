[CmdletBinding()]
param(
    [switch]$Stress,
    [ValidateRange(20, 1000)][int]$Repeat = 20
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
    $trackedRequirements = @(git ls-files -- 'JNSEC_LAB*_REQUIREMENTS.md' 'olds/**')
    if ($trackedRequirements.Count -ne 0) {
        throw 'the repository must not track root requirements documents or olds/'
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

Invoke-CargoStep 'V1.4 combination scenario group' @(
    'run', '-p', 'lab-cli', '--', 'run', '--group', 'combination'
)
Invoke-CargoStep 'V1.4 lifecycle scenario group' @(
    'run', '-p', 'lab-cli', '--', 'run', '--group', 'lifecycle'
)

foreach ($scenario in @(
    '091-pagination-second-page-rate-limit',
    '092-rate-limit-retry-deflate-success',
    '093-quota-recovery-brotli-success',
    '094-proxy-auth-then-source-rate-limit',
    '095-proxy-reset-then-retry-success',
    '096-connect-tunnel-truncated-payload',
    '097-source-503-then-chunked-success',
    '098-chunked-content-length-conflict',
    '099-multi-source-global-quota-isolation',
    '100-cancel-during-quota-recovery',
    '101-proxy-target-canonicalization',
    '102-proxy-authority-header-ambiguity',
    '103-proxy-encoded-and-userinfo-targets',
    '104-proxy-framing-and-header-limits',
    '105-stale-capability-after-reset-delete',
    '106-concurrent-cross-run-lifecycle',
    '107-json-structural-mutation-campaign',
    '108-text-html-csv-mutation-campaign',
    '109-pagination-token-mutation-campaign',
    '110-transport-framing-mutation-campaign',
    '111-mixed-lifecycle-soak',
    '112-concurrent-mixed-fault-soak',
    '113-replay-provenance-and-multi-diff',
    '114-coverage-and-baseline-integrity'
)) {
    Invoke-CargoStep "V1.4 black-box conformance: $scenario" @(
        'run', '-p', 'lab-cli', '--', 'conformance', '--scenario', $scenario
    )
}

Invoke-CargoStep 'proxy canonicalization, authority and framing regression' @(
    'run', '-p', 'lab-cli', '--', 'proxy-regression'
)

foreach ($campaign in @(
    @{ Id = '107-json-structural-mutation-campaign'; Seed = 10701 },
    @{ Id = '108-text-html-csv-mutation-campaign'; Seed = 10801 },
    @{ Id = '109-pagination-token-mutation-campaign'; Seed = 10901 },
    @{ Id = '110-transport-framing-mutation-campaign'; Seed = 11001 }
)) {
    $campaignReport = Join-Path (Get-Location) ("artifacts\campaigns\{0}-seed-{1}.json" -f $campaign.Id, $campaign.Seed)
    Invoke-CargoStep "campaign run: $($campaign.Id)" @(
        'run', '-p', 'lab-cli', '--', 'campaign', 'run', '--campaign', $campaign.Id, '--seed', $campaign.Seed
    )
    Invoke-CargoStep "campaign replay: $($campaign.Id)" @(
        'run', '-p', 'lab-cli', '--', 'campaign', 'replay', '--report', $campaignReport
    )
}

Invoke-CargoStep 'coverage matrix JSON' @(
    'run', '-p', 'lab-cli', '--', 'coverage', '--format', 'json', '--output', 'artifacts/coverage.json'
)
Invoke-CargoStep 'coverage matrix Markdown' @(
    'run', '-p', 'lab-cli', '--', 'coverage', '--format', 'markdown', '--output', 'artifacts/coverage.md'
)
Invoke-CargoStep 'coverage completeness check' @('run', '-p', 'lab-cli', '--', 'coverage', '--check')

Invoke-CargoStep 'V1.4 logical baseline generation' @(
    'run', '-p', 'lab-cli', '--', 'baseline', 'generate', '--profile', 'v1.4-core'
)
Invoke-CargoStep 'V1.4 logical baseline comparison' @(
    'run', '-p', 'lab-cli', '--', 'baseline', 'check'
)

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

$v14StrictReport = Get-ChildItem -LiteralPath (Join-Path (Get-Location) 'artifacts\reports') -Filter '091-pagination-second-page-rate-limit-default-seed-*.json' | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1 -ExpandProperty FullName
if ([string]::IsNullOrEmpty($v14StrictReport)) {
    throw 'V1.4 strict replay source report was not created'
}
Invoke-CargoStep 'V1.4 strict replay success' @(
    'run', '-p', 'lab-cli', '--', 'replay', '--strict', '--report', $v14StrictReport
)
$provenanceDifferenceReport = Join-Path (Split-Path -Parent $v14StrictReport) '091-provenance-intentional-difference.json'
$provenancePayload = Get-Content -LiteralPath $v14StrictReport -Raw | ConvertFrom-Json
$provenancePayload.provenance.scenario_revision_digest = ('0' * 64)
[System.IO.File]::WriteAllText(
    $provenanceDifferenceReport,
    ($provenancePayload | ConvertTo-Json -Depth 100),
    $utf8NoBom
)
try {
    Invoke-ExpectedCargoFailure 'strict replay provenance explanation' @(
        'run', '-p', 'lab-cli', '--', 'replay', '--strict', '--report', $provenanceDifferenceReport
    ) 'provenance: scenario_revision_changed'
}
finally {
    Remove-Item -LiteralPath $provenanceDifferenceReport -Force -ErrorAction SilentlyContinue
}
$multiDifferenceReport = Join-Path (Split-Path -Parent $v14StrictReport) '091-multi-field-intentional-difference.json'
$multiPayload = Get-Content -LiteralPath $v14StrictReport -Raw | ConvertFrom-Json
$multiPayload.virtual_waited_ms = [long]$multiPayload.virtual_waited_ms + 1
$multiPayload.metrics.request_count = [long]$multiPayload.metrics.request_count + 1
[System.IO.File]::WriteAllText(
    $multiDifferenceReport,
    ($multiPayload | ConvertTo-Json -Depth 100),
    $utf8NoBom
)
try {
    Invoke-ExpectedCargoFailure 'strict replay multi-difference explanation' @(
        'run', '-p', 'lab-cli', '--', 'replay', '--strict', '--report', $multiDifferenceReport
    ) 'differences: '
}
finally {
    Remove-Item -LiteralPath $multiDifferenceReport -Force -ErrorAction SilentlyContinue
}

Invoke-CargoStep 'release lifecycle soak (1,000 operations, 8 concurrency)' @(
    'run', '-p', 'lab-cli', '--', 'soak', 'run', '--preset', 'release', '--seed', '11100'
)
Invoke-CargoStep "repeat verification ($Repeat rounds)" @(
    'run', '-p', 'lab-cli', '--', 'repeat', '--count', $Repeat
)
Invoke-NetworkIsolationCheck
Invoke-GitRangeCheck

Write-Host 'Verification completed successfully. Reports are in artifacts/reports/.'
