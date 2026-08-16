[CmdletBinding()]
param(
    [ValidateRange(20, 1000)][int]$Repeat = 20
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Split-Path -Parent $scriptRoot)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

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

function Invoke-CoveragePolicyNegativeChecks {
    $coveragePolicyPath = Join-Path (Get-Location) 'coverage-policy.yaml'
    $originalPolicy = [System.IO.File]::ReadAllText($coveragePolicyPath)
    try {
        $missingCombinationPolicy = $originalPolicy -replace '(?m)^  - campaign\+transport\r?\n', ''
        if ($missingCombinationPolicy -eq $originalPolicy) {
            throw 'could not construct a coverage policy with a missing required combination'
        }
        [System.IO.File]::WriteAllText($coveragePolicyPath, $missingCombinationPolicy, $utf8NoBom)
        Invoke-ExpectedCargoFailure 'coverage policy missing combination gate' @(
            'run', '-p', 'lab-cli', '--', 'coverage', '--check'
        ) 'coverage policy is missing required combination campaign+transport'

        $expiredExceptionPolicy = $originalPolicy -replace '(?m)^exceptions: \[\]\r?$', @'
exceptions:
  - id: verification-expired-exception
    rule: verification-temporary-uncovered-combination
    dimension: execution_style
    value: verification-temporary
    reason: temporary release verification negative test
    created_on: 2026-01-01
    expires_on: 2026-01-01
    reference: verification-only
    replacement: remove this temporary exception
    security_relevant: false
'@
        if ($expiredExceptionPolicy -eq $originalPolicy) {
            throw 'could not construct a coverage policy with an expired exception'
        }
        [System.IO.File]::WriteAllText($coveragePolicyPath, $expiredExceptionPolicy, $utf8NoBom)
        Invoke-ExpectedCargoFailure 'coverage policy expired exception gate' @(
            'run', '-p', 'lab-cli', '--', 'coverage', '--check'
        ) 'coverage exception verification-expired-exception is expired'
    }
    finally {
        [System.IO.File]::WriteAllText($coveragePolicyPath, $originalPolicy, $utf8NoBom)
    }
}

function Get-ReleaseSoakFailures {
    param(
        [Parameter(Mandatory = $true)]$Report
    )

    $failures = [System.Collections.Generic.List[string]]::new()
    $requiredScenarios = @(
        '091-pagination-second-page-rate-limit',
        '094-proxy-auth-then-source-rate-limit',
        '096-connect-tunnel-truncated-payload',
        '099-multi-source-global-quota-isolation',
        '101-proxy-target-canonicalization',
        '105-stale-capability-after-reset-delete',
        '106-concurrent-cross-run-lifecycle',
        '107-json-structural-mutation-campaign',
        '111-mixed-lifecycle-soak',
        '112-concurrent-mixed-fault-soak'
    )
    $requiredEndpoints = @(
        'control', 'manifest', 'source', 'proxy', 'connect',
        'submission', 'report', 'replay', 'stale_probe'
    )
    $evidenceEndpoints = @('source', 'proxy', 'connect', 'submission', 'report')
    $requiredTrace = @(
        'valid_submission', 'invalid_submission', 'expected_rejection',
        'strict_replay_matched', 'strict_replay_mismatch', 'script_fault',
        'campaign_or_dynamic_fixture', 'reset_stale_rejection',
        'delete_stale_rejection', 'multiple_lanes'
    )

    if ([long]$Report.operations -lt 1000) {
        $failures.Add('release soak performed fewer than 1,000 public actions')
    }
    if ([long]$Report.concurrency -lt 8) {
        $failures.Add('release soak used fewer than 8 lanes')
    }
    if ([string]::IsNullOrWhiteSpace([string]$Report.reproduction_command)) {
        $failures.Add('release soak report is missing a reproduction command')
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Report.last_failure)) {
        $failures.Add("release soak reported a failure: $($Report.last_failure)")
    }

    foreach ($scenario in $requiredScenarios) {
        if (@($Report.scenario_pool) -notcontains $scenario) {
            $failures.Add("release soak scenario pool is missing $scenario")
        }
    }
    foreach ($endpoint in $requiredEndpoints) {
        if (@($Report.action_trace | Where-Object { $_.endpoint -eq $endpoint }).Count -eq 0) {
            $failures.Add("release soak trace is missing endpoint category $endpoint")
        }
    }
    foreach ($endpoint in $evidenceEndpoints) {
        if (@($Report.action_trace | Where-Object {
                $_.endpoint -eq $endpoint -and [long]$_.audit_count -le 0
            }).Count -ne 0) {
            $failures.Add("release soak $endpoint actions are missing audit evidence")
        }
    }
    foreach ($traceName in $requiredTrace) {
        if ($Report.trace_coverage.$traceName -ne $true) {
            $failures.Add("release soak trace coverage is missing $traceName")
        }
    }
    if (@($Report.action_trace | Where-Object { $_.endpoint -eq 'internal-test-helper' }).Count -ne 0) {
        $failures.Add('release soak trace contains internal-test-helper')
    }
    if (@($Report.action_trace | Where-Object {
            [string]::IsNullOrWhiteSpace([string]$_.run_id) -or
            $_.run_id -notmatch '^[0-9a-f]{8}$'
        }).Count -ne 0) {
        $failures.Add('release soak trace contains a missing or unredacted run identifier')
    }
    if (@($Report.action_trace | Where-Object {
            $_.operation -eq 'submission_valid' -and $_.outcome -eq 'success'
        }).Count -eq 0) {
        $failures.Add('release soak is missing a successful public submission')
    }
    if (@($Report.action_trace | Where-Object {
            $_.operation -eq 'submission_invalid' -and $_.outcome -eq 'expected_rejected'
        }).Count -eq 0) {
        $failures.Add('release soak is missing a rejected public submission')
    }
    $resetStaleActions = @($Report.action_trace | Where-Object {
        $_.operation -eq 'stale_after_reset_source'
    })
    if ($resetStaleActions.Count -eq 0 -or @($resetStaleActions | Where-Object {
            $_.outcome -ne 'expected_rejected'
        }).Count -ne 0) {
        $failures.Add('release soak is missing the reset stale-capability rejection')
    }
    $deleteStaleActions = @($Report.action_trace | Where-Object {
        $_.operation -eq 'stale_after_delete'
    })
    if ($deleteStaleActions.Count -eq 0 -or @($deleteStaleActions | Where-Object {
            $_.outcome -ne 'expected_rejected'
        }).Count -ne 0) {
        $failures.Add('release soak is missing the delete stale-capability rejection')
    }

    foreach ($property in $Report.invariants.psobject.Properties) {
        if ($property.Value -ne $true) {
            $failures.Add("release soak invariant failed: $($property.Name)")
        }
    }
    foreach ($resourceName in @('active_runs', 'reset_runs', 'active_proxy_connections', 'quota_state_entries', 'audit_records', 'report_count', 'fixture_bytes')) {
        if ([long]$Report.resources.$resourceName -ne 0) {
            $failures.Add("release soak left resource $resourceName=$($Report.resources.$resourceName)")
        }
    }
    $temporaryReplayArtifacts = @(Get-ChildItem -LiteralPath 'artifacts\soak\replay' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'public-soak-replay-*' })
    if ($temporaryReplayArtifacts.Count -ne 0) {
        $failures.Add('release soak left temporary strict-replay artifacts')
    }
    return $failures.ToArray()
}

function Assert-ReleaseSoakReport {
    param(
        [Parameter(Mandatory = $true)]$Report
    )

    $failures = @(Get-ReleaseSoakFailures $Report)
    if ($failures.Count -ne 0) {
        throw ('release soak report failed machine-readable validation:' + [Environment]::NewLine + ($failures -join [Environment]::NewLine))
    }
}

function Invoke-ReleaseSoakNegativeChecks {
    param(
        [Parameter(Mandatory = $true)]$Report
    )

    $cases = @(
        @{ Name = 'internal helper trace'; Mutate = {
                param($copy)
                $copy.action_trace[0].endpoint = 'internal-test-helper'
            }
        },
        @{ Name = 'missing source trace'; Mutate = {
                param($copy)
                $copy.action_trace = @($copy.action_trace | Where-Object { $_.endpoint -ne 'source' })
            }
        },
        @{ Name = 'stale capability reaches source'; Mutate = {
                param($copy)
                ($copy.action_trace | Where-Object { $_.operation -eq 'stale_after_reset_source' } | Select-Object -First 1).outcome = 'success'
            }
        },
        @{ Name = 'cross-run submission marker'; Mutate = {
                param($copy)
                ($copy.action_trace | Where-Object { $_.operation -eq 'submission_valid' } | Select-Object -First 1).run_id = 'crossrun'
            }
        },
        @{ Name = 'resource residue'; Mutate = {
                param($copy)
                $copy.resources.active_proxy_connections = 1
            }
        },
        @{ Name = 'missing strict replay provenance'; Mutate = {
                param($copy)
                $copy.trace_coverage.strict_replay_matched = $false
            }
        }
    )
    foreach ($case in $cases) {
        $copy = $Report | ConvertTo-Json -Depth 100 | ConvertFrom-Json
        & $case.Mutate $copy
        if (@(Get-ReleaseSoakFailures $copy).Count -eq 0) {
            throw "release soak negative check unexpectedly passed: $($case.Name)"
        }
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

 $campaignArtifacts = @()
foreach ($campaign in @(
    @{ Id = '107-json-structural-mutation-campaign'; Seeds = @(10701, 10702) },
    @{ Id = '108-text-html-csv-mutation-campaign'; Seeds = @(10801, 10802) },
    @{ Id = '109-pagination-token-mutation-campaign'; Seeds = @(10901, 10902) },
    @{ Id = '110-transport-framing-mutation-campaign'; Seeds = @(11001, 11002) }
)) {
    $campaignReports = @()
    foreach ($seed in $campaign.Seeds) {
        $campaignReport = Join-Path (Get-Location) ("artifacts\campaigns\{0}-seed-{1}.json" -f $campaign.Id, $seed)
        Invoke-CargoStep "campaign run: $($campaign.Id), seed $seed" @(
            'run', '-p', 'lab-cli', '--', 'campaign', 'run', '--campaign', $campaign.Id, '--seed', $seed
        )
        Invoke-CargoStep "campaign replay: $($campaign.Id), seed $seed" @(
            'run', '-p', 'lab-cli', '--', 'campaign', 'replay', '--report', $campaignReport
        )
        $campaignPayload = Get-Content -LiteralPath $campaignReport -Raw | ConvertFrom-Json
        if ([string]::IsNullOrEmpty([string]$campaignPayload.report.provenance.actual_response_digest) -or
            [string]::IsNullOrEmpty([string]$campaignPayload.report.provenance.actual_truth_digest) -or
            @($campaignPayload.report.provenance.campaign_operators).Count -eq 0 -or
            @($campaignPayload.report.audit | Where-Object { -not [string]::IsNullOrEmpty([string]$_.response_digest) }).Count -eq 0) {
            throw "campaign $($campaign.Id), seed $seed did not record actual mutated response/truth provenance and source audit evidence"
        }
        $campaignReports += $campaignPayload
        $campaignArtifacts += $campaignReport
    }
    if ($campaignReports[0].manifest.fixture_digest -eq $campaignReports[1].manifest.fixture_digest -and
        $campaignReports[0].report.provenance.actual_response_digest -eq $campaignReports[1].report.provenance.actual_response_digest) {
        throw "campaign $($campaign.Id) did not change its fixture or actual response digest across two required seeds"
    }
}

$campaignTamperSource = $campaignArtifacts[0]
$campaignTamperReport = Join-Path (Split-Path -Parent $campaignTamperSource) 'campaign-report-intentional-tamper.json'
$campaignTamperPayload = Get-Content -LiteralPath $campaignTamperSource -Raw | ConvertFrom-Json
$campaignTamperPayload.manifest.fixture_digest = 'sha256:' + (('0' * 64) -join '')
[System.IO.File]::WriteAllText(
    $campaignTamperReport,
    ($campaignTamperPayload | ConvertTo-Json -Depth 100),
    $utf8NoBom
)
try {
    Invoke-ExpectedCargoFailure 'campaign replay provenance tamper gate' @(
        'run', '-p', 'lab-cli', '--', 'campaign', 'replay', '--report', $campaignTamperReport
    ) 'campaign replay: mismatch'
}
finally {
    Remove-Item -LiteralPath $campaignTamperReport -Force -ErrorAction SilentlyContinue
}

Invoke-CargoStep 'coverage matrix JSON' @(
    'run', '-p', 'lab-cli', '--', 'coverage', '--format', 'json', '--output', 'artifacts/coverage.json'
)
Invoke-CargoStep 'coverage matrix Markdown' @(
    'run', '-p', 'lab-cli', '--', 'coverage', '--format', 'markdown', '--output', 'artifacts/coverage.md'
)
Invoke-CargoStep 'coverage completeness check' @('run', '-p', 'lab-cli', '--', 'coverage', '--check')
Invoke-CoveragePolicyNegativeChecks

Invoke-CargoStep 'V1.4 logical baseline generation' @(
    'run', '-p', 'lab-cli', '--', 'baseline', 'generate', '--profile', 'v1.4-core'
)
Invoke-CargoStep 'V1.4 logical baseline comparison' @(
    'run', '-p', 'lab-cli', '--', 'baseline', 'check'
)

Invoke-CargoStep 'large dataset stress verification' @(
    'run', '-p', 'lab-cli', '--', 'run', '--scenario', '019-large-dataset', '--profile', 'stress'
)
Invoke-CargoStep 'V1.3 quota concurrency stress verification (100,000 unique records)' @(
    'run', '-p', 'lab-cli', '--', 'conformance', '--scenario', '090-quota-concurrent-atomicity'
)

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
$fixtureDifferenceReport = Join-Path (Split-Path -Parent $v14StrictReport) '091-fixture-intentional-difference.json'
$fixturePayload = Get-Content -LiteralPath $v14StrictReport -Raw | ConvertFrom-Json
$fixturePayload.provenance.fixture_digest = 'sha256:' + (('0' * 64) -join '')
[System.IO.File]::WriteAllText(
    $fixtureDifferenceReport,
    ($fixturePayload | ConvertTo-Json -Depth 100),
    $utf8NoBom
)
try {
    Invoke-ExpectedCargoFailure 'strict replay fixture or mutation explanation' @(
        'run', '-p', 'lab-cli', '--', 'replay', '--strict', '--report', $fixtureDifferenceReport
    ) 'provenance: fixture_or_mutation_changed'
}
finally {
    Remove-Item -LiteralPath $fixtureDifferenceReport -Force -ErrorAction SilentlyContinue
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
$releaseSoakPath = Join-Path (Get-Location) 'artifacts\soak\release-seed-11100.json'
if (-not (Test-Path -LiteralPath $releaseSoakPath)) {
    throw 'release soak report was not created'
}
$releaseSoakReport = Get-Content -LiteralPath $releaseSoakPath -Raw | ConvertFrom-Json
Assert-ReleaseSoakReport $releaseSoakReport
Invoke-ReleaseSoakNegativeChecks $releaseSoakReport
Invoke-CargoStep "repeat verification ($Repeat rounds)" @(
    'run', '-p', 'lab-cli', '--', 'repeat', '--count', $Repeat
)
Invoke-NetworkIsolationCheck
Invoke-GitRangeCheck

$consoleVerificationDirectory = Join-Path (Get-Location) 'artifacts\console'
[System.IO.Directory]::CreateDirectory($consoleVerificationDirectory) | Out-Null
$consoleVerificationSummary = [ordered]@{
    schema_version = 1
    status = 'passed'
    completed_at = [DateTime]::UtcNow.ToString('o')
    command = ".\\scripts\\verify.ps1 -Repeat $Repeat"
    repeat = $Repeat
    scenario_count = 114
    release_soak_operations = [int]$releaseSoakReport.operations
}
[System.IO.File]::WriteAllText(
    (Join-Path $consoleVerificationDirectory 'verification-summary.json'),
    ($consoleVerificationSummary | ConvertTo-Json),
    $utf8NoBom
)

Write-Host 'Verification completed successfully. Reports are in artifacts/reports/.'
