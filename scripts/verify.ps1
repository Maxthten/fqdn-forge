[CmdletBinding()]
param(
    [switch]$Stress
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

Invoke-CargoStep 'format check' @('fmt', '--all', '--', '--check')
Invoke-CargoStep 'clippy' @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings')
Invoke-CargoStep 'workspace tests' @('test', '--workspace', '--all-targets')
Invoke-CargoStep 'scenario validation' @('run', '-p', 'lab-cli', '--', 'validate')
Invoke-CargoStep 'all scenario regression' @('run', '-p', 'lab-cli', '--', 'run', '--all')
Invoke-CargoStep 'negative self-test' @('run', '-p', 'lab-cli', '--', 'self-test')

if ($Stress) {
    Invoke-CargoStep 'large dataset stress verification' @(
        'run', '-p', 'lab-cli', '--', 'run', '--scenario', '019-large-dataset', '--profile', 'stress'
    )
}

Write-Host 'Verification completed successfully. Reports are in artifacts/reports/.'
