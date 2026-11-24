param(
    [string]$InputCsv = "data/network_metrics.csv"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
$Python = (Get-Command python -ErrorAction Stop).Source

function Invoke-Checked {
    param(
        [string]$Description,
        [scriptblock]$Command
    )

    Write-Host "`n========== $Description ==========" -ForegroundColor Cyan

    & $Command

    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

Write-Host "Starting complete PS2 network investigation pipeline..." -ForegroundColor Green

Invoke-Checked "CONFIGURE CMAKE" {
    cmake -S . -B build
}

Invoke-Checked "BUILD C MODULES" {
    cmake --build build
}

Invoke-Checked "C NETWORK ANALYSIS" {
    .\build\network_pipeline_demo.exe $InputCsv output
}

Invoke-Checked "GENERATE CONSOLIDATED EVIDENCE" {
    & $Python .\python\network_evidence.py `
        .\output\network_anomaly_report.json `
        .\output\network_analytics_report.json `
        .\output\network_trend_report.json `
        .\output\ps2_investigation_evidence.json
}

Invoke-Checked "RUN PS2 MOCK AI" {
    & $Python .\python\network_mock_ai.py `
        .\output\ps2_investigation_evidence.json `
        .\output\ps2_ai_investigation_report.json
}

Invoke-Checked "VALIDATE EVIDENCE JSON" {
    & $Python -m json.tool .\output\ps2_investigation_evidence.json > $null
}

Invoke-Checked "VALIDATE INVESTIGATION JSON" {
    & $Python -m json.tool .\output\ps2_ai_investigation_report.json > $null
}

Write-Host "`n============================================" -ForegroundColor Green
Write-Host "PS2 PIPELINE COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "============================================"

Write-Host "`nFinal reports:"
Write-Host "output\network_anomaly_report.json"
Write-Host "output\network_analytics_report.json"
Write-Host "output\network_trend_report.json"
Write-Host "output\ps2_investigation_evidence.json"
Write-Host "output\ps2_ai_investigation_report.json"
