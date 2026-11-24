param(
    [ValidateSet("strict", "balanced", "report_only")]
    [string]$Profile = "balanced",
    [string]$ScanTarget,
    [switch]$ApproveRemediation
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
$PythonVenv = Join-Path $ProjectRoot ".venv-win\Scripts\python.exe"

if (Test-Path $PythonVenv) {
    $Python = $PythonVenv
}
else {
    $Python = (Get-Command python -ErrorAction Stop).Source
}

Write-Host "Using Python: $Python" -ForegroundColor Yellow

$Arguments = @(
    ".\devsecops\agent\orchestrator.py",
    "--project-root", $ProjectRoot,
    "--profile", $Profile
)

if ($ScanTarget) {
    $Arguments += @("--scan-target", $ScanTarget)
}
if ($ApproveRemediation) {
    $Arguments += "--approve-remediation"
}

& $Python @Arguments
$pythonExitCode = $LASTEXITCODE

$reportPath = Join-Path $ProjectRoot "devsecops\reports\pipeline_report.json"

if (-not (Test-Path $reportPath)) {
    throw "Pipeline report not found. Python exit code: $pythonExitCode"
}

$report = Get-Content $reportPath -Raw | ConvertFrom-Json

$validExecution = (
    $report.execution_status -eq "passed" -and
    $report.summary.failed -eq 0 -and
    $report.summary.skipped -eq 0 -and
    $report.overall_status -in @("passed", "partially_verified")
)

if ($validExecution) {
    Write-Host ""
    Write-Host "DevSecOps pipeline execution completed successfully." -ForegroundColor Green
    Write-Host "Overall status: $($report.overall_status)"
    Write-Host "Steps: $($report.summary.passed) passed, $($report.summary.failed) failed, $($report.summary.skipped) skipped"

    if ($report.overall_status -eq "partially_verified") {
        Write-Warning "Security findings remain. Manual review is still required."
    }

    $global:LASTEXITCODE = 0
}
else {
    throw (
        "DevSecOps pipeline unsuccessful. Overall status: " +
        "$($report.overall_status); execution status: " +
        "$($report.execution_status). Inspect the pipeline report."
    )
}
