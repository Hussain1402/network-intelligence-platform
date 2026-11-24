param(
    [ValidateSet("strict", "balanced", "report_only")]
    [string]$Profile = "balanced",
    [string]$ScanTarget,
    [switch]$ApproveRemediation
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
$Python = (Get-Command python -ErrorAction Stop).Source

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
if ($LASTEXITCODE -ne 0) {
    Write-Error (
        "DevSecOps pipeline returned $LASTEXITCODE. Inspect " +
        "devsecops\reports\pipeline_report.json for blocked or failed stages."
    )
}
