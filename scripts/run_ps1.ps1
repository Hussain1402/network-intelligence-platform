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

function Invoke-Checked {
    param([string]$Description, [scriptblock]$Command)
    Write-Host "`n========== $Description ==========" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

Invoke-Checked "CONFIGURE CMAKE" {
    cmake -S . -B build
}
Invoke-Checked "BUILD FUNCTIONLOG TARGETS" {
    cmake --build build --target functionlog_c_demo functionlog_cpp_demo
}
Invoke-Checked "RUN C FUNCTIONLOG DEMO" {
    .\build\functionlog_c_demo.exe
}
Invoke-Checked "RUN C++ FUNCTIONLOG DEMO" {
    .\build\functionlog_cpp_demo.exe
}
Invoke-Checked "RUN FUNCTIONLOG MOCK INVESTIGATOR" {
    & $Python .\python\functionlog_mock_ai.py `
        .\output\function_execution_evidence.json `
        .\output\function_execution_ai_report.json
}
Invoke-Checked "VALIDATE FUNCTIONLOG JSON" {
    & $Python -m json.tool .\output\function_execution_evidence.json > $null
    & $Python -m json.tool .\output\function_execution_ai_report.json > $null
}

Write-Host "`nPS1 examples and investigation completed." -ForegroundColor Green
