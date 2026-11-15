@echo off
setlocal
set "remo_install=%~dp0"
pushd "%~dp0"
"%~dp0runtime\python.exe" -S -m support_setup uninstall -console
set "remo_result=%errorlevel%"
popd
if not "%remo_result%"=="0" exit /b %remo_result%
cd /d "%SystemRoot%"
powershell.exe -NoProfile -Command "$remo_deadline=(Get-Date).AddSeconds(35); while ((Test-Path -LiteralPath $env:remo_install) -and (Get-Date) -lt $remo_deadline) { Start-Sleep -Milliseconds 200 }; if (Test-Path -LiteralPath $env:remo_install) { Write-Host 'Removal incomplete: some installation files could not be deleted. Restart Windows and retry.'; exit 2 }; Write-Host 'Successfully removed.'; exit 0"
exit /b %errorlevel%
