#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonW = Join-Path $Root '.venv\Scripts\pythonw.exe'
if (-not (Test-Path $PythonW)) {
    throw 'Run start_huc.bat once before installing the persistent guard.'
}
$Action = New-ScheduledTaskAction -Execute $PythonW -Argument '-m huc.guard' -WorkingDirectory $Root
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'HUCGuard' -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName 'HUCGuard'
Write-Host 'HUC Guard installed and started.' -ForegroundColor Green
