#Requires -RunAsAdministrator
$ErrorActionPreference = 'SilentlyContinue'
Stop-ScheduledTask -TaskName 'HUCGuard'
Unregister-ScheduledTask -TaskName 'HUCGuard' -Confirm:$false
Write-Host 'HUC Guard removed.' -ForegroundColor Green
