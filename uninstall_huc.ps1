param(
    [switch]$RemoveProgramFiles,
    [int]$WaitForPid = 0
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    $argsList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $MyInvocation.MyCommand.Path)
    )
    if ($RemoveProgramFiles) {
        $argsList += '-RemoveProgramFiles'
    }
    if ($WaitForPid -gt 0) {
        $argsList += @('-WaitForPid', $WaitForPid)
    }

    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList $argsList | Out-Null
    }
    catch {
        Write-Host 'HUC uninstall cancelled or elevation failed.' -ForegroundColor Yellow
        exit 1
    }
    exit 0
}

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$DataDir = Join-Path $env:ProgramData 'HUC'

Write-Host 'Removing HUC Guard...' -ForegroundColor Cyan
try {
    Stop-ScheduledTask -TaskName 'HUCGuard' -ErrorAction SilentlyContinue
}
catch {}

try {
    Unregister-ScheduledTask -TaskName 'HUCGuard' -Confirm:$false -ErrorAction SilentlyContinue
}
catch {}

Write-Host 'Removing HUC blocklist and logs...' -ForegroundColor Cyan
if (Test-Path $DataDir) {
    Remove-Item -LiteralPath $DataDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $RemoveProgramFiles) {
    Write-Host ''
    Write-Host 'HUC Guard and local HUC data were removed.' -ForegroundColor Green
    Write-Host 'Program files were kept.' -ForegroundColor Green
    exit 0
}

if ($WaitForPid -gt 0) {
    Write-Host "Waiting for HUC process $WaitForPid to close..." -ForegroundColor Cyan
    try {
        Wait-Process -Id $WaitForPid -Timeout 20 -ErrorAction SilentlyContinue
    }
    catch {}
}

# Never recursively delete a folder unless it looks exactly like an HUC checkout.
$Readme = Join-Path $Root 'README.md'
$Package = Join-Path $Root 'huc'
$MarkerOk = (Test-Path $Readme) -and (Test-Path $Package) -and
            ((Get-Content -LiteralPath $Readme -Raw -ErrorAction SilentlyContinue) -match 'Hardware Usage Controller')

if (-not $MarkerOk) {
    Write-Host ''
    Write-Host 'Guard/data removed, but program-folder deletion was refused.' -ForegroundColor Yellow
    Write-Host "Safety check did not recognize this directory as HUC: $Root" -ForegroundColor Yellow
    exit 2
}

# Leave the install directory before deleting it.
Set-Location $env:TEMP

Write-Host "Removing HUC program files: $Root" -ForegroundColor Cyan
for ($attempt = 1; $attempt -le 8; $attempt++) {
    try {
        if (Test-Path $Root) {
            Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction Stop
        }
        break
    }
    catch {
        Start-Sleep -Milliseconds 750
    }
}

if (Test-Path $Root) {
    Write-Host ''
    Write-Host 'HUC data/Guard were removed, but some program files are still in use.' -ForegroundColor Yellow
    Write-Host "Delete this folder after closing remaining HUC processes: $Root" -ForegroundColor Yellow
    exit 3
}

Write-Host ''
Write-Host 'HUC was fully uninstalled.' -ForegroundColor Green
exit 0
