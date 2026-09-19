# HUC — Hardware Usage Controller

HUC is a Windows-first local process monitor and executable blocker.

## v0.1

- Live per-process CPU %, RAM MB, disk read/write MB/s and thread count
- NVIDIA per-process GPU utilization when `nvidia-smi` is available
- Full executable path and “Open file location”
- End a selected process
- Persistent blocklist using exact executable path + SHA-256
- Optional HUC Guard scheduled task that starts at logon and terminates matching blocked executables
- Built-in uninstaller plus standalone `uninstall_huc.ps1`
- Protected-process denylist for core Windows components
- Blocklist: `%ProgramData%\HUC\blocklist.json`
- Guard log: `%ProgramData%\HUC\guard.log`

## Run

Requires Windows 10/11 and Python 3.11+.

1. Clone/download the repo.
2. Double-click `start_huc.bat`.

Or:

~~~powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m huc
~~~

## Persistent guard

Run HUC at least once. Then open PowerShell as Administrator in the repo folder:

~~~powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install_guard.ps1
~~~

Remove it with:

~~~powershell
.\uninstall_guard.ps1
~~~

### What “BAN” means

v0.1 uses a user-space watchdog. It detects a running executable by path or SHA-256 and terminates it quickly. It does not install a kernel driver or modify Windows security policy, so the blocked executable can technically begin executing briefly before termination.

Strict pre-execution blocking with AppLocker/WDAC is planned as an optional future mode.

## GPU notes

NVIDIA GPU usage is sampled through `nvidia-smi pmon` when available. AMD/Intel per-process GPU support is planned.

## Safety

HUC refuses to block core process names including `csrss.exe`, `wininit.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`, and `svchost.exe`.

## Roadmap

- AMD/Intel Windows GPU counter support
- Per-process network throughput via ETW
- Signed publisher / signature verification
- Parent process tree and startup origin
- Hardware history graphs
- Counter cross-check / suspicious-reporting mode
- Optional AppLocker/WDAC rule generation
- Packaged Windows executable

MIT licensed.
