# HUC — Hardware Usage Controller

HUC is a Windows-first local process monitor, hardware/network telemetry viewer, counter verifier, and executable blocker.

## v0.2

- Live per-process CPU %, RAM MB, process I/O read/write MB/s and thread count
- Vendor-neutral Windows GPU Engine monitoring for AMD, Intel, and NVIDIA
- NVIDIA `nvidia-smi` cross-check when available
- Per-process TCP/UDP upload and download rates from Windows ETW
- Independent CPU/RAM verification using Windows PerfLib/WMI counters
- Counter status per process:
  - `OK` — independent sources agree within tolerance
  - `CHECK` — meaningful counter disagreement or ETW event loss
  - `LIMITED` — not enough independent sources are available
- Full executable path and **Open file location**
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

For the richest telemetry, run HUC elevated. The per-process ETW network session can require Administrator rights depending on the Windows configuration.

## Telemetry sources

### GPU

HUC first reads Windows GPU Engine performance data through WMI/PerfLib. Those counters are provided by Windows and work across compatible AMD, Intel, and NVIDIA drivers.

On NVIDIA systems HUC also samples `nvidia-smi` and compares it with the Windows value. A large difference is surfaced as a `CHECK` result instead of silently choosing one source.

GPU memory is reported in MB from the Windows GPU Process Memory counter set.

### Network

HUC subscribes to `Microsoft-Windows-Kernel-Network` through ETW and aggregates byte counts by PID.

It tracks:

- TCP IPv4 send/receive
- TCP IPv6 send/receive
- UDP IPv4 send/receive
- UDP IPv6 send/receive

The displayed values are per-process payload throughput. They are not intended to equal exact on-the-wire Ethernet byte counts because lower-layer framing, retransmission/offload behavior, VPNs, and driver processing can differ.

If the ETW consumer reports lost events, affected network-active processes are marked `CHECK`.

### Counter verification

HUC compares independent sources where possible:

- CPU: `psutil` process time vs Windows formatted process counters
- RAM: `psutil` resident working set vs Windows working-set counters
- Process I/O: `psutil` I/O counters vs Windows formatted process I/O counters
- GPU: Windows GPU Engine vs NVIDIA vendor counters when available
- Network integrity: ETW event/buffer loss state

Counter verification is diagnostic, not proof that a program is malicious. Different APIs can have different sampling windows and definitions, so HUC uses generous tolerances before flagging disagreement.

## Persistent guard

Run HUC at least once. Then open PowerShell as Administrator in the repo folder:

~~~powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install_guard.ps1
~~~

Remove only the Guard with:

~~~powershell
.\uninstall_guard.ps1
~~~

### What “BAN” means

v0.2 uses a user-space watchdog. It detects a running executable by path or SHA-256 and terminates it quickly. It does not install a kernel driver or modify Windows security policy, so the blocked executable can technically begin executing briefly before termination.

Strict pre-execution blocking with AppLocker/WDAC is planned as an optional future mode.

## Uninstall HUC

From the GUI, click **Uninstall HUC…**. You can choose either:

- remove the Guard + HUC blocklist/logs while keeping the program files, or
- perform a full uninstall, including the local `.venv` and HUC program folder.

You can also run the standalone uninstaller from an Administrator PowerShell:

~~~powershell
.\uninstall_huc.ps1
~~~

For a full self-removal:

~~~powershell
.\uninstall_huc.ps1 -RemoveProgramFiles
~~~

## Safety

HUC refuses to block core process names including `csrss.exe`, `wininit.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`, and `svchost.exe`.

## Roadmap

- Signed publisher / Authenticode verification
- Parent process tree and startup origin
- Hardware and network history graphs
- Adapter-level network reconciliation
- Optional AppLocker/WDAC rule generation
- Packaged and signed Windows executable
- Process reputation / hash inspection integrations

MIT licensed.
