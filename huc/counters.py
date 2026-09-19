from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class WindowsProcessCounters:
    cpu_percent: float | None = None
    working_set_mb: float | None = None


class WindowsProcessCounterSampler:
    """Independent Windows WMI/PerfLib process counters used for verification."""

    def __init__(self) -> None:
        self._service = None
        self._class_name = ""
        self._error = ""
        if os.name == "nt":
            self._connect()

    def _connect(self) -> None:
        try:
            import win32com.client

            self._service = win32com.client.GetObject(
                r"winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2"
            )
            for class_name in (
                "Win32_PerfFormattedData_Counters_ProcessV2",
                "Win32_PerfFormattedData_PerfProc_Process",
            ):
                try:
                    self._service.ExecQuery(f"SELECT * FROM {class_name}")
                    self._class_name = class_name
                    return
                except Exception:
                    continue
            self._error = "No formatted process counter class available"
        except Exception as exc:
            self._error = f"WMI unavailable: {exc}"

    @property
    def available(self) -> bool:
        return self._service is not None and bool(self._class_name)

    @property
    def source(self) -> str:
        return f"Windows PerfLib/WMI ({self._class_name})" if self.available else "Unavailable"

    @property
    def error(self) -> str:
        return self._error

    def sample(self) -> dict[int, WindowsProcessCounters]:
        if not self.available:
            return {}
        result: dict[int, WindowsProcessCounters] = {}
        try:
            rows = self._service.ExecQuery(
                f"SELECT IDProcess,PercentProcessorTime,WorkingSet FROM {self._class_name}"
            )
            for row in rows:
                try:
                    pid = int(row.IDProcess)
                except Exception:
                    continue
                if pid < 0:
                    continue
                try:
                    cpu = float(row.PercentProcessorTime)
                except Exception:
                    cpu = None
                try:
                    working_set = float(row.WorkingSet) / 1024 / 1024
                except Exception:
                    working_set = None
                result[pid] = WindowsProcessCounters(cpu, working_set)
        except Exception as exc:
            self._error = f"WMI process sample failed: {exc}"
        return result


@dataclass(frozen=True)
class CounterAssessment:
    state: str
    details: str
    mismatches: int
    checks: int


def relative_mismatch(a: float | None, b: float | None, *, absolute_floor: float, relative_limit: float) -> bool:
    if a is None or b is None:
        return False
    delta = abs(a - b)
    scale = max(abs(a), abs(b), 1.0)
    return delta > max(absolute_floor, scale * relative_limit)


def assess_counters(
    *,
    psutil_cpu: float,
    windows_cpu: float | None,
    psutil_ram_mb: float,
    windows_ram_mb: float | None,
    gpu_primary: float | None,
    gpu_secondary: float | None,
    network_events_lost: int = 0,
) -> CounterAssessment:
    issues: list[str] = []
    checks = 0

    if windows_cpu is not None:
        checks += 1
        if relative_mismatch(psutil_cpu, windows_cpu, absolute_floor=15.0, relative_limit=0.45):
            issues.append(f"CPU disagreement psutil={psutil_cpu:.1f}% Windows={windows_cpu:.1f}%")

    if windows_ram_mb is not None:
        checks += 1
        if relative_mismatch(psutil_ram_mb, windows_ram_mb, absolute_floor=64.0, relative_limit=0.20):
            issues.append(f"RAM disagreement psutil={psutil_ram_mb:.0f}MB Windows={windows_ram_mb:.0f}MB")

    if gpu_primary is not None and gpu_secondary is not None:
        checks += 1
        if relative_mismatch(gpu_primary, gpu_secondary, absolute_floor=20.0, relative_limit=0.50):
            issues.append(f"GPU disagreement Windows={gpu_primary:.0f}% vendor={gpu_secondary:.0f}%")

    if network_events_lost > 0:
        checks += 1
        issues.append(f"ETW lost {network_events_lost} event(s)")

    if issues:
        return CounterAssessment("CHECK", "; ".join(issues), len(issues), checks)
    if checks:
        return CounterAssessment("OK", "Independent counters agree within tolerance.", 0, checks)
    return CounterAssessment("LIMITED", "Not enough independent counters are available to verify this process.", 0, 0)
