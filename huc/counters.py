from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class WindowsProcessCounters:
    cpu_percent: float | None = None
    working_set_mb: float | None = None
    io_read_mbps: float | None = None
    io_write_mbps: float | None = None


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
                "SELECT IDProcess,PercentProcessorTime,WorkingSet,"
                f"IOReadBytesPersec,IOWriteBytesPersec FROM {self._class_name}"
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
                try:
                    io_read = float(row.IOReadBytesPersec) / 1024 / 1024
                except Exception:
                    io_read = None
                try:
                    io_write = float(row.IOWriteBytesPersec) / 1024 / 1024
                except Exception:
                    io_write = None
                result[pid] = WindowsProcessCounters(
                    cpu_percent=cpu,
                    working_set_mb=working_set,
                    io_read_mbps=io_read,
                    io_write_mbps=io_write,
                )
        except Exception as exc:
            self._error = f"WMI process sample failed: {exc}"
        return result


@dataclass(frozen=True)
class CounterAssessment:
    state: str
    details: str
    mismatches: int
    checks: int


def relative_mismatch(
    a: float | None,
    b: float | None,
    *,
    absolute_floor: float,
    relative_limit: float,
) -> bool:
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
    psutil_io_read_mbps: float | None = None,
    windows_io_read_mbps: float | None = None,
    psutil_io_write_mbps: float | None = None,
    windows_io_write_mbps: float | None = None,
    network_events_lost: int = 0,
) -> CounterAssessment:
    issues: list[str] = []
    checks = 0

    if windows_cpu is not None:
        checks += 1
        if relative_mismatch(psutil_cpu, windows_cpu, absolute_floor=15.0, relative_limit=0.45):
            issues.append(
                f"CPU disagreement psutil={psutil_cpu:.1f}% Windows={windows_cpu:.1f}%"
            )

    if windows_ram_mb is not None:
        checks += 1
        if relative_mismatch(
            psutil_ram_mb,
            windows_ram_mb,
            absolute_floor=64.0,
            relative_limit=0.20,
        ):
            issues.append(
                f"RAM disagreement psutil={psutil_ram_mb:.0f}MB Windows={windows_ram_mb:.0f}MB"
            )

    if gpu_primary is not None and gpu_secondary is not None:
        checks += 1
        if relative_mismatch(
            gpu_primary,
            gpu_secondary,
            absolute_floor=20.0,
            relative_limit=0.50,
        ):
            issues.append(
                f"GPU disagreement Windows={gpu_primary:.0f}% vendor={gpu_secondary:.0f}%"
            )

    if windows_io_read_mbps is not None and psutil_io_read_mbps is not None:
        checks += 1
        if relative_mismatch(
            psutil_io_read_mbps,
            windows_io_read_mbps,
            absolute_floor=1.0,
            relative_limit=0.60,
        ):
            issues.append(
                f"I/O read disagreement psutil={psutil_io_read_mbps:.2f}MB/s "
                f"Windows={windows_io_read_mbps:.2f}MB/s"
            )

    if windows_io_write_mbps is not None and psutil_io_write_mbps is not None:
        checks += 1
        if relative_mismatch(
            psutil_io_write_mbps,
            windows_io_write_mbps,
            absolute_floor=1.0,
            relative_limit=0.60,
        ):
            issues.append(
                f"I/O write disagreement psutil={psutil_io_write_mbps:.2f}MB/s "
                f"Windows={windows_io_write_mbps:.2f}MB/s"
            )

    if network_events_lost > 0:
        checks += 1
        issues.append(f"ETW lost {network_events_lost} event(s)")

    if issues:
        return CounterAssessment("CHECK", "; ".join(issues), len(issues), checks)
    if checks:
        return CounterAssessment(
            "OK",
            "Independent counters agree within tolerance.",
            0,
            checks,
        )
    return CounterAssessment(
        "LIMITED",
        "Not enough independent counters are available to verify this process.",
        0,
        0,
    )
