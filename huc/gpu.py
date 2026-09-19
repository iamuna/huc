from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass


_PID_RE = re.compile(r"(?:^|_)pid_(\d+)(?:_|$)", re.IGNORECASE)


def parse_gpu_instance_pid(name: str | None) -> int | None:
    if not name:
        return None
    match = _PID_RE.search(str(name))
    if not match:
        return None
    try:
        pid = int(match.group(1))
    except ValueError:
        return None
    return pid if pid > 0 else None


@dataclass(frozen=True)
class GpuUsage:
    utilization: float | None = None
    dedicated_mb: float | None = None
    shared_mb: float | None = None
    vendor_utilization: float | None = None
    source: str = ""


class NvidiaGpuSampler:
    """Best-effort NVIDIA cross-check using nvidia-smi pmon."""

    def __init__(self) -> None:
        self.executable = shutil.which("nvidia-smi")

    @property
    def available(self) -> bool:
        return bool(self.executable)

    def sample(self) -> dict[int, float]:
        if not self.executable:
            return {}
        try:
            cp = subprocess.run(
                [self.executable, "pmon", "-c", "1", "-s", "u"],
                capture_output=True,
                text=True,
                timeout=2.5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError):
            return {}
        if cp.returncode != 0:
            return {}

        result: dict[int, float] = {}
        for raw in cp.stdout.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"\s+", line)
            if len(parts) < 5:
                continue
            try:
                pid = int(parts[1])
                sm = None if parts[3] == "-" else float(parts[3])
                mem = None if parts[4] == "-" else float(parts[4])
            except ValueError:
                continue
            if pid <= 0:
                continue
            values = [v for v in (sm, mem) if v is not None]
            if values:
                result[pid] = max(values)
        return result


class WindowsGpuSampler:
    """Vendor-neutral GPU counters exposed by Windows PerfLib/WMI."""

    ENGINE_CLASS = "Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine"
    MEMORY_CLASS = "Win32_PerfFormattedData_GPUPerformanceCounters_GPUProcessMemory"

    def __init__(self) -> None:
        self._service = None
        self._error = ""
        if os.name == "nt":
            self._connect()

    def _connect(self) -> None:
        try:
            import win32com.client

            self._service = win32com.client.GetObject(
                r"winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2"
            )
            self._service.ExecQuery(
                f"SELECT Name,UtilizationPercentage FROM {self.ENGINE_CLASS}"
            )
        except Exception as exc:
            self._service = None
            self._error = f"Windows GPU counters unavailable: {exc}"

    @property
    def available(self) -> bool:
        return self._service is not None

    @property
    def error(self) -> str:
        return self._error

    def sample(self) -> dict[int, GpuUsage]:
        if not self.available:
            return {}

        engines: dict[int, list[float]] = {}
        memory: dict[int, list[float]] = {}
        try:
            rows = self._service.ExecQuery(
                f"SELECT Name,UtilizationPercentage FROM {self.ENGINE_CLASS}"
            )
            for row in rows:
                pid = parse_gpu_instance_pid(getattr(row, "Name", ""))
                if pid is None:
                    continue
                try:
                    value = float(row.UtilizationPercentage)
                except Exception:
                    continue
                engines.setdefault(pid, []).append(max(0.0, value))

            try:
                mem_rows = self._service.ExecQuery(
                    f"SELECT Name,DedicatedUsage,SharedUsage FROM {self.MEMORY_CLASS}"
                )
                for row in mem_rows:
                    pid = parse_gpu_instance_pid(getattr(row, "Name", ""))
                    if pid is None:
                        continue
                    try:
                        dedicated = float(row.DedicatedUsage) / 1024 / 1024
                    except Exception:
                        dedicated = 0.0
                    try:
                        shared = float(row.SharedUsage) / 1024 / 1024
                    except Exception:
                        shared = 0.0
                    current = memory.setdefault(pid, [0.0, 0.0])
                    current[0] += max(0.0, dedicated)
                    current[1] += max(0.0, shared)
            except Exception:
                pass
        except Exception as exc:
            self._error = f"Windows GPU sample failed: {exc}"
            return {}

        result: dict[int, GpuUsage] = {}
        for pid in set(engines) | set(memory):
            # A process may use several GPU engines simultaneously. For a Task-Manager-like
            # 0..100 column use the busiest engine, while retaining memory independently.
            utilization = max(engines.get(pid, [0.0])) if engines.get(pid) else None
            dedicated, shared = memory.get(pid, [0.0, 0.0])
            result[pid] = GpuUsage(
                utilization=utilization,
                dedicated_mb=dedicated,
                shared_mb=shared,
                source="Windows GPU Engine",
            )
        return result


class GpuSampler:
    """Primary Windows GPU telemetry plus optional vendor cross-check."""

    def __init__(self) -> None:
        self.windows = WindowsGpuSampler()
        self.nvidia = NvidiaGpuSampler()

    @property
    def source(self) -> str:
        parts: list[str] = []
        if self.windows.available:
            parts.append("Windows GPU Engine (AMD/Intel/NVIDIA)")
        if self.nvidia.available:
            parts.append("nvidia-smi cross-check")
        return " + ".join(parts) if parts else "Unavailable"

    def sample(self) -> dict[int, GpuUsage]:
        primary = self.windows.sample()
        vendor = self.nvidia.sample()

        if primary:
            merged: dict[int, GpuUsage] = {}
            for pid in set(primary) | set(vendor):
                win = primary.get(pid)
                if win is None:
                    merged[pid] = GpuUsage(
                        utilization=vendor.get(pid),
                        vendor_utilization=vendor.get(pid),
                        source="nvidia-smi",
                    )
                else:
                    merged[pid] = GpuUsage(
                        utilization=win.utilization,
                        dedicated_mb=win.dedicated_mb,
                        shared_mb=win.shared_mb,
                        vendor_utilization=vendor.get(pid),
                        source=win.source,
                    )
            return merged

        return {
            pid: GpuUsage(
                utilization=value,
                vendor_utilization=value,
                source="nvidia-smi",
            )
            for pid, value in vendor.items()
        }
