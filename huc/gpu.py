from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class GpuUsage:
    utilization: float | None = None
    memory_utilization: float | None = None


class NvidiaGpuSampler:
    """Best-effort per-process NVIDIA sampler using nvidia-smi pmon."""

    def __init__(self) -> None:
        self.executable = shutil.which("nvidia-smi")

    @property
    def available(self) -> bool:
        return bool(self.executable)

    def sample(self) -> dict[int, GpuUsage]:
        if not self.executable:
            return {}
        try:
            cp = subprocess.run(
                [self.executable, "pmon", "-c", "1", "-s", "um"],
                capture_output=True,
                text=True,
                timeout=2.5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError):
            return {}
        if cp.returncode != 0:
            return {}

        result: dict[int, GpuUsage] = {}
        for raw in cp.stdout.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"\s+", line)
            if len(parts) < 6:
                continue
            try:
                pid = int(parts[1])
            except ValueError:
                continue
            if pid <= 0:
                continue

            def pct(token: str) -> float | None:
                try:
                    return float(token) if token != "-" else None
                except ValueError:
                    return None

            result[pid] = GpuUsage(
                utilization=pct(parts[3]),
                memory_utilization=pct(parts[4]),
            )
        return result
