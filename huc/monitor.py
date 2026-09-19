from __future__ import annotations

import time
from dataclasses import dataclass

import psutil

from .blocklist import BlockList
from .gpu import NvidiaGpuSampler


@dataclass
class ProcessUsage:
    pid: int
    name: str
    cpu_percent: float
    ram_mb: float
    gpu_percent: float | None
    gpu_mem_percent: float | None
    disk_read_mbps: float
    disk_write_mbps: float
    threads: int
    path: str
    blocked: bool


class ProcessSampler:
    def __init__(self, blocklist: BlockList | None = None) -> None:
        self.blocklist = blocklist or BlockList()
        self.gpu = NvidiaGpuSampler()
        self._last_io: dict[int, tuple[float, int, int]] = {}
        self._known: dict[int, psutil.Process] = {}

    @property
    def gpu_source(self) -> str:
        return "NVIDIA nvidia-smi" if self.gpu.available else "Unavailable"

    def sample(self) -> list[ProcessUsage]:
        now = time.monotonic()
        gpu = self.gpu.sample()
        rows: list[ProcessUsage] = []
        live_pids: set[int] = set()

        for proc in psutil.process_iter(["pid", "name", "exe", "memory_info", "num_threads"]):
            pid = proc.info["pid"]
            live_pids.add(pid)
            try:
                if pid not in self._known:
                    proc.cpu_percent(None)
                    self._known[pid] = proc
                    cpu = 0.0
                else:
                    cpu = max(0.0, proc.cpu_percent(None))

                mem = proc.info.get("memory_info")
                ram_mb = (mem.rss / 1024 / 1024) if mem else 0.0
                path = proc.info.get("exe") or ""
                name = proc.info.get("name") or str(pid)
                threads = int(proc.info.get("num_threads") or 0)

                read_rate = write_rate = 0.0
                try:
                    io = proc.io_counters()
                    previous = self._last_io.get(pid)
                    if previous:
                        dt = max(0.001, now - previous[0])
                        read_rate = max(0, io.read_bytes - previous[1]) / dt / 1024 / 1024
                        write_rate = max(0, io.write_bytes - previous[2]) / dt / 1024 / 1024
                    self._last_io[pid] = (now, io.read_bytes, io.write_bytes)
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    pass

                g = gpu.get(pid)
                rows.append(ProcessUsage(
                    pid=pid,
                    name=name,
                    cpu_percent=cpu,
                    ram_mb=ram_mb,
                    gpu_percent=g.utilization if g else None,
                    gpu_mem_percent=g.memory_utilization if g else None,
                    disk_read_mbps=read_rate,
                    disk_write_mbps=write_rate,
                    threads=threads,
                    path=path,
                    blocked=self.blocklist.path_blocked(path),
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue

        stale = set(self._known) - live_pids
        for pid in stale:
            self._known.pop(pid, None)
            self._last_io.pop(pid, None)
        return rows
