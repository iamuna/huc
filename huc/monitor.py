from __future__ import annotations

import time
from dataclasses import dataclass

import psutil

from .blocklist import BlockList
from .counters import WindowsProcessCounterSampler, assess_counters
from .gpu import GpuSampler
from .network import NetworkEtwSampler


@dataclass
class ProcessUsage:
    pid: int
    name: str
    cpu_percent: float
    ram_mb: float
    gpu_percent: float | None
    gpu_mem_mb: float | None
    net_down_mbps: float
    net_up_mbps: float
    io_read_mbps: float
    io_write_mbps: float
    threads: int
    verification_state: str
    verification_details: str
    path: str
    blocked: bool


class ProcessSampler:
    def __init__(self, blocklist: BlockList | None = None) -> None:
        self.blocklist = blocklist or BlockList()
        self.gpu = GpuSampler()
        self.network = NetworkEtwSampler()
        self.windows = WindowsProcessCounterSampler()
        self._last_io: dict[int, tuple[float, int, int]] = {}
        self._known: dict[int, psutil.Process] = {}

    @property
    def gpu_source(self) -> str:
        return self.gpu.source

    @property
    def network_source(self) -> str:
        health = self.network.health
        if not health.available:
            return f"Unavailable ({health.error or 'ETW not started'})"
        if health.events_lost:
            return f"{health.source} ({health.events_lost} lost)"
        return health.source

    @property
    def verification_source(self) -> str:
        return self.windows.source

    def sample(self) -> list[ProcessUsage]:
        now = time.monotonic()
        gpu = self.gpu.sample()
        network = self.network.sample()
        windows = self.windows.sample()
        net_health = self.network.health

        rows: list[ProcessUsage] = []
        live_pids: set[int] = set()

        for proc in psutil.process_iter(["pid", "name", "exe", "memory_info", "num_threads"]):
            pid = proc.info["pid"]
            live_pids.add(pid)
            try:
                first_cpu_sample = pid not in self._known
                if first_cpu_sample:
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
                io_available = False
                try:
                    io = proc.io_counters()
                    previous = self._last_io.get(pid)
                    if previous:
                        dt = max(0.001, now - previous[0])
                        read_rate = max(0, io.read_bytes - previous[1]) / dt / 1024 / 1024
                        write_rate = max(0, io.write_bytes - previous[2]) / dt / 1024 / 1024
                        io_available = True
                    self._last_io[pid] = (now, io.read_bytes, io.write_bytes)
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    pass

                g = gpu.get(pid)
                n = network.get(pid)
                w = windows.get(pid)

                gpu_primary = g.utilization if g else None
                gpu_secondary = (
                    g.vendor_utilization
                    if g and g.source.startswith("Windows GPU Engine")
                    else None
                )
                net_down = n.download_mbps if n else 0.0
                net_up = n.upload_mbps if n else 0.0
                lost_for_process = (
                    net_health.events_lost
                    if n and (n.sent_bytes > 0 or n.received_bytes > 0)
                    else 0
                )

                assessment = assess_counters(
                    psutil_cpu=cpu,
                    windows_cpu=None if first_cpu_sample or w is None else w.cpu_percent,
                    psutil_ram_mb=ram_mb,
                    windows_ram_mb=w.working_set_mb if w else None,
                    gpu_primary=gpu_primary,
                    gpu_secondary=gpu_secondary,
                    psutil_io_read_mbps=read_rate if io_available else None,
                    windows_io_read_mbps=w.io_read_mbps if w else None,
                    psutil_io_write_mbps=write_rate if io_available else None,
                    windows_io_write_mbps=w.io_write_mbps if w else None,
                    network_events_lost=lost_for_process,
                )

                rows.append(
                    ProcessUsage(
                        pid=pid,
                        name=name,
                        cpu_percent=cpu,
                        ram_mb=ram_mb,
                        gpu_percent=gpu_primary,
                        gpu_mem_mb=(
                            (g.dedicated_mb or 0.0) + (g.shared_mb or 0.0)
                            if g and (g.dedicated_mb is not None or g.shared_mb is not None)
                            else None
                        ),
                        net_down_mbps=net_down,
                        net_up_mbps=net_up,
                        io_read_mbps=read_rate,
                        io_write_mbps=write_rate,
                        threads=threads,
                        verification_state=assessment.state,
                        verification_details=assessment.details,
                        path=path,
                        blocked=self.blocklist.path_blocked(path),
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue

        stale = set(self._known) - live_pids
        for pid in stale:
            self._known.pop(pid, None)
            self._last_io.pop(pid, None)
        return rows

    def close(self) -> None:
        self.network.close()
