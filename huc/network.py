from __future__ import annotations

import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass


SEND_EVENT_IDS = {10, 26, 42, 58}
RECV_EVENT_IDS = {11, 27, 43, 59}
NETWORK_EVENT_IDS = sorted(SEND_EVENT_IDS | RECV_EVENT_IDS)
IPV4_IPV6_KEYWORDS = 0x10 | 0x20


@dataclass(frozen=True)
class NetworkUsage:
    upload_mbps: float = 0.0
    download_mbps: float = 0.0
    sent_bytes: int = 0
    received_bytes: int = 0


@dataclass(frozen=True)
class NetworkHealth:
    source: str
    available: bool
    events_lost: int = 0
    error: str = ""

    @property
    def reliable(self) -> bool:
        return self.available and self.events_lost == 0 and not self.error


def parse_network_event(event_id: int, properties: dict, header_pid: int = 0) -> tuple[int, int, bool] | None:
    if event_id not in SEND_EVENT_IDS and event_id not in RECV_EVENT_IDS:
        return None
    try:
        pid = int(properties.get("PID") or properties.get("ProcessId") or header_pid or 0)
        size = int(properties.get("size") or properties.get("Size") or 0)
    except (TypeError, ValueError):
        return None
    if pid <= 0 or size < 0:
        return None
    return pid, size, event_id in SEND_EVENT_IDS


class NetworkEtwSampler:
    """Per-process TCP/UDP byte rates from Microsoft-Windows-Kernel-Network ETW."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._totals: dict[int, list[int]] = defaultdict(lambda: [0, 0])
        self._last_snapshot: dict[int, tuple[float, int, int]] = {}
        self._session = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._available = False
        self._error = ""
        self._events_lost = 0
        if os.name == "nt":
            self._start()

    def _start(self) -> None:
        try:
            from pyetwkit._core import EtwProvider, EtwSession
        except Exception as exc:
            self._error = f"pyetwkit unavailable: {exc}"
            return

        try:
            provider = EtwProvider(
                "7dd42a49-5329-4832-8dfd-43d979153a88",
                "Microsoft-Windows-Kernel-Network",
            )
            provider = provider.level(5).keywords_any(IPV4_IPV6_KEYWORDS).event_ids(NETWORK_EVENT_IDS)
            session = EtwSession(f"HUC-Network-{os.getpid()}")
            session.add_provider(provider)
            session.start()
            self._session = session
            self._available = True
            self._thread = threading.Thread(
                target=self._consume,
                name="HUC-Network-ETW",
                daemon=True,
            )
            self._thread.start()
        except Exception as exc:
            self._error = f"ETW start failed: {exc}"
            self._available = False

    def _consume(self) -> None:
        assert self._session is not None
        while not self._stop.is_set():
            try:
                event = self._session.next_event_timeout(250)
                if event is None:
                    self._refresh_loss_counter()
                    continue
                payload = event.to_dict().get("properties", {})
                parsed = parse_network_event(
                    int(event.event_id),
                    payload,
                    int(getattr(event, "process_id", 0) or 0),
                )
                if parsed is None:
                    continue
                pid, size, is_send = parsed
                with self._lock:
                    slot = self._totals[pid]
                    slot[0 if is_send else 1] += size
                self._refresh_loss_counter()
            except Exception as exc:
                with self._lock:
                    self._error = f"ETW consume failed: {exc}"
                break

    def _refresh_loss_counter(self) -> None:
        if self._session is None:
            return
        try:
            stats = self._session.stats()
            lost = int(getattr(stats, "events_lost", 0) or 0) + int(
                getattr(stats, "buffers_lost", 0) or 0
            )
            with self._lock:
                self._events_lost = lost
        except Exception:
            pass

    @property
    def health(self) -> NetworkHealth:
        with self._lock:
            return NetworkHealth(
                source="Windows ETW Kernel-Network",
                available=self._available,
                events_lost=self._events_lost,
                error=self._error,
            )

    def sample(self) -> dict[int, NetworkUsage]:
        now = time.monotonic()
        with self._lock:
            totals = {pid: (v[0], v[1]) for pid, v in self._totals.items()}

        result: dict[int, NetworkUsage] = {}
        for pid, (sent, received) in totals.items():
            previous = self._last_snapshot.get(pid)
            up = down = 0.0
            if previous is not None:
                dt = max(0.001, now - previous[0])
                up = max(0, sent - previous[1]) / dt / 1024 / 1024
                down = max(0, received - previous[2]) / dt / 1024 / 1024
            result[pid] = NetworkUsage(
                upload_mbps=up,
                download_mbps=down,
                sent_bytes=sent,
                received_bytes=received,
            )
            self._last_snapshot[pid] = (now, sent, received)

        stale = set(self._last_snapshot) - set(totals)
        for pid in stale:
            self._last_snapshot.pop(pid, None)
        return result

    def close(self) -> None:
        self._stop.set()
        if self._session is not None:
            try:
                self._session.stop()
            except Exception:
                pass
        self._available = False
